//! # ntex-basicauth
//!
//! Secure and high-performance Basic Authentication middleware for the [ntex](https://github.com/ntex-rs/ntex) web framework.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use ntex::web;
//! use ntex_basicauth::BasicAuthBuilder;
//! use std::collections::HashMap;
//!
//! #[ntex::main]
//! async fn main() -> std::io::Result<()> {
//!
//!     web::HttpServer::new(move || {
//!         // Create authentication middleware
//!         let auth = BasicAuthBuilder::new()
//!             .user("admin", "secret")
//!             .user("user", "password")
//!             .realm("My Application")
//!             .build()
//!             .expect("Failed to configure authentication");
//!         web::App::new()
//!             .wrap(auth)
//!             .route("/protected", web::get().to(protected_handler))
//!             .route("/public", web::get().to(public_handler))
//!     })
//!     .bind("127.0.0.1:8080")?
//!     .run()
//!     .await
//! }
//!
//! async fn protected_handler() -> &'static str {
//!     "This is protected content!"
//! }
//!
//! async fn public_handler() -> &'static str {
//!     "This is public content"
//! }
//! ```
//!
//! ## Feature Flags
//!
//! - `json` (enabled by default): JSON error response support
//! - `cache` (enabled by default): Authentication result caching
//! - `regex` (enabled by default): Regex path matching
//! - `timing-safe` (enabled by default): Timing-safe password comparison
//! - `bcrypt`: BCrypt password hash support
//! - `tokio` (enabled by default): Tokio async runtime support

#![doc(html_root_url = "https://docs.rs/ntex-basicauth/")]
#![warn(missing_docs)]
#![warn(clippy::all)]
#![forbid(unsafe_code)]

mod auth;
mod error;
mod utils;

#[cfg(feature = "cache")]
mod cache;

// 核心类型导出
pub use auth::{BasicAuth, BasicAuthConfig, Credentials, StaticUserValidator, UserValidator};
pub use error::{AuthError, AuthResult};
pub use utils::{
    BasicAuthBuilder, PathFilter, common_skip_paths, extract_credentials, extract_credentials_web,
    get_username, is_user, is_valid_username,
};

// 条件特性导出
#[cfg(feature = "bcrypt")]
pub use auth::BcryptUserValidator;

#[cfg(feature = "cache")]
pub use cache::{AuthCache, CacheConfig, CacheStats};

// 为了保持向后兼容性的别名
pub use auth::BasicAuth as BasicAuthMiddleware;

/// Prelude module, includes common types and traits
///
/// ```rust
/// use ntex_basicauth::prelude::*;
/// ```
pub mod prelude {
    pub use crate::{
        AuthError, AuthResult, BasicAuth, BasicAuthBuilder, BasicAuthConfig, Credentials,
        PathFilter, StaticUserValidator, UserValidator, extract_credentials, get_username, is_user,
    };

    #[cfg(feature = "bcrypt")]
    pub use crate::BcryptUserValidator;

    #[cfg(feature = "cache")]
    pub use crate::{AuthCache, CacheConfig};
}

/// Convenience function to create BasicAuth with a single user
///
/// # Example
///
/// ```rust
/// use ntex_basicauth::single_user_auth;
///
/// let auth = single_user_auth("admin", "secret", "My App").unwrap();
/// ```
pub fn single_user_auth(username: &str, password: &str, realm: &str) -> AuthResult<BasicAuth> {
    BasicAuthBuilder::new()
        .user(username, password)
        .realm(realm)
        .build()
}

/// Convenience function to create BasicAuth with multiple users
///
/// # Example
///
/// ```rust
/// use ntex_basicauth::multi_user_auth;
/// use std::collections::HashMap;
///
/// let mut users = HashMap::new();
/// users.insert("admin".to_string(), "secret".to_string());
/// users.insert("user".to_string(), "password".to_string());
///
/// let auth = multi_user_auth(users, "My App").unwrap();
/// ```
pub fn multi_user_auth(
    users: std::collections::HashMap<String, String>,
    realm: &str,
) -> AuthResult<BasicAuth> {
    BasicAuthBuilder::new().users(users).realm(realm).build()
}

/// Convenience function to create BasicAuth with common skip path rules
///
/// # Example
///
/// ```rust
/// use ntex_basicauth::auth_with_common_skips;
/// use std::collections::HashMap;
///
/// let mut users = HashMap::new();
/// users.insert("admin".to_string(), "secret".to_string());
///
/// let auth = auth_with_common_skips(users, "My App").unwrap();
/// ```
pub fn auth_with_common_skips(
    users: std::collections::HashMap<String, String>,
    realm: &str,
) -> AuthResult<BasicAuth> {
    BasicAuthBuilder::new()
        .users(users)
        .realm(realm)
        .path_filter(common_skip_paths())
        .build()
}

#[cfg(feature = "bcrypt")]
/// Convenience function to create BasicAuth using BCrypt
///
/// # Example
///
/// ```rust
/// use ntex_basicauth::bcrypt_auth;
/// use std::collections::HashMap;
///
/// let mut users = HashMap::new();
/// users.insert("admin".to_string(), "$2b$12$...".to_string()); // BCrypt hash
///
/// let auth = bcrypt_auth(users, "My App").unwrap();
/// ```
pub fn bcrypt_auth(
    users: std::collections::HashMap<String, String>,
    realm: &str,
) -> AuthResult<BasicAuth> {
    let validator = std::sync::Arc::new(auth::BcryptUserValidator::from_hashes(users));
    let config = BasicAuthConfig::new(validator).realm(realm.to_string());
    BasicAuth::new(config)
}

/// Version info
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Get library version info
pub fn version() -> &'static str {
    VERSION
}

/// Library detailed info
pub struct LibInfo {
    /// Version
    pub version: &'static str,
    /// Package name
    pub name: &'static str,
    /// Description
    pub description: &'static str,
    /// Authors
    pub authors: &'static str,
    /// Enabled features
    pub enabled_features: Vec<&'static str>,
}

/// Get library detailed info
pub fn lib_info() -> LibInfo {
    let mut features = Vec::new();

    #[cfg(feature = "json")]
    features.push("json");

    #[cfg(feature = "cache")]
    features.push("cache");

    #[cfg(feature = "regex")]
    features.push("regex");

    #[cfg(feature = "timing-safe")]
    features.push("timing-safe");

    #[cfg(feature = "bcrypt")]
    features.push("bcrypt");

    LibInfo {
        version: VERSION,
        name: env!("CARGO_PKG_NAME"),
        description: env!("CARGO_PKG_DESCRIPTION"),
        authors: env!("CARGO_PKG_AUTHORS"),
        enabled_features: features,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_single_user_auth() {
        let auth = single_user_auth("admin", "secret", "Test").unwrap();
        assert_eq!(auth.config.realm, "Test");
    }

    #[tokio::test]
    async fn test_multi_user_auth() {
        let mut users = HashMap::new();
        users.insert("admin".to_string(), "secret".to_string());
        users.insert("user".to_string(), "password".to_string());

        let auth = multi_user_auth(users, "Test App").unwrap();
        assert_eq!(auth.config.realm, "Test App");
    }

    #[tokio::test]
    async fn test_auth_with_common_skips() {
        let mut users = HashMap::new();
        users.insert("admin".to_string(), "secret".to_string());

        let auth = auth_with_common_skips(users, "Test").unwrap();
        assert!(auth.config.path_filter.is_some());

        let filter = auth.config.path_filter.as_ref().unwrap();
        assert!(filter.should_skip("/health"));
        assert!(filter.should_skip("/static/css/main.css"));
        assert!(!filter.should_skip("/api/users"));
    }

    #[cfg(feature = "bcrypt")]
    #[tokio::test]
    async fn test_bcrypt_auth() {
        let mut users = HashMap::new();
        // This is a sample BCrypt hash for the password "secret"
        users.insert(
            "admin".to_string(),
            "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj6QJEo4m7HS".to_string(),
        );

        let auth = bcrypt_auth(users, "Test").unwrap();
        assert_eq!(auth.config.realm, "Test");
    }

    #[test]
    fn test_version_info() {
        let version = version();
        assert!(!version.is_empty());

        let info = lib_info();
        assert_eq!(info.version, version);
        assert_eq!(info.name, "ntex-basicauth");
        assert!(!info.enabled_features.is_empty());
    }

    #[test]
    fn test_lib_info_features() {
        let info = lib_info();

        // Check if all expected features are enabled
        assert!(info.enabled_features.contains(&"json"));
        assert!(info.enabled_features.contains(&"cache"));
        assert!(info.enabled_features.contains(&"regex"));
        assert!(info.enabled_features.contains(&"timing-safe"));

        println!("Enabled features: {:?}", info.enabled_features);
    }

    #[test]
    fn test_prelude_imports() {
        use crate::prelude::*;

        // Check if prelude imports work correctly
        let _builder = BasicAuthBuilder::new();
        let _filter = PathFilter::new();
        let _error = AuthError::MissingHeader;
    }
}

/// Examples and documentation test module
#[cfg(doctest)]
mod doctests {
    /// Basic usage example
    ///
    /// ```rust
    /// use ntex_basicauth::{BasicAuthBuilder, PathFilter};
    /// use std::collections::HashMap;
    ///
    /// // Create user list
    /// let mut users = HashMap::new();
    /// users.insert("admin".to_string(), "secret".to_string());
    /// users.insert("user".to_string(), "password".to_string());
    ///
    /// // Build authentication middleware
    /// let auth = BasicAuthBuilder::new()
    ///     .users(users)
    ///     .realm("My Application")
    ///     .log_failures(true)
    ///     .skip_paths(["/health", "/metrics"])
    ///     .build()
    ///     .expect("Failed to configure authentication");
    /// ```
    fn _basic_usage() {}

    /// Advanced configuration example
    ///
    /// ```rust
    /// use ntex_basicauth::{BasicAuthBuilder, PathFilter, common_skip_paths};
    ///
    /// let auth = BasicAuthBuilder::new()
    ///     .user("admin", "secret")
    ///     .realm("Admin Panel")
    ///     .case_sensitive(false)
    ///     .max_header_size(4096)
    ///     .path_filter(common_skip_paths())
    ///     .build()
    ///     .expect("Configuration failed");
    /// ```
    #[cfg(feature = "cache")]
    fn _advanced_config() {}

    /// Cache configuration example
    ///
    /// ```rust,no_run
    /// use ntex_basicauth::{BasicAuthBuilder, CacheConfig};
    /// use std::time::Duration;
    ///
    /// let cache_config = CacheConfig::new()
    ///     .max_size(1000)
    ///     .ttl_minutes(10)
    ///     .cleanup_interval_seconds(300);
    ///
    /// let auth = BasicAuthBuilder::new()
    ///     .user("admin", "secret")
    ///     .with_cache(cache_config)
    ///     .build()
    ///     .expect("Configuration failed");
    /// ```
    #[cfg(feature = "cache")]
    fn _cache_config() {}
}
