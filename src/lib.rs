mod auth;
mod error;
mod utils;

#[cfg(feature = "cache")]
mod cache;

pub use auth::{BasicAuth, BasicAuthConfig, Credentials, UserValidator, StaticUserValidator};
pub use error::{AuthError, AuthResult};
pub use utils::{
    extract_credentials, extract_credentials_web, get_username, is_user, get_username_ref,
    PathFilter, BasicAuthBuilder
};

#[cfg(feature = "bcrypt")]
pub use auth::BcryptUserValidator;

#[cfg(feature = "cache")]
pub use cache::{CacheConfig, AuthCache};

// Re-export for convenience
pub use auth::BasicAuth as BasicAuthMiddleware;

/// Prelude module for convenient imports
pub mod prelude {
    pub use crate::{
        BasicAuth, BasicAuthBuilder, BasicAuthConfig, Credentials, 
        PathFilter, AuthError, AuthResult
    };
    
    #[cfg(feature = "bcrypt")]
    pub use crate::BcryptUserValidator;
}