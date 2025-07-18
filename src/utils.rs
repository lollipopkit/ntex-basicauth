//! Utility functions and helper types

use crate::{Credentials, BasicAuth, BasicAuthConfig, UserValidator, AuthError, AuthResult};
use ntex::web::{HttpRequest, WebRequest};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

#[cfg(feature = "regex")]
use regex::Regex;

#[cfg(feature = "cache")]
use crate::cache::CacheConfig;

#[cfg(feature = "regex")]
use std::sync::OnceLock;

#[cfg(feature = "regex")]
static REGEX_CACHE: OnceLock<dashmap::DashMap<String, Regex>> = OnceLock::new();

/// Extract authenticated user credentials from request
pub fn extract_credentials(req: &HttpRequest) -> Option<Credentials> {
    req.extensions().get::<Credentials>().cloned()
}

/// Extract authenticated user credentials from WebRequest
pub fn extract_credentials_web<T>(req: &WebRequest<T>) -> Option<Credentials> {
    req.extensions().get::<Credentials>().cloned()
}

/// Get authenticated username from request
pub fn get_username(req: &HttpRequest) -> Option<String> {
    extract_credentials(req).map(|creds| creds.username.clone())
}

/// Check if current user matches a specific username
pub fn is_user(req: &HttpRequest, username: &str) -> bool {
    get_username(req).is_some_and(|user| user == username)
}

/// Path filter for conditional authentication
#[derive(Debug, Clone)]
pub struct PathFilter {
    patterns: Vec<PathPattern>,
}

#[derive(Debug, Clone)]
enum PathPattern {
    Exact(String),
    Prefix(String),
    Suffix(String),
    #[cfg(feature = "regex")]
    Regex(Regex),
}

impl PathFilter {
    /// Create a new PathFilter instance
    pub fn new() -> Self {
        Self {
            patterns: Vec::new(),
        }
    }

    /// Skip authentication for exact path
    pub fn skip_exact<P: Into<String>>(mut self, path: P) -> Self {
        self.patterns.push(PathPattern::Exact(path.into()));
        self
    }

    /// Skip authentication for paths with prefix
    pub fn skip_prefix<P: Into<String>>(mut self, prefix: P) -> Self {
        self.patterns.push(PathPattern::Prefix(prefix.into()));
        self
    }

    /// Skip authentication for paths with suffix
    pub fn skip_suffix<P: Into<String>>(mut self, suffix: P) -> Self {
        self.patterns.push(PathPattern::Suffix(suffix.into()));
        self
    }

    /// Skip authentication for paths matching regex pattern
    /// Requires "regex" feature
    #[cfg(feature = "regex")]
    pub fn skip_regex<P: AsRef<str>>(mut self, pattern: P) -> Result<Self, regex::Error> {
        let regex = Self::get_cached_regex(pattern.as_ref())?;
        self.patterns.push(PathPattern::Regex(regex));
        Ok(self)
    }

    /// Get cached regex pattern for better performance
    #[cfg(feature = "regex")]
    fn get_cached_regex(pattern: &str) -> Result<Regex, regex::Error> {
        let cache = REGEX_CACHE.get_or_init(|| dashmap::DashMap::new());
        
        if let Some(regex) = cache.get(pattern) {
            Ok(regex.clone())
        } else {
            let regex = Regex::new(pattern)?;
            cache.insert(pattern.to_string(), regex.clone());
            Ok(regex)
        }
    }

    /// Skip authentication for regex pattern (feature disabled version)
    #[cfg(not(feature = "regex"))]
    pub fn skip_regex<P: Into<String>>(self, _pattern: P) -> Result<Self, AuthError> {
        Err(AuthError::ConfigError("regex feature not enabled. Please use: features = [\"regex\"]".to_string()))
    }

    /// Skip authentication for multiple exact paths
    pub fn skip_paths<I, P>(mut self, paths: I) -> Self 
    where 
        I: IntoIterator<Item = P>,
        P: Into<String>,
    {
        for path in paths {
            self.patterns.push(PathPattern::Exact(path.into()));
        }
        self
    }

    /// Skip authentication for multiple prefixes
    pub fn skip_prefixes<I, P>(mut self, prefixes: I) -> Self 
    where 
        I: IntoIterator<Item = P>,
        P: Into<String>,
    {
        for prefix in prefixes {
            self.patterns.push(PathPattern::Prefix(prefix.into()));
        }
        self
    }

    /// Skip authentication for multiple suffixes
    pub fn skip_suffixes<I, P>(mut self, suffixes: I) -> Self 
    where 
        I: IntoIterator<Item = P>,
        P: Into<String>,
    {
        for suffix in suffixes {
            self.patterns.push(PathPattern::Suffix(suffix.into()));
        }
        self
    }

    /// Check if path should skip authentication
    pub fn should_skip(&self, path: &str) -> bool {
        self.patterns.iter().any(|pattern| match pattern {
            PathPattern::Exact(exact) => path == exact,
            PathPattern::Prefix(prefix) => path.starts_with(prefix),
            PathPattern::Suffix(suffix) => path.ends_with(suffix),
            #[cfg(feature = "regex")]
            PathPattern::Regex(regex) => regex.is_match(path),
        })
    }

    /// Get number of patterns
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    /// Check if filter is empty
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Get all exact match paths
    pub fn exact_paths(&self) -> Vec<&str> {
        self.patterns.iter()
            .filter_map(|pattern| match pattern {
                PathPattern::Exact(path) => Some(path.as_str()),
                _ => None,
            })
            .collect()
    }

    /// Get all prefixes
    pub fn prefixes(&self) -> Vec<&str> {
        self.patterns.iter()
            .filter_map(|pattern| match pattern {
                PathPattern::Prefix(prefix) => Some(prefix.as_str()),
                _ => None,
            })
            .collect()
    }

    /// Clear all patterns
    pub fn clear(mut self) -> Self {
        self.patterns.clear();
        self
    }

    /// Remove a specific exact path pattern
    pub fn remove_exact_path(mut self, path: &str) -> Self {
        self.patterns.retain(|pattern| {
            !matches!(pattern, PathPattern::Exact(p) if p == path)
        });
        self
    }
}

impl Default for PathFilter {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for BasicAuth, provides extra convenience methods
pub struct BasicAuthBuilder {
    users: Option<HashMap<String, String>>,
    validator: Option<Arc<dyn UserValidator>>,
    realm: Option<String>,
    #[cfg(feature = "cache")]
    cache_config: Option<CacheConfig>,
    path_filter: Option<PathFilter>,
    max_header_size: Option<usize>,
    log_failures: bool,
    case_sensitive: bool,
    // New enhanced configuration fields
    max_concurrent_validations: Option<usize>,
    validation_timeout: Option<Duration>,
    rate_limit_per_ip: Option<(usize, Duration)>,
    enable_metrics: bool,
    log_usernames_in_production: bool,
}

impl BasicAuthBuilder {
    /// Create a new BasicAuthBuilder instance
    pub fn new() -> Self {
        Self {
            users: None,
            validator: None,
            realm: None,
            #[cfg(feature = "cache")]
            cache_config: None,
            path_filter: None,
            max_header_size: None,
            log_failures: false,
            case_sensitive: true,
            max_concurrent_validations: None,
            validation_timeout: None,
            rate_limit_per_ip: None,
            enable_metrics: true,
            log_usernames_in_production: false,
        }
    }

    /// Add a single user
    pub fn user<U: Into<String>, P: Into<String>>(mut self, username: U, password: P) -> Self {
        let users = self.users.get_or_insert_with(HashMap::new);
        users.insert(username.into(), password.into());
        self
    }

    /// Add multiple users from HashMap
    pub fn users(mut self, users: HashMap<String, String>) -> Self {
        match &mut self.users {
            Some(existing) => existing.extend(users),
            None => self.users = Some(users),
        }
        self
    }

    /// Add users from iterator
    pub fn users_from_iter<I, U, P>(mut self, users: I) -> Self 
    where
        I: IntoIterator<Item = (U, P)>,
        U: Into<String>,
        P: Into<String>,
    {
        let mut users_map = self.users.get_or_insert_with(HashMap::new).clone();
        for (username, password) in users {
            users_map.insert(username.into(), password.into());
        }
        self.users = Some(users_map);
        self
    }

    /// Load users from file (format: username:password, one per line)
    pub fn users_from_file<P: AsRef<std::path::Path>>(mut self, path: P) -> AuthResult<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| AuthError::ConfigError(format!("Failed to read user file: {}", e)))?;
        
        let mut users_map = self.users.get_or_insert_with(HashMap::new).clone();
        
        for (line_num, line) in content.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue; // Skip empty lines and comments
            }
            
            let colon_pos = line.find(':')
                .ok_or_else(|| AuthError::ConfigError(
                    format!("User file line {} format error: missing colon separator", line_num + 1)
                ))?;
            
            let username = line[..colon_pos].trim().to_string();
            let password = line[colon_pos + 1..].trim().to_string();
            
            // Allow empty usernames per RFC 7617
            if !is_valid_username(&username) {
                return Err(AuthError::ConfigError(
                    format!("User file line {} format error: invalid username format", line_num + 1)
                ));
            }
            
            dbg!("Loaded user: {}   {}", &username, &password);
            users_map.insert(username, password);
        }
        self.users = Some(users_map);
        
        Ok(self)
    }

    /// Set custom validator
    pub fn validator(mut self, validator: Arc<dyn UserValidator>) -> Self {
        self.validator = Some(validator);
        self
    }

    /// Set authentication realm
    pub fn realm<R: Into<String>>(mut self, realm: R) -> Self {
        self.realm = Some(realm.into());
        self
    }

    /// Set username case sensitivity
    pub fn case_sensitive(mut self, sensitive: bool) -> Self {
        self.case_sensitive = sensitive;
        self
    }

    /// Enable authentication cache
    #[cfg(feature = "cache")]
    pub fn with_cache(mut self, config: CacheConfig) -> Self {
        self.cache_config = Some(config);
        self
    }

    /// Disable authentication cache
    #[cfg(feature = "cache")]
    pub fn disable_cache(mut self) -> Self {
        self.cache_config = None;
        self
    }

    /// Set cache TTL (seconds)
    #[cfg(feature = "cache")]
    pub fn cache_ttl_seconds(mut self, seconds: u64) -> Self {
        let config = self.cache_config.take().unwrap_or_default();
        self.cache_config = Some(config.ttl_seconds(seconds));
        self
    }

    /// Set cache TTL (minutes, convenience)
    #[cfg(feature = "cache")]
    pub fn cache_ttl_minutes(self, minutes: u64) -> Self {
        self.cache_ttl_seconds(minutes * 60)
    }

    /// Set cache TTL (hours, convenience)
    #[cfg(feature = "cache")]
    pub fn cache_ttl_hours(self, hours: u64) -> Self {
        self.cache_ttl_seconds(hours * 3600)
    }

    /// Set cache size limit
    #[cfg(feature = "cache")]
    pub fn cache_size_limit(mut self, limit: usize) -> Self {
        let config = self.cache_config.take().unwrap_or_default();
        self.cache_config = Some(config.max_size(limit));
        self
    }

    /// Set path filter
    pub fn path_filter(mut self, filter: PathFilter) -> Self {
        self.path_filter = Some(filter);
        self
    }

    /// Configure path filter (builder pattern)
    pub fn configure_paths<F>(mut self, configure: F) -> Self 
    where 
        F: FnOnce(PathFilter) -> PathFilter,
    {
        let filter = self.path_filter.take().unwrap_or_default();
        self.path_filter = Some(configure(filter));
        self
    }

    /// Add skip paths (convenience)
    pub fn skip_paths<I, P>(mut self, paths: I) -> Self 
    where 
        I: IntoIterator<Item = P>,
        P: Into<String>,
    {
        let mut filter = self.path_filter.take().unwrap_or_default();
        filter = filter.skip_paths(paths);
        self.path_filter = Some(filter);
        self
    }

    /// Set request header size limit
    pub fn max_header_size(mut self, size: usize) -> Self {
        self.max_header_size = Some(size);
        self
    }

    /// Enable authentication failure logging
    pub fn log_failures(mut self, enabled: bool) -> Self {
        self.log_failures = enabled;
        self
    }

    /// Set maximum concurrent validations
    pub fn max_concurrent_validations(mut self, max: usize) -> Self {
        self.max_concurrent_validations = Some(max);
        self
    }

    /// Set validation timeout
    pub fn validation_timeout(mut self, timeout: Duration) -> Self {
        self.validation_timeout = Some(timeout);
        self
    }

    /// Set rate limiting per IP
    pub fn rate_limit_per_ip(mut self, max_requests: usize, window: Duration) -> Self {
        self.rate_limit_per_ip = Some((max_requests, window));
        self
    }

    /// Enable or disable metrics collection
    pub fn enable_metrics(mut self, enabled: bool) -> Self {
        self.enable_metrics = enabled;
        self
    }

    /// Enable or disable logging usernames in production (security risk)
    pub fn log_usernames_in_production(mut self, enabled: bool) -> Self {
        self.log_usernames_in_production = enabled;
        self
    }

    /// Build BasicAuth instance
    pub fn build(self) -> AuthResult<BasicAuth> {
        let validator = if let Some(validator) = self.validator {
            validator
        } else if let Some(users) = self.users {
            use crate::auth::StaticUserValidator;
            Arc::new(if self.case_sensitive {
                StaticUserValidator::from_map(users)
            } else {
                StaticUserValidator::from_map_case_insensitive(users)
            })
        } else {
            return Err(AuthError::ConfigError(
                "A validator or user list must be provided".to_string()
            ));
        };

        let mut config = BasicAuthConfig::new(validator);
        
        if let Some(realm) = self.realm {
            config = config.realm(realm);
        }
        
        #[cfg(feature = "cache")]
        {
            if let Some(cache_config) = self.cache_config {
                config = config.with_cache(cache_config)?;
            }
        }

        if let Some(filter) = self.path_filter {
            config = config.path_filter(filter);
        }

        if let Some(size) = self.max_header_size {
            config = config.max_header_size(size);
        }

        config = config.log_failures(self.log_failures);

        // Apply new enhanced configuration options
        if let Some(max_concurrent) = self.max_concurrent_validations {
            config = config.max_concurrent_validations(max_concurrent);
        }

        if let Some(timeout) = self.validation_timeout {
            config = config.validation_timeout(timeout);
        }

        if let Some((max_requests, window)) = self.rate_limit_per_ip {
            config = config.rate_limit_per_ip(max_requests, window);
        }

        config = config.enable_metrics(self.enable_metrics);
        config = config.log_usernames_in_production(self.log_usernames_in_production);

        BasicAuth::new(config)
    }

    /// Build and wrap error handling
    pub fn try_build(self) -> AuthResult<BasicAuth> {
        self.build()
    }
}

impl Default for BasicAuthBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience macro for creating PathFilter
#[macro_export]
macro_rules! path_filter {
    // Only exact match
    (exact: [$($path:expr),* $(,)?]) => {
        {
            let mut filter = $crate::PathFilter::new();
            $(
                filter = filter.skip_exact($path);
            )*
            filter
        }
    };
    
    // Only prefix match
    (prefix: [$($prefix:expr),* $(,)?]) => {
        {
            let mut filter = $crate::PathFilter::new();
            $(
                filter = filter.skip_prefix($prefix);
            )*
            filter
        }
    };
    
    // Only suffix match
    (suffix: [$($suffix:expr),* $(,)?]) => {
        {
            let mut filter = $crate::PathFilter::new();
            $(
                filter = filter.skip_suffix($suffix);
            )*
            filter
        }
    };
    
    // Mixed mode
    (
        $(exact: [$($exact:expr),* $(,)?])?
        $(prefix: [$($prefix:expr),* $(,)?])?
        $(suffix: [$($suffix:expr),* $(,)?])?
        $(regex: [$($regex:expr),* $(,)?])?
    ) => {
        {
            let mut filter = $crate::PathFilter::new();
            
            $($(
                filter = filter.skip_exact($exact);
            )*)?
            
            $($(
                filter = filter.skip_prefix($prefix);
            )*)?
            
            $($(
                filter = filter.skip_suffix($suffix);
            )*)?
            
            #[cfg(feature = "regex")]
            $($(
                filter = filter.skip_regex($regex).expect("Invalid regex pattern");
            )*)?
            
            filter
        }
    };
}

/// Validate if username format is valid
pub fn is_valid_username(username: &str) -> bool {
    !username.contains(':') && 
    !username.contains('\n') &&
    !username.contains('\r') &&
    username.len() <= 255 && // Reasonable length limit
    username.chars().all(|c| c.is_ascii_graphic() || c == ' ')
}

/// Create a PathFilter with common skip paths
pub(crate) fn common_skip_paths() -> PathFilter {
    PathFilter::new()
        .skip_paths([
            "/health",
            "/healthcheck", 
            "/ping",
            "/status",
            "/metrics",
            "/favicon.ico"
        ])
        .skip_prefixes([
            "/static/",
            "/assets/",
            "/public/",
            "/.well-known/"
        ])
        .skip_suffixes([
            ".css",
            ".js",
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".ico",
            ".svg",
            ".woff",
            ".woff2",
            ".ttf",
            ".eot"
        ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_filter_comprehensive() {
        let filter = PathFilter::new()
            .skip_exact("/health")
            .skip_prefix("/public/")
            .skip_suffix(".css")
            .skip_paths(["/api/status", "/metrics"]);

        assert!(filter.should_skip("/health"));
        assert!(filter.should_skip("/public/images/logo.png"));
        assert!(filter.should_skip("/assets/style.css"));
        assert!(filter.should_skip("/api/status"));
        assert!(filter.should_skip("/metrics"));
        assert!(!filter.should_skip("/api/users"));
        assert!(!filter.should_skip("/healthcheck"));
    }

    #[cfg(feature = "regex")]
    #[test]
    fn test_regex_path_filter() {
        let filter = PathFilter::new()
            .skip_regex(r"^/api/v\d+/public/.*$")
            .expect("Valid regex");

        assert!(filter.should_skip("/api/v1/public/data"));
        assert!(filter.should_skip("/api/v2/public/files"));
        assert!(!filter.should_skip("/api/v1/private/data"));
        assert!(!filter.should_skip("/api/public/data"));
    }

    #[test]
    fn test_builder_comprehensive() {
        let auth = BasicAuthBuilder::new()
            .user("admin", "secret")
            .user("user", "password")
            .users_from_iter([("guest", "guest123")])
            .realm("Test Application")
            .skip_paths(["/health", "/metrics"])
            .log_failures(true)
            .case_sensitive(false)
            .max_header_size(4096)
            .build()
            .expect("Valid configuration");

        assert_eq!(auth.config.realm, "Test Application");
        assert_eq!(auth.config.max_header_size, 4096);
        assert!(auth.config.log_failures);
    }

    #[test]
    fn test_common_skip_paths() {
        let filter = common_skip_paths();
        
        assert!(filter.should_skip("/health"));
        assert!(filter.should_skip("/static/css/main.css"));
        assert!(filter.should_skip("/favicon.ico"));
        assert!(filter.should_skip("/public/images/logo.png"));
        assert!(filter.should_skip("/.well-known/acme-challenge/test"));
        assert!(!filter.should_skip("/api/users"));
    }

    #[test]
    fn test_username_validation() {
        assert!(is_valid_username("admin"));
        assert!(is_valid_username("user123"));
        assert!(is_valid_username("test user")); // contains space
        
        // Now allows empty username per RFC 7617
        assert!(is_valid_username(""));
        assert!(!is_valid_username("user:name")); // contains colon
        assert!(!is_valid_username("user\nname")); // contains newline
        assert!(!is_valid_username(&"a".repeat(256))); // too long
    }

    #[test]
    fn test_builder_from_file() -> std::io::Result<()> {
        use std::io::Write;
        
        // Create temporary file
        let mut temp_file = tempfile::NamedTempFile::new()?;
        writeln!(temp_file, "# This is a comment")?;
        writeln!(temp_file, "admin:secret")?;
        writeln!(temp_file, "user:password:with:colons")?;
        writeln!(temp_file, "")?; // empty line
        writeln!(temp_file, "guest:guest123")?;
        
        let builder = BasicAuthBuilder::new()
            .users_from_file(temp_file.path())
            .expect("Failed to load users from file");
        
        let auth = builder.build().expect("Failed to build authentication");
        
        // Verify users are loaded correctly
        let validator = auth.config.validator.as_ref();
        dbg!("User validator: {:?}", validator);
        assert_eq!(validator.user_count(), 3);
        
        Ok(())
    }

    #[test]
    fn test_path_filter_modification() {
        let filter = PathFilter::new()
            .skip_exact("/health")
            .skip_exact("/status");
        
        assert_eq!(filter.pattern_count(), 2);
        
        let filter = filter.remove_exact_path("/health");
        assert_eq!(filter.pattern_count(), 1);
        
        let filter = filter.clear();
        assert_eq!(filter.pattern_count(), 0);
        assert!(filter.is_empty());
    }
}