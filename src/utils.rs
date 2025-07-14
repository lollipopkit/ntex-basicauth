use crate::{Credentials, BasicAuth, BasicAuthConfig, UserValidator};
use ntex::web::{HttpRequest, WebRequest};
use std::collections::HashMap;
use std::sync::Arc;

#[cfg(feature = "regex")]
use regex::Regex;

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
    extract_credentials(req).map(|creds| creds.username)
}

/// Check if current user matches a specific username
pub fn is_user(req: &HttpRequest, username: &str) -> bool {
    get_username(req).map_or(false, |user| user == username)
}

/// Get authenticated username as &str from request (more efficient for comparisons)
pub fn get_username_ref(req: &HttpRequest) -> Option<String> {
    req.extensions().get::<Credentials>().map(|creds| creds.username.clone())
}

/// Path filter for conditional authentication
#[derive(Debug, Clone)]
pub struct PathFilter {
    pub(crate) patterns: Vec<PathPattern>,
}

#[derive(Debug, Clone)]
pub(crate) enum PathPattern {
    Exact(String),
    Prefix(String),
    Suffix(String),
    #[cfg(feature = "regex")]
    Regex(Regex),
}

impl PathFilter {
    pub fn new() -> Self {
        Self {
            patterns: Vec::new(),
        }
    }

    /// Skip authentication for exact path match
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
        let regex = Regex::new(pattern.as_ref())?;
        self.patterns.push(PathPattern::Regex(regex));
        Ok(self)
    }

    /// Skip authentication for paths matching regex pattern (feature disabled version)
    #[cfg(not(feature = "regex"))]
    pub fn skip_regex<P: Into<String>>(self, pattern: P) -> Result<Self, &'static str> {
        let _ = pattern;
        Err("Regex feature is not enabled. Enable with: features = [\"regex\"]")
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

    /// Check if path should skip authentication
    pub fn should_skip(&self, path: &str) -> bool {
        self.patterns.iter().any(|pattern| match pattern {
            PathPattern::Exact(exact) => path == exact,
            PathPattern::Prefix(prefix) => path.starts_with(prefix),
            PathPattern::Suffix(suffix) => path.ends_with(suffix),
            #[cfg(feature = "regex")]
            PathPattern::Regex(regex) => regex.is_match(path),
            #[cfg(not(feature = "regex"))]
            PathPattern::Regex(_) => false,
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
}

impl Default for PathFilter {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for BasicAuth with additional convenience methods
pub struct BasicAuthBuilder {
    users: Option<HashMap<String, String>>,
    validator: Option<Arc<dyn UserValidator>>,
    realm: Option<String>,
    #[cfg(feature = "cache")]
    cache_enabled: bool,
    #[cfg(feature = "cache")]
    cache_size_limit: usize,
    #[cfg(feature = "cache")]
    cache_ttl_seconds: u64,
    path_filter: Option<PathFilter>,
}

impl BasicAuthBuilder {
    pub fn new() -> Self {
        Self {
            users: None,
            validator: None,
            realm: None,
            #[cfg(feature = "cache")]
            cache_enabled: true,
            #[cfg(feature = "cache")]
            cache_size_limit: 1000,
            #[cfg(feature = "cache")]
            cache_ttl_seconds: 300,
            path_filter: None,
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
        let users_map = self.users.get_or_insert_with(HashMap::new);
        for (username, password) in users {
            users_map.insert(username.into(), password.into());
        }
        self
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

    /// Disable authentication cache
    #[cfg(feature = "cache")]
    pub fn disable_cache(mut self) -> Self {
        self.cache_enabled = false;
        self
    }

    /// Enable authentication cache (default)
    #[cfg(feature = "cache")]
    pub fn enable_cache(mut self) -> Self {
        self.cache_enabled = true;
        self
    }

    /// Set cache size limit
    #[cfg(feature = "cache")]
    pub fn cache_size_limit(mut self, limit: usize) -> Self {
        self.cache_size_limit = limit;
        self
    }

    /// Set cache TTL in seconds
    #[cfg(feature = "cache")]
    pub fn cache_ttl_seconds(mut self, seconds: u64) -> Self {
        self.cache_ttl_seconds = seconds;
        self
    }

    /// Set cache TTL in minutes (convenience method)
    #[cfg(feature = "cache")]
    pub fn cache_ttl_minutes(self, minutes: u64) -> Self {
        self.cache_ttl_seconds(minutes * 60)
    }

    /// Set cache TTL in hours (convenience method)
    #[cfg(feature = "cache")]
    pub fn cache_ttl_hours(self, hours: u64) -> Self {
        self.cache_ttl_seconds(hours * 3600)
    }

    /// Set path filter for conditional authentication
    pub fn path_filter(mut self, filter: PathFilter) -> Self {
        self.path_filter = Some(filter);
        self
    }

    /// Configure path filter with builder pattern
    pub fn configure_paths<F>(mut self, configure: F) -> Self 
    where 
        F: FnOnce(PathFilter) -> PathFilter,
    {
        let filter = self.path_filter.take().unwrap_or_default();
        self.path_filter = Some(configure(filter));
        self
    }

    /// Add skip paths (convenience method)
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

    /// Build BasicAuth instance
    pub fn build(self) -> Result<BasicAuth, crate::error::AuthError> {
        let validator = if let Some(validator) = self.validator {
            validator
        } else if let Some(users) = self.users {
            use crate::auth::StaticUserValidator;
            Arc::new(StaticUserValidator::from_map(users))
        } else {
            return Err(crate::error::AuthError::ConfigError(
                "Either validator or users must be provided".to_string()
            ));
        };

        let mut config = BasicAuthConfig::new(validator);
        
        if let Some(realm) = self.realm {
            config = config.realm(realm);
        }
        
        #[cfg(feature = "cache")]
        {
            if !self.cache_enabled {
                config = config.disable_cache();
            }
            config = config.cache_size_limit(self.cache_size_limit);
            config = config.cache_ttl(self.cache_ttl_seconds);
        }

        if let Some(filter) = self.path_filter {
            config = config.path_filter(filter);
        }

        Ok(BasicAuth::new(config))
    }

    /// Build and wrap with error handling
    pub fn try_build(self) -> crate::error::AuthResult<BasicAuth> {
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
    (exact: [$($path:expr),*]) => {
        {
            let mut filter = $crate::PathFilter::new();
            $(
                filter = filter.skip_exact($path);
            )*
            filter
        }
    };
    (prefix: [$($prefix:expr),*]) => {
        {
            let mut filter = $crate::PathFilter::new();
            $(
                filter = filter.skip_prefix($prefix);
            )*
            filter
        }
    };
    (suffix: [$($suffix:expr),*]) => {
        {
            let mut filter = $crate::PathFilter::new();
            $(
                filter = filter.skip_suffix($suffix);
            )*
            filter
        }
    };
    (
        $(exact: [$($exact:expr),*])?
        $(prefix: [$($prefix:expr),*])?
        $(suffix: [$($suffix:expr),*])?
        $(regex: [$($regex:expr),*])?
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
            .build()
            .expect("Valid configuration");

        // Test that it was built successfully
        assert_eq!(auth.config.realm, "Test Application");
    }

    #[test]
    fn test_macro_path_filter() {
        let _filter = path_filter!(
            exact: ["/health", "/status"]
            prefix: ["/public/", "/assets/"]
            suffix: [".css", ".js"]
        );

        // Test that macro compiles and creates valid filter
    }

    #[cfg(feature = "cache")]
    #[test]
    fn test_builder_cache_configuration() {
        let auth = BasicAuthBuilder::new()
            .user("test", "password")
            .cache_ttl_minutes(10)
            .cache_size_limit(500)
            .build()
            .expect("Valid configuration");

        assert_eq!(auth.config.cache_ttl_seconds, 600); // 10 minutes
        assert_eq!(auth.config.cache_size_limit, 500);
    }
}