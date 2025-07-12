use crate::{Credentials, BasicAuth, BasicAuthConfig, UserValidator};
use ntex::web::{HttpRequest, WebRequest};
use std::collections::HashMap;
use std::sync::Arc;

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
    #[allow(dead_code)]
    Regex(String), // Store as string for simplicity
}

impl PathFilter {
    pub fn new() -> Self {
        Self {
            patterns: Vec::new(),
        }
    }

    /// Skip authentication for exact path match
    pub fn skip_exact(mut self, path: &str) -> Self {
        self.patterns.push(PathPattern::Exact(path.to_string()));
        self
    }

    /// Skip authentication for paths with prefix
    pub fn skip_prefix(mut self, prefix: &str) -> Self {
        self.patterns.push(PathPattern::Prefix(prefix.to_string()));
        self
    }

    /// Skip authentication for paths with suffix
    pub fn skip_suffix(mut self, suffix: &str) -> Self {
        self.patterns.push(PathPattern::Suffix(suffix.to_string()));
        self
    }

    /// Check if path should skip authentication
    pub fn should_skip(&self, path: &str) -> bool {
        self.patterns.iter().any(|pattern| match pattern {
            PathPattern::Exact(exact) => path == exact,
            PathPattern::Prefix(prefix) => path.starts_with(prefix),
            PathPattern::Suffix(suffix) => path.ends_with(suffix),
            PathPattern::Regex(_) => false, // TODO: implement regex matching
        })
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
    cache_enabled: bool,
    cache_size_limit: usize,
    path_filter: Option<PathFilter>,
}

impl BasicAuthBuilder {
    pub fn new() -> Self {
        Self {
            users: None,
            validator: None,
            realm: None,
            cache_enabled: true,
            cache_size_limit: 1000,
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
        self.users = Some(users);
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
    pub fn disable_cache(mut self) -> Self {
        self.cache_enabled = false;
        self
    }

    /// Set cache size limit
    pub fn cache_size_limit(mut self, limit: usize) -> Self {
        self.cache_size_limit = limit;
        self
    }

    /// Set path filter for conditional authentication
    pub fn path_filter(mut self, filter: PathFilter) -> Self {
        self.path_filter = Some(filter);
        self
    }

    /// Build BasicAuth instance
    pub fn build(self) -> Result<BasicAuth, &'static str> {
        let validator = if let Some(validator) = self.validator {
            validator
        } else if let Some(users) = self.users {
            use crate::auth::StaticUserValidator;
            Arc::new(StaticUserValidator::from_map(users))
        } else {
            return Err("Either validator or users must be provided");
        };

        let mut config = BasicAuthConfig::new(validator);
        
        if let Some(realm) = self.realm {
            config = config.realm(realm);
        }
        
        if !self.cache_enabled {
            config = config.disable_cache();
        }
        
        config = config.cache_size_limit(self.cache_size_limit);

        Ok(BasicAuth::new(config))
    }
}

impl Default for BasicAuthBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_filter() {
        let filter = PathFilter::new()
            .skip_exact("/health")
            .skip_prefix("/public/")
            .skip_suffix(".css");

        assert!(filter.should_skip("/health"));
        assert!(filter.should_skip("/public/images/logo.png"));
        assert!(filter.should_skip("/assets/style.css"));
        assert!(!filter.should_skip("/api/users"));
        assert!(!filter.should_skip("/healthcheck"));
    }
}