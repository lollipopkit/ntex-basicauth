use crate::error::{AuthError, AuthResult};
use base64::{engine::general_purpose::STANDARD, Engine};
use dashmap::DashMap;
use ntex::{web, Middleware, Service, ServiceCtx};
use std::collections::HashMap;
use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// User credentials
#[derive(Debug, Clone, PartialEq)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

/// User validation trait for custom authentication logic
pub trait UserValidator: Send + Sync {
    fn validate<'a>(
        &'a self,
        credentials: &'a Credentials,
    ) -> Pin<Box<dyn Future<Output = AuthResult<bool>> + Send + 'a>>;
}

impl Debug for dyn UserValidator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UserValidator")
    }
}

/// Static user list validator
#[derive(Debug)]
pub struct StaticUserValidator {
    users: HashMap<String, String>,
}

impl StaticUserValidator {
    pub fn new() -> Self {
        Self {
            users: HashMap::new(),
        }
    }

    pub fn add_user(&mut self, username: String, password: String) -> &mut Self {
        self.users.insert(username, password);
        self
    }

    pub fn from_map(users: HashMap<String, String>) -> Self {
        Self { users }
    }
}

impl UserValidator for StaticUserValidator {
    fn validate<'a>(
        &'a self,
        credentials: &'a Credentials,
    ) -> Pin<Box<dyn Future<Output = AuthResult<bool>> + Send + 'a>> {
        Box::pin(async move {
            match self.users.get(&credentials.username) {
                Some(stored_password) => Ok(stored_password == &credentials.password),
                None => Ok(false),
            }
        })
    }
}

/// BCrypt password validator (requires bcrypt feature)
#[cfg(feature = "bcrypt")]
#[derive(Debug)]
pub struct BcryptUserValidator {
    users: HashMap<String, String>, // username -> bcrypt hash
}

#[cfg(feature = "bcrypt")]
impl BcryptUserValidator {
    pub fn new() -> Self {
        Self {
            users: HashMap::new(),
        }
    }

    pub fn add_user(&mut self, username: String, bcrypt_hash: String) -> &mut Self {
        self.users.insert(username, bcrypt_hash);
        self
    }

    pub fn add_user_with_password(&mut self, username: String, password: &str) -> AuthResult<&mut Self> {
        let hash = bcrypt::hash(password, bcrypt::DEFAULT_COST)
            .map_err(|e| AuthError::ValidationFailed(format!("BCrypt hash failed: {}", e)))?;
        self.users.insert(username, hash);
        Ok(self)
    }
}

#[cfg(feature = "bcrypt")]
impl UserValidator for BcryptUserValidator {
    fn validate<'a>(
        &'a self,
        credentials: &'a Credentials,
    ) -> Pin<Box<dyn Future<Output = AuthResult<bool>> + Send + 'a>> {
        Box::pin(async move {
            match self.users.get(&credentials.username) {
                Some(stored_hash) => {
                    bcrypt::verify(&credentials.password, stored_hash)
                        .map_err(|e| AuthError::ValidationFailed(format!("BCrypt verify failed: {}", e)))
                }
                None => Ok(false),
            }
        })
    }
}

/// Basic Authentication configuration
#[derive(Debug)]
pub struct BasicAuthConfig {
    pub realm: String,
    pub validator: Arc<dyn UserValidator>,
    pub cache_enabled: bool,
    pub cache_size_limit: usize,
}

impl BasicAuthConfig {
    pub fn new(validator: Arc<dyn UserValidator>) -> Self {
        Self {
            realm: "Restricted Area".to_string(),
            validator,
            cache_enabled: true,
            cache_size_limit: 1000,
        }
    }

    pub fn realm(mut self, realm: String) -> Self {
        self.realm = realm;
        self
    }

    pub fn disable_cache(mut self) -> Self {
        self.cache_enabled = false;
        self
    }

    pub fn cache_size_limit(mut self, limit: usize) -> Self {
        self.cache_size_limit = limit;
        self
    }
}

/// Basic Authentication middleware
pub struct BasicAuth {
    config: BasicAuthConfig,
    // Cache successful authentications to reduce validation overhead
    auth_cache: Option<DashMap<String, bool>>,
}

impl BasicAuth {
    pub fn new(config: BasicAuthConfig) -> Self {
        let auth_cache = if config.cache_enabled {
            Some(DashMap::new())
        } else {
            None
        };

        Self { config, auth_cache }
    }

    /// Create BasicAuth with static user list
    pub fn with_users(users: HashMap<String, String>) -> Self {
        let validator = Arc::new(StaticUserValidator::from_map(users));
        let config = BasicAuthConfig::new(validator);
        Self::new(config)
    }

    /// Create BasicAuth with single user
    pub fn with_user(username: String, password: String) -> Self {
        let mut users = HashMap::new();
        users.insert(username, password);
        Self::with_users(users)
    }

    /// Parse Authorization header and extract credentials
    fn parse_credentials(auth_header: &str) -> AuthResult<Credentials> {
        if !auth_header.starts_with("Basic ") {
            return Err(AuthError::InvalidFormat);
        }

        let encoded = &auth_header[6..]; // Remove "Basic " prefix
        let decoded = STANDARD
            .decode(encoded)
            .map_err(|_| AuthError::InvalidBase64)?;

        let decoded_str = String::from_utf8(decoded)
            .map_err(|_| AuthError::InvalidBase64)?;

        let parts: Vec<&str> = decoded_str.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(AuthError::InvalidFormat);
        }

        Ok(Credentials {
            username: parts[0].to_string(),
            password: parts[1].to_string(),
        })
    }

    /// Check if credentials are cached and valid
    fn check_cache(&self, credentials: &Credentials) -> Option<bool> {
        self.auth_cache.as_ref().and_then(|cache| {
            let cache_key = format!("{}:{}", credentials.username, credentials.password);
            cache.get(&cache_key).map(|entry| *entry.value())
        })
    }

    /// Cache authentication result
    fn cache_result(&self, credentials: &Credentials, result: bool) {
        if let Some(cache) = &self.auth_cache { 
            // Limit cache size to prevent memory exhaustion
            if cache.len() >= self.config.cache_size_limit {
                cache.clear();
            }
            
            let cache_key = format!("{}:{}", credentials.username, credentials.password);
            cache.insert(cache_key, result);
        }
    }

    /// Authenticate user credentials
    async fn authenticate(&self, credentials: &Credentials) -> AuthResult<bool> {
        // Check cache first
        if let Some(cached_result) = self.check_cache(credentials) {
            return Ok(cached_result);
        }

        // Validate with configured validator
        let result = self.config.validator.validate(credentials).await?;
        
        // Cache the result
        self.cache_result(credentials, result);
        
        Ok(result)
    }
}

impl<S> Middleware<S> for BasicAuth {
    type Service = BasicAuthMiddlewareService<S>;

    fn create(&self, service: S) -> Self::Service {
        BasicAuthMiddlewareService {
            service,
            config: BasicAuthConfig {
                realm: self.config.realm.clone(),
                validator: Arc::clone(&self.config.validator),
                cache_enabled: self.config.cache_enabled,
                cache_size_limit: self.config.cache_size_limit,
            },
            auth_cache: self.auth_cache.clone(),
        }
    }
}

pub struct BasicAuthMiddlewareService<S> {
    service: S,
    config: BasicAuthConfig,
    auth_cache: Option<DashMap<String, bool>>,
}

impl<S, Err> Service<web::WebRequest<Err>> for BasicAuthMiddlewareService<S>
where
    S: Service<web::WebRequest<Err>, Response = web::WebResponse, Error = web::Error> + 'static,
    Err: web::ErrorRenderer,
{
    type Response = web::WebResponse;
    type Error = web::Error;

    async fn call(
        &self,
        req: web::WebRequest<Err>,
        ctx: ServiceCtx<'_, Self>,
    ) -> Result<Self::Response, Self::Error> {
        // Extract Authorization header
        let auth_header = req
            .headers()
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            .ok_or(AuthError::MissingHeader)?;

        // Parse credentials
        let credentials = BasicAuth::parse_credentials(auth_header)?;

        // Check cache first
        let is_authenticated = if let Some(cache) = &self.auth_cache {
            let cache_key = format!("{}:{}", credentials.username, credentials.password);
            if let Some(cached_result) = cache.get(&cache_key) {
                *cached_result.value()
            } else {
                // Validate with configured validator
                let result = self.config.validator.validate(&credentials).await?;
                
                // Cache the result
                if cache.len() < self.config.cache_size_limit {
                    cache.insert(cache_key, result);
                }
                
                result
            }
        } else {
            // No cache, validate directly
            self.config.validator.validate(&credentials).await?
        };

        if !is_authenticated {
            return Err(AuthError::InvalidCredentials.into());
        }

        // Add credentials to request extensions for downstream access
        req.extensions_mut().insert(credentials);

        // Continue with the request
        ctx.call(&self.service, req).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_credentials() {
        // "admin:secret" base64 encoded
        let auth_header = "Basic YWRtaW46c2VjcmV0";
        let creds = BasicAuth::parse_credentials(auth_header).unwrap();
        
        assert_eq!(creds.username, "admin");
        assert_eq!(creds.password, "secret");
    }

    #[test]
    fn test_parse_credentials_invalid() {
        assert!(BasicAuth::parse_credentials("Bearer token").is_err());
        assert!(BasicAuth::parse_credentials("Basic invalid-base64").is_err());
        assert!(BasicAuth::parse_credentials("Basic bm90Y29sb24=").is_err()); // "notcolon"
    }
}