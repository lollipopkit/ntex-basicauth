use crate::error::{AuthError, AuthResult};
use base64::{Engine, engine::general_purpose::STANDARD};
use ntex::{Middleware, Service, ServiceCtx, web};
use std::collections::HashMap;
use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

#[cfg(feature = "cache")]
use {
    dashmap::DashMap,
    sha2::{Sha256, Digest},
    std::time::{SystemTime, UNIX_EPOCH},
};

/// User credentials
#[derive(Debug, Clone, PartialEq)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

impl Credentials {
    /// Generate secure cache key using SHA256 hash
    #[cfg(feature = "cache")]
    pub fn cache_key(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.username.as_bytes());
        hasher.update(b":");
        hasher.update(self.password.as_bytes());
        format!("{:x}", hasher.finalize())
    }
    
    /// Constant-time password comparison to prevent timing attacks
    #[cfg(feature = "timing-safe")]
    pub fn verify_password(&self, expected: &str) -> bool {
        self.constant_time_eq(&self.password, expected)
    }
    
    #[cfg(feature = "timing-safe")]
    fn constant_time_eq(&self, a: &str, b: &str) -> bool {
        let a_bytes = a.as_bytes();
        let b_bytes = b.as_bytes();
        
        if a_bytes.len() != b_bytes.len() {
            return false;
        }
        
        let mut result = 0u8;
        for i in 0..a_bytes.len() {
            result |= a_bytes[i] ^ b_bytes[i];
        }
        result == 0
    }
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
        f.write_str("UserValidator")
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
                Some(stored_password) => {
                    #[cfg(feature = "timing-safe")]
                    {
                        Ok(credentials.verify_password(stored_password))
                    }
                    #[cfg(not(feature = "timing-safe"))]
                    {
                        Ok(stored_password == &credentials.password)
                    }
                }
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

    pub fn add_user_with_password(
        &mut self,
        username: String,
        password: &str,
    ) -> AuthResult<&mut Self> {
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
                    bcrypt::verify(&credentials.password, stored_hash).map_err(|e| {
                        AuthError::ValidationFailed(format!("BCrypt verify failed: {}", e))
                    })
                }
                None => Ok(false),
            }
        })
    }
}

/// Cache entry with TTL support
#[cfg(feature = "cache")]
#[derive(Debug, Clone)]
struct CacheEntry {
    value: bool,
    expires_at: u64,
}

#[cfg(feature = "cache")]
impl CacheEntry {
    fn new(value: bool, ttl_seconds: u64) -> Self {
        let expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() + ttl_seconds;
        
        Self { value, expires_at }
    }
    
    fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now > self.expires_at
    }
}

/// Basic Authentication configuration
#[derive(Debug)]
pub struct BasicAuthConfig {
    pub realm: String,
    pub validator: Arc<dyn UserValidator>,
    #[cfg(feature = "cache")]
    pub cache_enabled: bool,
    #[cfg(feature = "cache")]
    pub cache_size_limit: usize,
    #[cfg(feature = "cache")]
    pub cache_ttl_seconds: u64,
    pub path_filter: Option<Arc<crate::utils::PathFilter>>,
}

impl BasicAuthConfig {
    pub fn new(validator: Arc<dyn UserValidator>) -> Self {
        Self {
            realm: "Restricted Area".to_string(),
            validator,
            #[cfg(feature = "cache")]
            cache_enabled: true,
            #[cfg(feature = "cache")]
            cache_size_limit: 1000,
            #[cfg(feature = "cache")]
            cache_ttl_seconds: 300, // 5 minutes default TTL
            path_filter: None,
        }
    }

    pub fn realm(mut self, realm: String) -> Self {
        self.realm = realm;
        self
    }

    #[cfg(feature = "cache")]
    pub fn disable_cache(mut self) -> Self {
        self.cache_enabled = false;
        self
    }

    #[cfg(feature = "cache")]
    pub fn cache_size_limit(mut self, limit: usize) -> Self {
        self.cache_size_limit = limit;
        self
    }

    #[cfg(feature = "cache")]
    pub fn cache_ttl(mut self, seconds: u64) -> Self {
        self.cache_ttl_seconds = seconds;
        self
    }

    pub fn path_filter(mut self, filter: crate::utils::PathFilter) -> Self {
        self.path_filter = Some(Arc::new(filter));
        self
    }
}

/// Basic Authentication middleware
pub struct BasicAuth {
    pub(crate) config: BasicAuthConfig,
    #[cfg(feature = "cache")]
    auth_cache: Option<DashMap<String, CacheEntry>>,
}

impl BasicAuth {
    pub fn new(config: BasicAuthConfig) -> Self {
        #[cfg(feature = "cache")]
        let auth_cache = if config.cache_enabled {
            Some(DashMap::new())
        } else {
            None
        };

        Self { 
            config,
            #[cfg(feature = "cache")]
            auth_cache,
        }
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
    /// 支持包含冒号的密码
    fn parse_credentials(auth_header: &str) -> AuthResult<Credentials> {
        if !auth_header.starts_with("Basic ") {
            return Err(AuthError::InvalidFormat);
        }

        let encoded = &auth_header[6..]; // Remove "Basic " prefix
        let decoded = STANDARD
            .decode(encoded)
            .map_err(|_| AuthError::InvalidBase64)?;

        let decoded_str = String::from_utf8(decoded).map_err(|_| AuthError::InvalidBase64)?;

        // 只在第一个冒号处分割，支持密码中包含冒号
        let colon_pos = decoded_str.find(':').ok_or(AuthError::InvalidFormat)?;
        let username = decoded_str[..colon_pos].to_string();
        let password = decoded_str[colon_pos + 1..].to_string();

        Ok(Credentials { username, password })
    }

    /// Check if credentials are cached and valid
    #[cfg(feature = "cache")]
    fn check_cache(&self, credentials: &Credentials) -> Option<bool> {
        self.auth_cache.as_ref().and_then(|cache| {
            let cache_key = credentials.cache_key();
            cache.get(&cache_key).and_then(|entry| {
                if entry.is_expired() {
                    cache.remove(&cache_key);
                    None
                } else {
                    Some(entry.value)
                }
            })
        })
    }

    /// Cache authentication result with TTL
    #[cfg(feature = "cache")]
    fn cache_result(&self, credentials: &Credentials, result: bool) {
        if let Some(cache) = &self.auth_cache {
            // Clean expired entries and limit cache size
            if cache.len() >= self.config.cache_size_limit {
                self.cleanup_cache(cache);
            }

            let cache_key = credentials.cache_key();
            let entry = CacheEntry::new(result, self.config.cache_ttl_seconds);
            cache.insert(cache_key, entry);
        }
    }

    /// Clean up expired cache entries
    #[cfg(feature = "cache")]
    fn cleanup_cache(&self, cache: &DashMap<String, CacheEntry>) {
        cache.retain(|_, entry| !entry.is_expired());
        
        // If still too large after cleanup, clear half of it
        if cache.len() >= self.config.cache_size_limit {
            let keys_to_remove: Vec<String> = cache
                .iter()
                .take(cache.len() / 2)
                .map(|item| item.key().clone())
                .collect();
            
            for key in keys_to_remove {
                cache.remove(&key);
            }
        }
    }

    /// Authenticate user credentials
    async fn authenticate(&self, credentials: &Credentials) -> AuthResult<bool> {
        // Check cache first
        #[cfg(feature = "cache")]
        {
            if let Some(cached_result) = self.check_cache(credentials) {
                return Ok(cached_result);
            }
        }

        // Validate with configured validator
        let result = self.config.validator.validate(credentials).await?;

        // Cache the result
        #[cfg(feature = "cache")]
        {
            self.cache_result(credentials, result);
        }

        Ok(result)
    }
}

impl<S> Middleware<S> for BasicAuth {
    type Service = BasicAuthMiddlewareService<S>;

    fn create(&self, service: S) -> Self::Service {
        BasicAuthMiddlewareService {
            service,
            auth: BasicAuth {
                config: BasicAuthConfig {
                    realm: self.config.realm.clone(),
                    validator: Arc::clone(&self.config.validator),
                    #[cfg(feature = "cache")]
                    cache_enabled: self.config.cache_enabled,
                    #[cfg(feature = "cache")]
                    cache_size_limit: self.config.cache_size_limit,
                    #[cfg(feature = "cache")]
                    cache_ttl_seconds: self.config.cache_ttl_seconds,
                    path_filter: self.config.path_filter.clone(),
                },
                #[cfg(feature = "cache")]
                auth_cache: self.auth_cache.clone(),
            },
        }
    }
}

pub struct BasicAuthMiddlewareService<S> {
    service: S,
    auth: BasicAuth,
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
        // Check if this path should skip authentication
        if let Some(filter) = &self.auth.config.path_filter {
            if filter.should_skip(req.path()) {
                return ctx.call(&self.service, req).await;
            }
        }

        // Extract Authorization header
        let auth_header = req
            .headers()
            .get("authorization")
            .and_then(|h| h.to_str().ok());

        // Handle missing authorization header
        let auth_header = match auth_header {
            Some(header) => header,
            None => {
                let response = AuthError::MissingHeader.to_response(&self.auth.config.realm);
                return Ok(req.into_response(response));
            }
        };

        // Parse credentials
        let credentials = match BasicAuth::parse_credentials(auth_header) {
            Ok(creds) => creds,
            Err(err) => {
                let response = err.to_response(&self.auth.config.realm);
                return Ok(req.into_response(response));
            }
        };

        // Authenticate using BasicAuth methods
        let is_authenticated = match self.auth.authenticate(&credentials).await {
            Ok(result) => result,
            Err(err) => {
                let response = err.to_response(&self.auth.config.realm);
                return Ok(req.into_response(response));
            }
        };

        if !is_authenticated {
            let response = AuthError::InvalidCredentials.to_response(&self.auth.config.realm);
            return Ok(req.into_response(response));
        }

        // Add credentials to request extensions for downstream access
        req.extensions_mut().insert(credentials);

        // Continue with the request
        ctx.call(&self.service, req).await
    }
}

// 保持原有测试，但添加新的安全性测试
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[ntex::test]
    async fn test_static_validator() {
        let mut users = HashMap::new();
        users.insert("admin".to_string(), "secret".to_string());
        users.insert("user".to_string(), "password:with:colons".to_string());

        let validator = StaticUserValidator::from_map(users);

        let valid_creds = Credentials {
            username: "admin".to_string(),
            password: "secret".to_string(),
        };

        let colon_password_creds = Credentials {
            username: "user".to_string(),
            password: "password:with:colons".to_string(),
        };

        assert!(validator.validate(&valid_creds).await.unwrap());
        assert!(validator.validate(&colon_password_creds).await.unwrap());
    }

    #[test]
    fn test_parse_credentials_with_colons() {
        // Test password containing colons
        use base64::Engine;
        let credentials = "admin:pass:word:with:colons";
        let encoded = STANDARD.encode(credentials.as_bytes());
        let auth_header = format!("Basic {}", encoded);
        
        let creds = BasicAuth::parse_credentials(&auth_header).unwrap();
        assert_eq!(creds.username, "admin");
        assert_eq!(creds.password, "pass:word:with:colons");
    }

    #[cfg(feature = "cache")]
    #[test]
    fn test_secure_cache_key() {
        let creds = Credentials {
            username: "admin".to_string(),
            password: "secret".to_string(),
        };
        
        let key1 = creds.cache_key();
        let key2 = creds.cache_key();
        
        // Same credentials should produce same key
        assert_eq!(key1, key2);
        
        // Key should not contain plaintext password
        assert!(!key1.contains("secret"));
        assert!(!key1.contains("admin"));
    }
}