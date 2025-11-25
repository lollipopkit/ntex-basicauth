//! Core implementation of basic authentication

use crate::{
    error::{AuthError, AuthResult},
    is_valid_username,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use ntex::{Middleware, Service, ServiceCtx, web};
use std::collections::HashMap;
use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[cfg(feature = "timing-safe")]
use subtle::ConstantTimeEq;

#[cfg(feature = "secure-memory")]
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "cache")]
use {
    crate::cache::{AuthCache, CacheConfig},
    sha2::{Digest, Sha256},
};

/// User credentials
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "secure-memory", derive(Zeroize, ZeroizeOnDrop))]
pub struct Credentials {
    /// Username
    #[cfg_attr(feature = "secure-memory", zeroize(skip))]
    pub username: String,
    /// Password
    pub password: String,
}

impl Credentials {
    /// Create new credentials instance
    pub fn new(username: String, password: String) -> Self {
        Self { username, password }
    }

    /// Generate secure cache key (using SHA256 hash with application-specific salt)
    #[cfg(feature = "cache")]
    pub fn cache_key(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        // Add application-specific salt to prevent rainbow table attacks
        hasher.update(b"ntex-basicauth-v1:");
        hasher.update(self.username.as_bytes());
        hasher.update(b":");
        hasher.update(self.password.as_bytes());
        hasher.finalize().into()
    }

    /// Enhanced timing-safe password verification to prevent timing attacks
    #[cfg(feature = "timing-safe")]
    pub fn verify_password(&self, expected: &str) -> bool {
        // Ensure both strings have the same length before comparison
        if self.password.len() != expected.len() {
            // Execute a dummy comparison to maintain timing consistency
            let _ = b"dummy_password_123".ct_eq(b"dummy_password_123");
            return false;
        }
        self.password.as_bytes().ct_eq(expected.as_bytes()).into()
    }

    /// Non-timing-safe password verification (fallback if timing-safe feature is off)
    #[cfg(not(feature = "timing-safe"))]
    pub fn verify_password(&self, expected: &str) -> bool {
        self.password == expected
    }

    /// Get username reference (avoid clone)
    pub fn username_ref(&self) -> &str {
        &self.username
    }

    /// Validate credentials format
    pub fn is_valid_format(&self) -> bool {
        is_valid_username(&self.username) && !self.password.chars().any(|c| c.is_control())
    }
}

/// User validator trait for custom authentication logic
pub trait UserValidator: Send + Sync + Debug {
    /// Validate user credentials
    fn validate<'a>(
        &'a self,
        credentials: &'a Credentials,
    ) -> Pin<Box<dyn Future<Output = AuthResult<bool>> + Send + 'a>>;

    /// Get validator name (for logging)
    fn name(&self) -> &'static str {
        "UserValidator"
    }

    /// Pre-validation check (optional)
    fn pre_validate(&self, credentials: &Credentials) -> AuthResult<()> {
        if !credentials.is_valid_format() {
            return Err(AuthError::InvalidCredentials);
        }
        Ok(())
    }

    /// Get user count
    fn user_count(&self) -> usize {
        0
    }
}

/// Static user list validator
#[derive(Debug)]
pub struct StaticUserValidator {
    users: HashMap<String, String>,
    case_sensitive: bool,
}

impl StaticUserValidator {
    /// Create a new static user validator
    pub fn new() -> Self {
        Self {
            users: HashMap::new(),
            case_sensitive: true,
        }
    }

    /// Set to case insensitive
    pub fn case_insensitive(mut self) -> Self {
        self.case_sensitive = false;
        self
    }

    /// Add a user
    pub fn add_user(&mut self, username: String, password: String) -> &mut Self {
        let key = if self.case_sensitive {
            username
        } else {
            username.to_lowercase()
        };
        self.users.insert(key, password);
        self
    }

    /// Create validator from HashMap
    pub fn from_map(users: HashMap<String, String>) -> Self {
        Self {
            users,
            case_sensitive: true,
        }
    }

    /// Create validator from HashMap (case insensitive)
    pub fn from_map_case_insensitive(users: HashMap<String, String>) -> Self {
        let normalized_users: HashMap<String, String> = users
            .into_iter()
            .map(|(k, v)| (k.to_lowercase(), v))
            .collect();

        Self {
            users: normalized_users,
            case_sensitive: false,
        }
    }

    /// Check if user exists
    pub fn contains_user(&self, username: &str) -> bool {
        let key = if self.case_sensitive {
            username
        } else {
            &username.to_lowercase()
        };
        self.users.contains_key(key)
    }
}

impl Default for StaticUserValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl UserValidator for StaticUserValidator {
    fn validate<'a>(
        &'a self,
        credentials: &'a Credentials,
    ) -> Pin<Box<dyn Future<Output = AuthResult<bool>> + Send + 'a>> {
        Box::pin(async move {
            let username = if self.case_sensitive {
                &credentials.username
            } else {
                &credentials.username.to_lowercase()
            };

            match self.users.get(username) {
                Some(stored_password) => Ok(credentials.verify_password(stored_password)),
                None => Ok(false),
            }
        })
    }

    fn name(&self) -> &'static str {
        "StaticUserValidator"
    }

    /// Get user count
    fn user_count(&self) -> usize {
        self.users.len()
    }
}

/// BCrypt password validator (requires bcrypt feature)
#[cfg(feature = "bcrypt")]
#[derive(Debug)]
pub struct BcryptUserValidator {
    users: HashMap<String, String>, // username -> bcrypt hash
    cost: u32,
}

#[cfg(feature = "bcrypt")]
impl BcryptUserValidator {
    /// Create a new BCrypt user validator
    pub fn new() -> Self {
        Self {
            users: HashMap::new(),
            cost: bcrypt::DEFAULT_COST,
        }
    }

    /// Set BCrypt cost factor
    pub fn with_cost(mut self, cost: u32) -> Self {
        self.cost = cost;
        self
    }

    /// Add a user with precomputed BCrypt hash
    pub fn add_user(&mut self, username: String, bcrypt_hash: String) -> &mut Self {
        self.users.insert(username, bcrypt_hash);
        self
    }

    /// Add a user with password, automatically hashing it with BCrypt
    pub fn add_user_with_password(
        &mut self,
        username: String,
        password: &str,
    ) -> AuthResult<&mut Self> {
        let hash = bcrypt::hash(password, self.cost)
            .map_err(|e| AuthError::ValidationFailed(format!("BCrypt hash failed: {}", e)))?;
        self.users.insert(username, hash);
        Ok(self)
    }

    /// Create validator from HashMap of usernames and BCrypt hashes
    pub fn from_hashes(users: HashMap<String, String>) -> Self {
        Self {
            users,
            cost: bcrypt::DEFAULT_COST,
        }
    }
}

#[cfg(feature = "bcrypt")]
impl Default for BcryptUserValidator {
    fn default() -> Self {
        Self::new()
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
                    // Bcrypt verification is blocking, so we use spawn_blocking
                    let password = credentials.password.clone();
                    let hash = stored_hash.clone();

                    let result =
                        ntex::rt::spawn_blocking(move || bcrypt::verify(&password, &hash)).await;

                    match result {
                        Ok(Ok(is_valid)) => Ok(is_valid),
                        Ok(Err(e)) => Err(AuthError::ValidationFailed(format!(
                            "BCrypt verify failed: {}",
                            e
                        ))),
                        Err(e) => Err(AuthError::InternalError(format!("Task join failed: {}", e))),
                    }
                }
                None => Ok(false),
            }
        })
    }

    fn name(&self) -> &'static str {
        "BcryptUserValidator"
    }

    fn user_count(&self) -> usize {
        self.users.len()
    }
}

/// Authentication metrics for monitoring
#[derive(Debug, Default)]
pub struct AuthMetrics {
    /// Total authentication requests
    pub total_requests: AtomicU64,
    /// Successful authentications
    pub successful_auths: AtomicU64,
    /// Failed authentications
    pub failed_auths: AtomicU64,
    /// Cached authentication hits
    pub cached_hits: AtomicU64,
    /// Total validation time in milliseconds
    pub validation_time_ms: AtomicU64,
}

impl AuthMetrics {
    /// Create new metrics instance
    pub fn new() -> Self {
        Self::default()
    }

    /// Get total requests
    pub fn total_requests(&self) -> u64 {
        self.total_requests.load(Ordering::Relaxed)
    }

    /// Get successful authentications
    pub fn successful_auths(&self) -> u64 {
        self.successful_auths.load(Ordering::Relaxed)
    }

    /// Get failed authentications
    pub fn failed_auths(&self) -> u64 {
        self.failed_auths.load(Ordering::Relaxed)
    }

    /// Get cache hits
    pub fn cached_hits(&self) -> u64 {
        self.cached_hits.load(Ordering::Relaxed)
    }

    /// Get average validation time in milliseconds
    pub fn avg_validation_time_ms(&self) -> f64 {
        let total_time = self.validation_time_ms.load(Ordering::Relaxed);
        let total_requests = self.total_requests.load(Ordering::Relaxed);
        if total_requests > 0 {
            total_time as f64 / total_requests as f64
        } else {
            0.0
        }
    }

    /// Get success rate as percentage
    pub fn success_rate(&self) -> f64 {
        let successful = self.successful_auths.load(Ordering::Relaxed);
        let total = self.total_requests.load(Ordering::Relaxed);
        if total > 0 {
            (successful as f64 / total as f64) * 100.0
        } else {
            0.0
        }
    }

    /// Get cache hit rate as percentage
    pub fn cache_hit_rate(&self) -> f64 {
        let hits = self.cached_hits.load(Ordering::Relaxed);
        let total = self.total_requests.load(Ordering::Relaxed);
        if total > 0 {
            (hits as f64 / total as f64) * 100.0
        } else {
            0.0
        }
    }

    /// Reset all metrics
    pub fn reset(&self) {
        self.total_requests.store(0, Ordering::Relaxed);
        self.successful_auths.store(0, Ordering::Relaxed);
        self.failed_auths.store(0, Ordering::Relaxed);
        self.cached_hits.store(0, Ordering::Relaxed);
        self.validation_time_ms.store(0, Ordering::Relaxed);
    }

    /// Increment total authentication request counter
    pub fn incr_total_requests(&self) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment successful authentication counter
    pub fn incr_successful_auths(&self) {
        self.successful_auths.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment failed authentication counter
    pub fn incr_failed_auths(&self) {
        self.failed_auths.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment cached authentication hit counter
    pub fn incr_cached_hits(&self) {
        self.cached_hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Add validation time in milliseconds
    pub fn add_validation_time(&self, duration: Duration) {
        let ms = duration.as_millis() as u64;
        self.validation_time_ms.fetch_add(ms, Ordering::Relaxed);
    }
}

/// Basic authentication config
pub struct BasicAuthConfig {
    /// Authentication realm (for WWW-Authenticate header)
    pub realm: String,
    /// User validator
    pub validator: Arc<dyn UserValidator>,
    #[cfg(feature = "cache")]
    /// Auth result cache (optional)
    pub cache: Option<Arc<AuthCache>>,
    /// Path filter (optional)
    pub path_filter: Option<Arc<crate::utils::PathFilter>>,
    /// Request header size limit (bytes)
    pub max_header_size: usize,
    /// Log details on authentication failure
    pub log_failures: bool,
    /// Custom error handler
    pub custom_error_handler:
        Option<Arc<dyn Fn(&AuthError, &str) -> web::HttpResponse + Send + Sync>>,
    /// Maximum concurrent authentication validations
    pub max_concurrent_validations: Option<usize>,
    /// Validation timeout
    pub validation_timeout: Option<Duration>,
    /// Rate limiting: (max_requests, time_window)
    pub rate_limit_per_ip: Option<(usize, Duration)>,
    /// Enable metrics collection
    pub enable_metrics: bool,
    /// Log usernames in production (security risk)
    pub log_usernames_in_production: bool,
}

impl BasicAuthConfig {
    /// Create new basic auth config
    pub fn new(validator: Arc<dyn UserValidator>) -> Self {
        Self {
            realm: "Restricted Area".to_string(),
            validator,
            #[cfg(feature = "cache")]
            cache: None,
            path_filter: None,
            max_header_size: 8192, // 8KB
            log_failures: false,
            custom_error_handler: None,
            max_concurrent_validations: None,
            validation_timeout: Some(Duration::from_secs(30)),
            rate_limit_per_ip: None,
            enable_metrics: true,
            log_usernames_in_production: false,
        }
    }

    /// Set authentication realm
    pub fn realm(mut self, realm: String) -> Self {
        self.realm = realm;
        self
    }

    #[cfg(feature = "cache")]
    /// Create auth config with cache config
    pub fn with_cache(mut self, cache_config: CacheConfig) -> AuthResult<Self> {
        self.cache = Some(Arc::new(AuthCache::new(cache_config)?));
        Ok(self)
    }

    #[cfg(feature = "cache")]
    /// Disable cache
    pub fn disable_cache(mut self) -> Self {
        self.cache = None;
        self
    }

    /// Set path filter
    pub fn path_filter(mut self, filter: crate::utils::PathFilter) -> Self {
        self.path_filter = Some(Arc::new(filter));
        self
    }

    /// Set max request header size
    pub fn max_header_size(mut self, size: usize) -> Self {
        self.max_header_size = size;
        self
    }

    /// Enable or disable logging on authentication failure
    pub fn log_failures(mut self, enabled: bool) -> Self {
        self.log_failures = enabled;
        self
    }

    /// Set custom error handler function
    pub fn custom_error_handler<F>(mut self, handler: F) -> Self
    where
        F: Fn(&AuthError, &str) -> web::HttpResponse + Send + Sync + 'static,
    {
        self.custom_error_handler = Some(Arc::new(handler));
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

    /// Enhanced config validation
    pub fn validate(&self) -> AuthResult<()> {
        if self.realm.is_empty() {
            return Err(AuthError::ConfigError("realm cannot be empty".to_string()));
        }
        if self.max_header_size == 0 {
            return Err(AuthError::ConfigError(
                "max_header_size must be greater than 0".to_string(),
            ));
        }
        if self.max_header_size > 1024 * 1024 {
            // 1MB limit
            return Err(AuthError::ConfigError(
                "max_header_size too large (max 1MB)".to_string(),
            ));
        }

        if let Some(max_concurrent) = self.max_concurrent_validations {
            if max_concurrent == 0 {
                return Err(AuthError::ConfigError(
                    "max_concurrent_validations must be greater than 0".to_string(),
                ));
            }
            if max_concurrent > 10000 {
                return Err(AuthError::ConfigError(
                    "max_concurrent_validations too large (max 10000)".to_string(),
                ));
            }
        }

        if let Some(timeout) = self.validation_timeout {
            if timeout.is_zero() {
                return Err(AuthError::ConfigError(
                    "validation_timeout must be greater than 0".to_string(),
                ));
            }
            if timeout > Duration::from_secs(300) {
                // 5 minutes
                return Err(AuthError::ConfigError(
                    "validation_timeout too large (max 5 minutes)".to_string(),
                ));
            }
        }

        if let Some((max_requests, window)) = self.rate_limit_per_ip {
            if max_requests == 0 {
                return Err(AuthError::ConfigError(
                    "rate_limit max_requests must be greater than 0".to_string(),
                ));
            }
            if window.is_zero() {
                return Err(AuthError::ConfigError(
                    "rate_limit window must be greater than 0".to_string(),
                ));
            }
        }

        #[cfg(feature = "cache")]
        if let Some(cache) = &self.cache {
            let stats = cache.stats();
            if stats.total_entries > 100000 {
                // Reasonable cache size limit
                eprintln!(
                    "Warning: Cache has {} entries, consider reducing TTL",
                    stats.total_entries
                );
            }
        }

        Ok(())
    }
}

/// Basic authentication middleware
pub struct BasicAuth {
    pub(crate) config: BasicAuthConfig,
    pub(crate) metrics: Arc<AuthMetrics>,
}

impl BasicAuth {
    /// Create new BasicAuth instance
    pub fn new(config: BasicAuthConfig) -> AuthResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            metrics: Arc::new(AuthMetrics::new()),
        })
    }

    /// Get metrics reference
    pub fn metrics(&self) -> &AuthMetrics {
        &self.metrics
    }

    /// Create BasicAuth with static user list
    pub fn with_users(users: HashMap<String, String>) -> AuthResult<Self> {
        let validator = Arc::new(StaticUserValidator::from_map(users));
        let config = BasicAuthConfig::new(validator);
        Self::new(config)
    }

    /// Create BasicAuth with a single user
    pub fn with_user(username: String, password: String) -> AuthResult<Self> {
        let mut users = HashMap::new();
        users.insert(username, password);
        Self::with_users(users)
    }

    /// Parse Authorization header and extract credentials
    /// Supports colons in password
    fn parse_credentials(auth_header: &str, max_size: usize) -> AuthResult<Credentials> {
        if auth_header.len() > max_size {
            return Err(AuthError::InvalidFormat);
        }

        if auth_header.len() < 6 {
            return Err(AuthError::InvalidFormat);
        }

        let scheme = &auth_header[..6];
        if !scheme.eq_ignore_ascii_case("Basic ") {
            return Err(AuthError::InvalidFormat);
        }

        let encoded = &auth_header[6..]; // Remove "Basic " prefix

        // Check Base64 string length
        if encoded.len() > (max_size * 3 / 4) {
            return Err(AuthError::InvalidFormat);
        }

        let decoded = STANDARD
            .decode(encoded)
            .map_err(|_| AuthError::InvalidBase64)?;

        let decoded_str = String::from_utf8(decoded).map_err(|_| AuthError::InvalidBase64)?;

        // Split only at the first colon, support colons in password
        let colon_pos = decoded_str.find(':').ok_or(AuthError::InvalidFormat)?;

        let username = decoded_str[..colon_pos].to_string();
        let password = decoded_str[colon_pos + 1..].to_string();

        let credentials = Credentials::new(username, password);

        // Validate credentials format
        if !credentials.is_valid_format() {
            return Err(AuthError::InvalidCredentials);
        }

        Ok(credentials)
    }

    /// Authenticate user credentials
    async fn authenticate(&self, credentials: &Credentials) -> AuthResult<bool> {
        // Pre-validation check
        self.config.validator.pre_validate(credentials)?;

        // Check cache and cache result (compute key only once)
        #[cfg(feature = "cache")]
        {
            if let Some(cache) = &self.config.cache {
                let cache_key = credentials.cache_key();
                if let Some(cached_result) = cache.get(&cache_key) {
                    if self.config.enable_metrics {
                        self.metrics.incr_cached_hits();
                    }
                    return Ok(cached_result);
                }

                let start = Instant::now();

                // Validate using configured validator
                let result = self.config.validator.validate(credentials).await?;

                if self.config.enable_metrics {
                    self.metrics.add_validation_time(start.elapsed());
                }

                // Cache result using the same key
                if let Err(e) = cache.insert(cache_key, result) {
                    // Cache failure should not affect authentication result, just log error
                    eprintln!("Failed to cache authentication result: {}", e);
                }

                return Ok(result);
            }
        }

        // Validate using configured validator (when cache is disabled)
        let start = Instant::now();
        let result = self.config.validator.validate(credentials).await?;

        if self.config.enable_metrics {
            self.metrics.add_validation_time(start.elapsed());
        }
        Ok(result)
    }

    /// Handle authentication error
    fn handle_auth_error(&self, error: &AuthError) -> web::HttpResponse {
        if let Some(handler) = &self.config.custom_error_handler {
            handler(error, &self.config.realm)
        } else {
            error.to_response(&self.config.realm)
        }
    }

    /// Log authentication failure (if enabled) with enhanced security
    fn log_auth_failure(&self, error: &AuthError, username: Option<&str>) {
        if self.config.log_failures {
            // In production, avoid logging usernames unless explicitly configured
            let safe_username = if self.config.log_usernames_in_production || cfg!(debug_assertions)
            {
                username
            } else {
                None // Don't log usernames in production for security
            };

            match safe_username {
                Some(user) => eprintln!("Authentication failed - user: {}, error: {}", user, error),
                None => eprintln!("Authentication failed - error: {}", error),
            }
        }
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
                    cache: self.config.cache.clone(),
                    path_filter: self.config.path_filter.clone(),
                    max_header_size: self.config.max_header_size,
                    log_failures: self.config.log_failures,
                    custom_error_handler: self.config.custom_error_handler.clone(),
                    max_concurrent_validations: self.config.max_concurrent_validations,
                    validation_timeout: self.config.validation_timeout,
                    rate_limit_per_ip: self.config.rate_limit_per_ip,
                    enable_metrics: self.config.enable_metrics,
                    log_usernames_in_production: self.config.log_usernames_in_production,
                },
                metrics: Arc::clone(&self.metrics),
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
        let metrics_enabled = self.auth.config.enable_metrics;

        // Check if path filter is configured and should skip authentication
        if let Some(filter) = &self.auth.config.path_filter {
            if filter.should_skip(req.path()) {
                return ctx.call(&self.service, req).await;
            }
        }

        if metrics_enabled {
            self.auth.metrics.incr_total_requests();
        }

        // Extract authorization header
        let auth_header = req
            .headers()
            .get("authorization")
            .and_then(|h| h.to_str().ok());

        // Handle missing or malformed Authorization header
        let auth_header = match auth_header {
            Some(header) => header,
            None => {
                let error = AuthError::MissingHeader;
                self.auth.log_auth_failure(&error, None);
                let response = self.auth.handle_auth_error(&error);
                if metrics_enabled {
                    self.auth.metrics.incr_failed_auths();
                }
                return Ok(req.into_response(response));
            }
        };

        // Parse credentials from Authorization header
        let credentials =
            match BasicAuth::parse_credentials(auth_header, self.auth.config.max_header_size) {
                Ok(creds) => creds,
                Err(err) => {
                    self.auth.log_auth_failure(&err, None);
                    let response = self.auth.handle_auth_error(&err);
                    if metrics_enabled {
                        self.auth.metrics.incr_failed_auths();
                    }
                    return Ok(req.into_response(response));
                }
            };

        // Authenticate user credentials
        let is_authenticated = match self.auth.authenticate(&credentials).await {
            Ok(result) => result,
            Err(err) => {
                self.auth
                    .log_auth_failure(&err, Some(&credentials.username));
                let response = self.auth.handle_auth_error(&err);
                if metrics_enabled {
                    self.auth.metrics.incr_failed_auths();
                }
                return Ok(req.into_response(response));
            }
        };

        if !is_authenticated {
            let error = AuthError::InvalidCredentials;
            self.auth
                .log_auth_failure(&error, Some(&credentials.username));
            let response = self.auth.handle_auth_error(&error);
            if metrics_enabled {
                self.auth.metrics.incr_failed_auths();
            }
            return Ok(req.into_response(response));
        }

        if metrics_enabled {
            self.auth.metrics.incr_successful_auths();
        }

        // Add credentials to request extensions for further processing
        req.extensions_mut().insert(credentials);
        ctx.call(&self.service, req).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_static_validator() {
        let mut users = HashMap::new();
        users.insert("admin".to_string(), "secret".to_string());
        users.insert("user".to_string(), "password:with:colons".to_string());

        let validator = StaticUserValidator::from_map(users);

        let valid_creds = Credentials::new("admin".to_string(), "secret".to_string());
        let colon_password_creds =
            Credentials::new("user".to_string(), "password:with:colons".to_string());
        let invalid_creds = Credentials::new("admin".to_string(), "wrong".to_string());

        assert!(validator.validate(&valid_creds).await.unwrap());
        assert!(validator.validate(&colon_password_creds).await.unwrap());
        assert!(!validator.validate(&invalid_creds).await.unwrap());
    }

    #[test]
    fn test_parse_credentials_with_colons() {
        use base64::Engine;
        let credentials = "admin:pass:word:with:colons";
        let encoded = STANDARD.encode(credentials.as_bytes());
        let auth_header = format!("Basic {}", encoded);

        let creds = BasicAuth::parse_credentials(&auth_header, 8192).unwrap();
        assert_eq!(creds.username, "admin");
        assert_eq!(creds.password, "pass:word:with:colons");
    }

    #[test]
    fn test_credentials_validation() {
        let valid_creds = Credentials::new("user".to_string(), "pass".to_string());
        let valid_empty_user = Credentials::new("".to_string(), "pass".to_string()); // Now valid per RFC 7617
        let invalid_creds1 = Credentials::new("user:name".to_string(), "pass".to_string());
        let invalid_creds2 = Credentials::new("user".to_string(), "pass\nword".to_string());
        let invalid_creds3 = Credentials::new("user".to_string(), "pass\tword".to_string()); // Tab is control character

        assert!(valid_creds.is_valid_format());
        assert!(valid_empty_user.is_valid_format());
        assert!(!invalid_creds1.is_valid_format());
        assert!(!invalid_creds2.is_valid_format());
        assert!(!invalid_creds3.is_valid_format());
    }

    #[cfg(feature = "cache")]
    #[test]
    fn test_secure_cache_key() {
        let creds = Credentials::new("admin".to_string(), "secret".to_string());

        let key1 = creds.cache_key();
        let key2 = creds.cache_key();

        // The same credentials should produce the same cache key
        assert_eq!(key1, key2);

        // Cache key should be a 32-byte array (does not contain sensitive information)
        assert_eq!(key1.len(), 32);
    }

    #[test]
    fn test_case_insensitive_validator() {
        let mut users = HashMap::new();
        users.insert("admin".to_string(), "secret".to_string());

        let validator = StaticUserValidator::from_map_case_insensitive(users);

        assert!(validator.contains_user("admin"));
        assert!(validator.contains_user("ADMIN"));
        assert!(validator.contains_user("Admin"));
    }

    #[tokio::test]
    async fn test_validator_pre_validation() {
        let validator = StaticUserValidator::new();
        let invalid_creds = Credentials::new("user:name".to_string(), "pass".to_string());

        assert!(validator.pre_validate(&invalid_creds).is_err());
    }

    #[test]
    fn test_config_validation() {
        let validator = Arc::new(StaticUserValidator::new());

        let valid_config = BasicAuthConfig::new(validator.clone());
        assert!(valid_config.validate().is_ok());

        let invalid_config = BasicAuthConfig::new(validator).realm("".to_string());
        assert!(invalid_config.validate().is_err());
    }

    #[cfg(feature = "bcrypt")]
    #[tokio::test]
    async fn test_bcrypt_validator() {
        let mut validator = BcryptUserValidator::new();
        validator
            .add_user_with_password("admin".to_string(), "secret")
            .unwrap();

        let valid_creds = Credentials::new("admin".to_string(), "secret".to_string());
        let invalid_creds = Credentials::new("admin".to_string(), "wrong".to_string());

        assert!(validator.validate(&valid_creds).await.unwrap());
        assert!(!validator.validate(&invalid_creds).await.unwrap());
    }
}
