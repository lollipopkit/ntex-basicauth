//! Cache of recently successful authentications

use crate::error::{AuthError, AuthResult};
use crate::validator::Credentials;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Cache configuration.
///
/// Only successful authentications are cached, so failed guesses can neither
/// fill the cache nor be answered from it. A cached entry stays valid until it
/// expires, even if the backend changes the password in the meantime; call
/// [`BasicAuth::clear_cache`](crate::BasicAuth::clear_cache) after such changes.
#[derive(Debug, Clone)]
pub struct CacheConfig {
    max_size: usize,
    ttl: Duration,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_size: 1000,
            ttl: Duration::from_secs(300),
        }
    }
}

impl CacheConfig {
    /// Default config: 1000 entries, 5 minutes TTL
    pub fn new() -> Self {
        Self::default()
    }

    /// Maximum number of cached entries
    pub fn max_size(mut self, size: usize) -> Self {
        self.max_size = size;
        self
    }

    /// Time to live of a cached entry
    pub fn ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    fn validate(&self) -> AuthResult<()> {
        if self.max_size == 0 {
            return Err(AuthError::Config(
                "cache max_size must be greater than 0".into(),
            ));
        }
        if self.ttl.is_zero() {
            return Err(AuthError::Config("cache ttl must be greater than 0".into()));
        }
        Ok(())
    }
}

pub(crate) type CacheKey = [u8; 32];

/// Set of credential digests with expiry. Keys are SHA-256 over a per-instance
/// random secret, so they are useless outside this process.
pub(crate) struct AuthCache {
    secret: [u8; 32],
    config: CacheConfig,
    entries: Mutex<HashMap<CacheKey, Instant>>,
}

impl AuthCache {
    pub(crate) fn new(config: CacheConfig) -> AuthResult<Self> {
        config.validate()?;
        let mut secret = [0; 32];
        getrandom::fill(&mut secret)
            .map_err(|e| AuthError::Config(format!("failed to seed cache key: {e}")))?;
        Ok(Self {
            secret,
            config,
            entries: Mutex::new(HashMap::new()),
        })
    }

    pub(crate) fn key(&self, credentials: &Credentials) -> CacheKey {
        // Usernames cannot contain ':', so the encoding is unambiguous.
        Sha256::new()
            .chain_update(self.secret)
            .chain_update(credentials.username.as_bytes())
            .chain_update(b":")
            .chain_update(credentials.password.as_bytes())
            .finalize()
            .into()
    }

    pub(crate) fn contains(&self, key: &CacheKey) -> bool {
        let mut entries = self.lock();
        match entries.get(key) {
            Some(expires) if *expires > Instant::now() => true,
            Some(_) => {
                entries.remove(key);
                false
            }
            None => false,
        }
    }

    pub(crate) fn insert(&self, key: CacheKey) {
        let now = Instant::now();
        let mut entries = self.lock();
        if entries.len() >= self.config.max_size && !entries.contains_key(&key) {
            entries.retain(|_, expires| *expires > now);
            if entries.len() >= self.config.max_size
                && let Some(oldest) = entries.iter().min_by_key(|(_, e)| **e).map(|(k, _)| *k)
            {
                entries.remove(&oldest);
            }
        }
        entries.insert(key, now + self.config.ttl);
    }

    pub(crate) fn clear(&self) {
        self.lock().clear();
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.lock().len()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<CacheKey, Instant>> {
        // The map stays consistent even if a holder panicked.
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_contains_expire() {
        let cache = AuthCache::new(CacheConfig::new().ttl(Duration::from_millis(20))).unwrap();
        let key = cache.key(&Credentials::new("admin", "secret"));
        assert!(!cache.contains(&key));
        cache.insert(key);
        assert!(cache.contains(&key));
        std::thread::sleep(Duration::from_millis(30));
        assert!(!cache.contains(&key));
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn bounded_size() {
        let cache = AuthCache::new(CacheConfig::new().max_size(3)).unwrap();
        for i in 0..10u8 {
            cache.insert([i; 32]);
        }
        assert_eq!(cache.len(), 3);
        assert!(cache.contains(&[9; 32]));
    }

    #[test]
    fn keys_are_instance_specific() {
        let creds = Credentials::new("admin", "secret");
        let a = AuthCache::new(CacheConfig::new()).unwrap();
        let b = AuthCache::new(CacheConfig::new()).unwrap();
        assert_eq!(a.key(&creds), a.key(&creds));
        assert_ne!(a.key(&creds), b.key(&creds));
        assert_ne!(a.key(&creds), a.key(&Credentials::new("admin", "secreT")));
    }

    #[test]
    fn config_validation() {
        assert!(CacheConfig::new().max_size(0).validate().is_err());
        assert!(CacheConfig::new().ttl(Duration::ZERO).validate().is_err());
        assert!(CacheConfig::new().validate().is_ok());
    }
}
