//! Authentication cache implementation with TTL and size management

use dashmap::DashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::Arc;
use tokio::time::{interval, Duration};
use crate::error::AuthResult;

/// Cache entry with TTL support
#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub value: bool,
    pub expires_at: u64,
    pub created_at: u64,
}

impl CacheEntry {
    pub fn new(value: bool, ttl_seconds: u64) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            value,
            expires_at: now + ttl_seconds,
            created_at: now,
        }
    }
    
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now > self.expires_at
    }
    
    pub fn age_seconds(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now.saturating_sub(self.created_at)
    }
}

/// Cache configuration
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Maximum number of entries
    pub max_size: usize,
    /// TTL in seconds
    pub ttl_seconds: u64,
    /// Cleanup interval in seconds
    pub cleanup_interval_seconds: u64,
    /// Whether to enable automatic cleanup
    pub auto_cleanup: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_size: 1000,
            ttl_seconds: 300, // 5 minutes
            cleanup_interval_seconds: 60, // 1 minute
            auto_cleanup: true,
        }
    }
}

impl CacheConfig {
    pub fn new() -> Self {
        Self::default()
    }
    
    pub fn max_size(mut self, size: usize) -> Self {
        self.max_size = size;
        self
    }
    
    pub fn ttl_seconds(mut self, seconds: u64) -> Self {
        self.ttl_seconds = seconds;
        self
    }
    
    pub fn ttl_minutes(self, minutes: u64) -> Self {
        self.ttl_seconds(minutes * 60)
    }
    
    pub fn ttl_hours(self, hours: u64) -> Self {
        self.ttl_seconds(hours * 3600)
    }
    
    pub fn cleanup_interval_seconds(mut self, seconds: u64) -> Self {
        self.cleanup_interval_seconds = seconds;
        self
    }
    
    pub fn disable_auto_cleanup(mut self) -> Self {
        self.auto_cleanup = false;
        self
    }
}

/// Authentication cache with TTL and automatic cleanup
#[derive(Debug)]
pub struct AuthCache {
    cache: Arc<DashMap<String, CacheEntry>>,
    config: CacheConfig,
    _cleanup_handle: Option<tokio::task::JoinHandle<()>>,
}

impl AuthCache {
    pub fn new(config: CacheConfig) -> Self {
        let cache = Arc::new(DashMap::new());
        
        let cleanup_handle = if config.auto_cleanup {
            Some(Self::start_cleanup_task(Arc::clone(&cache), config.clone()))
        } else {
            None
        };
        
        Self {
            cache,
            config,
            _cleanup_handle: cleanup_handle,
        }
    }
    
    /// Start background cleanup task
    fn start_cleanup_task(
        cache: Arc<DashMap<String, CacheEntry>>,
        config: CacheConfig,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(config.cleanup_interval_seconds));
            
            loop {
                interval.tick().await;
                Self::cleanup_expired(&cache);
                
                // If cache is still too large, perform size-based cleanup
                if cache.len() > config.max_size {
                    Self::cleanup_by_size(&cache, config.max_size);
                }
            }
        })
    }
    
    /// Get value from cache
    pub fn get(&self, key: &str) -> Option<bool> {
        if let Some(entry) = self.cache.get(key) {
            if entry.is_expired() {
                self.cache.remove(key);
                None
            } else {
                Some(entry.value)
            }
        } else {
            None
        }
    }
    
    /// Insert value into cache
    pub fn insert(&self, key: String, value: bool) -> AuthResult<()> {
        // Check size limit before insertion
        if self.cache.len() >= self.config.max_size {
            self.cleanup();
        }
        
        let entry = CacheEntry::new(value, self.config.ttl_seconds);
        self.cache.insert(key, entry);
        Ok(())
    }
    
    /// Remove entry from cache
    pub fn remove(&self, key: &str) -> Option<bool> {
        self.cache.remove(key).map(|(_, entry)| entry.value)
    }
    
    /// Manual cleanup of expired entries
    pub fn cleanup(&self) {
        Self::cleanup_expired(&self.cache);
        
        // If still too large, cleanup by size
        if self.cache.len() > self.config.max_size {
            Self::cleanup_by_size(&self.cache, self.config.max_size);
        }
    }
    
    /// Clear all entries
    pub fn clear(&self) {
        self.cache.clear();
    }
    
    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        let mut expired_count = 0;
        let mut total_count = 0;
        let mut total_age = 0;
        
        for entry in self.cache.iter() {
            total_count += 1;
            total_age += entry.age_seconds();
            
            if entry.is_expired() {
                expired_count += 1;
            }
        }
        
        CacheStats {
            total_entries: total_count,
            expired_entries: expired_count,
            valid_entries: total_count - expired_count,
            average_age_seconds: if total_count > 0 { total_age / total_count } else { 0 },
            memory_usage_estimate: (total_count as usize) * std::mem::size_of::<CacheEntry>(),
        }
    }
    
    /// Check if cache contains key (without checking expiration)
    pub fn contains_key(&self, key: &str) -> bool {
        self.cache.contains_key(key)
    }
    
    /// Get current cache size
    pub fn len(&self) -> usize {
        self.cache.len()
    }
    
    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
    
    /// Get cache configuration
    pub fn config(&self) -> &CacheConfig {
        &self.config
    }
    
    /// Clean up expired entries
    fn cleanup_expired(cache: &DashMap<String, CacheEntry>) {
        cache.retain(|_, entry| !entry.is_expired());
    }
    
    /// Clean up by size (remove oldest entries)
    fn cleanup_by_size(cache: &DashMap<String, CacheEntry>, max_size: usize) {
        if cache.len() <= max_size {
            return;
        }
        
        // Collect entries with their ages
        let mut entries: Vec<(String, u64)> = cache
            .iter()
            .map(|item| (item.key().clone(), item.value().age_seconds()))
            .collect();
        
        // Sort by age (oldest first)
        entries.sort_by(|a, b| b.1.cmp(&a.1));
        
        // Remove oldest entries to reach target size
        let remove_count = cache.len() - max_size;
        for (key, _) in entries.into_iter().take(remove_count) {
            cache.remove(&key);
        }
    }
}

impl Drop for AuthCache {
    fn drop(&mut self) {
        if let Some(handle) = self._cleanup_handle.take() {
            handle.abort();
        }
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub total_entries: u64,
    pub expired_entries: u64,
    pub valid_entries: u64,
    pub average_age_seconds: u64,
    pub memory_usage_estimate: usize,
}

impl CacheStats {
    pub fn hit_ratio(&self) -> f64 {
        if self.total_entries == 0 {
            0.0
        } else {
            self.valid_entries as f64 / self.total_entries as f64
        }
    }
    
    pub fn is_healthy(&self) -> bool {
        self.hit_ratio() > 0.8 && self.expired_entries < self.total_entries / 4
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, Duration};

    #[test]
    fn test_cache_entry() {
        let entry = CacheEntry::new(true, 1);
        assert_eq!(entry.value, true);
        assert!(!entry.is_expired());
        
        // Test expiration would require sleep, better as integration test
    }

    #[tokio::test]
    async fn test_cache_basic_operations() {
        let config = CacheConfig::new().max_size(100).ttl_seconds(60);
        let cache = AuthCache::new(config);
        
        // Test insertion and retrieval
        cache.insert("key1".to_string(), true).unwrap();
        assert_eq!(cache.get("key1"), Some(true));
        
        // Test non-existent key
        assert_eq!(cache.get("nonexistent"), None);
        
        // Test removal
        assert_eq!(cache.remove("key1"), Some(true));
        assert_eq!(cache.get("key1"), None);
    }

    #[tokio::test]
    async fn test_cache_expiration() {
        let config = CacheConfig::new()
            .max_size(100)
            .ttl_seconds(1) // 1 second TTL
            .disable_auto_cleanup();
        
        let cache = AuthCache::new(config);
        
        cache.insert("key1".to_string(), true).unwrap();
        assert_eq!(cache.get("key1"), Some(true));
        
        // Wait for expiration
        sleep(Duration::from_secs(2)).await;
        
        // Should return None due to expiration
        assert_eq!(cache.get("key1"), None);
    }

    #[test]
    fn test_cache_stats() {
        let config = CacheConfig::new().disable_auto_cleanup();
        let cache = AuthCache::new(config);
        
        cache.insert("key1".to_string(), true).unwrap();
        cache.insert("key2".to_string(), false).unwrap();
        
        let stats = cache.stats();
        assert_eq!(stats.total_entries, 2);
        assert!(stats.hit_ratio() > 0.0);
    }

    #[test]
    fn test_cache_size_limit() {
        let config = CacheConfig::new()
            .max_size(2)
            .disable_auto_cleanup();
        
        let cache = AuthCache::new(config);
        
        cache.insert("key1".to_string(), true).unwrap();
        cache.insert("key2".to_string(), true).unwrap();
        cache.insert("key3".to_string(), true).unwrap(); // Should trigger cleanup
        
        // Cache should not exceed max size
        assert!(cache.len() <= 2);
    }
}