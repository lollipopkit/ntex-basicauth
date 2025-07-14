//! Auth cache implementation with TTL and size management

use dashmap::DashMap;
use ntex::time::interval;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::{AuthError, AuthResult};

/// Cache entry with TTL support
#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub value: bool,
    pub expires_at: u64,
    pub created_at: u64,
    pub access_count: u64,
    pub last_accessed: u64,
}

impl CacheEntry {
    pub fn new(value: bool, ttl_seconds: u64) -> Self {
        let now = current_timestamp();

        Self {
            value,
            expires_at: now + ttl_seconds,
            created_at: now,
            access_count: 1,
            last_accessed: now,
        }
    }

    pub fn is_expired(&self) -> bool {
        current_timestamp() > self.expires_at
    }

    pub fn age_seconds(&self) -> u64 {
        current_timestamp().saturating_sub(self.created_at)
    }

    pub fn time_since_last_access(&self) -> u64 {
        current_timestamp().saturating_sub(self.last_accessed)
    }

    /// Update access info
    pub fn mark_accessed(&mut self) {
        self.access_count += 1;
        self.last_accessed = current_timestamp();
    }

    /// Calculate entry hotness score (for cleanup decisions)
    pub fn hotness_score(&self) -> f64 {
        let age = self.age_seconds() as f64;
        let access_rate = self.access_count as f64 / age.max(1.0);
        let recency = 1.0 / (self.time_since_last_access() as f64 + 1.0);

        access_rate * recency
    }
}

/// Cache configuration
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Maximum number of entries
    pub max_size: usize,
    /// TTL (seconds)
    pub ttl_seconds: u64,
    /// Cleanup interval (seconds)
    pub cleanup_interval_seconds: u64,
    /// Enable auto cleanup
    pub auto_cleanup: bool,
    /// Soft limit cleanup threshold (start cleanup when exceeded)
    pub soft_limit_ratio: f64,
    /// Max entries to clean per batch
    pub cleanup_batch_size: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_size: 1000,
            ttl_seconds: 300,             // 5 minutes
            cleanup_interval_seconds: 60, // 1 minute
            auto_cleanup: true,
            soft_limit_ratio: 0.8, // Start cleanup at 80%
            cleanup_batch_size: 100,
        }
    }
}

impl CacheConfig {
    /// Create new default config
    pub fn new() -> Self {
        Self::default()
    }

    /// Set max entries
    pub fn max_size(mut self, size: usize) -> Self {
        self.max_size = size;
        self
    }

    /// Set TTL (seconds)
    pub fn ttl_seconds(mut self, seconds: u64) -> Self {
        self.ttl_seconds = seconds;
        self
    }

    /// Set TTL (minutes)
    pub fn ttl_minutes(self, minutes: u64) -> Self {
        self.ttl_seconds(minutes * 60)
    }

    /// Set TTL (hours)
    pub fn ttl_hours(self, hours: u64) -> Self {
        self.ttl_seconds(hours * 3600)
    }

    /// Set cleanup interval (seconds)
    pub fn cleanup_interval_seconds(mut self, seconds: u64) -> Self {
        self.cleanup_interval_seconds = seconds;
        self
    }

    /// Disable auto cleanup
    pub fn disable_auto_cleanup(mut self) -> Self {
        self.auto_cleanup = false;
        self
    }

    /// Set soft limit ratio (start cleanup when exceeded)
    pub fn soft_limit_ratio(mut self, ratio: f64) -> Self {
        self.soft_limit_ratio = ratio;
        self
    }

    /// Set max entries to clean per batch
    pub fn cleanup_batch_size(mut self, size: usize) -> Self {
        self.cleanup_batch_size = size;
        self
    }

    /// Validate config
    pub fn validate(&self) -> AuthResult<()> {
        if self.max_size == 0 {
            return Err(AuthError::ConfigError(
                "max_size must be greater than 0".to_string(),
            ));
        }
        if self.ttl_seconds == 0 {
            return Err(AuthError::ConfigError(
                "ttl_seconds must be greater than 0".to_string(),
            ));
        }
        if self.cleanup_interval_seconds == 0 {
            return Err(AuthError::ConfigError(
                "cleanup_interval_seconds must be greater than 0".to_string(),
            ));
        }
        if !(0.1..=0.95).contains(&self.soft_limit_ratio) {
            return Err(AuthError::ConfigError(
                "soft_limit_ratio must be between 0.1 and 0.95".to_string(),
            ));
        }
        Ok(())
    }
}

/// Auth cache with TTL and auto cleanup
pub struct AuthCache {
    cache: Arc<DashMap<String, CacheEntry>>,
    config: CacheConfig,
    stats: CacheStatistics,
    _cleanup_handle: Option<ntex::rt::JoinHandle<()>>,
}

impl AuthCache {
    /// Create a new auth cache instance
    pub fn new(config: CacheConfig) -> AuthResult<Self> {
        config.validate()?;

        let cache = Arc::new(DashMap::new());
        let stats = CacheStatistics::new();

        let cleanup_handle = if config.auto_cleanup {
            Some(Self::start_cleanup_task(
                Arc::clone(&cache),
                config.clone(),
                stats.clone(),
            ))
        } else {
            None
        };

        Ok(Self {
            cache,
            config,
            stats,
            _cleanup_handle: cleanup_handle,
        })
    }

    /// Start background cleanup task
    fn start_cleanup_task(
        cache: Arc<DashMap<String, CacheEntry>>,
        config: CacheConfig,
        stats: CacheStatistics,
    ) -> ntex::rt::JoinHandle<()> {
        ntex::rt::spawn(async move {
            let interval = interval(Duration::from_secs(config.cleanup_interval_seconds));

            loop {
                interval.tick().await;

                // Clean up expired entries
                let expired_count = Self::cleanup_expired(&cache);
                stats.add_expired_cleaned(expired_count);

                // Check if size cleanup is needed
                let soft_limit = (config.max_size as f64 * config.soft_limit_ratio) as usize;
                if cache.len() > soft_limit {
                    let cleaned = Self::cleanup_by_hotness(&cache, config.cleanup_batch_size);
                    stats.add_size_cleaned(cleaned);
                }
            }
        })
    }

    /// Get value from cache
    pub fn get(&self, key: &str) -> Option<bool> {
        self.stats.add_access();

        if let Some(mut entry) = self.cache.get_mut(key) {
            if entry.is_expired() {
                drop(entry); // Release the lock before removing
                self.cache.remove(key);
                self.stats.add_miss();
                None
            } else {
                entry.mark_accessed();
                let value = entry.value;
                self.stats.add_hit();
                Some(value)
            }
        } else {
            self.stats.add_miss();
            None
        }
    }

    /// Insert value into cache
    pub fn insert(&self, key: String, value: bool) -> AuthResult<()> {
        // Check the size limit before insertion
        if self.cache.len() >= self.config.max_size {
            self.force_cleanup();
        }

        let entry = CacheEntry::new(value, self.config.ttl_seconds);
        self.cache.insert(key, entry);
        self.stats.add_insertion();
        Ok(())
    }

    /// Remove entry from cache
    pub fn remove(&self, key: &str) -> Option<bool> {
        self.cache.remove(key).map(|(_, entry)| {
            self.stats.add_removal();
            entry.value
        })
    }

    /// Force cleanup (sync)
    pub fn force_cleanup(&self) {
        let expired_count = Self::cleanup_expired(&self.cache);
        self.stats.add_expired_cleaned(expired_count);

        // If size exceeds max_size, clean up by hotness
        if self.cache.len() > self.config.max_size {
            let cleaned = Self::cleanup_by_hotness(&self.cache, self.config.cleanup_batch_size);
            self.stats.add_size_cleaned(cleaned);
        }
    }

    /// Clear the entire cache
    pub fn clear(&self) {
        let count = self.cache.len();
        self.cache.clear();
        self.stats.add_cleared(count);
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        let total_entries = self.cache.len() as u64;
        let expired_count = self.cache.iter().filter(|entry| entry.is_expired()).count() as u64;

        let (total_age, min_age, max_age) = if total_entries > 0 {
            let ages: Vec<u64> = self.cache.iter().map(|entry| entry.age_seconds()).collect();

            let total: u64 = ages.iter().sum();
            let min = *ages.iter().min().unwrap_or(&0);
            let max = *ages.iter().max().unwrap_or(&0);

            (total, min, max)
        } else {
            (0, 0, 0)
        };

        CacheStats {
            total_entries,
            expired_entries: expired_count,
            valid_entries: total_entries - expired_count,
            average_age_seconds: if total_entries > 0 {
                total_age / total_entries
            } else {
                0
            },
            min_age_seconds: min_age,
            max_age_seconds: max_age,
            memory_usage_estimate: total_entries as usize * std::mem::size_of::<CacheEntry>(),
            hit_count: self.stats.hit_count.load(Ordering::Relaxed),
            miss_count: self.stats.miss_count.load(Ordering::Relaxed),
            total_accesses: self.stats.total_accesses.load(Ordering::Relaxed),
            insertions: self.stats.insertions.load(Ordering::Relaxed),
            removals: self.stats.removals.load(Ordering::Relaxed),
            expired_cleaned: self.stats.expired_cleaned.load(Ordering::Relaxed),
            size_cleaned: self.stats.size_cleaned.load(Ordering::Relaxed),
        }
    }

    /// Check if the cache contains a key
    pub fn contains_key(&self, key: &str) -> bool {
        self.cache.contains_key(key)
    }

    /// Get the number of entries in the cache
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Check if the cache is empty
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// Get the cache configuration
    pub fn config(&self) -> &CacheConfig {
        &self.config
    }

    /// Cleanup expired entries
    fn cleanup_expired(cache: &DashMap<String, CacheEntry>) -> u64 {
        let initial_len = cache.len();
        cache.retain(|_, entry| !entry.is_expired());
        (initial_len - cache.len()) as u64
    }

    /// Cleanup by hotness score
    fn cleanup_by_hotness(cache: &DashMap<String, CacheEntry>, max_remove: usize) -> u64 {
        if cache.len() == 0 {
            return 0;
        }

        // Collect entries and their hotness scores
        let mut entries: Vec<(String, f64)> = cache
            .iter()
            .map(|item| (item.key().clone(), item.value().hotness_score()))
            .collect();

        // Sort by hotness score (ascending)
        entries.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));

        // Remove the least hot entries
        let remove_count = max_remove.min(entries.len());
        let mut removed = 0;

        for (key, _) in entries.into_iter().take(remove_count) {
            if cache.remove(&key).is_some() {
                removed += 1;
            }
        }

        removed
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Total entries
    pub total_entries: u64,
    /// Expired entries
    pub expired_entries: u64,
    /// Valid entries
    pub valid_entries: u64,
    /// Average entry age (seconds)
    pub average_age_seconds: u64,
    /// Minimum entry age (seconds)
    pub min_age_seconds: u64,
    /// Maximum entry age (seconds)
    pub max_age_seconds: u64,
    /// Memory usage estimate (bytes)
    pub memory_usage_estimate: usize,
    /// Hit count
    pub hit_count: u64,
    /// Miss count
    pub miss_count: u64,
    /// Total accesses
    pub total_accesses: u64,
    /// Insertions
    pub insertions: u64,
    /// Removals
    pub removals: u64,
    /// Expired cleaned count
    pub expired_cleaned: u64,
    /// Size cleaned count
    pub size_cleaned: u64,
}

impl CacheStats {
    /// Hit ratio
    pub fn hit_ratio(&self) -> f64 {
        if self.total_accesses == 0 {
            0.0
        } else {
            self.hit_count as f64 / self.total_accesses as f64
        }
    }

    /// Miss ratio
    pub fn miss_ratio(&self) -> f64 {
        1.0 - self.hit_ratio()
    }

    /// Is healthy (hit ratio > 0.8 and expired entries < 1/4 of total)
    pub fn is_healthy(&self) -> bool {
        self.hit_ratio() > 0.8 && self.expired_entries < self.total_entries / 4
    }

    /// Efficiency score (hit ratio * (1 - expired ratio))
    pub fn efficiency_score(&self) -> f64 {
        let hit_ratio = self.hit_ratio();
        let expired_ratio = if self.total_entries > 0 {
            self.expired_entries as f64 / self.total_entries as f64
        } else {
            0.0
        };

        hit_ratio * (1.0 - expired_ratio)
    }
}

/// Internal cache statistics structure
#[derive(Debug, Clone)]
struct CacheStatistics {
    hit_count: Arc<AtomicU64>,
    miss_count: Arc<AtomicU64>,
    total_accesses: Arc<AtomicU64>,
    insertions: Arc<AtomicU64>,
    removals: Arc<AtomicU64>,
    expired_cleaned: Arc<AtomicU64>,
    size_cleaned: Arc<AtomicU64>,
}

impl CacheStatistics {
    fn new() -> Self {
        Self {
            hit_count: Arc::new(AtomicU64::new(0)),
            miss_count: Arc::new(AtomicU64::new(0)),
            total_accesses: Arc::new(AtomicU64::new(0)),
            insertions: Arc::new(AtomicU64::new(0)),
            removals: Arc::new(AtomicU64::new(0)),
            expired_cleaned: Arc::new(AtomicU64::new(0)),
            size_cleaned: Arc::new(AtomicU64::new(0)),
        }
    }

    fn add_hit(&self) {
        self.hit_count.fetch_add(1, Ordering::Relaxed);
    }

    fn add_miss(&self) {
        self.miss_count.fetch_add(1, Ordering::Relaxed);
    }

    fn add_access(&self) {
        self.total_accesses.fetch_add(1, Ordering::Relaxed);
    }

    fn add_insertion(&self) {
        self.insertions.fetch_add(1, Ordering::Relaxed);
    }

    fn add_removal(&self) {
        self.removals.fetch_add(1, Ordering::Relaxed);
    }

    fn add_expired_cleaned(&self, count: u64) {
        self.expired_cleaned.fetch_add(count, Ordering::Relaxed);
    }

    fn add_size_cleaned(&self, count: u64) {
        self.size_cleaned.fetch_add(count, Ordering::Relaxed);
    }

    fn add_cleared(&self, count: usize) {
        self.removals.fetch_add(count as u64, Ordering::Relaxed);
    }
}

/// Get the current timestamp in seconds since UNIX epoch
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{Duration, sleep};

    #[test]
    fn test_cache_entry() {
        let entry = CacheEntry::new(true, 60);
        assert_eq!(entry.value, true);
        assert!(!entry.is_expired());
        assert_eq!(entry.access_count, 1);
    }

    #[ntex::test]
    async fn test_cache_basic_operations() {
        let config = CacheConfig::new().max_size(100).ttl_seconds(60);
        let cache = AuthCache::new(config).unwrap();

        // Test insert and get
        cache.insert("key1".to_string(), true).unwrap();
        assert_eq!(cache.get("key1"), Some(true));

        // Test non-existent key
        assert_eq!(cache.get("nonexistent"), None);

        // Test remove
        assert_eq!(cache.remove("key1"), Some(true));
        assert_eq!(cache.get("key1"), None);
    }

    #[tokio::test]
    async fn test_cache_expiration() {
        let config = CacheConfig::new()
            .max_size(100)
            .ttl_seconds(1)
            .disable_auto_cleanup();

        let cache = AuthCache::new(config).unwrap();

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
        let cache = AuthCache::new(config).unwrap();

        cache.insert("key1".to_string(), true).unwrap();
        cache.insert("key2".to_string(), false).unwrap();

        // Trigger some accesses to generate stats
        cache.get("key1");
        cache.get("key2");
        cache.get("nonexistent");

        let stats = cache.stats();
        assert_eq!(stats.total_entries, 2);
        assert!(stats.hit_ratio() > 0.0);
        assert!(stats.efficiency_score() > 0.0);
    }

    #[test]
    fn test_hotness_score() {
        let entry1 = CacheEntry::new(true, 60);
        let mut entry2 = CacheEntry::new(true, 60);

        // Simulate multiple accesses
        for _ in 0..10 {
            entry2.mark_accessed();
        }

        // entry2 should have higher hotness score
        assert!(entry2.hotness_score() > entry1.hotness_score());
    }

    #[test]
    fn test_config_validation() {
        assert!(CacheConfig::new().max_size(0).validate().is_err());
        assert!(CacheConfig::new().ttl_seconds(0).validate().is_err());
        assert!(CacheConfig::new().soft_limit_ratio(1.5).validate().is_err());
        assert!(CacheConfig::new().validate().is_ok());
    }
}
