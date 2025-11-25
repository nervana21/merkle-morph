//! High-performance cache layer for sibling hash provider
//!
//! This module provides a caching wrapper around a sibling hash provider,
//! using a sharded, concurrent cache (quick-cache with S3-FIFO eviction policy)
//! to store frequently accessed sibling hashes in memory.
//! This significantly improves performance for repeated proof generation requests.

use std::hash::Hash;
use std::sync::Arc;

use quick_cache::sync::Cache;

use crate::global::smt::{SmtConfig, SmtHasher, SmtSiblingProvider};
use crate::types::WalletId;
use crate::{Bytes32, Result};

/// Cache key for sibling hashes
///
/// Combines wallet ID and depth into a single cache key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct CacheKey {
    wallet_id: WalletId,
    depth: u8,
}

impl CacheKey {
    fn new(wallet_id: WalletId, depth: u8) -> Self { Self { wallet_id, depth } }
}

/// Cached sibling hash provider
///
/// Wraps another sibling provider with a high-performance concurrent cache to improve
/// performance for repeated lookups. The cache uses S3-FIFO eviction policy (scan-resistant
/// and high hit rate) and automatically evicts entries when it reaches capacity.
///
/// # Performance
///
/// - Cache hits: O(1) lookup with lock-free reads (RwLock)
/// - Cache misses: Delegates to underlying provider
/// - Thread-safe: Concurrent design with minimal contention
///
/// # Example
///
/// ```rust,no_run
/// use merkle_morph::global::commitment::{
///     CachedSiblingProvider, Database, DatabaseSiblingProvider, MerkleMorphV0Config,
///     Poseidon2Hasher,
/// };
/// use merkle_morph::global::smt::{SmtConfig, SmtHasher, SmtSiblingProvider};
/// use std::sync::Arc;
///
/// // Create a sibling provider implementing the SmtSiblingProvider trait
/// // let db: Arc<dyn Database> = Arc::new(your_database_backend);
/// // let db_provider = DatabaseSiblingProvider::new(db);
/// // let mut cached_provider = CachedSiblingProvider::new(db_provider, 10000);
/// // let hasher = Poseidon2Hasher;
/// // let config = MerkleMorphV0Config;
/// // let sibling_hash = cached_provider.get_sibling_hash([1u8; 32], 0, &hasher, &config)?;
/// # Ok::<(), merkle_morph::errors::Error>(())
/// ```
pub struct CachedSiblingProvider<P> {
    provider: P,
    cache: Arc<Cache<CacheKey, Bytes32>>,
}

impl<P> CachedSiblingProvider<P> {
    /// Creates a new cached sibling provider
    ///
    /// # Arguments
    /// * `provider` - The underlying sibling provider to wrap
    /// * `capacity` - Maximum number of entries in the cache (approximately)
    pub fn new(provider: P, capacity: usize) -> Self {
        Self { provider, cache: Arc::new(Cache::new(capacity.max(1))) }
    }

    /// Clears the cache
    ///
    /// This is useful when wallet commitments are updated and cached
    /// sibling hashes may be invalid.
    pub fn clear_cache(&mut self) { self.cache.clear(); }

    /// Invalidates cache entries for a specific wallet ID
    ///
    /// When a wallet commitment is updated, all sibling hashes along
    /// its path may change. This function removes all cached entries
    /// for the given wallet ID.
    ///
    /// # Arguments
    /// * `wallet_id` - The wallet ID to invalidate
    pub fn invalidate_wallet(&mut self, wallet_id: WalletId) {
        // Use retain to remove all entries for this wallet (all depths)
        // This is more efficient than iterating and removing individually
        self.cache.retain(|key, _| key.wallet_id != wallet_id);
    }
}

impl<P, H: SmtHasher, C: SmtConfig> SmtSiblingProvider<H, C> for CachedSiblingProvider<P>
where
    P: SmtSiblingProvider<H, C>,
{
    fn get_sibling_hash(
        &mut self,
        wallet_id: WalletId,
        depth: u8,
        hasher: &H,
        config: &C,
    ) -> Result<Bytes32> {
        let cache_key = CacheKey::new(wallet_id, depth);

        if let Some(cached_hash) = self.cache.get(&cache_key) {
            return Ok(cached_hash);
        }

        let hash = self.provider.get_sibling_hash(wallet_id, depth, hasher, config)?;

        self.cache.insert(cache_key, hash);

        Ok(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::global::commitment::{MerkleMorphV0Config, Poseidon2Hasher};

    struct MockProvider {
        hash: Bytes32,
    }

    impl<H: SmtHasher, C: SmtConfig> SmtSiblingProvider<H, C> for MockProvider {
        fn get_sibling_hash(
            &mut self,
            _wallet_id: WalletId,
            _depth: u8,
            _hasher: &H,
            _config: &C,
        ) -> Result<Bytes32> {
            Ok(self.hash)
        }
    }

    #[test]
    fn test_new() {
        let provider = MockProvider { hash: [1u8; 32] };

        let cached = CachedSiblingProvider::new(provider, 0);

        assert_eq!(cached.cache.capacity(), 1);

        let provider = MockProvider { hash: [2u8; 32] };

        let cached = CachedSiblingProvider::new(provider, 10);

        assert_eq!(cached.cache.capacity(), 10);
    }

    #[test]
    fn test_clear_cache() {
        let provider = MockProvider { hash: [1u8; 32] };
        let mut cached = CachedSiblingProvider::new(provider, 10);
        let hasher = Poseidon2Hasher;
        let config = MerkleMorphV0Config;
        let wallet_id = [1u8; 32];
        let _ = cached
            .get_sibling_hash(wallet_id, 0, &hasher, &config)
            .expect("should get sibling hash");
        assert!(cached.cache.get(&CacheKey::new(wallet_id, 0)).is_some());

        cached.clear_cache();

        assert!(cached.cache.get(&CacheKey::new(wallet_id, 0)).is_none());
    }

    #[test]
    fn test_invalidate_wallet() {
        let provider = MockProvider { hash: [1u8; 32] };
        let mut cached = CachedSiblingProvider::new(provider, 10);
        let hasher = Poseidon2Hasher;
        let config = MerkleMorphV0Config;
        let wallet_id1 = [1u8; 32];
        let wallet_id2 = [2u8; 32];
        let _ = cached
            .get_sibling_hash(wallet_id1, 0, &hasher, &config)
            .expect("should get sibling hash");
        let _ = cached
            .get_sibling_hash(wallet_id1, 1, &hasher, &config)
            .expect("should get sibling hash");
        let _ = cached
            .get_sibling_hash(wallet_id2, 0, &hasher, &config)
            .expect("should get sibling hash");
        assert!(cached.cache.get(&CacheKey::new(wallet_id1, 0)).is_some());
        assert!(cached.cache.get(&CacheKey::new(wallet_id1, 1)).is_some());
        assert!(cached.cache.get(&CacheKey::new(wallet_id2, 0)).is_some());

        cached.invalidate_wallet(wallet_id1);

        assert!(cached.cache.get(&CacheKey::new(wallet_id1, 0)).is_none());
        assert!(cached.cache.get(&CacheKey::new(wallet_id1, 1)).is_none());
        assert!(cached.cache.get(&CacheKey::new(wallet_id2, 0)).is_some());
    }

    #[test]
    fn test_get_sibling_hash() {
        let provider = MockProvider { hash: [5u8; 32] };
        let mut cached = CachedSiblingProvider::new(provider, 10);
        let hasher = Poseidon2Hasher;
        let config = MerkleMorphV0Config;
        let wallet_id = [1u8; 32];
        let depth = 0;

        let hash1 = cached
            .get_sibling_hash(wallet_id, depth, &hasher, &config)
            .expect("should get sibling hash");

        assert_eq!(hash1, [5u8; 32]);
        assert!(cached.cache.get(&CacheKey::new(wallet_id, depth)).is_some());

        let hash2 = cached
            .get_sibling_hash(wallet_id, depth, &hasher, &config)
            .expect("should get sibling hash");

        assert_eq!(hash2, [5u8; 32]);
        assert_eq!(hash1, hash2);
    }
}
