// SPDX-License-Identifier: CC0-1.0

//! Data-availability interface for batches.
//!
//! The scheduler uses a DA backend to publish serialized batch bodies and return
//! a `da_hash` that is anchored on-chain. Implementations can be local storage,
//! external services, or in-protocol gossip. This trait stays minimal so it can
//! be swapped without touching scheduling logic.
use crate::types::DaHash;
use crate::Result;

/// Data-availability interface for batch blobs.
pub trait DAStore {
    /// Publish a serialized batch blob. Returns a hash/commitment used in anchors.
    fn publish(&self, batch_blob: &[u8]) -> Result<DaHash>;

    /// Retrieve a serialized batch blob, if available.
    fn get(&self, da_hash: &DaHash) -> Result<Option<Vec<u8>>>;
}

/// Async version of the DAStore trait for network-based implementations.
///
/// This trait provides async methods for DA stores that need to perform network I/O,
/// such as IPFS, Celestia, or other distributed storage systems.
#[async_trait::async_trait]
pub trait AsyncDAStore: Send + Sync {
    /// Publish a serialized batch blob (async). Returns a hash/commitment used in anchors.
    async fn publish(&self, batch_blob: &[u8]) -> Result<DaHash>;

    /// Retrieve a serialized batch blob, if available (async).
    async fn get(&self, da_hash: &DaHash) -> Result<Option<Vec<u8>>>;
}

/// Simple in-memory DA store for testing and reference usage.
#[derive(Default)]
pub struct InMemoryDAStore {
    blobs: std::sync::Mutex<std::collections::HashMap<DaHash, Vec<u8>>>,
}

impl InMemoryDAStore {
    /// Initialize an empty in-memory DA store.
    pub fn new() -> Self { Self { blobs: std::sync::Mutex::new(std::collections::HashMap::new()) } }
}

impl DAStore for InMemoryDAStore {
    fn publish(&self, batch_blob: &[u8]) -> Result<DaHash> {
        let hash = crate::zkp::poseidon2_hash_bytes(batch_blob);
        let mut guard = self.blobs.lock().expect("mutex poisoned");
        guard.insert(hash, batch_blob.to_vec());
        Ok(hash)
    }

    fn get(&self, da_hash: &DaHash) -> Result<Option<Vec<u8>>> {
        let guard = self.blobs.lock().expect("mutex poisoned");
        Ok(guard.get(da_hash).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let store = InMemoryDAStore::new();

        let guard = store.blobs.lock().expect("mutex poisoned");
        assert!(guard.is_empty());
    }

    #[test]
    fn test_publish() {
        let store = InMemoryDAStore::new();
        let blob = b"test".to_vec();

        let hash = store.publish(&blob).expect("publish failed");

        let guard = store.blobs.lock().expect("mutex poisoned");
        assert_eq!(guard.get(&hash), Some(&blob));
    }

    #[test]
    fn test_get() {
        let store = InMemoryDAStore::new();
        let missing_hash: DaHash = [0u8; 32];

        assert_eq!(store.get(&missing_hash).expect("get failed"), None);

        let blob = b"test".to_vec();

        let da_hash = store.publish(&blob).expect("publish failed");

        assert_eq!(store.get(&da_hash).expect("get failed"), Some(blob));
    }
}
