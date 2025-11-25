//! Sibling hash provider implementations

use std::collections::BTreeMap;
use std::sync::Arc;

use super::builder;
use super::database::Database;
use super::keys::{compute_sibling_prefix_bytes, encode_sibling_node_key};
use super::proof::compute_sibling_hash_at_depth;
use crate::global::smt::{SmtConfig, SmtHasher, SmtSiblingProvider};
use crate::types::{WalletCommitment, WalletId};
use crate::{Bytes32, Result};

/// In-memory sibling hash provider
///
/// This provider wraps a `BTreeMap` of wallet commitment hashes and computes
/// sibling hashes on-demand. It's useful for:
/// - Testing and development
/// - Small-scale systems where available commitment hashes fit in memory
///
/// For systems with many users, consider implementing a database-backed
/// provider that can query sibling hashes from stored subtree roots or SMT nodes.
///
/// # Example
///
/// ```rust,no_run
/// use merkle_morph::global::commitment::{InMemorySiblingProvider, MerkleMorphV0Config, Poseidon2Hasher};
/// use merkle_morph::global::smt::{SmtConfig, SmtHasher, SmtSiblingProvider};
/// use std::collections::BTreeMap;
///
/// let mut commitments = BTreeMap::new();
/// commitments.insert([1u8; 32], [2u8; 32]);
/// let mut provider = InMemorySiblingProvider::new(&commitments);
/// let hasher = Poseidon2Hasher;
/// let config = MerkleMorphV0Config;
/// let sibling_hash = provider.get_sibling_hash([1u8; 32], 0, &hasher, &config)?;
/// # Ok::<(), merkle_morph::errors::Error>(())
/// ```
pub struct InMemorySiblingProvider<'a> {
    wallet_commitments: &'a BTreeMap<WalletId, WalletCommitment>,
}

impl<'a> InMemorySiblingProvider<'a> {
    /// Creates a new in-memory sibling provider from a map of wallet commitment hashes
    ///
    /// # Arguments
    /// * `wallet_commitments` - Reference to a map of wallet ID to commitment hash
    pub fn new(wallet_commitments: &'a BTreeMap<WalletId, WalletCommitment>) -> Self {
        Self { wallet_commitments }
    }
}

impl<'a, H: SmtHasher, C: SmtConfig> SmtSiblingProvider<H, C> for InMemorySiblingProvider<'a> {
    fn get_sibling_hash(
        &mut self,
        wallet_id: WalletId,
        depth: u8,
        hasher: &H,
        config: &C,
    ) -> Result<Bytes32> {
        compute_sibling_hash_at_depth(wallet_id, depth, hasher, config, self.wallet_commitments)
    }
}

/// Database-backed sibling hash provider
///
/// This provider stores SMT intermediate nodes in a database and queries
/// them directly, enabling efficient proof generation at scale. Nodes are
/// computed lazily (on-demand) if they don't exist in the database.
///
/// # Performance
///
/// - Direct node lookups: O(1) after indexing
/// - Lazy population: Computes and stores missing nodes
/// - Suitable for systems with billions of users
///
/// # Example
///
/// ```rust,no_run
/// use merkle_morph::global::commitment::{
///     Database, DatabaseSiblingProvider, MerkleMorphV0Config, Poseidon2Hasher,
/// };
/// use merkle_morph::global::smt::{SmtConfig, SmtHasher, SmtSiblingProvider};
/// use std::sync::Arc;
///
/// // Create a database backend implementing the Database trait
/// // let db: Arc<dyn Database> = Arc::new(your_database_backend);
/// // let mut provider = DatabaseSiblingProvider::new(db);
/// // let hasher = Poseidon2Hasher;
/// // let config = MerkleMorphV0Config;
/// // let sibling_hash = provider.get_sibling_hash([1u8; 32], 0, &hasher, &config)?;
/// # Ok::<(), merkle_morph::errors::Error>(())
/// ```
pub struct DatabaseSiblingProvider {
    db: Arc<dyn Database>,
}

impl DatabaseSiblingProvider {
    /// Creates a new database-backed sibling provider
    ///
    /// # Arguments
    /// * `db` - The database backend (wrapped in Arc for shared ownership)
    pub fn new(db: Arc<dyn Database>) -> Self { Self { db } }

    /// Computes and stores a sibling subtree node
    ///
    /// This is called when a node is not found in the database (lazy population).
    /// It queries available wallet commitments in the sibling subtree, computes the node hash,
    /// and stores it for future use.
    ///
    /// # Arguments
    /// * `wallet_id` - The wallet ID we're generating a proof for
    /// * `depth` - The depth of the sibling node
    /// * `hasher` - The hash function implementation
    /// * `config` - The SMT configuration
    ///
    /// # Returns
    /// The computed sibling node hash
    fn compute_and_store_sibling_node<H: SmtHasher, C: SmtConfig>(
        &self,
        wallet_id: WalletId,
        depth: u8,
        hasher: &H,
        config: &C,
    ) -> Result<Bytes32> {
        // Get available wallet commitments in the sibling subtree
        let sibling_prefix = compute_sibling_prefix_bytes(&wallet_id, depth);
        let sibling_wallets = self.db.get_wallets_by_prefix(&sibling_prefix, depth)?;

        // Compute the sibling subtree root starting from depth+1
        let sibling_hash = if sibling_wallets.is_empty() {
            hasher.zero_hash()
        } else {
            builder::build_smt_node_with(&sibling_wallets, depth + 1, hasher, config)
        };

        // Store the computed node for future use
        let node_key = encode_sibling_node_key(&wallet_id, depth);
        self.db.put_smt_node(&node_key, &sibling_hash)?;

        Ok(sibling_hash)
    }
}

impl<H: SmtHasher, C: SmtConfig> SmtSiblingProvider<H, C> for DatabaseSiblingProvider {
    fn get_sibling_hash(
        &mut self,
        wallet_id: WalletId,
        depth: u8,
        hasher: &H,
        config: &C,
    ) -> Result<Bytes32> {
        // Encode the sibling node key
        let node_key = encode_sibling_node_key(&wallet_id, depth);

        // Try to get from database first
        match self.db.get_smt_node(&node_key)? {
            Some(hash) => Ok(hash),
            None => {
                // Node not found - compute it lazily and store it
                self.compute_and_store_sibling_node(wallet_id, depth, hasher, config)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use super::*;
    use crate::global::commitment::database::DbOperation;

    struct TestDatabase;

    impl Database for TestDatabase {
        fn get_wallet_commitment(&self, _wallet_id: &[u8; 32]) -> Result<Option<Bytes32>> {
            Ok(None)
        }

        fn put_wallet_commitment(
            &self,
            _wallet_id: &[u8; 32],
            _commitment: &Bytes32,
        ) -> Result<()> {
            Ok(())
        }

        fn get_smt_node(&self, _node_key: &[u8]) -> Result<Option<Bytes32>> { Ok(None) }

        fn put_smt_node(&self, _node_key: &[u8], _node_hash: &Bytes32) -> Result<()> { Ok(()) }

        fn delete_smt_node(&self, _node_key: &[u8]) -> Result<()> { Ok(()) }

        fn get_wallets_by_prefix(
            &self,
            _prefix: &[u8],
            _depth: u8,
        ) -> Result<BTreeMap<[u8; 32], Bytes32>> {
            Ok(BTreeMap::new())
        }

        fn batch_write(&self, _ops: Vec<DbOperation>) -> Result<()> { Ok(()) }
    }

    #[test]
    fn test_new() {
        let wallet_commitments = BTreeMap::new();
        let _provider = InMemorySiblingProvider::new(&wallet_commitments);
    }

    #[test]
    fn test_new_database() {
        let db = Arc::new(TestDatabase);
        let _provider = DatabaseSiblingProvider::new(db);
    }
}
