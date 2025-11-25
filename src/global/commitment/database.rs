//! Database abstraction layer for SMT node storage
//!
//! This module provides a trait-based abstraction for database backends,
//! allowing different storage implementations (RocksDB, PostgreSQL, etc.)
//! to be used interchangeably.

use std::collections::BTreeMap;

use crate::{Bytes32, Result};

/// Database trait for storing and retrieving SMT nodes and wallet commitments
///
/// This trait abstracts over different database backends, allowing the
/// system to work with embedded databases (RocksDB) or remote databases
/// (PostgreSQL) without changing the core logic.
pub trait Database: Send + Sync {
    /// Gets a wallet commitment by wallet ID
    ///
    /// # Arguments
    /// * `wallet_id` - The wallet ID to look up
    ///
    /// # Returns
    /// `Ok(Some(commitment))` if found, `Ok(None)` if not found, or error
    fn get_wallet_commitment(&self, wallet_id: &[u8; 32]) -> Result<Option<Bytes32>>;

    /// Stores a wallet commitment
    ///
    /// # Arguments
    /// * `wallet_id` - The wallet ID
    /// * `commitment` - The wallet commitment
    fn put_wallet_commitment(&self, wallet_id: &[u8; 32], commitment: &Bytes32) -> Result<()>;

    /// Gets an SMT node hash by node key
    ///
    /// The node key encodes the bit-prefix path to the node in the tree.
    ///
    /// # Arguments
    /// * `node_key` - The encoded node key (depth + bit-prefix)
    ///
    /// # Returns
    /// `Ok(Some(hash))` if found, `Ok(None)` if not found, or error
    fn get_smt_node(&self, node_key: &[u8]) -> Result<Option<Bytes32>>;

    /// Stores an SMT node hash
    ///
    /// # Arguments
    /// * `node_key` - The encoded node key
    /// * `node_hash` - The node hash to store
    fn put_smt_node(&self, node_key: &[u8], node_hash: &Bytes32) -> Result<()>;

    /// Deletes an SMT node
    ///
    /// # Arguments
    /// * `node_key` - The encoded node key to delete
    fn delete_smt_node(&self, node_key: &[u8]) -> Result<()>;

    /// Gets wallet commitments in a range
    ///
    /// This is used for computing subtrees when nodes are not pre-computed.
    /// The range is defined by bit-prefix matching. Returns available wallet
    /// commitment hashes that match the prefix.
    ///
    /// # Arguments
    /// * `prefix` - The bit-prefix to match (up to depth bits)
    /// * `depth` - The depth (number of bits in prefix)
    ///
    /// # Returns
    /// Map of wallet IDs to commitments that match the prefix
    fn get_wallets_by_prefix(
        &self,
        prefix: &[u8],
        depth: u8,
    ) -> Result<BTreeMap<[u8; 32], Bytes32>>;

    /// Batch write operations
    ///
    /// Allows multiple operations to be performed atomically.
    ///
    /// # Arguments
    /// * `ops` - Vector of database operations
    fn batch_write(&self, ops: Vec<DbOperation>) -> Result<()>;
}

/// Database operation for batch writes
#[derive(Clone, Debug)]
pub enum DbOperation {
    /// Store a wallet commitment
    PutWalletCommitment {
        /// The wallet ID
        wallet_id: [u8; 32],

        /// The wallet commitment
        commitment: Bytes32,
    },
    /// Store an SMT node
    PutSmtNode {
        /// The encoded node key
        node_key: Vec<u8>,
        /// The node hash to store
        node_hash: Bytes32,
    },
    /// Delete an SMT node
    DeleteSmtNode {
        /// The encoded node key to delete
        node_key: Vec<u8>,
    },
}
