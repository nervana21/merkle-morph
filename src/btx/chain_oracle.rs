// SPDX-License-Identifier: CC0-1.0

//! Chain Oracle pattern for Bitcoin chain queries
//!
//! This module provides a Chain Oracle abstraction that allows querying Bitcoin
//! chain state without tight coupling to specific chain data sources. This enables:
//!
//! - P2A anchor confirmation verification
//! - Force-close timelock validation with chain height queries
//! - Testability with mock implementations
//! - Support for multiple chain data sources (bitcoind RPC, esplora, etc.)
//!
//! # Example
//!
//! ```rust,no_run
//! use merkle_morph::btx::chain_oracle::ChainOracle;
//! use bitcoin::BlockHash;
//! use bitcoin::hashes::Hash;
//!
//! // Use a chain oracle to verify an anchor is confirmed
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # struct MyChainOracle;
//! # impl ChainOracle for MyChainOracle {
//! #     type Error = std::convert::Infallible;
//! #     fn is_block_in_chain(&self, block: BlockHash, tip: BlockHash) -> Result<Option<bool>, Self::Error> {
//! #         Ok(Some(true))
//! #     }
//! #     fn get_chain_tip(&self) -> Result<BlockHash, Self::Error> {
//! #         Ok(BlockHash::from_byte_array([0u8; 32]))
//! #     }
//! # }
//! # let oracle = MyChainOracle;
//! # let block_hash = BlockHash::from_byte_array([0u8; 32]);
//! let tip = oracle.get_chain_tip()?;
//! let is_confirmed = oracle.is_block_in_chain(block_hash, tip)?;
//! # Ok(())
//! # }
//! ```

use std::collections::BTreeSet;

use bitcoin::BlockHash;

/// Trait for querying Bitcoin chain state
///
/// This trait provides two essential operations:
/// - Checking if a block is in the best chain
/// - Getting the current chain tip
pub trait ChainOracle {
    /// Error type for chain oracle operations
    type Error: std::fmt::Debug;

    /// Determines whether `block` exists as an ancestor of `chain_tip`.
    ///
    /// This method checks if a given block is part of the chain leading to
    /// the specified chain tip. This is useful for verifying that a transaction
    /// or anchor is confirmed in the best chain.
    ///
    /// # Arguments
    /// * `block` - The block hash to check
    /// * `chain_tip` - The chain tip to check against
    ///
    /// # Returns
    /// * `Ok(Some(true))` - Block is confirmed in the chain
    /// * `Ok(Some(false))` - Block is not in the chain (or is in a different fork)
    /// * `Ok(None)` - Cannot determine (e.g., unknown block, tip mismatch, or implementation limitation)
    /// * `Err` - Error during query
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use merkle_morph::btx::chain_oracle::ChainOracle;
    /// use bitcoin::BlockHash;
    /// use bitcoin::hashes::Hash;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # struct MyChainOracle;
    /// # impl ChainOracle for MyChainOracle {
    /// #     type Error = std::convert::Infallible;
    /// #     fn is_block_in_chain(&self, block: BlockHash, tip: BlockHash) -> Result<Option<bool>, Self::Error> {
    /// #         Ok(Some(true))
    /// #     }
    /// #     fn get_chain_tip(&self) -> Result<BlockHash, Self::Error> {
    /// #         Ok(BlockHash::from_byte_array([0u8; 32]))
    /// #     }
    /// # }
    /// # let oracle = MyChainOracle;
    /// # let block_hash = BlockHash::from_byte_array([0u8; 32]);
    /// let tip = oracle.get_chain_tip()?;
    /// match oracle.is_block_in_chain(block_hash, tip)? {
    ///     Some(true) => println!("Block is confirmed"),
    ///     Some(false) => println!("Block is not in chain"),
    ///     None => println!("Cannot determine"),
    /// }
    /// # Ok(())
    /// # }
    /// ```
    fn is_block_in_chain(
        &self,
        block: BlockHash,
        chain_tip: BlockHash,
    ) -> Result<Option<bool>, Self::Error>;

    /// Get the best chain's chain tip.
    ///
    /// Returns the block hash of the current best chain tip (the most recent
    /// block in the longest valid chain).
    ///
    /// # Returns
    /// * `Ok(BlockHash)` - The current chain tip
    /// * `Err` - Error during query
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use merkle_morph::btx::chain_oracle::ChainOracle;
    /// use bitcoin::hashes::Hash;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # struct MyChainOracle;
    /// # impl ChainOracle for MyChainOracle {
    /// #     type Error = std::convert::Infallible;
    /// #     fn is_block_in_chain(&self, _block: bitcoin::BlockHash, _tip: bitcoin::BlockHash) -> Result<Option<bool>, Self::Error> {
    /// #         Ok(Some(true))
    /// #     }
    /// #     fn get_chain_tip(&self) -> Result<bitcoin::BlockHash, Self::Error> {
    /// #         Ok(bitcoin::BlockHash::from_byte_array([0u8; 32]))
    /// #     }
    /// # }
    /// # let oracle = MyChainOracle;
    /// let tip = oracle.get_chain_tip()?;
    /// println!("Current chain tip: {}", tip);
    /// # Ok(())
    /// # }
    /// ```
    fn get_chain_tip(&self) -> Result<BlockHash, Self::Error>;
}

/// Mock implementation of ChainOracle for testing
///
/// This implementation maintains a simple set of known blocks and a chain tip.
/// It's useful for unit tests where you need to control chain state without
/// requiring a real Bitcoin node or chain data source.
///
/// # Example
///
/// ```rust
/// use merkle_morph::btx::chain_oracle::{ChainOracle, MockChainOracle};
/// use bitcoin::BlockHash;
/// use bitcoin::hashes::Hash;
///
/// let mut oracle = MockChainOracle::new(BlockHash::from_byte_array([0u8; 32]));
/// let block1 = BlockHash::from_byte_array([1u8; 32]);
/// oracle.add_block(block1);
///
/// let tip = oracle.get_chain_tip().unwrap();
/// assert!(oracle.is_block_in_chain(block1, tip).unwrap().unwrap());
/// ```
#[derive(Clone, Debug)]
pub struct MockChainOracle {
    /// Current chain tip
    tip: BlockHash,
    /// Set of blocks known to be in the chain
    blocks: BTreeSet<BlockHash>,
}

impl MockChainOracle {
    /// Create a new mock chain oracle with the given chain tip
    ///
    /// # Arguments
    /// * `tip` - The initial chain tip
    pub fn new(tip: BlockHash) -> Self {
        let mut blocks = BTreeSet::new();
        blocks.insert(tip);
        Self { tip, blocks }
    }

    /// Add a block to the known chain
    ///
    /// # Arguments
    /// * `block` - The block hash to add
    pub fn add_block(&mut self, block: BlockHash) { self.blocks.insert(block); }

    /// Update the chain tip
    ///
    /// # Arguments
    /// * `tip` - The new chain tip
    pub fn set_tip(&mut self, tip: BlockHash) {
        self.tip = tip;
        self.blocks.insert(tip);
    }

    /// Get the current chain tip (without going through the trait)
    pub fn tip(&self) -> BlockHash { self.tip }
}

impl ChainOracle for MockChainOracle {
    type Error = std::convert::Infallible;

    fn is_block_in_chain(
        &self,
        block: BlockHash,
        chain_tip: BlockHash,
    ) -> Result<Option<bool>, Self::Error> {
        // If the tip doesn't match our known tip, we can't determine
        if chain_tip != self.tip {
            return Ok(None);
        }
        // Check if the block is in our known set
        Ok(Some(self.blocks.contains(&block)))
    }

    fn get_chain_tip(&self) -> Result<BlockHash, Self::Error> { Ok(self.tip) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let tip = BlockHash::from_byte_array([1u8; 32]);

        let oracle = MockChainOracle::new(tip);

        assert_eq!(oracle.get_chain_tip().unwrap(), tip);
        assert_eq!(oracle.is_block_in_chain(tip, tip).unwrap(), Some(true));
    }

    #[test]
    fn test_add_block() {
        let tip = BlockHash::from_byte_array([1u8; 32]);
        let mut oracle = MockChainOracle::new(tip);
        let block = BlockHash::from_byte_array([2u8; 32]);

        oracle.add_block(block);

        assert_eq!(oracle.is_block_in_chain(block, tip).unwrap(), Some(true));
    }

    #[test]
    fn test_set_tip() {
        let tip1 = BlockHash::from_byte_array([1u8; 32]);
        let mut oracle = MockChainOracle::new(tip1);
        let tip2 = BlockHash::from_byte_array([2u8; 32]);

        oracle.set_tip(tip2);

        assert_eq!(oracle.get_chain_tip().unwrap(), tip2);
        assert_eq!(oracle.is_block_in_chain(tip2, tip2).unwrap(), Some(true));
    }

    #[test]
    fn test_tip() {
        let tip = BlockHash::from_byte_array([1u8; 32]);
        let oracle = MockChainOracle::new(tip);

        assert_eq!(oracle.tip(), tip);
    }

    #[test]
    fn test_is_block_in_chain() {
        let tip1 = BlockHash::from_byte_array([1u8; 32]);
        let mut oracle = MockChainOracle::new(tip1);
        let block = BlockHash::from_byte_array([2u8; 32]);
        oracle.add_block(block);
        let tip2 = BlockHash::from_byte_array([3u8; 32]);
        let unknown_block = BlockHash::from_byte_array([4u8; 32]);

        assert_eq!(oracle.is_block_in_chain(block, tip2).unwrap(), None);

        assert_eq!(oracle.is_block_in_chain(block, tip1).unwrap(), Some(true));

        assert_eq!(oracle.is_block_in_chain(unknown_block, tip1).unwrap(), Some(false));
    }

    #[test]
    fn test_get_chain_tip() {
        let tip = BlockHash::from_byte_array([1u8; 32]);
        let oracle = MockChainOracle::new(tip);

        assert_eq!(oracle.get_chain_tip().unwrap(), tip);
    }
}
