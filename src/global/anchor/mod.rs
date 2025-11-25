// SPDX-License-Identifier: CC0-1.0

//! Bitcoin anchoring for global state
//!
//! This module provides the interface and types for anchoring global state
//! roots to Bitcoin. Bitcoin anchoring provides:
//! - Global ordering and timestamping
//! - Double-spending prevention
//! - Canonical state for dispute resolution

mod commitment;
mod multi_party_anchoring;
mod p2a;
mod types;

use bitcoin::BlockHash;

use crate::btx::chain_oracle::ChainOracle;
use crate::btx::state::{BitcoinTransaction, TxInputData};
use crate::types::Bytes32;

#[rustfmt::skip]
pub use {
    commitment::{compute_commitment_hash, compute_commitment_preimage, MERKLE_MORPH_DOMAIN},
    p2a::{
        build_p2a_txout, derive_default_p2a_internal_key, derive_p2a_address, derive_p2a_script,
        derive_p2a_spend_info, verify_p2a_script,
    },
    multi_party_anchoring::{
        add_multi_party_contribution, build_multi_party_anchor_tx, calculate_multi_party_fee_split,
        default_contribute_to_multi_party_anchor, default_create_multi_party_anchor_request,
        default_finalize_multi_party_anchor, validate_multi_party_contribution,
    },
    types::{
        AnchorResult, BitcoinAnchor, MultiPartyAnchorRequest, MultiPartyAnchoringConfig,
        MultiPartyContribution, MultiPartySessionState,
    },
};

/// Trait for Bitcoin anchoring operations
///
/// Implementations of this trait handle the actual Bitcoin transaction
/// creation and broadcasting. The anchoring system provides a flexible,
/// permissionless model with built-in cost sharing:
///
/// - **Multi-party anchoring support**: Use the multi-party anchoring trait methods (`create_multi_party_anchor_request`,
///   `contribute_to_multi_party_anchor`, `finalize_multi_party_anchor`) to enable cost sharing
///   across multiple participants. Contributors can join anchor transactions
///   to distribute fees proportionally. For multi-party anchoring with just the initiator (no additional
///   contributors), create a session with empty contributions and finalize.
/// - **Permissionless publishing**: Anyone can publish anchors without
///   permission. Multiple parties can publish the same root, providing
///   redundancy and resilience.
/// - **Flexible transaction building**: All anchoring operations support
///   explicit transaction building. Build transactions manually and call
///   `anchor_global_root_from_tx`.
///
/// # Example
///
/// ```rust,no_run
/// use merkle_morph::global::anchor::{
///     BitcoinAnchoring, AnchorResult, MultiPartyAnchoringConfig, MultiPartyContribution,
///     MultiPartySessionState, MultiPartyAnchorRequest
/// };
/// use merkle_morph::types::Bytes32;
/// use merkle_morph::btx::state::{BitcoinTransaction, TxInputData};
///
/// struct ExampleAnchoring {
///     // Example implementation fields
/// }
///
/// impl BitcoinAnchoring for ExampleAnchoring {
///     fn anchor_global_root_from_tx(
///         &mut self,
///         tx: &BitcoinTransaction,
///         global_root: Bytes32,
///         nonce: u32,
///     ) -> Result<AnchorResult, String> {
///         // Concrete implementations must sign and broadcast Bitcoin transaction here
///         // For example: use a Bitcoin RPC client to sign and broadcast
///         Err("Must be implemented by concrete BitcoinAnchoring type".to_string())
///     }
///
///     fn get_latest_anchor(&self) -> Option<merkle_morph::global::anchor::BitcoinAnchor> {
///         None
///     }
///
///     fn verify_against_anchor(&self, _global_root: Bytes32) -> Result<bool, String> {
///         Ok(false)
///     }
///
///     fn create_multi_party_anchor_request(
///         &mut self,
///         global_root: Bytes32,
///         nonce: u32,
///         fee_rate: u64,
///         initiator_inputs: Vec<TxInputData>,
///         config: Option<MultiPartyAnchoringConfig>,
///     ) -> Result<MultiPartyAnchorRequest, String> {
///         // Use default implementation or provide custom logic
///         merkle_morph::global::anchor::default_create_multi_party_anchor_request(
///             global_root, nonce, fee_rate, initiator_inputs, config
///         )
///     }
///
///     fn contribute_to_multi_party_anchor(
///         &mut self,
///         session: &MultiPartySessionState,
///         contribution: MultiPartyContribution,
///     ) -> Result<MultiPartySessionState, String> {
///         // Use default implementation or provide custom logic
///         merkle_morph::global::anchor::default_contribute_to_multi_party_anchor(session, contribution)
///     }
///
///     fn finalize_multi_party_anchor(
///         &mut self,
///         session: &MultiPartySessionState,
///     ) -> Result<AnchorResult, String> {
///         // Concrete implementations must sign all inputs and broadcast the transaction
///         // The default implementation only validates; override to actually broadcast
///         Err("Must be implemented by concrete BitcoinAnchoring type".to_string())
///     }
/// }
/// ```
pub trait BitcoinAnchoring {
    /// Anchor a global root using a specific transaction
    ///
    /// This is the primary method for anchoring. It takes an explicit transaction
    /// that must contain a P2A anchor output. Implementations must sign all inputs
    /// and broadcast the transaction to the Bitcoin network.
    ///
    /// # Arguments
    /// * `tx` - The Bitcoin transaction to anchor (must contain P2A anchor output)
    /// * `global_root` - The global root being anchored
    /// * `nonce` - Nonce for this anchor
    ///
    /// # Returns
    /// Anchor result indicating success or failure
    fn anchor_global_root_from_tx(
        &mut self,
        tx: &BitcoinTransaction,
        global_root: Bytes32,
        nonce: u32,
    ) -> Result<AnchorResult, String>;

    /// Get the latest anchored global root
    ///
    /// Returns the most recent Bitcoin-anchored global root, or None if
    /// no roots have been anchored yet.
    fn get_latest_anchor(&self) -> Option<BitcoinAnchor>;

    /// Verify that a global root matches the latest Bitcoin-anchored root
    ///
    /// This is used to ensure local state is consistent with the canonical
    /// Bitcoin-anchored state.
    fn verify_against_anchor(&self, global_root: Bytes32) -> Result<bool, String>;

    /// Create a multi-party anchor request with a partial transaction
    ///
    /// Creates a partial transaction containing the anchor output and the
    /// initiator's inputs. This transaction is opened to multi-party contributions, allowing
    /// other participants to contribute additional inputs.
    ///
    /// # Arguments
    /// * `global_root` - The global root to anchor
    /// * `nonce` - Nonce for this anchor
    /// * `fee_rate` - Fee rate in sats per vbyte
    /// * `initiator_inputs` - Inputs from the initiator to fund the transaction
    /// * `config` - Multi-party anchoring configuration (uses defaults if None)
    ///
    /// # Returns
    /// A `MultiPartyAnchorRequest` ready for contributions
    fn create_multi_party_anchor_request(
        &mut self,
        global_root: Bytes32,
        nonce: u32,
        fee_rate: u64,
        initiator_inputs: Vec<TxInputData>,
        config: Option<MultiPartyAnchoringConfig>,
    ) -> Result<MultiPartyAnchorRequest, String>;

    /// Contribute inputs to an existing multi-party anchor request
    ///
    /// Adds the contributor's inputs to the partial transaction. Validates
    /// the contribution and returns the updated transaction state.
    ///
    /// # Arguments
    /// * `session` - Current multi-party session state
    /// * `contribution` - The contribution to add
    ///
    /// # Returns
    /// Updated `MultiPartySessionState` with the new contribution merged
    fn contribute_to_multi_party_anchor(
        &mut self,
        session: &MultiPartySessionState,
        contribution: MultiPartyContribution,
    ) -> Result<MultiPartySessionState, String>;

    /// Finalize and broadcast a multi-party anchor transaction
    ///
    /// Validates the completed transaction, ensures all requirements are met,
    /// signs all inputs, and broadcasts to the network. Returns the anchor
    /// result once confirmed.
    ///
    /// # Arguments
    /// * `session` - Completed multi-party session state
    ///
    /// # Returns
    /// Anchor result indicating success or failure
    fn finalize_multi_party_anchor(
        &mut self,
        session: &MultiPartySessionState,
    ) -> Result<AnchorResult, String>;
}

/// Verify that a Bitcoin anchor is confirmed in the best chain
///
/// This function uses a `ChainOracle` to verify that the block containing
/// the anchor transaction is part of the current best chain. This is essential
/// for ensuring that anchored global state roots are actually confirmed on Bitcoin.
///
/// # Arguments
/// * `anchor` - The Bitcoin anchor to verify
/// * `chain` - A chain oracle implementation for querying chain state
///
/// # Returns
/// * `Ok(true)` - Anchor is confirmed in the best chain
/// * `Ok(false)` - Anchor is not confirmed (block not in chain, or cannot determine)
/// * `Err` - Error during chain query
///
/// # Example
///
/// ```rust,no_run
/// use merkle_morph::global::anchor::{BitcoinAnchor, verify_anchor_confirmed};
/// use merkle_morph::btx::chain_oracle::{ChainOracle, MockChainOracle};
/// use bitcoin::BlockHash;
/// use bitcoin::hashes::Hash;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let anchor = BitcoinAnchor {
/// #     global_root: [0u8; 32],
/// #     txid: [0u8; 32],
/// #     block_height: 100,
/// #     block_hash: [1u8; 32],
/// #     nonce: 0,
/// # };
/// # let block_hash = BlockHash::from_byte_array([1u8; 32]);
/// # let mut oracle = MockChainOracle::new(block_hash);
/// # oracle.add_block(block_hash);
/// let is_confirmed = verify_anchor_confirmed(&anchor, &oracle)?;
/// # Ok(())
/// # }
/// ```
pub fn verify_anchor_confirmed<C: ChainOracle>(
    anchor: &BitcoinAnchor,
    chain: &C,
) -> Result<bool, C::Error> {
    // Get the current chain tip
    let chain_tip = chain.get_chain_tip()?;

    // Convert Bytes32 block hash to BlockHash
    let block_hash = BlockHash::from_byte_array(anchor.block_hash);

    // Check if the anchor's block is in the chain
    match chain.is_block_in_chain(block_hash, chain_tip)? {
        Some(true) => Ok(true),
        Some(false) | None => Ok(false),
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::btx::chain_oracle::ChainOracle;

    struct TestChainOracle {
        get_chain_tip_result: Result<BlockHash, String>,
        is_block_in_chain_result: Result<Option<bool>, String>,
    }

    impl ChainOracle for TestChainOracle {
        type Error = String;

        fn get_chain_tip(&self) -> Result<BlockHash, Self::Error> {
            self.get_chain_tip_result.clone()
        }

        fn is_block_in_chain(
            &self,
            _block: BlockHash,
            _chain_tip: BlockHash,
        ) -> Result<Option<bool>, Self::Error> {
            self.is_block_in_chain_result.clone()
        }
    }

    #[test]
    fn test_verify_anchor_confirmed() {
        let anchor = BitcoinAnchor {
            global_root: [0u8; 32],
            txid: [0u8; 32],
            block_height: 100,
            block_hash: [1u8; 32],
            nonce: 0,
        };

        let tip = BlockHash::from_byte_array([2u8; 32]);
        let oracle1 = TestChainOracle {
            get_chain_tip_result: Err("chain error".to_string()),
            is_block_in_chain_result: Ok(Some(true)),
        };
        assert!(verify_anchor_confirmed(&anchor, &oracle1).is_err());

        let oracle2 = TestChainOracle {
            get_chain_tip_result: Ok(tip),
            is_block_in_chain_result: Err("block check error".to_string()),
        };
        assert!(verify_anchor_confirmed(&anchor, &oracle2).is_err());

        let oracle3 = TestChainOracle {
            get_chain_tip_result: Ok(tip),
            is_block_in_chain_result: Ok(Some(true)),
        };
        assert!(verify_anchor_confirmed(&anchor, &oracle3).expect("should verify anchor"));

        let oracle4 = TestChainOracle {
            get_chain_tip_result: Ok(tip),
            is_block_in_chain_result: Ok(Some(false)),
        };
        assert!(!verify_anchor_confirmed(&anchor, &oracle4).expect("should verify anchor"));
    }
}
