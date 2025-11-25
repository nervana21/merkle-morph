// SPDX-License-Identifier: CC0-1.0

//! Core types for Bitcoin anchoring

use crate::btx::state::{BitcoinTransaction, TxInputData, Utxo};
use crate::global::commitment::types::GlobalRoot;
use crate::types::{BitcoinBlockHash, BitcoinTxId, WalletId};

/// Bitcoin anchor structure
///
/// Bitcoin anchor information for a global state root. Anchors provide global ordering,
/// timestamping, and canonical state for dispute resolution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitcoinAnchor {
    /// The global root that was anchored
    pub global_root: GlobalRoot,
    /// Bitcoin transaction ID (32 bytes, little-endian)
    pub txid: BitcoinTxId,
    /// Block height when anchored
    pub block_height: u32,
    /// Block hash containing the transaction
    pub block_hash: BitcoinBlockHash,
    /// Nonce for this anchor
    pub nonce: u32,
}

/// Result of attempting to anchor a global root to Bitcoin
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnchorResult {
    /// Successfully confirmed on Bitcoin
    Confirmed(BitcoinAnchor),
    /// Failed to anchor (e.g., network error, insufficient fees, or not confirmed)
    Failed {
        /// The global root that failed to anchor
        global_root: GlobalRoot,
        /// Error message
        error: String,
    },
}

/// Configuration for multi-party anchor transactions
///
/// Uses a hybrid approach with sensible defaults:
/// - Timeout ensures progress (fallback to regular anchoring if no takers)
/// - Max contributors prevents transaction size issues
/// - Min funding ensures we can pay fees
/// - Initiator alone is always acceptable; additional contributors are welcome
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultiPartyAnchoringConfig {
    /// Minimum total input value required (in sats) before finalizing
    /// If None, calculated dynamically based on fee rate
    pub min_total_funding: Option<u64>,

    /// Maximum number of contributors (prevents transaction size issues)
    /// Default: 50 (keeps transaction well under Bitcoin's ~100KB limit)
    pub max_contributors: Option<u32>,

    /// Timeout in seconds for the multi-party anchoring session
    /// Default: 60 seconds (balance between participation and speed)
    /// This timeout is checked during finalization to ensure the session hasn't expired
    pub timeout_seconds: Option<u64>,
}

impl Default for MultiPartyAnchoringConfig {
    fn default() -> Self {
        Self {
            min_total_funding: None, // Calculate dynamically
            max_contributors: Some(50),
            timeout_seconds: Some(60),
        }
    }
}

/// Multi-party anchor request containing partial transaction ready for contributions
#[derive(Clone, Debug)]
pub struct MultiPartyAnchorRequest {
    /// Partial transaction with anchor output and initiator's inputs
    pub partial_tx: BitcoinTransaction,
    /// The global root being anchored
    pub global_root: GlobalRoot,
    /// Nonce for this anchor
    pub nonce: u32,
    /// Index of anchor output in partial_tx.outputs
    pub anchor_output_index: usize,
    /// Fee rate in sats per vbyte
    pub fee_rate: u64,
    /// Multi-party anchoring configuration
    pub config: MultiPartyAnchoringConfig,
    /// Timestamp when request was created (Unix timestamp in seconds)
    pub created_at: u64,
}

/// Contribution from a participant to a multi-party anchor transaction
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultiPartyContribution {
    /// Inputs to add to the transaction
    pub inputs: Vec<TxInputData>,
    /// Optional change output for the contributor
    pub change_output: Option<Utxo>,
    /// Optional identifier for the contributor
    pub contributor_id: Option<WalletId>,
}

/// State tracking a multi-party anchoring session
#[derive(Clone, Debug)]
pub struct MultiPartySessionState {
    /// The original multi-party anchor request
    pub request: MultiPartyAnchorRequest,
    /// All contributions received so far
    pub contributions: Vec<MultiPartyContribution>,
    /// Current state of transaction with all contributions merged
    pub current_tx: BitcoinTransaction,
}
