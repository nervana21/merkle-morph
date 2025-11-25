//! Wallet public inputs for zero-knowledge proof verification
//!
//! This module defines the public inputs structure for wallet commitment proofs.
//!
//! Public inputs are values that are revealed to the verifier as part of the proof.

use crate::types::{WalletCommitment, WalletId};

/// Wallet public inputs structure
///
/// Public inputs for wallet commitment proof verification. This struct contains only
/// public values that are committed in the proof. These values are revealed to the
/// verifier and must match what is attested in the zero-knowledge proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletPublicInputs {
    /// Wallet identifier
    pub wallet_id: WalletId,
    /// Wallet commitment (commitment to the aggregated channel states)
    pub wallet_commitment: WalletCommitment,
}

/// Wallet transition public inputs structure
///
/// Public inputs for wallet transition proof verification. This struct contains the
/// public values for proving wallet state transitions. These values are revealed to
/// the verifier and must match what is attested in the zero-knowledge proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletTransitionPublicInputs {
    /// Wallet identifier
    pub wallet_id: WalletId,
    /// Initial wallet commitment (before the transition(s))
    pub initial_wallet_commitment: WalletCommitment,
    /// Final wallet commitment (after the transition(s))
    pub final_wallet_commitment: WalletCommitment,
}
