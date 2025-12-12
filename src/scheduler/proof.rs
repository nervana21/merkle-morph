// SPDX-License-Identifier: CC0-1.0

//! Batch-level proof wrapper types.
//!
//! Keeps the scheduler decoupled from the proof backend by only exposing opaque
//! proof artifacts. Concrete generation/verification lives in `zkp`.

use crate::Proof;

/// Opaque proof artifact for wallet-level updates.
pub type WalletProof = Proof;

/// Opaque proof artifact for the composed global root.
pub type GlobalProof = Proof;

/// Minimal verification metadata that can accompany proofs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofMetadata {
    /// Optional human-readable description or versioning tag.
    pub label: Option<String>,
}
