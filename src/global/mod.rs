#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
//! Global state module
//!
//! This module provides the global state structure that maintains only the
//! Merkle root of wallet commitments. Global state roots are anchored
//! to Bitcoin to provide:
//! - Global ordering and timestamping
//! - Double-spending prevention
//! - Canonical state for dispute resolution
//!
//! While individual wallet/channel transitions can occur offline, global state
//! transitions must be anchored to Bitcoin to ensure global consistency.

pub mod anchor;
pub mod commitment;
pub mod smt;
pub mod state;

pub use anchor::{
    decode_op_return_data, encode_op_return_data, AnchorResult, BitcoinAnchor, BitcoinAnchoring,
};
pub use commitment::{
    compose_to_global_root, compute_subtree_root, generate_merkle_proof,
    generate_merkle_proof_with_provider, verify_merkle_proof, InMemorySiblingProvider, MerkleProof,
    SubtreeRoot,
};
pub use smt::{get_bit_at_depth, SmtConfig, SmtHasher, SmtSiblingProvider, SparseMerkleTree};
pub use state::GlobalState;
