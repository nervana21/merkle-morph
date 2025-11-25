//! Zero-knowledge proof module for Perfect Mathematical Composability (PMC)
//!
//! This module provides zero-knowledge proofs for state transitions
//! at the channel level, with aggregation at wallet and global levels.

mod builder_wrapper;
mod channel;
mod column_slice;
pub mod global;
mod poseidon2_common;
mod poseidon2_hash;
mod prover_common;
pub mod subtree;
pub mod types;
mod verifier_common;
mod wallet;

pub use channel::{prove_channel_transition, verify_channel_transition, ChannelPublicInputs};
pub use global::{
    global_trace_cols, prove_global_root_composition, verify_global_root,
    verify_global_root_composition,
};
pub use poseidon2_hash::{poseidon2_hash_bytes, poseidon2_hash_fixed};
pub use subtree::{
    prove_subtree_root_validity, verify_subtree_root_validity, SubtreeRootPublicInput,
};
pub use types::{create_config, Proof, StarkConfig};
pub use wallet::{
    prove_wallet_commitment, prove_wallet_transition, verify_channel_aggregation,
    verify_channel_aggregation_commitment, verify_wallet_commitment, verify_wallet_transition,
    wallet_trace_cols, WalletPublicInputs, WalletTransitionPublicInputs,
};
