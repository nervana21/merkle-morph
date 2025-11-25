//! Wallet zero-knowledge proofs
//!
//! This module provides zero-knowledge proofs for wallet
//! commitment aggregation.

mod aggregation;
mod air;
mod poseidon2_air;
mod poseidon2_trace_common;
mod prover;
mod public_inputs;
mod trace;
mod transition_air;
mod transition_poseidon2_air;
mod transition_trace;
mod verifier;

pub use aggregation::{verify_channel_aggregation, verify_channel_aggregation_commitment};
pub use poseidon2_air::wallet_trace_cols;
pub use prover::{prove_wallet_commitment, prove_wallet_transition};
pub use public_inputs::{WalletPublicInputs, WalletTransitionPublicInputs};
pub use verifier::{verify_wallet_commitment, verify_wallet_transition};
