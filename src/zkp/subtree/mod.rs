//! Subtree root validity zero-knowledge proofs
//!
//! This module provides zero-knowledge proofs for subtree root validity,
//! enabling composability by allowing verification of subtree roots from
//! untrusted parties without requiring all wallet commitments.

mod air;
mod poseidon2_air;
mod prover;
mod public_inputs;
mod trace;
mod verifier;

pub use prover::prove_subtree_root_validity;
pub use public_inputs::SubtreeRootPublicInput;
pub use verifier::verify_subtree_root_validity;
