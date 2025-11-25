//! Channel zero-knowledge proofs
//!
//! This module provides zero-knowledge proofs for channel
//! state transitions.

mod air;
mod poseidon2_air;
mod prover;
mod public_inputs;
mod trace;
mod verifier;

pub use prover::prove_channel_transition;
pub use public_inputs::ChannelPublicInputs;
pub use verifier::verify_channel_transition;
