//! Channel commitment computation
//!
//! This module provides functions for computing cryptographic commitments
//! over channel states using Poseidon2 hashing.
//!
//! Commitments are domain-separated and include all state information
//! needed for verification and aggregation.

pub mod script_commitment;
pub mod state_commitment;

pub use script_commitment::compute_script_commitment;
pub use state_commitment::{
    compute_channel_commitment, compute_closed_commitment, compute_cooperative_closing_commitment,
    compute_force_closing_pending_commitment, compute_open_commitment, compute_open_state_hash,
};
