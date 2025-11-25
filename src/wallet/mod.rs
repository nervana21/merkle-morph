#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
//! Wallet module for channel commitment aggregation
//!
//! This module provides wallet structures that aggregate channel
//! commitments and compute their Merkle root.

pub mod commitment;
pub mod input;
pub mod state;
pub mod transition;

pub use commitment::compute_commitment;
pub use input::WalletInput;
pub use state::WalletState;
pub use transition::{apply_input, get_channel, insert_channel, remove_channel};
