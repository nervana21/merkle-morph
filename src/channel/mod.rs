#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
//! Channel module for unidirectional payment channels
//!
//! This module provides a deterministic state machine for unidirectional
//! payment channels. Each channel maintains balances for two parties and
//! supports pure state transitions. The channel is between a sender and a
//! receiver, where the sender can make transfers unilaterally to the
//! receiver.

pub mod commitment;
pub mod input;
pub mod state;
pub mod transition;

pub use commitment::{compute_channel_commitment, compute_commitment};
pub use input::TransferAmount;
pub use state::ChannelState;
pub use transition::{
    apply_close, apply_close_with_fees, apply_force_close_with_fees, apply_transfer,
    calculate_cooperative_close_outputs, calculate_force_close_outputs, TransferResult,
};
