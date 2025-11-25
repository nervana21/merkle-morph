//! Channel module for unidirectional payment channels
//!
//! This module provides a deterministic state machine for unidirectional
//! payment channels. Each channel maintains balances for two parties and
//! supports pure state transitions. The channel is between a sender and a
//! receiver, where the sender can make transfers unilaterally to the
//! receiver.
//!
//! # Structure
//!
//! The module is organized into functional domains:
//! - `state/`: Lifecycle states (Open, CooperativeClosing, ForceClosingPending, Closed)
//! - `transition/`: State transitions (transfer, cooperative_close, force_close, recover)
//! - `commitment/`: Commitment computation
//! - `tx/`: Bitcoin transaction builders

pub mod commitment;
pub mod state;
pub mod transition;
pub mod tx;

/// Anchor output utilities for transaction builders
pub mod anchor;
/// Close output calculation utilities
pub mod close_utils;
/// Channel funding utilities
pub mod funding;
/// Silent payment utilities for transaction builders
pub(crate) mod silent_payment;

#[cfg(test)]
pub mod test_utils;

pub use anchor::{
    build_anchor_output, build_anchor_output_default, build_anchor_script,
    DEFAULT_ANCHOR_VALUE_SATS,
};
pub use close_utils::{
    calculate_close_outputs, calculate_close_outputs_with_contributions, CloseOutputsParams,
};
pub use commitment::{
    compute_channel_commitment, compute_closed_commitment, compute_cooperative_closing_commitment,
    compute_force_closing_pending_commitment, compute_open_commitment,
};
pub use funding::ChannelFunding;
pub use state::{ChannelLifecycle, Closed, CooperativeClosing, ForceClosingPending, Open};
pub use transition::transfer::TransferAmount;
pub use transition::{
    apply_cooperative_close, apply_cooperative_close_with_fee_contributions, apply_force_close,
    apply_recover, apply_transfer, TransferResult,
};
pub use tx::{
    build_all_challenge_transactions, build_challenge_transaction_for_output,
    build_cooperative_close_transaction, build_force_close_transaction,
};
