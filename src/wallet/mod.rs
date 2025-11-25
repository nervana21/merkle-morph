//! Wallet module for channel commitment aggregation
//!
//! This module provides wallet structures that aggregate channel
//! commitments and compute their Merkle root. Wallets serve as an
//! intermediate aggregation layer between channels and the global state,
//! enabling efficient verification and management of multiple channels
//! under a single wallet identifier.
//!
//! # Structure
//!
//! The module is organized into functional domains:
//! - `commitment`: Commitment computation (hash chain over channel commitments)
//! - `operation`: Transition types for wallet state transitions (WalletTransition)
//! - `state`: Wallet state representation (WalletState)
//! - `transition`: State transitions (apply_insert_channel, apply_remove_channel, apply_operation)

pub mod commitment;
pub mod operation;
pub mod state;
pub mod transition;

pub use commitment::compute_commitment_from_channels;
pub use operation::WalletTransition;
pub use state::WalletState;
pub use transition::{apply_insert_channel, apply_operation, apply_remove_channel};
