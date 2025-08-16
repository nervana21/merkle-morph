#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! # Merkle Morph
//!
//! A Rust library for unilateral state channels and
//! zero-knowledge authentication.

// Channel state management and operations
pub mod channel;

// Global state management and top-level propagation functions.
pub mod global;

// Cryptographic hash functions and state management
pub mod utils;

// Wallet state management and operations
pub mod wallet;

// Re-export commonly used types and functions
pub use channel::{compute_channel_commitment, transfer, ChannelId, ChannelState};
pub use global::{get_wallet, insert_wallet, GlobalState};
pub use utils::{Bytes32, State};
pub use wallet::{insert_channel, WalletId, WalletState};
