#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! # Merkle Morph
//!
//! A Rust library for unilateral state channels and
//! zero-knowledge authentication.

// Channel state management and operations
pub mod channel;

// Cryptographic hash functions and state management
pub mod utils;

// Re-export commonly used types and functions
pub use channel::{compute_channel_commitment, transfer, ChannelId, ChannelState};
pub use utils::{Bytes32, State};
