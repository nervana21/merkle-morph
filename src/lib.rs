#![warn(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
#![warn(unreachable_pub)]

//! # Merkle Morph
//!
//! A Rust library for unidirectional state channels with
//! zero-knowledge proofs.

// Bitcoin transaction category
pub mod btx;

// Channel state management and operations
pub mod channel;

// Error types and handling
pub mod errors;

// Global state management
pub mod global;

// Core type definitions
pub mod types;

// Wallet state management and operations
pub mod wallet;

// Zero-knowledge proof module for PMC
pub mod zkp;

// Commonly exported types
pub use errors::{Error, Result};
pub use types::Bytes32;
pub use zkp::{Proof, StarkConfig};
