#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(unreachable_pub)]

//! # Merkle Morph
//!
//! A Rust library for unilateral state channels and
//! zero-knowledge authentication.

// Channel state management and operations
pub mod channel;

// Error types and handling
pub mod errors;

// Core type definitions
pub mod types;

// Utility functions
mod utils;

// Commonly exported types
pub use errors::{Error, Result};
pub use types::Bytes32;
