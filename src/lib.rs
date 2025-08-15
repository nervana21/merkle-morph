#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! # Merkle Morph
//!
//! A Rust library for unilateral state channels and
//! zero-knowledge authentication.

// Cryptographic hash functions and state management
pub mod utils;

// Re-export commonly used types and functions
pub use utils::{Bytes32, State};
