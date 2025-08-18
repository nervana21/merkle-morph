#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(unreachable_pub)]

//! # Merkle Morph
//!
//! A Rust library for unilateral state channels and
//! zero-knowledge authentication.

// Error types and handling
pub mod errors;

// Core type definitions
pub mod types;

// Commonly exported types
pub use errors::{Error, Result};
pub use types::Bytes32;
