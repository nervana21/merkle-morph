//! Error types for the Merkle Morph library
//!
//! This module defines all error types used throughout the library,
//! providing detailed error information for debugging and handling.

use thiserror::Error;

/// The main error type for the Merkle Morph library
#[derive(Error, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {}

/// Result type alias for the library
pub type Result<T> = std::result::Result<T, Error>;
