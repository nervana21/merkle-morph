// SPDX-License-Identifier: CC0-1.0

//! # Merkle Morph
//!
//! A Rust library for zero-knowledge state channels anchored to Bitcoin.

// (These configurations inspired by rust-bitcoin crate's configuration)
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![deny(clippy::unwrap_used)]
#![deny(unsafe_code)]
#![warn(missing_docs)]
#![allow(clippy::needless_question_mark)]
#![allow(clippy::manual_range_contains)]
#![allow(clippy::needless_borrows_for_generic_args)]

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

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use crate::{
    errors::{Error, Result},
    types::Bytes32,
    zkp::{Proof, StarkConfig},
};
