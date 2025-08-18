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

// Global scheduler and batch orchestration
pub mod scheduler;

// Core type definitions
pub mod types;

// Wallet state management and operations
pub mod wallet;

// Zero-knowledge proof module for PMC
pub mod zkp;

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use crate::{
    channel::{Open, TransferAmount},
    errors::{Error, Result},
    global::{
        build_p2a_txout, compose_to_global_root, compute_subtree_root,
        derive_default_p2a_internal_key, GlobalRoot, TransitionWitnessHash, SubtreeRoot,
    },
    scheduler::Batch,
    types::{Bytes32, ChannelId, WalletCommitment, WalletId},
    wallet::{
        apply_operation, compute_commitment_from_channels, WalletState, WalletTransition,
    },
    zkp::{
        create_config, poseidon2_hash_bytes, poseidon2_hash_fixed, prove_wallet_transition,
        Proof, StarkConfig,
    },
};
