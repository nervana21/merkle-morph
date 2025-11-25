//! Global commitment computation
//!
//! This module provides functions for computing the global Merkle root
//! from wallet commitments using a Sparse Merkle Tree (SMT). This
//! enables incremental verification through subtree root composition.
//! This approach maintains full cryptographic security - subtree roots are
//! Merkle commitments that are composed deterministically, and the final
//! global root verification ensures consistency.

mod builder;
mod cache;
mod config;
mod database;
mod hasher;
mod keys;
mod proof;
mod provider;
mod subtree;
mod types;
mod updater;

pub use builder::{build_smt_node_with, build_smt_root_with};
pub use cache::CachedSiblingProvider;
pub use config::MerkleMorphV0Config;
pub use database::{Database, DbOperation};
pub use hasher::Poseidon2Hasher;
pub use keys::{
    compute_prefix_bytes, compute_sibling_prefix_bytes, decode_node_key, encode_node_key,
    encode_sibling_node_key, matches_prefix,
};
pub use proof::{generate_merkle_proof, verify_merkle_proof, verify_merkle_proof_with};
pub use provider::{DatabaseSiblingProvider, InMemorySiblingProvider};
pub use subtree::{
    compose_subtree_roots, compose_subtrees_at_depth, compose_to_global_root, compute_subtree_root,
};
pub use types::{MerkleProof, SubtreeRoot};
pub use updater::update_wallet_commitments;
