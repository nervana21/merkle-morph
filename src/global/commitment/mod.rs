// SPDX-License-Identifier: CC0-1.0

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
mod transition_witness;
mod transition_witness_cache;
pub mod types;
mod updater;

#[rustfmt::skip]
pub use {
    builder::{build_smt_node_with, build_smt_root_with},
    cache::CachedSiblingProvider,
    config::MerkleMorphV0Config,
    database::{Database, DbOperation},
    hasher::Poseidon2Hasher,
    keys::{
        compute_prefix_bytes, compute_sibling_prefix_bytes, decode_node_key, encode_node_key,
        encode_sibling_node_key, matches_prefix,
    },
    proof::{generate_merkle_proof, verify_merkle_proof, verify_merkle_proof_with},
    provider::{DatabaseSiblingProvider, InMemorySiblingProvider},
    transition_witness::GlobalTransitionWitness,
    transition_witness_cache::TransitionWitnessCache,
    subtree::{
        compose_subtree_roots, compose_subtrees_at_depth, compose_to_global_root, compute_subtree_root,
    },
    types::{GlobalRoot, MerkleProof, TransitionWitnessHash, SubtreeRoot},
    updater::{update_wallet_commitments, UpdatedGlobalRoot},
};
