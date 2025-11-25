//! Global state module
//!
//! This module provides the global state structure that maintains the Merkle
//! root of the global Sparse Merkle Tree. The global root is computed by composing
//! subtree roots, enabling verification without access to individual wallet commitments.
//! Global state roots are anchored to Bitcoin for ordering, double-spending prevention,
//! and dispute resolution.

pub mod anchor;
pub mod commitment;
pub mod smt;
pub mod state;

pub use anchor::{
    decode_op_return_data, encode_op_return_data, AnchorResult, BitcoinAnchor, BitcoinAnchoring,
};
pub use commitment::{
    compose_subtree_roots, compose_to_global_root, compute_subtree_root, generate_merkle_proof,
    update_wallet_commitments, verify_merkle_proof, verify_merkle_proof_with,
    CachedSiblingProvider, Database, DatabaseSiblingProvider, InMemorySiblingProvider,
    MerkleMorphV0Config, MerkleProof, Poseidon2Hasher, SubtreeRoot,
};
pub use smt::{get_bit_at_depth, SmtConfig, SmtHasher, SmtSiblingProvider, SparseMerkleTree};
pub use state::GlobalState;
