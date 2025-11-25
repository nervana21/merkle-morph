// SPDX-License-Identifier: CC0-1.0

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
    add_multi_party_contribution, build_multi_party_anchor_tx, build_p2a_txout,
    calculate_multi_party_fee_split, default_contribute_to_multi_party_anchor,
    default_create_multi_party_anchor_request, default_finalize_multi_party_anchor,
    derive_default_p2a_internal_key, derive_p2a_address, derive_p2a_script, derive_p2a_spend_info,
    validate_multi_party_contribution, verify_p2a_script, AnchorResult, BitcoinAnchor,
    BitcoinAnchoring, MultiPartyAnchorRequest, MultiPartyAnchoringConfig, MultiPartyContribution,
    MultiPartySessionState,
};
pub use commitment::{
    compose_subtree_roots, compose_to_global_root, compute_subtree_root, generate_merkle_proof,
    update_wallet_commitments, verify_merkle_proof, verify_merkle_proof_with,
    CachedSiblingProvider, Database, DatabaseSiblingProvider, GlobalRoot, InMemorySiblingProvider,
    MerkleMorphV0Config, MerkleProof, Poseidon2Hasher, SubtreeRoot, TransitionWitnessHash,
};
pub use smt::{get_bit_at_depth, SmtConfig, SmtHasher, SmtSiblingProvider, SparseMerkleTree};
pub use state::GlobalState;
