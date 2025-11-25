// SPDX-License-Identifier: CC0-1.0

//! Global transition witness type
//!
//! This module defines the transition witness structure that bundles all data needed to verify
//! a wallet state transition: the wallet ID, previous and next global roots, old and
//! new wallet commitments, and Merkle proofs.
//!
//! Transition witnesses enforce the **uniqueness invariant**: for any `(wallet_id, prev_global_root)`
//! pair, at most one wallet update may be accepted. This prevents double-spending and
//! state inconsistencies. Transition witnesses are keyed by `(wallet_id, prev_root)`, allowing
//! the [`TransitionWitnessCache`](super::transition_witness_cache::TransitionWitnessCache) to detect
//! and reject duplicate transitions from the same starting state.

use crate::global::commitment::types::{GlobalRoot, MerkleProof, TransitionWitnessHash};
use crate::poseidon2_hash_fixed;
use crate::types::{WalletCommitment, WalletId, TRANSITION_WITNESS_DOMAIN_TAG};

/// Witness for a global wallet state transition
///
/// This struct packages all the data needed to verify and enforce the
/// uniqueness invariant: at most one wallet update per (wallet_id, prev_global_root).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GlobalTransitionWitness {
    /// The wallet ID being updated
    pub wallet_id: WalletId,
    /// The global root before this transition
    pub prev_root: GlobalRoot,
    /// The wallet commitment before this transition
    pub old_wallet_commitment: WalletCommitment,
    /// Merkle proof for the old wallet commitment
    pub merkle_proof_old: MerkleProof,
    /// The global root after this transition
    pub next_root: GlobalRoot,
    /// The wallet commitment after this transition
    pub new_wallet_commitment: WalletCommitment,
    /// Merkle proof for the new wallet commitment
    pub merkle_proof_new: MerkleProof,
}

impl GlobalTransitionWitness {
    /// Returns the key for this transition witness: (wallet_id, prev_root)
    ///
    /// This key is used to enforce the uniqueness invariant: at most one
    /// transition witness per (wallet_id, prev_root) pair.
    pub fn key(&self) -> (WalletId, GlobalRoot) { (self.wallet_id, self.prev_root) }

    /// Computes the commitment hash for this transition witness
    ///
    /// This hash commits to all the transition witness data and uniquely identifies the transition.
    /// Hash order: domain_tag || wallet_id || prev_root || old_wallet_commitment || next_root || new_wallet_commitment
    pub fn commitment_hash(&self) -> TransitionWitnessHash {
        poseidon2_hash_fixed(&[
            TRANSITION_WITNESS_DOMAIN_TAG,
            &self.wallet_id[..],
            &self.prev_root[..],
            &self.old_wallet_commitment[..],
            &self.next_root[..],
            &self.new_wallet_commitment[..],
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key() {
        let wallet_id = [1u8; 32];
        let prev_root = [2u8; 32];
        let old_wallet_commitment = [3u8; 32];
        let next_root = [4u8; 32];
        let new_wallet_commitment = [5u8; 32];
        let merkle_proof_old = MerkleProof { path: vec![] };
        let merkle_proof_new = MerkleProof { path: vec![] };
        let witness = GlobalTransitionWitness {
            wallet_id,
            prev_root,
            old_wallet_commitment,
            merkle_proof_old,
            next_root,
            new_wallet_commitment,
            merkle_proof_new,
        };

        let key = witness.key();

        assert_eq!(key, (wallet_id, prev_root));
    }

    #[test]
    fn test_commitment_hash() {
        let wallet_id = [1u8; 32];
        let prev_root = [2u8; 32];
        let old_wallet_commitment = [3u8; 32];
        let next_root = [4u8; 32];
        let new_wallet_commitment = [5u8; 32];
        let merkle_proof_old = MerkleProof { path: vec![] };
        let merkle_proof_new = MerkleProof { path: vec![] };
        let witness = GlobalTransitionWitness {
            wallet_id,
            prev_root,
            old_wallet_commitment,
            merkle_proof_old,
            next_root,
            new_wallet_commitment,
            merkle_proof_new,
        };

        let hash = witness.commitment_hash();

        assert_ne!(hash, [0u8; 32]);
    }
}
