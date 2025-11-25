// SPDX-License-Identifier: CC0-1.0

//! Transition witness cache for enforcing uniqueness invariant
//!
//! This module provides an in-memory cache that enforces the invariant:
//! for any (wallet_id, prev_root), at most one wallet update may be accepted.

use std::collections::BTreeMap;

use super::transition_witness::GlobalTransitionWitness;
use super::types::{GlobalRoot, TransitionWitnessHash};
use crate::types::WalletId;
use crate::Result;

/// In-memory cache for global transition witnesses
///
/// This cache enforces the uniqueness invariant by tracking transition witnesses
/// keyed by (wallet_id, prev_root). If a duplicate key is inserted,
/// the insertion fails.
pub struct TransitionWitnessCache {
    /// Map from (wallet_id, prev_root) to transition witness commitment hash
    cache: BTreeMap<(WalletId, GlobalRoot), TransitionWitnessHash>,
}

impl TransitionWitnessCache {
    /// Creates a new empty transition witness cache
    pub fn new() -> Self { Self { cache: BTreeMap::new() } }

    /// Inserts a transition witness into the cache, enforcing the uniqueness invariant
    ///
    /// This method enforces the uniqueness invariant (no duplicate keys) and
    /// stores the commitment hash for future verification.
    ///
    /// # Arguments
    /// * `witness` - The transition witness to insert
    ///
    /// # Returns
    /// * `Ok(())` if the transition witness was successfully inserted
    /// * `Err(Error)` if a transition witness with the same (wallet_id, prev_root) already exists
    ///
    /// # Errors
    /// Returns an error if:
    /// - The key (wallet_id, prev_root) already exists in the cache
    pub fn insert(&mut self, witness: &GlobalTransitionWitness) -> Result<()> {
        let (wallet_id, prev_root) = witness.key();
        let key = (wallet_id, prev_root);
        if self.cache.contains_key(&key) {
            return Err(crate::Error::Global(
                crate::errors::GlobalError::DuplicateTransitionWitnessViolation {
                    wallet_id,
                    prev_root,
                },
            ));
        }

        let commitment_hash = witness.commitment_hash();
        self.cache.insert(key, commitment_hash);
        Ok(())
    }

    /// Checks if a key exists in the cache
    ///
    /// # Arguments
    /// * `wallet_id` - The wallet ID
    /// * `prev_root` - The previous global root
    ///
    /// # Returns
    /// `true` if the key exists, `false` otherwise
    pub fn contains_key(&self, wallet_id: WalletId, prev_root: GlobalRoot) -> bool {
        self.cache.contains_key(&(wallet_id, prev_root))
    }

    /// Verifies a transition witness against a stored transition hash
    ///
    /// This method can be used to verify that a transition witness matches what was previously
    /// stored in the cache. This provides additional verification when retrieving
    /// transition witnesses from persistent storage.
    ///
    /// # Arguments
    /// * `witness` - The transition witness to verify
    ///
    /// # Returns
    /// * `Ok(())` if the transition witness's commitment hash matches the stored value
    /// * `Err(Error)` if the key doesn't exist or the hash doesn't match
    ///
    /// # Errors
    /// Returns an error if:
    /// - The key (wallet_id, prev_root) doesn't exist in the cache
    /// - The transition witness's commitment hash doesn't match the stored value
    pub fn verify_witness(&self, witness: &GlobalTransitionWitness) -> Result<()> {
        let (wallet_id, prev_root) = witness.key();
        let key = (wallet_id, prev_root);
        let stored_hash = self.cache.get(&key).ok_or_else(|| {
            crate::Error::Global(crate::errors::GlobalError::Internal(format!(
                "Transition witness key not found in cache: wallet_id {:?}, prev_root {:?}",
                wallet_id, prev_root
            )))
        })?;

        let computed_hash = witness.commitment_hash();
        if *stored_hash != computed_hash {
            return Err(crate::Error::Global(crate::errors::GlobalError::Internal(format!(
                "Transition witness commitment hash mismatch: stored {:?}, computed {:?}",
                stored_hash, computed_hash
            ))));
        }

        Ok(())
    }
}

impl Default for TransitionWitnessCache {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::global::commitment::types::MerkleProof;

    #[test]
    fn test_new() -> Result<()> {
        let cache = TransitionWitnessCache::new();

        assert!(!cache.contains_key([1u8; 32], [2u8; 32]));
        Ok(())
    }

    #[test]
    fn test_insert() -> Result<()> {
        let wallet_id = [1u8; 32];
        let prev_root = [2u8; 32];
        let old_wallet_commitment = [3u8; 32];
        let next_root = [4u8; 32];
        let new_wallet_commitment = [5u8; 32];
        let merkle_proof_old = MerkleProof { path: vec![] };
        let merkle_proof_new = MerkleProof { path: vec![] };
        let witness1 = GlobalTransitionWitness {
            wallet_id,
            prev_root,
            old_wallet_commitment,
            merkle_proof_old: merkle_proof_old.clone(),
            next_root,
            new_wallet_commitment,
            merkle_proof_new: merkle_proof_new.clone(),
        };
        let mut cache = TransitionWitnessCache::new();

        cache.insert(&witness1)?;

        assert!(cache.contains_key(wallet_id, prev_root));

        let witness2 = GlobalTransitionWitness {
            wallet_id,
            prev_root,
            old_wallet_commitment: [6u8; 32],
            merkle_proof_old: merkle_proof_old.clone(),
            next_root: [7u8; 32],
            new_wallet_commitment: [8u8; 32],
            merkle_proof_new: merkle_proof_new.clone(),
        };

        let result = cache.insert(&witness2);

        assert!(result.is_err());
        assert!(matches!(
            result.expect_err("duplicate transition witness violation"),
            crate::Error::Global(
                crate::errors::GlobalError::DuplicateTransitionWitnessViolation { .. }
            )
        ));
        Ok(())
    }

    #[test]
    fn test_contains_key() -> Result<()> {
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
            merkle_proof_old: merkle_proof_old.clone(),
            next_root,
            new_wallet_commitment,
            merkle_proof_new: merkle_proof_new.clone(),
        };
        let mut cache = TransitionWitnessCache::new();
        cache.insert(&witness)?;

        let exists = cache.contains_key(wallet_id, prev_root);

        assert!(exists);

        let wallet_id2 = [6u8; 32];
        let prev_root2 = [7u8; 32];

        let not_exists = cache.contains_key(wallet_id2, prev_root2);

        assert!(!not_exists);
        Ok(())
    }

    #[test]
    fn test_verify_witness() -> Result<()> {
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
            merkle_proof_old: merkle_proof_old.clone(),
            next_root,
            new_wallet_commitment,
            merkle_proof_new: merkle_proof_new.clone(),
        };
        let cache = TransitionWitnessCache::new();

        let result = cache.verify_witness(&witness);

        assert!(result.is_err());
        assert!(matches!(
            result.expect_err("witness not in cache"),
            crate::Error::Global(crate::errors::GlobalError::Internal(_))
        ));

        let wallet_id2 = [6u8; 32];
        let prev_root2 = [7u8; 32];
        let old_wallet_commitment2 = [8u8; 32];
        let next_root2 = [9u8; 32];
        let new_wallet_commitment2 = [10u8; 32];
        let witness2 = GlobalTransitionWitness {
            wallet_id: wallet_id2,
            prev_root: prev_root2,
            old_wallet_commitment: old_wallet_commitment2,
            merkle_proof_old: merkle_proof_old.clone(),
            next_root: next_root2,
            new_wallet_commitment: new_wallet_commitment2,
            merkle_proof_new: merkle_proof_new.clone(),
        };
        let mut cache2 = TransitionWitnessCache::new();
        cache2.insert(&witness2)?;
        let witness3 = GlobalTransitionWitness {
            wallet_id: wallet_id2,
            prev_root: prev_root2,
            old_wallet_commitment: [11u8; 32],
            merkle_proof_old: merkle_proof_old.clone(),
            next_root: [12u8; 32],
            new_wallet_commitment: [13u8; 32],
            merkle_proof_new: merkle_proof_new.clone(),
        };

        let result2 = cache2.verify_witness(&witness3);

        assert!(result2.is_err());
        assert!(matches!(
            result2.expect_err("mismatched hash"),
            crate::Error::Global(crate::errors::GlobalError::Internal(_))
        ));

        let wallet_id3 = [14u8; 32];
        let prev_root3 = [15u8; 32];
        let old_wallet_commitment3 = [16u8; 32];
        let next_root3 = [17u8; 32];
        let new_wallet_commitment3 = [18u8; 32];
        let witness4 = GlobalTransitionWitness {
            wallet_id: wallet_id3,
            prev_root: prev_root3,
            old_wallet_commitment: old_wallet_commitment3,
            merkle_proof_old: merkle_proof_old.clone(),
            next_root: next_root3,
            new_wallet_commitment: new_wallet_commitment3,
            merkle_proof_new: merkle_proof_new.clone(),
        };
        let mut cache3 = TransitionWitnessCache::new();
        cache3.insert(&witness4)?;

        cache3.verify_witness(&witness4)?;

        assert!(cache3.contains_key(wallet_id3, prev_root3));
        Ok(())
    }
}
