// SPDX-License-Identifier: CC0-1.0

//! Incremental update system for SMT nodes
//!
//! This module provides functions to update wallet commitments and
//! incrementally recompute affected SMT nodes, maintaining the tree
//! structure efficiently.

use std::collections::BTreeMap;

use super::builder::build_smt_node_with;
use super::database::{Database, DbOperation};
use super::keys::{compute_sibling_prefix_bytes, encode_node_key, encode_sibling_node_key};
use super::proof::{generate_merkle_proof, verify_merkle_proof_with};
use super::provider::InMemorySiblingProvider;
use super::transition_witness::GlobalTransitionWitness;
use super::types::{GlobalRoot, SmtNodeHash};
use crate::global::smt::{get_bit_at_depth, SmtConfig, SmtHasher};
use crate::types::{WalletCommitment, WalletId};
use crate::Result;

/// Computes a sibling subtree hash
///
/// # Arguments
/// * `wallet_id` - The wallet ID (used to determine sibling)
/// * `depth` - The depth at which to find the sibling
/// * `hasher` - The hash function implementation
/// * `config` - The SMT configuration
/// * `db` - The database backend
///
/// # Returns
/// The sibling subtree hash
fn compute_sibling_subtree_hash<H: SmtHasher, C: SmtConfig>(
    wallet_id: WalletId,
    depth: u8,
    hasher: &H,
    config: &C,
    db: &dyn Database,
) -> Result<SmtNodeHash> {
    let sibling_prefix = compute_sibling_prefix_bytes(&wallet_id, depth);
    let sibling_wallets = db.get_wallets_by_prefix(&sibling_prefix, depth)?;

    if sibling_wallets.is_empty() {
        Ok(hasher.zero_hash())
    } else {
        Ok(build_smt_node_with(&sibling_wallets, depth + 1, hasher, config))
    }
}

/// Result of updating wallet commitments
///
/// Contains the new global root and transition witnesses for each wallet update.
#[derive(Clone, Debug)]
pub struct UpdatedGlobalRoot {
    /// The new global root after the update
    pub root: GlobalRoot,
    /// Transition witnesses for each wallet update
    pub witnesses: Vec<GlobalTransitionWitness>,
}

/// Updates wallet commitments and recomputes all affected SMT nodes
///
/// When wallet commitments change, this function:
/// 1. Updates the wallet commitments in the database
/// 2. Recomputes leaf hashes for all updated wallets
/// 3. Walks up the tree, recomputing parent nodes while caching shared ancestors
/// 4. Updates all affected nodes in the database
/// 5. Invalidates sibling nodes that may have changed
/// 6. Creates transition witnesses for each wallet update
///
/// # Arguments
/// * `prev_root` - The global root before this update (validated against computed root)
/// * `updates` - Map of wallet ID(s) to new commitment(s)
/// * `hasher` - The hash function implementation
/// * `config` - The SMT configuration
/// * `db` - The database backend
///
/// # Returns
/// The new global root and transition witnesses for each update
///
/// # Errors
/// Returns an error if `prev_root` does not match the root computed from the database state
pub fn update_wallet_commitments<H: SmtHasher, C: SmtConfig>(
    prev_root: GlobalRoot,
    updates: &BTreeMap<WalletId, WalletCommitment>,
    hasher: &H,
    config: &C,
    db: &dyn Database,
) -> Result<UpdatedGlobalRoot> {
    if updates.is_empty() {
        // If no updates, return the current root from the database.
        // We use a canonical all-zero wallet ID to derive the root key.
        // If the root node is not yet stored, fall back to the empty-tree root.
        let root_wallet_id = [0u8; 32];
        let root_key = encode_node_key(&root_wallet_id, 0);
        let root_hash = db.get_smt_node(&root_key)?.unwrap_or_else(|| hasher.zero_hash());
        return Ok(UpdatedGlobalRoot { root: root_hash, witnesses: Vec::new() });
    }

    // Get all wallet commitments before update for generating merkle proofs
    // Use empty prefix at depth 0 to get all wallets
    let empty_prefix = Vec::new();
    let commitments_before = db.get_wallets_by_prefix(&empty_prefix, 0)?;

    // Get old wallet commitments for wallets being updated and ensure they're in commitments_before
    let mut commitments_before_with_updates = commitments_before.clone();
    for wallet_id in updates.keys() {
        let old_commitment = commitments_before
            .get(wallet_id)
            .copied()
            .or_else(|| db.get_wallet_commitment(wallet_id).ok().flatten())
            .unwrap_or_else(|| {
                // If wallet doesn't exist, use empty wallet commitment
                crate::wallet::commitment::compute_commitment_from_channels(
                    *wallet_id,
                    &BTreeMap::new(),
                )
                .unwrap_or([0u8; 32])
            });
        commitments_before_with_updates.insert(*wallet_id, old_commitment);
    }

    // Create commitments_after: commitments_before + updates
    let mut commitments_after = commitments_before_with_updates.clone();
    for (wallet_id, new_commitment) in updates.iter() {
        commitments_after.insert(*wallet_id, *new_commitment);
    }

    // Compute actual prev_root from commitments_before_with_updates to ensure it matches
    // the state used for proof generation. Validate that caller's prev_root matches.
    use super::builder::build_smt_root_with;
    let actual_prev_root = build_smt_root_with(&commitments_before_with_updates, hasher, config);

    // Assert that the caller's prev_root matches the computed root
    // This ensures the caller's understanding of state matches reality
    if prev_root != actual_prev_root {
        return Err(crate::Error::Global(crate::errors::GlobalError::InvalidParameters(format!(
            "prev_root mismatch: caller provided {:?}, but computed root from database state is {:?}",
            prev_root, actual_prev_root
        ))));
    }

    let max_depth = config.max_depth();
    let mut ops = Vec::new();

    // Update all wallet commitments and compute leaf hashes
    let mut computed_nodes: BTreeMap<Vec<u8>, SmtNodeHash> = BTreeMap::new();

    for (wallet_id, commitment) in updates.iter() {
        ops.push(DbOperation::PutWalletCommitment {
            wallet_id: *wallet_id,
            commitment: *commitment,
        });

        let leaf_hash = hasher.hash_leaf(config.leaf_domain_tag(), *wallet_id, *commitment);
        let leaf_key = encode_node_key(wallet_id, max_depth);
        computed_nodes.insert(leaf_key, leaf_hash);
    }

    // Walk up the tree from max_depth-1 to 0, recomputing shared ancestors only once
    // We process depth by depth, bottom-up, so that when we compute a parent, both children are already computed
    // For each depth, we iterate through all updated wallets and compute their path nodes,
    // but use the cache to avoid recomputing shared ancestors

    for depth in (0..max_depth).rev() {
        // Track which nodes at this depth we need to compute
        // Map from node_key to (left_hash, right_hash)
        let mut nodes_to_compute: BTreeMap<Vec<u8>, (SmtNodeHash, SmtNodeHash)> = BTreeMap::new();

        // For each updated wallet, compute the node at this depth if not already computed
        for wallet_id in updates.keys() {
            let node_key = encode_node_key(wallet_id, depth);

            // Skip if we already computed this node (shared ancestor)
            if computed_nodes.contains_key(&node_key) {
                continue;
            }

            // Get the child hash at depth+1 (should be in computed_nodes)
            let child_key = encode_node_key(wallet_id, depth + 1);
            let child_hash = computed_nodes.get(&child_key).copied().ok_or_else(|| {
                crate::Error::Global(crate::errors::GlobalError::Internal(format!(
                    "Child hash not found for wallet_id at depth {}",
                    depth + 1
                )))
            })?;

            // Get sibling hash
            let sibling_key = encode_sibling_node_key(wallet_id, depth);
            let sibling_hash = if let Some(hash) = computed_nodes.get(&sibling_key) {
                // Sibling was also updated, use computed value
                *hash
            } else if let Some(hash) = db.get_smt_node(&sibling_key)? {
                // Sibling exists in database
                hash
            } else {
                // Sibling not in database - compute it from subtree
                compute_sibling_subtree_hash(*wallet_id, depth, hasher, config, db)?
            };

            // Determine left/right based on bit at this depth
            let bit_value = get_bit_at_depth(wallet_id, depth);
            let (left_hash, right_hash) = if bit_value == 0 {
                (child_hash, sibling_hash)
            } else {
                (sibling_hash, child_hash)
            };

            // Store for batch computation (may have multiple wallets sharing same parent)
            nodes_to_compute.insert(node_key, (left_hash, right_hash));
        }

        // Compute all parent nodes at this depth
        for (node_key, (left_hash, right_hash)) in nodes_to_compute.iter() {
            let parent_hash =
                hasher.hash_internal(config.internal_domain_tag(), *left_hash, *right_hash);
            computed_nodes.insert(node_key.clone(), parent_hash);
        }
    }

    // Build the batch of database operations
    // Add all computed node updates
    for (node_key, node_hash) in computed_nodes.iter() {
        ops.push(DbOperation::PutSmtNode { node_key: node_key.clone(), node_hash: *node_hash });
    }

    // Delete sibling nodes that may have changed
    for wallet_id in updates.keys() {
        for depth in 0..max_depth {
            let sibling_key = encode_sibling_node_key(wallet_id, depth);
            // Only delete if we didn't just compute it (to avoid delete+put of same key)
            if !computed_nodes.contains_key(&sibling_key) {
                ops.push(DbOperation::DeleteSmtNode { node_key: sibling_key });
            }
        }
    }

    db.batch_write(ops)?;

    // Get the new root hash (at depth 0)
    // The root key is the same for all wallets (depth 0, no prefix)
    let root_key = encode_node_key(&updates.keys().next().copied().unwrap_or_default(), 0);
    let next_root = computed_nodes.get(&root_key).copied().ok_or_else(|| {
        crate::Error::Global(crate::errors::GlobalError::Internal(
            "Root hash not computed".to_string(),
        ))
    })?;

    // Compute actual next_root from commitments_after to ensure it matches
    // the state used for proof generation (for verification purposes)
    let actual_next_root = build_smt_root_with(&commitments_after, hasher, config);

    // Generate merkle proofs and create transition witnesses for each wallet update
    // Create providers once and reuse them for all wallets (O(n) instead of O(n²))
    let mut provider_old = InMemorySiblingProvider::new(&commitments_before_with_updates);
    let mut provider_new = InMemorySiblingProvider::new(&commitments_after);

    let mut witnesses = Vec::new();

    for (wallet_id, new_commitment) in updates.iter() {
        let old_commitment =
            commitments_before_with_updates.get(wallet_id).copied().unwrap_or_else(|| {
                crate::wallet::commitment::compute_commitment_from_channels(
                    *wallet_id,
                    &BTreeMap::new(),
                )
                .unwrap_or([0u8; 32])
            });

        // Generate old merkle proof from commitments_before snapshot
        let merkle_proof_old =
            generate_merkle_proof(*wallet_id, hasher, config, &mut provider_old)?;

        // Generate new merkle proof from commitments_after snapshot
        let merkle_proof_new =
            generate_merkle_proof(*wallet_id, hasher, config, &mut provider_new)?;

        // Verify proofs against the roots they claim to prove
        // Use actual_prev_root computed from commitments_before_with_updates
        let old_proof_valid = verify_merkle_proof_with(
            *wallet_id,
            old_commitment,
            &merkle_proof_old,
            actual_prev_root,
            hasher,
            config,
        )?;
        if !old_proof_valid {
            return Err(crate::Error::Global(crate::errors::GlobalError::Internal(format!(
                "Old merkle proof does not verify against prev_root for wallet {:?}",
                wallet_id
            ))));
        }

        let new_proof_valid = verify_merkle_proof_with(
            *wallet_id,
            *new_commitment,
            &merkle_proof_new,
            actual_next_root,
            hasher,
            config,
        )?;
        if !new_proof_valid {
            return Err(crate::Error::Global(crate::errors::GlobalError::Internal(format!(
                "New merkle proof does not verify against next_root for wallet {:?}",
                wallet_id
            ))));
        }

        let witness = GlobalTransitionWitness {
            wallet_id: *wallet_id,
            prev_root: actual_prev_root,
            old_wallet_commitment: old_commitment,
            merkle_proof_old,
            next_root: actual_next_root,
            new_wallet_commitment: *new_commitment,
            merkle_proof_new,
        };

        witnesses.push(witness);
    }

    Ok(UpdatedGlobalRoot { root: next_root, witnesses })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::global::commitment::Poseidon2Hasher;

    struct TestDatabase {
        smt_nodes: BTreeMap<Vec<u8>, SmtNodeHash>,
        wallets_by_prefix: BTreeMap<Vec<u8>, BTreeMap<WalletId, WalletCommitment>>,
    }

    impl TestDatabase {
        fn new() -> Self { Self { smt_nodes: BTreeMap::new(), wallets_by_prefix: BTreeMap::new() } }

        fn set_smt_node(&mut self, key: Vec<u8>, hash: SmtNodeHash) {
            self.smt_nodes.insert(key, hash);
        }

        fn set_wallets_by_prefix(
            &mut self,
            prefix: Vec<u8>,
            wallets: BTreeMap<WalletId, WalletCommitment>,
        ) {
            self.wallets_by_prefix.insert(prefix, wallets);
        }
    }

    impl Database for TestDatabase {
        fn get_wallet_commitment(&self, _wallet_id: &[u8; 32]) -> Result<Option<WalletCommitment>> {
            Ok(None)
        }

        fn put_wallet_commitment(
            &self,
            _wallet_id: &[u8; 32],
            _commitment: &WalletCommitment,
        ) -> Result<()> {
            Ok(())
        }

        fn get_smt_node(&self, node_key: &[u8]) -> Result<Option<SmtNodeHash>> {
            Ok(self.smt_nodes.get(node_key).copied())
        }

        fn put_smt_node(&self, _node_key: &[u8], _node_hash: &SmtNodeHash) -> Result<()> { Ok(()) }

        fn delete_smt_node(&self, _node_key: &[u8]) -> Result<()> { Ok(()) }

        fn get_wallets_by_prefix(
            &self,
            prefix: &[u8],
            _depth: u8,
        ) -> Result<BTreeMap<[u8; 32], WalletCommitment>> {
            Ok(self.wallets_by_prefix.get(prefix).cloned().unwrap_or_default())
        }

        fn batch_write(&self, _ops: Vec<DbOperation>) -> Result<()> { Ok(()) }
    }

    struct TestConfig;

    impl SmtConfig for TestConfig {
        fn leaf_domain_tag(&self) -> &[u8] { b"MM_WLT_v0" }

        fn internal_domain_tag(&self) -> &[u8] { b"MM_GLOBAL_v0" }

        fn max_depth(&self) -> u8 { 2 }
    }

    #[test]
    fn test_update_wallet_commitments() {
        let hasher = Poseidon2Hasher;
        let config = TestConfig;
        let empty_updates = BTreeMap::new();
        let db = TestDatabase::new();

        let prev_root = hasher.zero_hash();
        let empty_result =
            update_wallet_commitments(prev_root, &empty_updates, &hasher, &config, &db)
                .expect("empty updates should succeed");
        assert_eq!(empty_result.root, hasher.zero_hash());

        let mut wallet_id_0 = [0u8; 32];
        wallet_id_0[0] = 0b00000000u8;
        let commitment_0 = [0u8; 32];
        let mut wallet_id_1 = [1u8; 32];
        wallet_id_1[0] = 0b10000000u8;
        let commitment_1 = [1u8; 32];
        let mut _wallet_id_2 = [2u8; 32];
        _wallet_id_2[0] = 0b01000000u8;
        let _commitment_2 = [2u8; 32];
        let mut wallet_id_3 = [3u8; 32];
        wallet_id_3[0] = 0b11000000u8;
        let commitment_3 = [3u8; 32];

        let mut db = TestDatabase::new();
        let sibling_key_1_depth_1 = encode_sibling_node_key(&wallet_id_1, 1);
        let sibling_hash_in_db = [10u8; 32];
        db.set_smt_node(sibling_key_1_depth_1.clone(), sibling_hash_in_db);

        let sibling_prefix_0_depth_1 = compute_sibling_prefix_bytes(&wallet_id_0, 1);
        let empty_sibling_wallets = BTreeMap::new();
        db.set_wallets_by_prefix(sibling_prefix_0_depth_1, empty_sibling_wallets);

        let sibling_prefix_1_depth_1 = compute_sibling_prefix_bytes(&wallet_id_1, 1);
        let mut non_empty_sibling_wallets = BTreeMap::new();
        non_empty_sibling_wallets.insert(wallet_id_3, commitment_3);
        db.set_wallets_by_prefix(sibling_prefix_1_depth_1, non_empty_sibling_wallets);

        let mut updates = BTreeMap::new();
        updates.insert(wallet_id_0, commitment_0);
        updates.insert(wallet_id_1, commitment_1);

        // Compute prev_root from database state before update
        // This matches what update_wallet_commitments will compute internally
        let empty_prefix = Vec::new();
        let commitments_before =
            db.get_wallets_by_prefix(&empty_prefix, 0).expect("empty prefix should succeed");
        // Add old commitments for wallets being updated (they don't exist yet, so use empty)
        let mut commitments_before_with_updates = commitments_before.clone();
        for wallet_id in updates.keys() {
            let old_commitment = crate::wallet::commitment::compute_commitment_from_channels(
                *wallet_id,
                &BTreeMap::new(),
            )
            .unwrap_or([0u8; 32]);
            commitments_before_with_updates.insert(*wallet_id, old_commitment);
        }
        use crate::global::commitment::build_smt_root_with;
        let prev_root = build_smt_root_with(&commitments_before_with_updates, &hasher, &config);

        let result = update_wallet_commitments(prev_root, &updates, &hasher, &config, &db)
            .expect("wallet commitment update should succeed");

        assert_ne!(result.root, hasher.zero_hash());
    }
}
