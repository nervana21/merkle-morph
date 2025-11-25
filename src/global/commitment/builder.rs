//! Sparse Merkle Tree building functions

use std::collections::BTreeMap;

use crate::global::smt::{get_bit_at_depth, SmtConfig, SmtHasher};
use crate::types::{WalletCommitment, WalletId};
use crate::Bytes32;

/// Computes the SMT root with custom hasher and config
///
/// This function allows using different hash functions and configurations,
/// which is useful for protocol versioning and testing. Computes a subtree root
/// from available wallet commitment hashes.
///
/// # Arguments
/// * `wallet_commitments` - Map of wallet IDs to their commitments
/// * `hasher` - The hash function implementation
/// * `config` - The SMT configuration
///
/// # Returns
/// The root hash of the SMT, or the zero hash if empty
pub fn build_smt_root_with<H: SmtHasher, C: SmtConfig>(
    wallet_commitments: &BTreeMap<WalletId, WalletCommitment>,
    hasher: &H,
    config: &C,
) -> Bytes32 {
    if wallet_commitments.is_empty() {
        return hasher.zero_hash();
    }

    build_smt_node_with(wallet_commitments, 0, hasher, config)
}

/// Builds an SMT node at the given depth using the provided hasher and config
///
/// The tree is built recursively, with each level corresponding to one bit
/// of the wallet ID. At depth 0, we check bit 0; at depth 1, bit 1, etc.
/// When we reach the maximum depth, any remaining wallets are leaves.
///
/// # Invariant
/// At any depth d (including max_depth), if multiple wallets exist, they must be split by their
/// bit at depth d BEFORE checking termination conditions. The termination check applies AFTER
/// the split operation. This ensures wallets differing only at max_depth can be correctly processed.
pub fn build_smt_node_with<H: SmtHasher, C: SmtConfig>(
    wallet_commitments: &BTreeMap<WalletId, WalletCommitment>,
    depth: u8,
    hasher: &H,
    config: &C,
) -> Bytes32 {
    if wallet_commitments.is_empty() {
        return hasher.zero_hash();
    }

    let max_depth = config.max_depth();

    // Split wallets by their bit at this depth FIRST, before checking termination conditions
    // This ensures wallets differing only at max_depth can still be split correctly
    let mut left_wallets = BTreeMap::new();
    let mut right_wallets = BTreeMap::new();

    for (wallet_id, wallet_commitment) in wallet_commitments.iter() {
        let bit_value = get_bit_at_depth(wallet_id, depth);
        if bit_value == 0 {
            left_wallets.insert(*wallet_id, *wallet_commitment);
        } else {
            right_wallets.insert(*wallet_id, *wallet_commitment);
        }
    }

    // After splitting, check if we're at max_depth
    if depth >= max_depth {
        // At max_depth, after splitting, each branch should have at most one wallet
        if left_wallets.len() > 1 || right_wallets.len() > 1 {
            panic!(
                "Invalid SMT: multiple wallets at max_depth {} after splitting. Left: {}, Right: {}",
                max_depth, left_wallets.len(), right_wallets.len()
            );
        }

        // Handle left branch (if any)
        let left_child = if let Some((wallet_id, wallet_commitment)) = left_wallets.iter().next() {
            hasher.hash_leaf(config.leaf_domain_tag(), *wallet_id, *wallet_commitment)
        } else {
            hasher.zero_hash()
        };

        // Handle right branch (if any)
        let right_child = if let Some((wallet_id, wallet_commitment)) = right_wallets.iter().next()
        {
            hasher.hash_leaf(config.leaf_domain_tag(), *wallet_id, *wallet_commitment)
        } else {
            hasher.zero_hash()
        };

        // If we have both left and right, combine them with an internal node
        // Otherwise, return the single leaf (or zero hash if empty)
        if !left_wallets.is_empty() && !right_wallets.is_empty() {
            return hasher.hash_internal(config.internal_domain_tag(), left_child, right_child);
        } else if !left_wallets.is_empty() {
            return left_child;
        } else if !right_wallets.is_empty() {
            return right_child;
        } else {
            return hasher.zero_hash();
        }
    }

    // Not at max_depth yet, recursively build children
    let next_depth = depth + 1;
    let left_child = build_smt_node_with(&left_wallets, next_depth, hasher, config);
    let right_child = build_smt_node_with(&right_wallets, next_depth, hasher, config);

    let result = hasher.hash_internal(config.internal_domain_tag(), left_child, right_child);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::global::commitment::{MerkleMorphV0Config, Poseidon2Hasher};
    use crate::global::smt::SmtConfig;

    struct TestConfig;

    impl SmtConfig for TestConfig {
        fn leaf_domain_tag(&self) -> &[u8] { b"MM_WLT_v0" }

        fn internal_domain_tag(&self) -> &[u8] { b"MM_GLOBAL_v0" }

        fn max_depth(&self) -> u8 { 1 }
    }

    #[test]
    fn test_build_smt_root_with() {
        let hasher = Poseidon2Hasher;
        let config = MerkleMorphV0Config;
        let empty_map = BTreeMap::new();

        let empty_result = build_smt_root_with(&empty_map, &hasher, &config);

        assert_eq!(empty_result, hasher.zero_hash());

        let mut non_empty_map = BTreeMap::new();
        let wallet_id = [0u8; 32];
        let wallet_commitment = [1u8; 32];
        non_empty_map.insert(wallet_id, wallet_commitment);

        let non_empty_result = build_smt_root_with(&non_empty_map, &hasher, &config);

        assert_ne!(non_empty_result, hasher.zero_hash());
    }

    #[test]
    fn test_build_smt_node_with() {
        let hasher = Poseidon2Hasher;
        let test_config = TestConfig;
        let empty_map = BTreeMap::new();

        let empty_result = build_smt_node_with(&empty_map, 0, &hasher, &test_config);

        assert_eq!(empty_result, hasher.zero_hash());
        let mut single_wallet_map = BTreeMap::new();
        let wallet_id_1 = [0u8; 32];
        let wallet_commitment_1 = [1u8; 32];
        single_wallet_map.insert(wallet_id_1, wallet_commitment_1);
        let max_depth = test_config.max_depth();

        let single_at_max_result =
            build_smt_node_with(&single_wallet_map, max_depth, &hasher, &test_config);

        let expected_single_leaf =
            hasher.hash_leaf(test_config.leaf_domain_tag(), wallet_id_1, wallet_commitment_1);
        assert_eq!(single_at_max_result, expected_single_leaf);

        let mut split_wallets_map = BTreeMap::new();
        let left_wallet_id = [0b00000000u8; 32];
        let left_wallet_commitment = [4u8; 32];
        let right_wallet_id = [0b10000000u8; 32];
        let right_wallet_commitment = [5u8; 32];
        split_wallets_map.insert(left_wallet_id, left_wallet_commitment);
        split_wallets_map.insert(right_wallet_id, right_wallet_commitment);

        let split_result = build_smt_node_with(&split_wallets_map, 0, &hasher, &test_config);

        let left_leaf =
            hasher.hash_leaf(test_config.leaf_domain_tag(), left_wallet_id, left_wallet_commitment);
        let right_leaf = hasher.hash_leaf(
            test_config.leaf_domain_tag(),
            right_wallet_id,
            right_wallet_commitment,
        );
        let expected_split =
            hasher.hash_internal(test_config.internal_domain_tag(), left_leaf, right_leaf);
        assert_eq!(split_result, expected_split);
    }
}
