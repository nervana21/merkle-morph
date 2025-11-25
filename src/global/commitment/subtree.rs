//! Subtree root computation and composition
//!
//! This module implements subtree root computation and composition for Sparse Merkle Trees (SMT).
//! Based on monotree's SMT logic (https://github.com/thyeem/monotree), adapted for zero-knowledge
//! proof requirements.
//!
//! # Design: Explicit Depth Tracking
//!
//! This approach uses explicit depth tracking. ZK proofs require all tree levels in the trace.
//! The extra hash operations are negligible compared to proof generation costs, and avoiding
//! path expansion in-circuit significantly simplifies proof complexity.

use std::collections::BTreeMap;

use super::builder::build_smt_node_with;
use super::config::DEFAULT_CONFIG;
use super::hasher::{hash_internal_node, DEFAULT_HASHER};
use super::types::SubtreeRoot;
use crate::errors::GlobalError;
use crate::global::smt::{get_bit_at_depth, SmtConfig, SmtHasher};
use crate::types::{WalletCommitment, WalletId};
use crate::zkp::subtree::prove_subtree_root_validity;
use crate::zkp::types::StarkConfig;
use crate::{Bytes32, Result};

/// Computes a subtree root for a range of wallet IDs with proof
///
/// This function computes the SMT root for wallets within the specified
/// inclusive range [min_id, max_id], starting from the common prefix depth.
/// The subtree root is computed from `start_depth` (where wallet IDs start to differ),
/// not from depth 0, allowing proper composition with other subtrees.
/// It also generates a zero-knowledge proof that the subtree root is valid.
///
/// The `start_depth` is computed as the common prefix length between min_id and max_id,
/// which determines where the subtree begins in the SMT structure. This allows efficient
/// composition of multiple subtrees without recomputing the entire tree.
///
/// # Arguments
/// * `config` - STARK configuration for proof generation
/// * `wallet_commitments` - Map of wallet ID to commitment hash (only those in the range will be used)
/// * `min_id` - Minimum wallet ID (inclusive) in the range
/// * `max_id` - Maximum wallet ID (inclusive) in the range
///
/// # Returns
/// A `SubtreeRoot` containing the root hash, range, start depth, and validity proof
pub fn compute_subtree_root(
    config: &StarkConfig,
    wallet_commitments: &BTreeMap<WalletId, WalletCommitment>,
    min_id: WalletId,
    max_id: WalletId,
) -> Result<SubtreeRoot> {
    // Validate range
    if min_id > max_id {
        return Err(GlobalError::InvalidParameters(format!(
            "Invalid range: min_id ({:?}) > max_id ({:?})",
            min_id, max_id
        ))
        .into());
    }

    // Filter wallets in the range
    let mut subtree_wallets = BTreeMap::new();
    for (wallet_id, wallet_commitment) in wallet_commitments.iter() {
        if *wallet_id >= min_id && *wallet_id <= max_id {
            subtree_wallets.insert(*wallet_id, *wallet_commitment);
        }
    }

    // Compute start_depth: find the common prefix length between min_id and max_id
    // This is the depth at which wallet IDs in this subtree start to differ
    let start_depth = compute_common_prefix_depth(&min_id, &max_id);

    // Compute the root starting from start_depth
    let root = build_smt_node_with(&subtree_wallets, start_depth, &DEFAULT_HASHER, &DEFAULT_CONFIG);

    // Generate validity proof
    let validity_proof = prove_subtree_root_validity(wallet_commitments, min_id, max_id, config)?;

    Ok(SubtreeRoot {
        root,
        wallet_id_range: (min_id, max_id),
        start_depth,
        validity_proof: Some(std::sync::Arc::new(validity_proof)),
    })
}

/// Computes the depth (common prefix length) between two wallet IDs
///
/// This represents how many bits are the same between min_id and max_id,
/// which determines the depth of the subtree covering this range.
/// When min_id == max_id (single wallet), returns 0 since the subtree
/// should be computed from the root.
fn compute_common_prefix_depth(min_id: &WalletId, max_id: &WalletId) -> u8 {
    // Special case: if min_id == max_id, return 0 (single wallet subtree from root)
    if min_id == max_id {
        return 0;
    }

    for depth in 0..=255 {
        let min_bit = get_bit_at_depth(min_id, depth);
        let max_bit = get_bit_at_depth(max_id, depth);
        if min_bit != max_bit {
            return depth;
        }
    }
    255 // All bits are the same (shouldn't happen for different IDs)
}

/// Composes two adjacent subtree roots into a single subtree root
///
/// The subtrees should cover adjacent or overlapping ranges in the wallet ID space.
/// The resulting subtree covers the union of both ranges.
///
/// The new `start_depth` is computed as the common prefix depth of the combined range,
/// ensuring correctness when composing subtrees that may have been computed at different
/// depths.
///
/// # Arguments
/// * `left` - Left subtree root (should have smaller wallet IDs)
/// * `right` - Right subtree root (should have larger wallet IDs)
///
/// # Returns
/// A new `SubtreeRoot` representing the composition of both subtrees
pub fn compose_subtree_roots(left: &SubtreeRoot, right: &SubtreeRoot) -> Result<SubtreeRoot> {
    // Verify that left comes before right in sorted order
    // Allow adjacent ranges (left.end + 1 == right.start) but reject overlapping or out-of-order
    // For adjacent ranges, left.end < right.start (with no gap) means they can be composed
    if left.wallet_id_range.1 >= right.wallet_id_range.0 {
        // They overlap or are out of order - this is an error
        // Note: We allow left.end < right.start (with possible gap) or left.end + 1 == right.start (adjacent)
        // But we reject left.end >= right.start (overlap or out of order)
        return Err(GlobalError::InvalidParameters(
            format!(
                "Invalid subtree composition: left range ends at {:?} but right range starts at {:?} (overlap or out of order). For adjacent ranges, left.end should be less than right.start",
                left.wallet_id_range.1, right.wallet_id_range.0
            )
        ).into());
    }

    // Compose the roots: hash them together as siblings in the tree
    let composed_root = hash_internal_node(left.root, right.root);

    // The new range covers both subtrees
    let new_min = left.wallet_id_range.0;
    let new_max = right.wallet_id_range.1;

    // Compute the new start_depth as the common prefix depth of the combined range.
    let new_start_depth = compute_common_prefix_depth(&new_min, &new_max);

    // Composed subtrees don't have individual validity proofs since they're constructed
    // from already-verified subtrees. The proof is set to None.
    Ok(SubtreeRoot {
        root: composed_root,
        wallet_id_range: (new_min, new_max),
        start_depth: new_start_depth,
        validity_proof: None,
    })
}

/// Composes multiple subtree roots into a global root
///
/// This function builds an SMT structure from the provided subtrees.
/// Each subtree is treated as covering a range of wallet IDs. The function
/// builds the tree structure based on the wallet ID bit patterns.
///
/// The subtrees should be sorted by their minimum wallet ID and should cover
/// non-overlapping ranges (except possibly at boundaries). The function recursively
/// composes subtrees following the SMT bit-based structure.
///
/// # Arguments
/// * `subtrees` - Sorted slice of subtree roots covering the wallet ID space
///
/// # Returns
/// The computed global root
pub fn compose_to_global_root(subtrees: &[SubtreeRoot]) -> Result<Bytes32> {
    if subtrees.is_empty() {
        return Ok(DEFAULT_HASHER.zero_hash());
    }

    compose_subtrees_at_depth(subtrees, 0, &DEFAULT_HASHER, &DEFAULT_CONFIG, None) // depth 0 is the root
}

/// Shared helper for composing subtrees at a specific depth
///
/// This function provides the core logic for composing subtrees into an SMT structure.
/// It's used by both `compose_to_global_root` (for global root computation) and
/// `compose_at_depth` (for ZKP trace generation) to ensure consistent behavior.
///
/// # Arguments
/// * `subtrees` - Slice of subtree roots to compose
/// * `depth` - Current depth in the SMT (0 = root)
/// * `hasher` - Hasher implementation for computing hashes
/// * `config` - SMT configuration
/// * `max_depth` - Maximum depth to traverse (None = no limit)
///
/// # Returns
/// The composed root at the specified depth
pub fn compose_subtrees_at_depth<H: SmtHasher, C: SmtConfig>(
    subtrees: &[SubtreeRoot],
    depth: u8,
    hasher: &H,
    config: &C,
    max_depth: Option<u8>,
) -> Result<Bytes32> {
    let zero = hasher.zero_hash();

    if let Some(max) = max_depth {
        if depth >= max {
            return Ok(zero);
        }
    }

    // Handle empty case
    if subtrees.is_empty() {
        return Ok(zero);
    }

    // Handle single subtree
    if subtrees.len() == 1 {
        let subtree = &subtrees[0];

        // If depth == start_depth, return root directly
        if depth == subtree.start_depth {
            return Ok(subtree.root);
        }

        // If depth < start_depth, unwrap upward (add zero padding)
        if depth < subtree.start_depth {
            let mut current_root = subtree.root;
            for d in (depth..subtree.start_depth).rev() {
                let bit_value = get_bit_at_depth(&subtree.wallet_id_range.0, d);
                if bit_value == 0 {
                    // Zero goes on the right
                    current_root =
                        hasher.hash_internal(config.internal_domain_tag(), current_root, zero);
                } else {
                    // Zero goes on the left
                    current_root =
                        hasher.hash_internal(config.internal_domain_tag(), zero, current_root);
                }
            }
            return Ok(current_root);
        }

        // If depth > start_depth, the subtree is already complete from start_depth
        // It represents the entire subtree at that depth, so return it as-is
        return Ok(subtree.root);
    }

    // Multiple subtrees - need to split
    // Process subtrees: unwrap those with depth < start_depth
    // For those with depth > start_depth, they represent complete subtrees and will span both sides
    let mut processed_subtrees = Vec::new();
    for subtree in subtrees.iter() {
        if depth < subtree.start_depth {
            // Unwrap this subtree to current depth
            let mut current_root = subtree.root;
            for d in (depth..subtree.start_depth).rev() {
                let bit_value = get_bit_at_depth(&subtree.wallet_id_range.0, d);
                if bit_value == 0 {
                    current_root =
                        hasher.hash_internal(config.internal_domain_tag(), current_root, zero);
                } else {
                    current_root =
                        hasher.hash_internal(config.internal_domain_tag(), zero, current_root);
                }
            }
            // Create a new subtree with unwrapped root at current depth
            processed_subtrees.push(SubtreeRoot {
                root: current_root,
                wallet_id_range: subtree.wallet_id_range,
                start_depth: depth,
                validity_proof: None,
            });
        } else {
            // For depth >= start_depth, use subtree as-is (will be handled in splitting logic)
            // Subtrees with depth > start_depth will be detected as spanning both sides
            processed_subtrees.push(subtree.clone());
        }
    }

    // Split subtrees based on bit at current depth
    // At this point, all subtrees have depth == start_depth (we've unwrapped those with depth < start_depth)
    // and we've handled those with depth > start_depth
    let mut left_subtrees = Vec::new();
    let mut right_subtrees = Vec::new();

    for subtree in processed_subtrees.iter() {
        // Check if subtree spans both sides or is complete from a deeper depth
        // A subtree with depth > start_depth represents a complete subtree and spans both sides at current depth
        if depth > subtree.start_depth {
            // Subtree is complete from a deeper depth, so it spans both sides at current depth
            // Handle as single subtree case to prevent infinite recursion
            return compose_subtrees_at_depth(
                std::slice::from_ref(subtree),
                depth,
                hasher,
                config,
                max_depth,
            );
        }
        // Check if subtree spans both sides (min_bit != max_bit at this depth)
        let min_bit = get_bit_at_depth(&subtree.wallet_id_range.0, depth);
        let max_bit = get_bit_at_depth(&subtree.wallet_id_range.1, depth);
        if min_bit != max_bit {
            // Subtree spans both sides at this depth (depth == start_depth)
            // This means it's the only subtree that matters - handle as single subtree case
            return compose_subtrees_at_depth(
                std::slice::from_ref(subtree),
                depth,
                hasher,
                config,
                max_depth,
            );
        }
        // Subtree is on one side - split based on bit
        if min_bit == 0 {
            left_subtrees.push(subtree.clone());
        } else {
            right_subtrees.push(subtree.clone());
        }
    }

    // Safety check: prevent depth overflow (u8 max is 255)
    if depth == 255 {
        return Ok(zero);
    }

    // Recursively compose left and right subtrees
    let left_child = if !left_subtrees.is_empty() {
        compose_subtrees_at_depth(&left_subtrees, depth + 1, hasher, config, max_depth)?
    } else {
        zero
    };
    let right_child = if !right_subtrees.is_empty() {
        compose_subtrees_at_depth(&right_subtrees, depth + 1, hasher, config, max_depth)?
    } else {
        zero
    };

    // Compute internal node hash at current depth
    Ok(hasher.hash_internal(config.internal_domain_tag(), left_child, right_child))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::zkp::types::create_config;

    #[test]
    fn test_compute_subtree_root() {
        let config = create_config().expect("Should create config");
        let mut wallet_commitments = BTreeMap::new();
        let min_id = [0u8; 32];
        let max_id = [1u8; 32];
        wallet_commitments.insert(min_id, [2u8; 32]);

        let invalid_result = compute_subtree_root(&config, &wallet_commitments, max_id, min_id);

        assert!(invalid_result.is_err());

        let valid_result = compute_subtree_root(&config, &wallet_commitments, min_id, max_id);

        assert!(valid_result.is_ok());
    }

    #[test]
    fn test_compose_subtree_roots() {
        let config = create_config().expect("Should create config");
        let mut wallet_commitments = BTreeMap::new();
        let left_min_id = [0u8; 32];
        let left_max_id = [1u8; 32];
        let right_min_id = [2u8; 32];
        let right_max_id = [3u8; 32];
        wallet_commitments.insert(left_min_id, [4u8; 32]);
        wallet_commitments.insert(right_min_id, [5u8; 32]);
        let left_subtree =
            compute_subtree_root(&config, &wallet_commitments, left_min_id, left_max_id)
                .expect("Should create left subtree");
        let right_subtree =
            compute_subtree_root(&config, &wallet_commitments, right_min_id, right_max_id)
                .expect("Should create right subtree");

        let invalid_result = compose_subtree_roots(&right_subtree, &left_subtree);

        assert!(invalid_result.is_err());

        let valid_result = compose_subtree_roots(&left_subtree, &right_subtree);

        assert!(valid_result.is_ok());
    }

    #[test]
    fn test_compose_to_global_root() {
        let empty_result = compose_to_global_root(&[]);

        assert!(empty_result.is_ok());
        assert_eq!(empty_result.expect("Should return zero hash"), [0u8; 32]);

        let config = create_config().expect("Should create config");
        let mut wallet_commitments = BTreeMap::new();
        let wallet_id = [0u8; 32];
        wallet_commitments.insert(wallet_id, [1u8; 32]);
        let subtree = compute_subtree_root(&config, &wallet_commitments, wallet_id, wallet_id)
            .expect("Should create subtree");

        let non_empty_result = compose_to_global_root(&[subtree]);

        assert!(non_empty_result.is_ok());
    }

    #[test]
    fn test_compose_subtrees_at_depth() {
        let hasher = &DEFAULT_HASHER;
        let config = &DEFAULT_CONFIG;
        let zero = hasher.zero_hash();

        let max_depth_result = compose_subtrees_at_depth(&[], 5, hasher, config, Some(5));

        assert!(max_depth_result.is_ok());
        assert_eq!(max_depth_result.expect("Should return zero"), zero);

        let empty_result = compose_subtrees_at_depth(&[], 0, hasher, config, None);

        assert!(empty_result.is_ok());
        assert_eq!(empty_result.expect("Should return zero"), zero);

        let test_config = create_config().expect("Should create config");
        let mut wallet_commitments = BTreeMap::new();
        let wallet_id_0 = [0u8; 32];
        wallet_commitments.insert(wallet_id_0, [10u8; 32]);
        let subtree_single =
            compute_subtree_root(&test_config, &wallet_commitments, wallet_id_0, wallet_id_0)
                .expect("Should create subtree");

        let single_eq_result = compose_subtrees_at_depth(
            std::slice::from_ref(&subtree_single),
            subtree_single.start_depth,
            hasher,
            config,
            None,
        );

        assert!(single_eq_result.is_ok());
        let mut wallet_id_bit0 = [0u8; 32];
        wallet_id_bit0[31] = 0b00000000;
        let mut wallet_commitments_unwrap = BTreeMap::new();
        wallet_commitments_unwrap.insert(wallet_id_bit0, [30u8; 32]);
        let subtree_unwrap = compute_subtree_root(
            &test_config,
            &wallet_commitments_unwrap,
            wallet_id_bit0,
            wallet_id_bit0,
        )
        .expect("Should create subtree");

        // Only test unwrap behavior if start_depth > 0 (can't unwrap from depth 0)
        if subtree_unwrap.start_depth > 0 {
            let single_lt_bit0_result = compose_subtrees_at_depth(
                std::slice::from_ref(&subtree_unwrap),
                subtree_unwrap.start_depth - 1,
                hasher,
                config,
                None,
            );
            assert!(single_lt_bit0_result.is_ok());
        }

        let mut wallet_id_bit1 = [0u8; 32];
        wallet_id_bit1[31] = 0b10000000;
        let mut wallet_commitments_unwrap_bit1 = BTreeMap::new();
        wallet_commitments_unwrap_bit1.insert(wallet_id_bit1, [40u8; 32]);
        let subtree_unwrap_bit1 = compute_subtree_root(
            &test_config,
            &wallet_commitments_unwrap_bit1,
            wallet_id_bit1,
            wallet_id_bit1,
        )
        .expect("Should create subtree");

        // Only test unwrap behavior if start_depth > 0 (can't unwrap from depth 0)
        if subtree_unwrap_bit1.start_depth > 0 {
            let single_lt_bit1_result = compose_subtrees_at_depth(
                std::slice::from_ref(&subtree_unwrap_bit1),
                subtree_unwrap_bit1.start_depth - 1,
                hasher,
                config,
                None,
            );
            assert!(single_lt_bit1_result.is_ok());
        }

        let single_gt_result = compose_subtrees_at_depth(
            std::slice::from_ref(&subtree_single),
            subtree_single.start_depth + 1,
            hasher,
            config,
            None,
        );

        assert!(single_gt_result.is_ok());

        let mut wallet_id_left = [0u8; 32];
        wallet_id_left[31] = 0b00000000;
        let mut wallet_id_right = [0u8; 32];
        wallet_id_right[31] = 0b10000000;
        let mut wallet_commitments_multi = BTreeMap::new();
        wallet_commitments_multi.insert(wallet_id_left, [50u8; 32]);
        wallet_commitments_multi.insert(wallet_id_right, [60u8; 32]);
        let subtree_left = compute_subtree_root(
            &test_config,
            &wallet_commitments_multi,
            wallet_id_left,
            wallet_id_left,
        )
        .expect("Should create left subtree");
        let subtree_right = compute_subtree_root(
            &test_config,
            &wallet_commitments_multi,
            wallet_id_right,
            wallet_id_right,
        )
        .expect("Should create right subtree");

        let multi_result = compose_subtrees_at_depth(
            &[subtree_left.clone(), subtree_right.clone()],
            0,
            hasher,
            config,
            None,
        );

        assert!(multi_result.is_ok());
        let mut wallet_id_span_min = [0u8; 32];
        wallet_id_span_min[31] = 0b00000000;
        let mut wallet_id_span_max = [0u8; 32];
        wallet_id_span_max[31] = 0b10000000;
        let mut wallet_commitments_span = BTreeMap::new();
        wallet_commitments_span.insert(wallet_id_span_min, [70u8; 32]);
        wallet_commitments_span.insert(wallet_id_span_max, [80u8; 32]);
        let subtree_span = compute_subtree_root(
            &test_config,
            &wallet_commitments_span,
            wallet_id_span_min,
            wallet_id_span_max,
        )
        .expect("Should create spanning subtree");

        let span_result = compose_subtrees_at_depth(
            std::slice::from_ref(&subtree_span),
            subtree_span.start_depth,
            hasher,
            config,
            None,
        );

        assert!(span_result.is_ok());
        let mut wallet_id_process_lt = [0u8; 32];
        wallet_id_process_lt[31] = 0b00000000;
        let mut wallet_commitments_process = BTreeMap::new();
        wallet_commitments_process.insert(wallet_id_process_lt, [90u8; 32]);
        let subtree_process_lt = compute_subtree_root(
            &test_config,
            &wallet_commitments_process,
            wallet_id_process_lt,
            wallet_id_process_lt,
        )
        .expect("Should create subtree");

        // Only test unwrap behavior if start_depth > 0 (can't unwrap from depth 0)
        if subtree_process_lt.start_depth > 0 {
            let process_lt_result = compose_subtrees_at_depth(
                std::slice::from_ref(&subtree_process_lt),
                subtree_process_lt.start_depth - 1,
                hasher,
                config,
                None,
            );
            assert!(process_lt_result.is_ok());
        }

        let mut wallet_id_process_gt = [0u8; 32];
        wallet_id_process_gt[31] = 0b10000000;
        let mut wallet_commitments_process_gt = BTreeMap::new();
        wallet_commitments_process_gt.insert(wallet_id_process_gt, [100u8; 32]);
        let subtree_process_gt = compute_subtree_root(
            &test_config,
            &wallet_commitments_process_gt,
            wallet_id_process_gt,
            wallet_id_process_gt,
        )
        .expect("Should create subtree");
        let subtree_process_eq = compute_subtree_root(
            &test_config,
            &wallet_commitments_process,
            wallet_id_process_lt,
            wallet_id_process_lt,
        )
        .expect("Should create subtree");

        let process_multi_result = compose_subtrees_at_depth(
            &[subtree_process_lt.clone(), subtree_process_gt.clone(), subtree_process_eq.clone()],
            subtree_process_lt.start_depth,
            hasher,
            config,
            None,
        );

        assert!(process_multi_result.is_ok());

        let left_only_result =
            compose_subtrees_at_depth(std::slice::from_ref(&subtree_left), 0, hasher, config, None);

        assert!(left_only_result.is_ok());

        let right_only_result = compose_subtrees_at_depth(
            std::slice::from_ref(&subtree_right),
            0,
            hasher,
            config,
            None,
        );

        assert!(right_only_result.is_ok());

        let both_empty_result = compose_subtrees_at_depth(&[], 0, hasher, config, None);

        assert!(both_empty_result.is_ok());
    }
}
