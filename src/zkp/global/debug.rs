//! Debugging utilities for global/subtree ZKP abstraction
//!
//! This module provides helper functions for debugging and verifying
//! the correctness of subtree computation, composition, trace generation,
//! and proof generation.

use std::collections::BTreeMap;

use p3_field::PrimeField32;

use crate::global::commitment::{
    build_smt_node_with, MerkleMorphV0Config, Poseidon2Hasher, SubtreeRoot,
};
use crate::global::smt::{get_bit_at_depth, SmtConfig, SmtHasher};
use crate::types::{WalletCommitment, WalletId};
use crate::zkp::global::trace::build_global_trace;
use crate::zkp::types::{Trace, Val};
use crate::{Bytes32, Result};

/// Convert 8 field elements to Bytes32 (little-endian)
fn fields_to_bytes32(fields: &[Val]) -> Result<Bytes32> {
    if fields.len() != 8 {
        return Err(crate::Error::Zkp(crate::errors::ZkpError::TraceGenerationFailed(format!(
            "Expected 8 fields, got {}",
            fields.len()
        ))));
    }
    let mut bytes = [0u8; 32];
    for (i, field) in fields.iter().enumerate() {
        let val = PrimeField32::as_canonical_u32(field);
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&val.to_le_bytes());
    }
    Ok(bytes)
}

/// Print detailed information about a subtree root
pub fn print_subtree_details(subtree: &SubtreeRoot) {
    println!("Subtree Details:");
    println!("  Root: {:?}", subtree.root);
    println!("  Range: [{:?}, {:?}]", subtree.wallet_id_range.0, subtree.wallet_id_range.1);
    println!("  Start Depth: {}", subtree.start_depth);
    println!("  Has Proof: {}", subtree.validity_proof.is_some());
}

/// Compare two roots and print the result
pub fn compare_roots(expected: &Bytes32, actual: &Bytes32, context: &str) -> bool {
    if expected == actual {
        println!("✓ {}: Roots match", context);
        true
    } else {
        println!("✗ {}: Roots differ", context);
        println!("  Expected: {:?}", expected);
        println!("  Actual: {:?}", actual);
        false
    }
}

/// Verify that a subtree root matches manual computation
pub fn verify_subtree_root(
    subtree: &SubtreeRoot,
    wallet_commitments: &BTreeMap<WalletId, WalletCommitment>,
) -> Result<bool> {
    // Filter wallets in the range
    let mut subtree_wallets = BTreeMap::new();
    for (wallet_id, wallet_commitment) in wallet_commitments.iter() {
        if *wallet_id >= subtree.wallet_id_range.0 && *wallet_id <= subtree.wallet_id_range.1 {
            subtree_wallets.insert(*wallet_id, *wallet_commitment);
        }
    }

    // Manually compute root using build_smt_node_with with same start_depth
    let hasher = Poseidon2Hasher;
    let config = MerkleMorphV0Config;
    let manual_root = build_smt_node_with(&subtree_wallets, subtree.start_depth, &hasher, &config);

    // Compare
    let matches = compare_roots(&manual_root, &subtree.root, "Subtree root verification");
    Ok(matches)
}

/// Verify start_depth calculation
pub fn verify_start_depth(min_id: &WalletId, max_id: &WalletId, expected_start_depth: u8) -> bool {
    let computed = compute_common_prefix_depth(min_id, max_id);
    if computed == expected_start_depth {
        println!("✓ Start depth correct: {} (expected {})", computed, expected_start_depth);
        true
    } else {
        println!("✗ Start depth incorrect: {} (expected {})", computed, expected_start_depth);
        false
    }
}

/// Compute common prefix depth (same logic as in subtree.rs)
fn compute_common_prefix_depth(min_id: &WalletId, max_id: &WalletId) -> u8 {
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
    255
}

/// Verify trace structure
pub fn verify_trace_structure(trace: &Trace) -> Result<()> {
    use p3_matrix::Matrix;

    if trace.height() == 0 {
        return Err(crate::Error::Zkp(crate::errors::ZkpError::TraceGenerationFailed(
            "Trace has zero height".to_string(),
        )));
    }

    println!("Trace Structure:");
    println!("  Height: {}", trace.height());
    println!("  Width: {}", trace.width());

    // Verify first row has depth 0 (root level)
    use crate::zkp::global::poseidon2_air::column_offsets;
    let first_row = trace.row_slice(0).expect("Trace must have first row");

    // Extract composed root from first row
    let composed_root: Vec<_> =
        first_row[column_offsets::COMPOSED_ROOT_START..column_offsets::COMPOSED_ROOT_END].to_vec();

    println!("  First row composed root: {:?}", composed_root);

    Ok(())
}

/// Verify composition steps match expected values
pub fn verify_composition_steps(
    subtrees: &[SubtreeRoot],
    expected_global_root: &Bytes32,
) -> Result<bool> {
    use p3_matrix::Matrix;

    let trace = build_global_trace(subtrees)?;

    // Extract root from first row
    use crate::zkp::global::poseidon2_air::column_offsets;
    let first_row = trace.row_slice(0).expect("Trace must have first row");

    // Convert fields to bytes
    let root_fields: Vec<Val> =
        first_row[column_offsets::COMPOSED_ROOT_START..column_offsets::COMPOSED_ROOT_END].to_vec();
    let actual_root = fields_to_bytes32(&root_fields)?;

    // Compare with expected root
    let matches =
        compare_roots(expected_global_root, &actual_root, "Composition steps verification");

    // Verify trace structure
    verify_trace_structure(&trace)?;

    Ok(matches)
}

/// Print composition steps for debugging
pub fn print_composition_steps(subtrees: &[SubtreeRoot]) -> Result<()> {
    use p3_matrix::Matrix;

    use crate::zkp::global::poseidon2_air::column_offsets;

    let trace = build_global_trace(subtrees)?;

    println!("Composition Steps ({} rows):", trace.height());

    for i in 0..trace.height() {
        let row = trace.row_slice(i).expect("Row should exist");

        let left_fields: Vec<Val> =
            row[column_offsets::LEFT_ROOT_START..column_offsets::LEFT_ROOT_END].to_vec();
        let right_fields: Vec<Val> =
            row[column_offsets::RIGHT_ROOT_START..column_offsets::RIGHT_ROOT_END].to_vec();
        let composed_fields: Vec<Val> =
            row[column_offsets::COMPOSED_ROOT_START..column_offsets::COMPOSED_ROOT_END].to_vec();

        let left_root = fields_to_bytes32(&left_fields)?;
        let right_root = fields_to_bytes32(&right_fields)?;
        let composed_root = fields_to_bytes32(&composed_fields)?;

        println!(
            "  Row {}: left={:?}, right={:?}, composed={:?}",
            i, left_root, right_root, composed_root
        );
    }

    Ok(())
}

/// Verify step ordering (should be root-first, depth 0 to deeper levels)
pub fn verify_step_ordering(subtrees: &[SubtreeRoot]) -> Result<bool> {
    use p3_matrix::Matrix;

    let trace = build_global_trace(subtrees)?;

    // For now, we verify that the first row has a non-zero composed root
    // (indicating it's the root level composition)
    use crate::zkp::global::poseidon2_air::column_offsets;
    let first_row = trace.row_slice(0).expect("Trace must have first row");

    let composed_root_slice =
        &first_row[column_offsets::COMPOSED_ROOT_START..column_offsets::COMPOSED_ROOT_END];

    // Check that first row has non-zero composed root (for non-empty subtrees)
    if !subtrees.is_empty() {
        // Check if all fields are zero by checking their canonical representation
        let all_zero = composed_root_slice.iter().all(|&x| PrimeField32::as_canonical_u32(&x) == 0);
        if all_zero {
            println!("✗ Step ordering: First row has zero composed root (unexpected for non-empty subtrees)");
            return Ok(false);
        }
    }

    println!("✓ Step ordering: First row has valid composed root");
    Ok(true)
}

/// Verify Poseidon2 trace correctness
pub fn verify_poseidon2_trace(subtrees: &[SubtreeRoot]) -> Result<bool> {
    use p3_matrix::Matrix;

    use crate::global::commitment::{MerkleMorphV0Config, Poseidon2Hasher};
    use crate::zkp::global::poseidon2_air::column_offsets;
    use crate::zkp::poseidon2_common::{poseidon2_air_num_cols, poseidon2_output_offset};

    let trace = build_global_trace(subtrees)?;
    let hasher = Poseidon2Hasher;
    let config = MerkleMorphV0Config;

    let poseidon2_cols = poseidon2_air_num_cols();
    let output_offset = poseidon2_output_offset();

    for i in 0..trace.height() {
        let row = trace.row_slice(i).expect("Row should exist");

        // Extract left and right roots
        let left_fields: Vec<Val> =
            row[column_offsets::LEFT_ROOT_START..column_offsets::LEFT_ROOT_END].to_vec();
        let right_fields: Vec<Val> =
            row[column_offsets::RIGHT_ROOT_START..column_offsets::RIGHT_ROOT_END].to_vec();
        let composed_fields: Vec<Val> =
            row[column_offsets::COMPOSED_ROOT_START..column_offsets::COMPOSED_ROOT_END].to_vec();

        let left_root = fields_to_bytes32(&left_fields)?;
        let right_root = fields_to_bytes32(&right_fields)?;
        let expected_composed = fields_to_bytes32(&composed_fields)?;

        // Compute expected hash using the hasher's hash_internal method
        let computed_hash =
            hasher.hash_internal(config.internal_domain_tag(), left_root, right_root);

        // Extract computed root from Poseidon2 trace
        let last_perm_offset = column_offsets::INTERNAL_NODE_POSEIDON2_START
            + (column_offsets::INTERNAL_NODE_PERMUTATIONS - 1) * poseidon2_cols;
        let computed_fields: Vec<Val> = (0..8)
            .map(|j| {
                let col_idx = last_perm_offset + output_offset + j;
                row[col_idx]
            })
            .collect();
        let computed_from_trace = fields_to_bytes32(&computed_fields)?;

        // Verify computed hash matches expected
        if computed_hash != expected_composed {
            println!("✗ Poseidon2 trace row {}: computed hash doesn't match expected", i);
            println!("  Left: {:?}, Right: {:?}", left_root, right_root);
            println!("  Expected: {:?}, Computed: {:?}", expected_composed, computed_hash);
            return Ok(false);
        }

        // Verify trace output matches computed hash
        if computed_from_trace != computed_hash {
            println!("✗ Poseidon2 trace row {}: trace output doesn't match computed hash", i);
            println!(
                "  Computed hash: {:?}, Trace output: {:?}",
                computed_hash, computed_from_trace
            );
            return Ok(false);
        }
    }

    println!("✓ Poseidon2 trace: All rows verified");
    Ok(true)
}
