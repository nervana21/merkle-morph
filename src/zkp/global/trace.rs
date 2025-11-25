//! Trace generation for global root composition
//!
//! This module provides functions for generating execution traces
//! for global root composition proofs. The trace represents the SMT
//! composition process where subtree roots are composed into a global root.

use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

use crate::errors::Result;
use crate::global::commitment::{MerkleMorphV0Config, Poseidon2Hasher, SubtreeRoot};
use crate::global::get_bit_at_depth;
use crate::global::smt::{SmtConfig, SmtHasher};
use crate::types::{Bytes32, WalletId};
use crate::zkp::global::poseidon2_air::create_poseidon2_constants_and_params;
use crate::zkp::poseidon2_common::{
    Poseidon2Constants, POSEIDON2_HALF_FULL_ROUNDS, POSEIDON2_OUTPUT_SIZE,
    POSEIDON2_PARTIAL_ROUNDS, POSEIDON2_RATE, POSEIDON2_SBOX_DEGREE, POSEIDON2_SBOX_REGISTERS,
    POSEIDON2_WIDTH,
};
use crate::zkp::types::{bytes32_to_fields, Trace, Val};

mod column_offsets {
    // Re-export from poseidon2_air for consistency
    pub(super) use crate::zkp::global::poseidon2_air::column_offsets::{
        total_cols, COMPOSED_ROOT_END, COMPOSED_ROOT_START, INTERNAL_NODE_POSEIDON2_START,
        LEFT_ROOT_END, LEFT_ROOT_START, RIGHT_ROOT_END, RIGHT_ROOT_START,
    };
}

/// Maximum number of composition steps supported in a single global proof
#[allow(dead_code)]
pub(super) const MAX_COMPOSITION_STEPS: usize = 64;

/// Represents one internal node hash operation in the SMT composition process
#[derive(Clone, Debug)]
struct CompositionStep {
    /// Depth at which this composition occurs (0 = root)
    depth: u8,
    /// Left child root
    left_root: Bytes32,
    /// Right child root
    right_root: Bytes32,
    /// Composed root (hash of left and right)
    composed_root: Bytes32,
}

/// Hash a root with zero padding on the left or right side based on bit value.
/// If bit_value is 0, zero goes on the right; if 1, zero goes on the left.
fn hash_with_zero_padding(
    root: Bytes32,
    bit_value: u8,
    hasher: &Poseidon2Hasher,
    config: &MerkleMorphV0Config,
) -> Bytes32 {
    let zero = hasher.zero_hash();
    if bit_value == 0 {
        hasher.hash_internal(config.internal_domain_tag(), root, zero)
    } else {
        hasher.hash_internal(config.internal_domain_tag(), zero, root)
    }
}

/// Unwrap a root from start_depth down to target_depth by hashing with zero padding.
/// For each depth in the range, uses the bit at that depth to determine zero placement.
fn unwrap_root_from_depth_range(
    mut root: Bytes32,
    wallet_id: &WalletId,
    target_depth: u8,
    start_depth: u8,
    hasher: &Poseidon2Hasher,
    config: &MerkleMorphV0Config,
) -> Bytes32 {
    for d in (target_depth..start_depth).rev() {
        let bit_value = get_bit_at_depth(wallet_id, d);
        root = hash_with_zero_padding(root, bit_value, hasher, config);
    }
    root
}

/// Helper to compose subtrees at a specific depth (simplified version of compose_subtrees_smt)
fn compose_at_depth(
    subtrees: &[SubtreeRoot],
    depth: u8,
    hasher: &Poseidon2Hasher,
    config: &MerkleMorphV0Config,
) -> Result<Bytes32> {
    let zero = hasher.zero_hash();

    if subtrees.is_empty() {
        return Ok(zero);
    }
    if subtrees.len() == 1 {
        let subtree = &subtrees[0];
        if depth == subtree.start_depth {
            return Ok(subtree.root);
        }
        if depth < subtree.start_depth {
            return Ok(unwrap_root_from_depth_range(
                subtree.root,
                &subtree.wallet_id_range.0,
                depth,
                subtree.start_depth,
                hasher,
                config,
            ));
        }
    }

    // Split by bit at current depth
    let mut left_subtrees = Vec::new();
    let mut right_subtrees = Vec::new();
    for subtree in subtrees.iter() {
        let bit_value = get_bit_at_depth(&subtree.wallet_id_range.0, depth);
        if bit_value == 0 {
            left_subtrees.push(subtree.clone());
        } else {
            right_subtrees.push(subtree.clone());
        }
    }

    let left_child = compose_at_depth(&left_subtrees, depth + 1, hasher, config)?;
    let right_child = compose_at_depth(&right_subtrees, depth + 1, hasher, config)?;
    Ok(hasher.hash_internal(config.internal_domain_tag(), left_child, right_child))
}

/// Collect all composition steps by recursively traversing the SMT composition process.
/// Returns a vector of CompositionStep, ordered from root (depth 0) to deeper levels.
fn collect_composition_steps(
    subtrees: &[SubtreeRoot],
    depth: u8,
    hasher: &Poseidon2Hasher,
    config: &MerkleMorphV0Config,
) -> Result<Vec<CompositionStep>> {
    let zero = hasher.zero_hash();
    let mut steps = Vec::new();

    if subtrees.is_empty() {
        return Ok(steps);
    }

    if subtrees.len() == 1 {
        let subtree = &subtrees[0];
        if depth == subtree.start_depth {
            // Already at the subtree's start depth, no composition needed
            return Ok(steps);
        }
        if depth < subtree.start_depth {
            // Need to unwrap from start_depth down to depth
            // Collect a step for each unwrap operation
            // We need to build from start_depth-1 down to depth, then reverse to get root-first order
            let mut temp_steps = Vec::new();
            let mut current_root = subtree.root;
            for d in (depth..subtree.start_depth).rev() {
                let bit_value = get_bit_at_depth(&subtree.wallet_id_range.0, d);
                let left_root = if bit_value == 0 { current_root } else { zero };
                let right_root = if bit_value == 0 { zero } else { current_root };
                let composed_root =
                    hasher.hash_internal(config.internal_domain_tag(), left_root, right_root);

                temp_steps.push(CompositionStep { depth: d, left_root, right_root, composed_root });

                current_root = composed_root;
            }
            // Reverse to get root (depth 0) first, then deeper levels
            temp_steps.reverse();
            steps.extend(temp_steps);
            return Ok(steps);
        }
    }

    // Split by bit at current depth
    let mut left_subtrees = Vec::new();
    let mut right_subtrees = Vec::new();
    for subtree in subtrees.iter() {
        let bit_value = get_bit_at_depth(&subtree.wallet_id_range.0, depth);
        if bit_value == 0 {
            left_subtrees.push(subtree.clone());
        } else {
            right_subtrees.push(subtree.clone());
        }
    }

    // Recursively collect steps from left and right subtrees
    let mut left_steps = collect_composition_steps(&left_subtrees, depth + 1, hasher, config)?;
    let mut right_steps = collect_composition_steps(&right_subtrees, depth + 1, hasher, config)?;

    // Compute left and right child roots
    let left_child = compose_at_depth(&left_subtrees, depth + 1, hasher, config)?;
    let right_child = compose_at_depth(&right_subtrees, depth + 1, hasher, config)?;

    // Add the composition step at current depth
    let composed_root = hasher.hash_internal(config.internal_domain_tag(), left_child, right_child);
    steps.push(CompositionStep {
        depth,
        left_root: left_child,
        right_root: right_child,
        composed_root,
    });

    // Combine steps: current step first (root level), then left steps, then right steps
    // This orders from root (depth 0) to deeper levels
    steps.append(&mut left_steps);
    steps.append(&mut right_steps);

    Ok(steps)
}

/// Build a single trace row from a composition step.
/// This helper function generates the Poseidon2 trace and populates all columns.
fn build_composition_row(
    step: &CompositionStep,
    constants: &Poseidon2Constants,
    config: &MerkleMorphV0Config,
) -> Result<Vec<Val>> {
    let total_cols = column_offsets::total_cols();
    let mut row = vec![Val::ZERO; total_cols];

    // Set left_root, right_root, and composed_root fields
    let left_fields = bytes32_to_fields(step.left_root);
    row[column_offsets::LEFT_ROOT_START..column_offsets::LEFT_ROOT_END]
        .copy_from_slice(&left_fields);

    let right_fields = bytes32_to_fields(step.right_root);
    row[column_offsets::RIGHT_ROOT_START..column_offsets::RIGHT_ROOT_END]
        .copy_from_slice(&right_fields);

    let composed_fields = bytes32_to_fields(step.composed_root);
    row[column_offsets::COMPOSED_ROOT_START..column_offsets::COMPOSED_ROOT_END]
        .copy_from_slice(&composed_fields);

    // Generate Poseidon2 trace for internal node computation
    let hasher = Poseidon2Hasher;
    let computed_root_for_trace =
        hasher.hash_internal(config.internal_domain_tag(), step.left_root, step.right_root);

    // Verify the computed root matches the step's composed_root
    if computed_root_for_trace != step.composed_root {
        return Err(crate::errors::Error::Zkp(crate::errors::ZkpError::TraceGenerationFailed(
            format!(
                "Composition step root mismatch at depth {}: computed != step.composed_root",
                step.depth
            ),
        )));
    }

    let mut internal_input_bytes = Vec::new();
    internal_input_bytes.extend_from_slice(config.internal_domain_tag());
    internal_input_bytes.extend_from_slice(&step.left_root[..]);
    internal_input_bytes.extend_from_slice(&step.right_root[..]);

    let (internal_traces, computed_output) = generate_multi_permutation_traces(
        &internal_input_bytes,
        &constants.round_constants,
        &constants.external_constants,
        &constants.internal_constants,
    );

    // Verify computed output matches what the hash would produce
    let expected_fields = bytes32_to_fields(computed_root_for_trace);
    if computed_output != expected_fields {
        return Err(crate::errors::Error::Zkp(crate::errors::ZkpError::TraceGenerationFailed(
            format!("Internal node output mismatch at depth {}", step.depth),
        )));
    }

    // Copy traces to row
    copy_traces_to_row(&mut row, &internal_traces, column_offsets::INTERNAL_NODE_POSEIDON2_START);

    Ok(row)
}

/// Build trace matrix for global root composition.
///
/// The trace contains multiple rows (one per composition step, padded to power-of-2).
///
/// # Trace Structure
///
/// Each row represents one internal node composition step with the following column layout:
/// * Columns 0-7: `left_subtree_root` (8 fields)
/// * Columns 8-15: `right_subtree_root` (8 fields)
/// * Columns 16-23: `composed_root` (8 fields)
/// * Columns 24+: Hash trace columns for internal node computation
///
/// Padding rows after the last composition step have zero roots and stable composed_root.
pub(super) fn build_global_trace(subtrees: &[SubtreeRoot]) -> Result<Trace> {
    let total_cols = column_offsets::total_cols();
    const MIN_ROWS: usize = 8; // Minimum rows needed (power of 2)

    if subtrees.is_empty() {
        // Empty case: return trace with zero root
        // For empty case, we need to generate a proper Poseidon2 trace for zero inputs
        // The global root for empty is [0u8; 32], so we hash: poseidon2(MM_GLOBAL_v0 || [0u8; 32] || [0u8; 32])
        let num_rows = MIN_ROWS;
        let mut values = Vec::with_capacity(num_rows * total_cols);

        // Create constants for Poseidon2 trace generation
        let constants = create_poseidon2_constants_and_params();

        // Generate Poseidon2 trace for zero inputs
        let left_root = [0u8; 32];
        let right_root = [0u8; 32];
        let _hasher = Poseidon2Hasher;
        let config = MerkleMorphV0Config;

        // Generate input bytes for Poseidon2
        let mut internal_input_bytes = Vec::new();
        internal_input_bytes.extend_from_slice(config.internal_domain_tag());
        internal_input_bytes.extend_from_slice(&left_root[..]);
        internal_input_bytes.extend_from_slice(&right_root[..]);

        let (internal_traces, _computed_output) = generate_multi_permutation_traces(
            &internal_input_bytes,
            &constants.round_constants,
            &constants.external_constants,
            &constants.internal_constants,
        );

        // Create the first row with proper trace
        let mut first_row = vec![Val::ZERO; total_cols];
        // Left and right roots are zero (already set)
        // Composed root should be zero for empty case (the zero hash is [0u8; 32])
        let composed_fields = bytes32_to_fields([0u8; 32]);
        first_row[column_offsets::COMPOSED_ROOT_START..column_offsets::COMPOSED_ROOT_END]
            .copy_from_slice(&composed_fields);

        // Copy Poseidon2 traces
        copy_traces_to_row(
            &mut first_row,
            &internal_traces,
            column_offsets::INTERNAL_NODE_POSEIDON2_START,
        );

        values.extend_from_slice(&first_row);

        // For padding rows, copy the first row
        for _ in 1..num_rows {
            values.extend_from_slice(&first_row);
        }

        return Ok(RowMajorMatrix::new(values, total_cols));
    }

    // Collect all composition steps level by level
    let hasher = Poseidon2Hasher;
    let config = MerkleMorphV0Config;
    let composition_steps = collect_composition_steps(subtrees, 0, &hasher, &config)?;

    // Verify the final root matches what compose_to_global_root would compute
    // The root should be in the first step (depth 0) for the final composition
    let expected_root = crate::global::commitment::compose_to_global_root(subtrees)?;
    if let Some(first_step) = composition_steps.first() {
        // For depth 0, the composed_root should be the global root
        if first_step.depth == 0 && first_step.composed_root != expected_root {
            return Err(crate::errors::Error::Zkp(crate::errors::ZkpError::TraceGenerationFailed(
                format!(
                    "Final composition root mismatch at depth 0: expected {:?}, got {:?}",
                    expected_root, first_step.composed_root
                ),
            )));
        }
    } else if !subtrees.is_empty() {
        // No steps but we have subtrees - this shouldn't happen
        return Err(crate::errors::Error::Zkp(crate::errors::ZkpError::TraceGenerationFailed(
            "No composition steps collected for non-empty subtrees".to_string(),
        )));
    }

    // Create constants and hash parameters
    let constants = create_poseidon2_constants_and_params();

    // Generate rows for each composition step
    let mut values = Vec::with_capacity(composition_steps.len().max(MIN_ROWS) * total_cols);

    for step in &composition_steps {
        let row = build_composition_row(step, &constants, &config)?;
        values.extend_from_slice(&row);
    }

    // If no steps were collected but we have subtrees, something went wrong
    if composition_steps.is_empty() && !subtrees.is_empty() {
        return Err(crate::errors::Error::Zkp(crate::errors::ZkpError::TraceGenerationFailed(
            "No composition steps collected for non-empty subtrees".to_string(),
        )));
    }

    // Pad to power of 2
    let current_rows = values.len() / total_cols;
    let num_rows = current_rows.max(MIN_ROWS).next_power_of_two();
    let num_padding = num_rows - current_rows;

    // For padding rows, use the global root (from first row, depth 0) and zero inputs
    if num_padding > 0 && current_rows > 0 {
        // Get the global root from the first row (depth 0 is the root level)
        let first_row_start = 0;
        let first_row: Vec<Val> = values[first_row_start..first_row_start + total_cols].to_vec();

        // Get the composed root from the first row (this is the global root at depth 0)
        let global_root: Vec<Val> = first_row
            [column_offsets::COMPOSED_ROOT_START..column_offsets::COMPOSED_ROOT_END]
            .to_vec();

        let zero_left = [0u8; 32];
        let zero_right = [0u8; 32];
        let mut internal_input_bytes = Vec::new();
        internal_input_bytes.extend_from_slice(config.internal_domain_tag());
        internal_input_bytes.extend_from_slice(&zero_left[..]);
        internal_input_bytes.extend_from_slice(&zero_right[..]);

        let (zero_traces, _zero_output) = generate_multi_permutation_traces(
            &internal_input_bytes,
            &constants.round_constants,
            &constants.external_constants,
            &constants.internal_constants,
        );

        for _ in 0..num_padding {
            let mut padding_row = vec![Val::ZERO; total_cols];
            // Copy the global root from the first row to maintain stability
            // This ensures the last row constraint (composed_root == global_root_public) is satisfied
            padding_row[column_offsets::COMPOSED_ROOT_START..column_offsets::COMPOSED_ROOT_END]
                .copy_from_slice(&global_root);
            // Use zero hashes for left and right in padding rows (already set by vec![Val::ZERO])
            // Generate proper Poseidon2 trace for zero inputs
            copy_traces_to_row(
                &mut padding_row,
                &zero_traces,
                column_offsets::INTERNAL_NODE_POSEIDON2_START,
            );
            values.extend_from_slice(&padding_row);
        }
    } else if num_padding > 0 {
        // No rows generated, create padding with zero root (shouldn't happen for non-empty)
        let padding_row = vec![Val::ZERO; total_cols];
        for _ in 0..num_padding {
            values.extend_from_slice(&padding_row);
        }
    }

    Ok(RowMajorMatrix::new(values, total_cols))
}

/// Simulate sponge construction step-by-step to generate multi-permutation traces
/// Returns traces for each permutation needed to hash the input, and the final output
/// This matches the behavior of the hash function implementation
fn generate_multi_permutation_traces(
    input_bytes: &[u8],
    constants: &p3_poseidon2_air::RoundConstants<Val, 16, 4, 20>,
    external_constants: &p3_poseidon2::ExternalLayerConstants<Val, 16>,
    internal_constants: &[Val],
) -> (Vec<Vec<Val>>, [Val; 8]) {
    use p3_baby_bear::Poseidon2BabyBear;
    use p3_symmetric::Permutation;

    type Perm = Poseidon2BabyBear<POSEIDON2_WIDTH>;

    // Create the permutation using the same constants as the hash function
    let perm = Perm::new(external_constants.clone(), internal_constants.to_vec());

    // Convert bytes to field elements
    let mut fields = Vec::new();
    for chunk in input_bytes.chunks(4) {
        let mut arr = [0u8; 4];
        arr[..chunk.len()].copy_from_slice(chunk);
        let u32_val = u32::from_le_bytes(arr);
        fields.push(Val::new(u32_val));
    }

    // Simulate the sponge construction step-by-step
    let mut state = [Val::ZERO; POSEIDON2_WIDTH];
    let mut input_iter = fields.into_iter();
    let mut traces = Vec::new();

    'outer: loop {
        // Absorb up to POSEIDON2_RATE elements into state[0..POSEIDON2_RATE]
        let mut absorbed_count = 0;
        for i in 0..POSEIDON2_RATE {
            if let Some(x) = input_iter.next() {
                state[i] = x;
                absorbed_count += 1;
            } else {
                // No more input
                if absorbed_count > 0 {
                    // Generate trace for this final permutation
                    let input_state: [Val; POSEIDON2_WIDTH] = state;
                    traces
                        .push(generate_poseidon2_trace_row_with_constants(input_state, constants));
                    perm.permute_mut(&mut state);
                }
                break 'outer;
            }
        }

        // Generate trace for this permutation
        let input_state: [Val; POSEIDON2_WIDTH] = state;
        traces.push(generate_poseidon2_trace_row_with_constants(input_state, constants));
        perm.permute_mut(&mut state);
    }

    // Extract final output
    let mut output = [Val::ZERO; POSEIDON2_OUTPUT_SIZE];
    output.copy_from_slice(&state[..POSEIDON2_OUTPUT_SIZE]);

    (traces, output)
}

/// Generate hash trace for a single input with specified constants
fn generate_poseidon2_trace_row_with_constants(
    input: [Val; POSEIDON2_WIDTH],
    constants: &p3_poseidon2_air::RoundConstants<Val, 16, 4, 20>,
) -> Vec<Val> {
    use p3_baby_bear::GenericPoseidon2LinearLayersBabyBear;
    use p3_matrix::Matrix;
    use p3_poseidon2_air::generate_trace_rows;

    let trace = generate_trace_rows::<
        Val,
        GenericPoseidon2LinearLayersBabyBear,
        { POSEIDON2_WIDTH },
        POSEIDON2_SBOX_DEGREE,
        POSEIDON2_SBOX_REGISTERS,
        POSEIDON2_HALF_FULL_ROUNDS,
        POSEIDON2_PARTIAL_ROUNDS,
    >(vec![input], constants, 0);

    let row_slice = trace.row_slice(0).expect("Trace should have at least one row");
    row_slice.to_vec()
}

/// Copy traces into a row starting at the given offset
fn copy_traces_to_row(row: &mut [Val], traces: &[Vec<Val>], initial_offset: usize) {
    let mut offset = initial_offset;
    for trace in traces.iter() {
        if offset + trace.len() <= row.len() {
            row[offset..offset + trace.len()].copy_from_slice(trace);
            offset += trace.len();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use p3_matrix::Matrix;

    use super::*;
    use crate::global::commitment::compute_subtree_root;

    #[test]
    fn test_build_global_trace_empty() {
        let trace = build_global_trace(&[]).expect("Should build trace for empty subtrees");
        assert!(trace.height() > 0);
        assert!(trace.width() >= 8);
    }

    #[test]
    fn test_build_global_trace_single_subtree() {
        let mut commitments = BTreeMap::new();
        commitments.insert([1u8; 32], [2u8; 32]);
        let subtree = compute_subtree_root(&commitments, [1u8; 32], [1u8; 32])
            .expect("Should compute subtree");

        let trace = build_global_trace(&[subtree]).expect("Should build trace for single subtree");
        assert!(trace.height() > 0);
        assert!(trace.width() >= 8);
    }

    #[test]
    fn test_build_global_trace_multiple_subtrees() {
        let mut commitments1 = BTreeMap::new();
        commitments1.insert([1u8; 32], [2u8; 32]);
        let subtree1 = compute_subtree_root(&commitments1, [1u8; 32], [1u8; 32])
            .expect("Should compute subtree1");

        let mut commitments2 = BTreeMap::new();
        commitments2.insert([3u8; 32], [4u8; 32]);
        let subtree2 = compute_subtree_root(&commitments2, [3u8; 32], [3u8; 32])
            .expect("Should compute subtree2");

        let trace = build_global_trace(&[subtree1, subtree2])
            .expect("Should build trace for multiple subtrees");
        assert!(trace.height() > 0);
        assert!(trace.width() >= 8);
    }
}
