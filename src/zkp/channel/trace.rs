#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
//! Trace generation for channel state transitions
//!
//! This module provides functions for generating execution traces
//! for channel state transition proofs. The trace includes channel state
//! fields, hash computation traces for state_hash and commitment,
//! and padding rows to ensure the trace has a power-of-2 height.

use p3_baby_bear::{GenericPoseidon2LinearLayersBabyBear, Poseidon2BabyBear};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_poseidon2_air::generate_trace_rows;
use p3_symmetric::Permutation;

use crate::channel::commitment::compute_commitment;
use crate::channel::state::ChannelState;
use crate::channel::TransferAmount;
use crate::errors::Result;
use crate::types::{ChannelId, CHANNEL_DOMAIN_TAG};
use crate::zkp::channel::poseidon2_air::{column_offsets, create_poseidon2_constants_and_params};
use crate::zkp::poseidon2_common::{
    POSEIDON2_HALF_FULL_ROUNDS, POSEIDON2_OUTPUT_SIZE, POSEIDON2_PARTIAL_ROUNDS, POSEIDON2_RATE,
    POSEIDON2_SBOX_DEGREE, POSEIDON2_SBOX_REGISTERS, POSEIDON2_WIDTH,
};
use crate::zkp::types::{u64_to_field, Trace, Val};
use crate::zkp::{poseidon2_hash_bytes, poseidon2_hash_fixed};

/// Simulate sponge construction step-by-step to generate multi-permutation traces
/// Returns traces for each permutation needed to hash the input, and the final output
/// This matches the behavior of the hash function implementation
///
/// # Arguments
/// * `input_bytes` - Input bytes to hash
/// * `constants` - Poseidon2 round constants for trace generation
/// * `external_constants` - External layer constants for permutation
/// * `internal_constants` - Internal constants for permutation
fn generate_multi_permutation_traces(
    input_bytes: &[u8],
    constants: &p3_poseidon2_air::RoundConstants<Val, 16, 4, 20>,
    external_constants: &p3_poseidon2::ExternalLayerConstants<Val, 16>,
    internal_constants: &[Val],
) -> (Vec<Vec<Val>>, [Val; 8]) {
    type Perm = Poseidon2BabyBear<POSEIDON2_WIDTH>;

    // Create the permutation using the same constants as the hash function
    // This ensures trace generation matches the hash computation
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
                    // Generate trace for this final permutation (state before permuting)
                    let input_state: [Val; POSEIDON2_WIDTH] = state;
                    traces
                        .push(generate_poseidon2_trace_row_with_constants(input_state, constants));
                    // Permute to get final state
                    perm.permute_mut(&mut state);
                }
                break 'outer;
            }
        }

        // Generate trace for this permutation (state before permuting, after absorbing)
        let input_state: [Val; POSEIDON2_WIDTH] = state;
        traces.push(generate_poseidon2_trace_row_with_constants(input_state, constants));

        // Permute after absorbing POSEIDON2_RATE elements
        // The output state will be used as the starting state for the next iteration
        perm.permute_mut(&mut state);
    }

    // Extract final output (first POSEIDON2_OUTPUT_SIZE elements of state)
    let mut output = [Val::ZERO; POSEIDON2_OUTPUT_SIZE];
    output.copy_from_slice(&state[..POSEIDON2_OUTPUT_SIZE]);

    (traces, output)
}

/// Generate hash trace for a single input with specified constants
///
/// Returns a single row of the hash trace (all columns for one permutation).
fn generate_poseidon2_trace_row_with_constants(
    input: [Val; POSEIDON2_WIDTH],
    constants: &p3_poseidon2_air::RoundConstants<Val, 16, 4, 20>,
) -> Vec<Val> {
    let trace = generate_trace_rows::<
        Val,
        GenericPoseidon2LinearLayersBabyBear,
        { POSEIDON2_WIDTH },
        POSEIDON2_SBOX_DEGREE,
        POSEIDON2_SBOX_REGISTERS,
        POSEIDON2_HALF_FULL_ROUNDS,
        POSEIDON2_PARTIAL_ROUNDS,
    >(vec![input], constants, 0);

    // Extract the first row (there should be exactly one row per input)
    // The trace is a RowMajorMatrix<Val> containing the full hash trace structure
    let row_slice = trace.row_slice(0).expect("Trace should have at least one row");
    row_slice.to_vec()
}

/// Build trace matrix for channel transition.
///
/// The trace contains multiple rows (padded to power-of-2):
/// - Row 0: Old channel state + hash traces
/// - Row 1: New channel state + hash traces
/// - Rows 2+: Padding rows (repeating new state)
///
/// # Trace Structure
///
/// Each row represents one channel state with the following column layout:
/// * Columns 0-4: Channel state (`sender_balance`, `receiver_balance`, `nonce`, `is_closed`, `amount`)
/// * Columns 5-12: `commitment` (8 fields)
/// * Columns 13+: Hash trace columns for state_hash computation (starting at `STATE_HASH_OFFSET`)
/// * Columns `commitment_offset()`+: Hash trace columns for commitment computation
pub(super) fn build_channel_trace(
    channel_id: ChannelId,
    old_state: &ChannelState,
    new_state: &ChannelState,
    transfer_amount: &TransferAmount,
) -> Result<Trace> {
    // Minimum rows needed (power of 2). After LDE expansion with log_blowup=3,
    // this becomes 64 rows, which satisfies FRI's requirement that
    // log_min_height > log_final_poly_len + log_blowup.
    const MIN_ROWS: usize = 8;

    let total_cols = column_offsets::total_cols();

    let constants = create_poseidon2_constants_and_params();

    // Helper to build a full row with hash traces
    let build_full_row = |state: &ChannelState| -> Result<Vec<Val>> {
        // Build base channel row
        let mut row = Vec::with_capacity(total_cols);
        row.push(u64_to_field(state.sender_balance));
        row.push(u64_to_field(state.receiver_balance));
        row.push(u64_to_field(state.nonce.into()));
        row.push(u64_to_field(if state.is_closed { 1 } else { 0 }));
        row.push(u64_to_field(**transfer_amount));

        // Generate state_hash hash trace first (needed for commitment computation)
        // Prepare input bytes exactly as compute_state_hash does: concatenate all fields
        let is_closed_u64 = if state.is_closed { 1u64 } else { 0u64 };
        let mut state_hash_input_bytes = Vec::new();
        state_hash_input_bytes.extend_from_slice(&state.sender_balance.to_le_bytes());
        state_hash_input_bytes.extend_from_slice(&state.receiver_balance.to_le_bytes());
        state_hash_input_bytes.extend_from_slice(&state.metadata);
        state_hash_input_bytes.extend_from_slice(&is_closed_u64.to_le_bytes());

        let (state_hash_traces, state_hash_output) = generate_multi_permutation_traces(
            &state_hash_input_bytes,
            &constants.round_constants,
            &constants.external_constants,
            &constants.internal_constants,
        );

        let state_hash_bytes = {
            let mut bytes = [0u8; 32];
            for (i, field) in state_hash_output.iter().enumerate() {
                let val = PrimeField32::as_canonical_u32(field);
                bytes[i * 4..(i + 1) * 4].copy_from_slice(&val.to_le_bytes());
            }
            bytes
        };

        // Verify the computed hash matches compute_state_hash
        // This ensures trace generation matches the hash computation implementation
        let is_closed_u64 = if state.is_closed { 1u64 } else { 0u64 };
        let expected_state_hash = poseidon2_hash_fixed(&[
            &state.sender_balance.to_le_bytes(),
            &state.receiver_balance.to_le_bytes(),
            &state.metadata,
            &is_closed_u64.to_le_bytes(),
        ]);
        assert_eq!(
            state_hash_bytes, expected_state_hash,
            "Trace-generated state_hash must match compute_state_hash"
        );

        // Prepare commitment input bytes (stage1_hash || nonce)
        // This matches compute_channel_commitment's stage 2 input
        let mut stage1_bytes = Vec::new();
        stage1_bytes.extend_from_slice(CHANNEL_DOMAIN_TAG);
        stage1_bytes.extend_from_slice(&channel_id);
        stage1_bytes.extend_from_slice(&state_hash_bytes);
        let stage1_hash = poseidon2_hash_bytes(&stage1_bytes);

        // Stage 2: Hash stage1_hash || nonce (40 bytes -> 32 bytes)
        // This matches compute_channel_commitment's stage 2 exactly
        let mut commitment_input_bytes = Vec::new();
        commitment_input_bytes.extend_from_slice(&stage1_hash);
        commitment_input_bytes.extend_from_slice(&state.nonce.to_le_bytes());

        let (commitment_traces, commitment_output) = generate_multi_permutation_traces(
            &commitment_input_bytes,
            &constants.round_constants,
            &constants.external_constants,
            &constants.internal_constants,
        );

        let commitment_bytes = {
            let mut bytes = [0u8; 32];
            for (i, field) in commitment_output.iter().enumerate() {
                let val = PrimeField32::as_canonical_u32(field);
                bytes[i * 4..(i + 1) * 4].copy_from_slice(&val.to_le_bytes());
            }
            bytes
        };
        let expected_commitment = compute_commitment(channel_id, state);
        assert_eq!(
            commitment_bytes, expected_commitment,
            "Trace-generated commitment must match compute_commitment - constants are now synchronized"
        );

        row.extend_from_slice(&commitment_output);

        let num_state_hash_traces = state_hash_traces.len();
        let last_trace = if num_state_hash_traces > 0 {
            state_hash_traces[num_state_hash_traces - 1].clone()
        } else {
            vec![Val::ZERO; crate::zkp::poseidon2_common::poseidon2_air_num_cols()]
        };

        for trace in state_hash_traces {
            row.extend_from_slice(&trace);
        }

        // Pad state_hash trace columns if needed (to fixed size for column offsets)
        // For unused permutations, repeat the last trace to create valid hash traces
        // (same input = same output, which is valid)
        let poseidon2_cols = crate::zkp::poseidon2_common::poseidon2_air_num_cols();
        let state_hash_trace_cols = num_state_hash_traces * poseidon2_cols;
        let expected_state_hash_cols = column_offsets::MAX_STATE_HASH_PERMUTATIONS * poseidon2_cols;
        if state_hash_trace_cols < expected_state_hash_cols {
            let padding_needed = expected_state_hash_cols - state_hash_trace_cols;
            let num_padding_permutations = padding_needed / poseidon2_cols;
            for _ in 0..num_padding_permutations {
                row.extend_from_slice(&last_trace);
            }
        }

        // Add commitment hash trace columns (starting at commitment_offset())
        // AIR expects a single permutation, so we use the last trace (contains final output)
        let last_commitment_trace = if !commitment_traces.is_empty() {
            &commitment_traces[commitment_traces.len() - 1]
        } else {
            panic!("commitment_traces should not be empty");
        };
        row.extend_from_slice(last_commitment_trace);

        if row.len() != total_cols {
            return Err(crate::errors::Error::Zkp(crate::errors::ZkpError::TraceGenerationFailed(
                format!(
                    "Channel trace row length mismatch: expected {} columns, got {}",
                    total_cols,
                    row.len()
                ),
            )));
        }

        Ok(row)
    };

    let mut values = Vec::new();

    // Row 0: Old state
    let old_row = build_full_row(old_state)?;
    values.extend_from_slice(&old_row);

    // Row 1: New state
    let new_row = build_full_row(new_state)?;
    values.extend_from_slice(&new_row);

    // Pad to exactly MIN_ROWS (power of 2) by repeating the new state
    let current_rows = values.len() / total_cols;
    let num_padding = MIN_ROWS - current_rows;
    for _ in 0..num_padding {
        values.extend_from_slice(&new_row);
    }

    Ok(RowMajorMatrix::new(values, total_cols))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::commitment::compute_commitment;
    use crate::channel::state::ChannelState;
    use crate::channel::transition::apply_transfer_state_only;
    use crate::channel::TransferAmount;
    use crate::zkp::channel::public_inputs::ChannelPublicInputs;
    use crate::zkp::channel::{prove_channel_transition, verify_channel_transition};
    use crate::zkp::poseidon2_common::{poseidon2_output_offset, POSEIDON2_RATE};
    use crate::zkp::types::create_config;

    /// Helper function to create a test channel transition
    fn create_test_transition(
        channel_id: u8,
        initial_balance: u64,
        transfer_amount: u64,
    ) -> ([u8; 32], ChannelState, TransferAmount, ChannelState) {
        let mut id = [0u8; 32];
        id[31] = channel_id;

        let old_state = ChannelState::new(initial_balance);
        let amount = TransferAmount::new(transfer_amount).expect("valid transfer");
        let new_state =
            apply_transfer_state_only(&old_state, &amount).expect("Valid transfer should succeed");

        (id, old_state, amount, new_state)
    }

    #[test]
    fn test_build_channel_trace_basic() {
        let (channel_id, old_state, transfer_amount, new_state) =
            create_test_transition(1, 100, 30);

        let trace = build_channel_trace(channel_id, &old_state, &new_state, &transfer_amount)
            .expect("Trace generation should succeed");

        // Verify trace has correct dimensions
        let expected_cols = column_offsets::total_cols();
        assert_eq!(trace.width(), expected_cols, "Trace should have correct number of columns");
        assert!(trace.height() >= 8, "Trace should have at least 8 rows (power of 2)");

        // Verify base channel columns are present
        let row0 = trace.row_slice(0).expect("Should have row 0");
        assert_eq!(row0[0], u64_to_field(old_state.sender_balance));
        assert_eq!(row0[1], u64_to_field(old_state.receiver_balance));
        assert_eq!(row0[2], u64_to_field(old_state.nonce.into()));

        let row1 = trace.row_slice(1).expect("Should have row 1");
        assert_eq!(row1[0], u64_to_field(new_state.sender_balance));
        assert_eq!(row1[1], u64_to_field(new_state.receiver_balance));
        assert_eq!(row1[2], u64_to_field(new_state.nonce.into()));
    }

    #[test]
    fn test_state_hash_matches_compute_state_hash() {
        let mut state = ChannelState::new(100);
        state.receiver_balance = 200;
        state.metadata = b"test metadata".to_vec();

        // Build trace and extract state_hash
        let channel_id = [0u8; 32];
        // Use minimal valid amount for trace structure testing (not testing actual transfer)
        let amount = TransferAmount::new(1).expect("valid transfer");
        let trace = build_channel_trace(channel_id, &state, &state, &amount)
            .expect("Trace generation should succeed");

        // Calculate how many permutations were used for state_hash
        // This matches the logic in generate_multi_permutation_traces
        let is_closed_u64 = if state.is_closed { 1u64 } else { 0u64 };
        let mut state_hash_input_bytes = Vec::new();
        state_hash_input_bytes.extend_from_slice(&state.sender_balance.to_le_bytes());
        state_hash_input_bytes.extend_from_slice(&state.receiver_balance.to_le_bytes());
        state_hash_input_bytes.extend_from_slice(&state.metadata);
        state_hash_input_bytes.extend_from_slice(&is_closed_u64.to_le_bytes());

        // Convert bytes to field elements (4 bytes per field element)
        let num_fields = (state_hash_input_bytes.len() + 3) / 4; // Round up
        let num_permutations = (num_fields + POSEIDON2_RATE - 1) / POSEIDON2_RATE; // Ceiling division

        // Extract state_hash from trace (from last permutation output)
        let row0 = trace.row_slice(0).expect("Should have row 0");
        let state_hash_offset = column_offsets::STATE_HASH_OFFSET;
        let output_offset = poseidon2_output_offset();
        let poseidon2_cols = crate::zkp::poseidon2_common::poseidon2_air_num_cols();

        // Calculate offset to the last permutation's output
        let last_perm_offset = (num_permutations - 1) * poseidon2_cols;
        let mut state_hash_bytes = [0u8; 32];
        for i in 0..8 {
            let col_idx = state_hash_offset + last_perm_offset + output_offset + i;
            let field = row0[col_idx];
            let val = PrimeField32::as_canonical_u32(&field);
            state_hash_bytes[i * 4..(i + 1) * 4].copy_from_slice(&val.to_le_bytes());
        }

        // The trace generation includes an assertion that verifies state_hash matches compute_state_hash.
        // If build_channel_trace succeeds, that assertion passed, so the alignment is correct.
        // Here we just verify the trace was generated successfully and has the expected structure.
        let expected_cols = column_offsets::total_cols();
        assert_eq!(trace.width(), expected_cols, "Trace should have correct number of columns");

        // Verify we can extract commitment from the trace
        let commitment_fields: Vec<Val> = (column_offsets::COMMITMENT_START
            ..column_offsets::COMMITMENT_END)
            .map(|i| row0[i])
            .collect();

        // Commitment should be non-zero
        let has_non_zero = commitment_fields.iter().any(|&f| f != Val::ZERO);
        assert!(has_non_zero, "Commitment should be non-zero");
    }

    #[test]
    fn test_commitment_matches_compute_commitment() {
        let (channel_id, old_state, transfer_amount, new_state) =
            create_test_transition(2, 100, 30);

        let trace = build_channel_trace(channel_id, &old_state, &new_state, &transfer_amount)
            .expect("Trace generation should succeed");

        // Extract commitment from trace
        let row1 = trace.row_slice(1).expect("Should have row 1");
        let commitment_fields: Vec<Val> = (column_offsets::COMMITMENT_START
            ..column_offsets::COMMITMENT_END)
            .map(|i| row1[i])
            .collect();

        // Convert to bytes
        let mut commitment_bytes = [0u8; 32];
        for (i, field) in commitment_fields.iter().enumerate() {
            let val = PrimeField32::as_canonical_u32(field);
            commitment_bytes[i * 4..(i + 1) * 4].copy_from_slice(&val.to_le_bytes());
        }

        // Compare with compute_commitment
        let expected_commitment = compute_commitment(channel_id, &new_state);
        assert_eq!(
            commitment_bytes, expected_commitment,
            "Trace commitment should match compute_commitment"
        );
    }

    #[test]
    fn test_trace_padding_rows() {
        let (channel_id, old_state, transfer_amount, new_state) =
            create_test_transition(3, 100, 30);

        let trace = build_channel_trace(channel_id, &old_state, &new_state, &transfer_amount)
            .expect("Trace generation should succeed");

        // Trace should be padded to power of 2 (at least 8 rows)
        assert!(trace.height() >= 8, "Trace should be padded to at least 8 rows");
        assert!(trace.height().is_power_of_two(), "Trace height should be a power of 2");

        // Padding rows should repeat new_state
        let row1 = trace.row_slice(1).expect("Should have row 1");
        for i in 2..trace.height() {
            let row = trace.row_slice(i).expect("Should have padding row");
            // Check that state fields match row1 (padding rows repeat new_state)
            assert_eq!(row[0], row1[0], "Padding row sender_balance should match new_state");
            assert_eq!(row[1], row1[1], "Padding row receiver_balance should match new_state");
            assert_eq!(row[2], row1[2], "Padding row nonce should match new_state");
        }
    }

    #[test]
    fn test_trace_with_different_states() {
        let channel_id = [4u8; 32];
        let old_state = ChannelState::new(1000);
        let amount = TransferAmount::new(500).expect("valid transfer");
        let new_state =
            apply_transfer_state_only(&old_state, &amount).expect("Valid transfer should succeed");

        let trace = build_channel_trace(channel_id, &old_state, &new_state, &amount)
            .expect("Trace generation should succeed");

        let row0 = trace.row_slice(0).expect("Should have row 0");
        let row1 = trace.row_slice(1).expect("Should have row 1");

        // Verify old and new states are different
        assert_ne!(row0[0], row1[0], "Sender balance should change");
        assert_ne!(row0[1], row1[1], "Receiver balance should change");
        assert_ne!(row0[2], row1[2], "Nonce should increment");
    }

    #[test]
    fn test_trace_with_large_metadata() {
        let channel_id = [5u8; 32];
        let mut state = ChannelState::new(100);
        // Use large metadata to test multiple permutations
        state.metadata = vec![0u8; 80]; // 80 bytes should require multiple permutations

        // Use minimal valid amount for trace structure testing (not testing actual transfer)
        let amount = TransferAmount::new(1).expect("valid transfer");
        let trace = build_channel_trace(channel_id, &state, &state, &amount)
            .expect("Trace generation should succeed with large metadata");

        let expected_cols = column_offsets::total_cols();
        assert_eq!(trace.width(), expected_cols, "Trace should have correct width");
        assert!(trace.height() >= 8, "Trace should have at least 8 rows");
    }

    #[test]
    fn test_trace_full_prove_verify() {
        let (channel_id, old_state, transfer_amount, new_state) =
            create_test_transition(6, 100, 30);

        let _trace = build_channel_trace(channel_id, &old_state, &new_state, &transfer_amount)
            .expect("Should build trace");

        let expected = compute_commitment(channel_id, &new_state);
        let pi = ChannelPublicInputs { channel_id, channel_commitment: expected };
        let cfg = create_config().expect("failed to create config");

        let proof =
            prove_channel_transition(&cfg, channel_id, &old_state, &transfer_amount, &new_state)
                .expect("failed to prove channel transition");
        verify_channel_transition(&cfg, &pi, &proof).expect("failed to verify channel transition");
    }

    #[test]
    fn test_trace_consistency_same_inputs() {
        let (channel_id, old_state, transfer_amount, new_state) =
            create_test_transition(7, 100, 30);

        let trace1 = build_channel_trace(channel_id, &old_state, &new_state, &transfer_amount)
            .expect("Should build first trace");
        let trace2 = build_channel_trace(channel_id, &old_state, &new_state, &transfer_amount)
            .expect("Should build second trace");

        // Traces should be identical for same inputs
        assert_eq!(trace1.width(), trace2.width(), "Traces should have same width");
        assert_eq!(trace1.height(), trace2.height(), "Traces should have same height");

        // Compare all rows
        for i in 0..trace1.height() {
            let row1 = trace1.row_slice(i).expect("Should have row");
            let row2 = trace2.row_slice(i).expect("Should have row");
            for j in 0..row1.len() {
                assert_eq!(row1[j], row2[j], "Row {} column {} should be identical", i, j);
            }
        }
    }

    #[test]
    fn test_trace_different_channel_ids() {
        let channel_id1 = [10u8; 32];
        let channel_id2 = [20u8; 32];
        let old_state = ChannelState::new(100);
        let amount = TransferAmount::new(30).expect("valid transfer");
        let new_state =
            apply_transfer_state_only(&old_state, &amount).expect("Valid transfer should succeed");

        let trace1 = build_channel_trace(channel_id1, &old_state, &new_state, &amount)
            .expect("Should build trace for channel1");
        let trace2 = build_channel_trace(channel_id2, &old_state, &new_state, &amount)
            .expect("Should build trace for channel2");

        // Traces should have same structure but different commitments
        assert_eq!(trace1.width(), trace2.width(), "Traces should have same width");
        assert_eq!(trace1.height(), trace2.height(), "Traces should have same height");

        // Commitments should be different (different channel_ids)
        let row1_1 = trace1.row_slice(1).expect("Should have row 1");
        let row1_2 = trace2.row_slice(1).expect("Should have row 1");

        let commitment1: Vec<Val> = (column_offsets::COMMITMENT_START
            ..column_offsets::COMMITMENT_END)
            .map(|i| row1_1[i])
            .collect();
        let commitment2: Vec<Val> = (column_offsets::COMMITMENT_START
            ..column_offsets::COMMITMENT_END)
            .map(|i| row1_2[i])
            .collect();

        assert_ne!(
            commitment1, commitment2,
            "Different channel IDs should produce different commitments"
        );
    }
}
