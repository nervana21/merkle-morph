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

use crate::channel::commitment::state_commitment::compute_open_commitment;
use crate::channel::state::Open;
use crate::channel::TransferAmount;
use crate::types::{ChannelId, CHANNEL_DOMAIN_TAG};
use crate::zkp::channel::poseidon2_air::{column_offsets, create_poseidon2_constants_and_params};
use crate::zkp::poseidon2_common::{
    POSEIDON2_HALF_FULL_ROUNDS, POSEIDON2_OUTPUT_SIZE, POSEIDON2_PARTIAL_ROUNDS, POSEIDON2_RATE,
    POSEIDON2_SBOX_DEGREE, POSEIDON2_SBOX_REGISTERS, POSEIDON2_WIDTH,
};
use crate::zkp::types::{u64_to_field, Trace, Val};
use crate::zkp::{poseidon2_hash_bytes, poseidon2_hash_fixed};
use crate::Result;

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
/// * Columns 13-20: `auth_hash` (8 fields for sender authentication hash)
/// * Columns 21+: Hash trace columns for state_hash computation (starting at `STATE_HASH_OFFSET`)
/// * Columns `commitment_offset()`+: Hash trace columns for commitment computation
///
/// # Arguments
/// * `channel_id` - Channel identifier
/// * `old_state` - Previous channel state
/// * `new_state` - New channel state after transition
/// * `transfer_amount` - Transfer amount that caused the transition
/// * `sender_sk` - Sender's private key for computing authentication hash
pub(super) fn build_channel_trace(
    channel_id: ChannelId,
    old_state: &Open,
    new_state: &Open,
    transfer_amount: &TransferAmount,
    sender_sk: &bitcoin::secp256k1::SecretKey,
) -> Result<Trace> {
    // Minimum rows needed (power of 2). After LDE expansion with log_blowup=3,
    // this becomes 64 rows, which satisfies FRI's requirement that
    // log_min_height > log_final_poly_len + log_blowup.
    const MIN_ROWS: usize = 8;

    let total_cols = column_offsets::total_cols();

    let constants = create_poseidon2_constants_and_params();

    // Helper to build a full row with hash traces
    let build_full_row = |state: &Open| -> Result<Vec<Val>> {
        // Build base channel row
        let mut row = Vec::with_capacity(total_cols);
        row.push(u64_to_field(state.sender_balance));
        row.push(u64_to_field(state.receiver_balance));
        row.push(u64_to_field(state.nonce.into()));
        row.push(u64_to_field(0u64));
        row.push(u64_to_field(**transfer_amount));

        // Generate state_hash hash trace first (needed for commitment computation)
        let is_closed_u64 = 0u64;
        let mut sender_pubkey_le = state.sender_pubkey.serialize();
        sender_pubkey_le.reverse();
        let mut receiver_pubkey_le = state.receiver_pubkey.serialize();
        receiver_pubkey_le.reverse();
        let mut state_hash_input_bytes = Vec::new();
        state_hash_input_bytes.extend_from_slice(&state.sender_balance.to_le_bytes());
        state_hash_input_bytes.extend_from_slice(&state.receiver_balance.to_le_bytes());
        state_hash_input_bytes.extend_from_slice(&sender_pubkey_le);
        state_hash_input_bytes.extend_from_slice(&receiver_pubkey_le);
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
        let is_closed_u64 = 0u64;
        let mut sender_pubkey_le_expected = state.sender_pubkey.serialize();
        sender_pubkey_le_expected.reverse();
        let mut receiver_pubkey_le_expected = state.receiver_pubkey.serialize();
        receiver_pubkey_le_expected.reverse();
        let expected_state_hash = poseidon2_hash_fixed(&[
            &state.sender_balance.to_le_bytes(),
            &state.receiver_balance.to_le_bytes(),
            &sender_pubkey_le_expected,
            &receiver_pubkey_le_expected,
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
        let expected_commitment = compute_open_commitment(channel_id, state);
        assert_eq!(
            commitment_bytes, expected_commitment,
            "Trace-generated commitment must match compute_commitment - constants are now synchronized"
        );

        row.extend_from_slice(&commitment_output);

        // Compute auth_hash = poseidon2(channel_id || nonce || commitment || sender_sk_bytes)
        // This cryptographically binds the commitment to the sender's private key
        // Ordering: context (channel_id) → state (nonce) → data (commitment) → secret (sender_sk_bytes)
        let sender_sk_bytes = sender_sk.secret_bytes();
        let mut auth_hash_input = Vec::new();
        auth_hash_input.extend_from_slice(&channel_id);
        auth_hash_input.extend_from_slice(&state.nonce.to_le_bytes());
        auth_hash_input.extend_from_slice(&commitment_bytes);
        auth_hash_input.extend_from_slice(&sender_sk_bytes);
        let auth_hash = poseidon2_hash_bytes(&auth_hash_input);

        // Convert auth_hash to field elements and add to row
        let auth_hash_fields: Vec<Val> = (0..8)
            .map(|i| {
                let bytes = &auth_hash[i * 4..(i + 1) * 4];
                let u32_val = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                Val::new(u32_val)
            })
            .collect();
        row.extend_from_slice(&auth_hash_fields);

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
            return Err(crate::Error::Zkp(crate::errors::ZkpError::TraceGenerationFailed(
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
    use bitcoin::secp256k1::SecretKey;

    use super::*;
    use crate::channel::state::Open;
    use crate::channel::test_utils::test_keys;
    use crate::channel::TransferAmount;

    #[test]
    fn test_build_channel_trace() {
        let (sender_pubkey, receiver_pubkey) = test_keys();
        let sender_revocation_secret =
            SecretKey::from_slice(&[3u8; 32]).expect("Failed to create sender revocation secret");
        let receiver_revocation_secret =
            SecretKey::from_slice(&[4u8; 32]).expect("Failed to create receiver revocation secret");
        let mut old_state = Open::new(
            sender_pubkey,
            receiver_pubkey,
            100,
            sender_revocation_secret,
            receiver_revocation_secret,
        );
        old_state.metadata = vec![];
        old_state.nonce = 0;
        let mut new_state = old_state.clone();
        new_state.sender_balance = 90;
        new_state.receiver_balance = 10;
        new_state.metadata = vec![];
        new_state.nonce = 1;
        let transfer_amount = TransferAmount::new(10).expect("non-zero transfer amount");
        let channel_id = [0u8; 32];
        let sender_sk =
            SecretKey::from_slice(&[1u8; 32]).expect("32-byte array should always be valid");

        let trace =
            build_channel_trace(channel_id, &old_state, &new_state, &transfer_amount, &sender_sk)
                .expect("trace generation should succeed");

        assert_eq!(trace.height(), 8);
        assert_eq!(trace.width(), column_offsets::total_cols());
    }
}
