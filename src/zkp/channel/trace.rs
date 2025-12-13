// SPDX-License-Identifier: CC0-1.0

//! Execution trace generation for channel state transition proofs
//!
//! This module generates execution traces that serve as witness data for zero-knowledge
//! proofs of channel state transitions. These traces enable the prover to demonstrate
//! that a channel state transition is valid (e.g., balances are conserved, commitments
//! are correctly computed) without revealing sensitive information like private keys.
//!
//! The traces are consumed by the STARK proof system to generate proofs that can be
//! verified by anyone, enabling trustless verification of payment channel operations.

use p3_baby_bear::{GenericPoseidon2LinearLayersBabyBear, Poseidon2BabyBear};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_poseidon2_air::generate_trace_rows;
use p3_symmetric::Permutation;

use crate::channel::commitment::state_commitment::compute_channel_commitment;
use crate::channel::state::{Closed, CooperativeClosing, ForceClosingPending, Open};
use crate::types::{ChannelId, CHANNEL_DOMAIN_TAG};
use crate::zkp::channel::poseidon2_air::{column_offsets, create_poseidon2_constants_and_params};
use crate::zkp::poseidon2_common::{
    poseidon2_air_num_cols, POSEIDON2_HALF_FULL_ROUNDS, POSEIDON2_OUTPUT_SIZE,
    POSEIDON2_PARTIAL_ROUNDS, POSEIDON2_RATE, POSEIDON2_SBOX_DEGREE, POSEIDON2_SBOX_REGISTERS,
    POSEIDON2_WIDTH,
};
use crate::zkp::types::{u64_to_field, Trace, Val, BYTES_PER_U32};
use crate::zkp::{poseidon2_hash_bytes, poseidon2_hash_fixed};
use crate::{Result, TransferAmount};

/// Simulate sponge construction step-by-step to generate multi-permutation traces
/// Returns traces for each permutation needed to hash the input, and the final output
///
/// # Arguments
/// * `input_bytes` - Input bytes to hash
/// * `constants` - Poseidon2 round constants for trace generation
/// * `external_constants` - External layer constants for permutation
/// * `internal_constants` - Internal constants for permutation
fn generate_multi_permutation_traces(
    input_bytes: &[u8],
    constants: &p3_poseidon2_air::RoundConstants<
        Val,
        POSEIDON2_WIDTH,
        POSEIDON2_HALF_FULL_ROUNDS,
        POSEIDON2_PARTIAL_ROUNDS,
    >,
    external_constants: &p3_poseidon2::ExternalLayerConstants<Val, POSEIDON2_WIDTH>,
    internal_constants: &[Val],
) -> (Vec<Vec<Val>>, [Val; POSEIDON2_OUTPUT_SIZE]) {
    type Perm = Poseidon2BabyBear<POSEIDON2_WIDTH>;

    let perm = Perm::new(external_constants.clone(), internal_constants.to_vec());

    // Convert bytes to field elements
    let mut fields = Vec::new();
    for chunk in input_bytes.chunks(BYTES_PER_U32) {
        let mut arr = [0u8; BYTES_PER_U32];
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
    constants: &p3_poseidon2_air::RoundConstants<
        Val,
        POSEIDON2_WIDTH,
        POSEIDON2_HALF_FULL_ROUNDS,
        POSEIDON2_PARTIAL_ROUNDS,
    >,
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

/// Build base state fields (first 5 columns of a trace row)
fn build_base_state_fields(
    nonce: u32,
    is_closed: bool,
    sender_balance: u64,
    receiver_balance: u64,
    amount: u64,
) -> Vec<Val> {
    vec![
        u64_to_field(nonce.into()),
        u64_to_field(if is_closed { 1u64 } else { 0u64 }),
        u64_to_field(sender_balance),
        u64_to_field(receiver_balance),
        u64_to_field(amount),
    ]
}

/// Compute state hash with traces
///
/// Returns (traces, field output, byte representation)
fn compute_state_hash_with_traces(
    sender_balance: u64,
    receiver_balance: u64,
    sender_pubkey: &bitcoin::secp256k1::XOnlyPublicKey,
    receiver_pubkey: &bitcoin::secp256k1::XOnlyPublicKey,
    metadata: Option<&[u8]>,
    is_closed: bool,
    constants: &crate::zkp::poseidon2_common::Poseidon2Constants,
) -> (Vec<Vec<Val>>, [Val; POSEIDON2_OUTPUT_SIZE], [u8; 32]) {
    let is_closed_u64 = if is_closed { 1u64 } else { 0u64 };
    let mut sender_pubkey_le = sender_pubkey.serialize();
    sender_pubkey_le.reverse();
    let mut receiver_pubkey_le = receiver_pubkey.serialize();
    receiver_pubkey_le.reverse();
    let mut state_hash_input_bytes = Vec::new();
    state_hash_input_bytes.extend_from_slice(&sender_balance.to_le_bytes());
    state_hash_input_bytes.extend_from_slice(&receiver_balance.to_le_bytes());
    state_hash_input_bytes.extend_from_slice(&sender_pubkey_le);
    state_hash_input_bytes.extend_from_slice(&receiver_pubkey_le);
    state_hash_input_bytes.extend_from_slice(metadata.unwrap_or(&[]));
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
            bytes[i * BYTES_PER_U32..(i + 1) * BYTES_PER_U32].copy_from_slice(&val.to_le_bytes());
        }
        bytes
    };

    (state_hash_traces, state_hash_output, state_hash_bytes)
}

/// Compute commitment with traces
///
/// Returns (traces, field output, byte representation)
fn compute_commitment_with_traces(
    channel_id: ChannelId,
    state_hash_bytes: &[u8; 32],
    nonce: u32,
    constants: &crate::zkp::poseidon2_common::Poseidon2Constants,
) -> (Vec<Vec<Val>>, [Val; POSEIDON2_OUTPUT_SIZE], [u8; 32]) {
    // Prepare commitment input bytes (stage1_hash || nonce)
    let mut stage1_bytes = Vec::new();
    stage1_bytes.extend_from_slice(CHANNEL_DOMAIN_TAG);
    stage1_bytes.extend_from_slice(&channel_id);
    stage1_bytes.extend_from_slice(state_hash_bytes);
    let stage1_hash = poseidon2_hash_bytes(&stage1_bytes);

    // Hash stage1_hash || nonce (40 bytes -> 32 bytes)
    let mut commitment_input_bytes = Vec::new();
    commitment_input_bytes.extend_from_slice(&stage1_hash);
    commitment_input_bytes.extend_from_slice(&nonce.to_le_bytes());

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
            bytes[i * BYTES_PER_U32..(i + 1) * BYTES_PER_U32].copy_from_slice(&val.to_le_bytes());
        }
        bytes
    };

    (commitment_traces, commitment_output, commitment_bytes)
}

/// Add state hash traces with padding to the row
fn add_state_hash_traces_with_padding(row: &mut Vec<Val>, state_hash_traces: &[Vec<Val>]) {
    let num_state_hash_traces = state_hash_traces.len();
    let last_trace = if num_state_hash_traces > 0 {
        state_hash_traces[num_state_hash_traces - 1].clone()
    } else {
        vec![Val::ZERO; poseidon2_air_num_cols()]
    };

    for trace in state_hash_traces {
        row.extend_from_slice(trace);
    }

    // Pad state_hash trace columns if needed (to fixed size for column offsets)
    // For unused permutations, repeat the last trace to create valid hash traces
    // (same input = same output, which is valid)
    let poseidon2_cols = poseidon2_air_num_cols();
    let state_hash_trace_cols = num_state_hash_traces * poseidon2_cols;
    let expected_state_hash_cols = column_offsets::MAX_STATE_HASH_PERMUTATIONS * poseidon2_cols;
    if state_hash_trace_cols < expected_state_hash_cols {
        let padding_needed = expected_state_hash_cols - state_hash_trace_cols;
        let num_padding_permutations = padding_needed / poseidon2_cols;
        for _ in 0..num_padding_permutations {
            row.extend_from_slice(&last_trace);
        }
    }
}

/// Add commitment and its traces to the row
fn add_commitment_and_traces(
    row: &mut Vec<Val>,
    commitment_traces: &[Vec<Val>],
    commitment_output: &[Val; POSEIDON2_OUTPUT_SIZE],
) {
    // Add commitment (computed from state_hash + nonce)
    row.extend_from_slice(commitment_output);

    // Add commitment hash trace columns (immediately after commitment)
    // AIR expects a single permutation, so we use the last trace (contains final output)
    let last_commitment_trace = if !commitment_traces.is_empty() {
        &commitment_traces[commitment_traces.len() - 1]
    } else {
        panic!("commitment_traces should not be empty");
    };
    row.extend_from_slice(last_commitment_trace);
}

/// Compute auth hash fields
///
/// Returns either computed hash fields or zeros based on whether sender_sk is provided
fn compute_auth_hash_fields(
    channel_id: ChannelId,
    nonce: u32,
    commitment_bytes: &[u8; 32],
    sender_sk: Option<&bitcoin::secp256k1::SecretKey>,
) -> Vec<Val> {
    if let Some(sk) = sender_sk {
        // Compute auth_hash = poseidon2(channel_id || nonce || commitment || sender_sk_bytes)
        // This cryptographically binds the commitment to the sender's private key
        // Ordering: context (channel_id) → state (nonce) → data (commitment) → secret (sender_sk_bytes)
        let sender_sk_bytes = sk.to_secret_bytes();
        let mut auth_hash_input = Vec::new();
        auth_hash_input.extend_from_slice(&channel_id);
        auth_hash_input.extend_from_slice(&nonce.to_le_bytes());
        auth_hash_input.extend_from_slice(commitment_bytes);
        auth_hash_input.extend_from_slice(&sender_sk_bytes);
        let auth_hash = poseidon2_hash_bytes(&auth_hash_input);

        // Convert auth_hash to field elements
        (0..8)
            .map(|i| {
                let bytes = &auth_hash[i * BYTES_PER_U32..(i + 1) * BYTES_PER_U32];
                let u32_val = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                Val::new(u32_val)
            })
            .collect()
    } else {
        vec![Val::ZERO; 8]
    }
}

/// Build trace matrix from old and new rows
///
/// Pads to MIN_ROWS (8) by repeating the new state
fn build_trace_matrix(old_row: Vec<Val>, new_row: Vec<Val>, total_cols: usize) -> Trace {
    const MIN_ROWS: usize = 8;

    let mut values = Vec::new();
    values.extend_from_slice(&old_row);
    values.extend_from_slice(&new_row);

    // Pad to exactly MIN_ROWS (power of 2) by repeating the new state
    let current_rows = values.len() / total_cols;
    let num_padding = MIN_ROWS - current_rows;
    for _ in 0..num_padding {
        values.extend_from_slice(&new_row);
    }

    RowMajorMatrix::new(values, total_cols)
}

/// State information for building a trace row
struct StateInfo<'a> {
    nonce: u32,
    is_closed: bool,
    sender_balance: u64,
    receiver_balance: u64,
    sender_pubkey: &'a bitcoin::secp256k1::XOnlyPublicKey,
    receiver_pubkey: &'a bitcoin::secp256k1::XOnlyPublicKey,
    metadata: Option<&'a [u8]>,
}

/// Context information for building a trace row
struct TraceContext {
    channel_id: ChannelId,
    amount: u64,
    sender_sk: Option<bitcoin::secp256k1::SecretKey>,
}

/// Build a complete state row for the trace
///
/// This is the unified row builder that orchestrates all helper functions.
/// It handles state hash computation, commitment computation, trace generation,
/// and auth hash computation.
#[allow(clippy::too_many_arguments)]
fn build_state_row<F>(
    state: StateInfo<'_>,
    context: TraceContext,
    constants: &crate::zkp::poseidon2_common::Poseidon2Constants,
    validate_commitment: F,
) -> Result<Vec<Val>>
where
    F: FnOnce(ChannelId, &[u8; 32], u32) -> [u8; 32],
{
    let total_cols = column_offsets::total_cols();
    let mut row = Vec::with_capacity(total_cols);

    // Build base state fields
    row.extend_from_slice(&build_base_state_fields(
        state.nonce,
        state.is_closed,
        state.sender_balance,
        state.receiver_balance,
        context.amount,
    ));

    // Compute state hash with traces
    let (state_hash_traces, _state_hash_output, state_hash_bytes) = compute_state_hash_with_traces(
        state.sender_balance,
        state.receiver_balance,
        state.sender_pubkey,
        state.receiver_pubkey,
        state.metadata,
        state.is_closed,
        constants,
    );

    // For Open states, verify the computed hash matches compute_state_hash
    // (Closing states don't have a separate state_hash validation function)
    if !state.is_closed {
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
            state.metadata.unwrap_or(&[]),
            &is_closed_u64.to_le_bytes(),
        ]);
        assert_eq!(
            state_hash_bytes, expected_state_hash,
            "Trace-generated state_hash must match compute_state_hash"
        );
    }

    // Add state hash traces with padding
    add_state_hash_traces_with_padding(&mut row, &state_hash_traces);

    // Compute commitment with traces
    let (commitment_traces, commitment_output, commitment_bytes) = compute_commitment_with_traces(
        context.channel_id,
        &state_hash_bytes,
        state.nonce,
        constants,
    );

    // Validate commitment
    let expected_commitment =
        validate_commitment(context.channel_id, &state_hash_bytes, state.nonce);
    assert_eq!(
        commitment_bytes, expected_commitment,
        "Trace-generated commitment must match compute_commitment - constants are now synchronized"
    );

    // Add commitment and its traces
    add_commitment_and_traces(&mut row, &commitment_traces, &commitment_output);

    // Compute auth hash fields
    let auth_hash_fields = compute_auth_hash_fields(
        context.channel_id,
        state.nonce,
        &commitment_bytes,
        context.sender_sk.as_ref(),
    );
    row.extend_from_slice(&auth_hash_fields);

    // Validate row length
    if row.len() != total_cols {
        return Err(crate::Error::Zkp(crate::errors::ZkpError::TraceGenerationFailed(format!(
            "Channel trace row length mismatch: expected {} columns, got {}",
            total_cols,
            row.len()
        ))));
    }

    Ok(row)
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
/// * Columns 0-4: Channel state (`nonce`, `is_closed`, `sender_balance`, `receiver_balance`, `amount`)
/// * Columns `STATE_HASH_OFFSET`+: Hash trace columns for state_hash computation (multiple permutations)
/// * Columns `commitment_start()`..`commitment_end()`: `commitment` (8 fields, computed from state_hash)
/// * Columns `commitment_offset()`+: Hash trace columns for commitment computation
/// * Columns `auth_hash_start()`..`auth_hash_end()`: `auth_hash` (8 fields, computed from commitment)
///
/// # Arguments
/// * `channel_id` - Channel identifier
/// * `old_state` - Previous channel state
/// * `transfer_amount` - Transfer amount that caused the transition
/// * `new_state` - New channel state after transition
/// * `sender_sk` - Sender's private key for computing authentication hash
pub(super) fn build_channel_trace(
    channel_id: ChannelId,
    old_state: &Open,
    transfer_amount: &TransferAmount,
    new_state: &Open,
    sender_sk: &bitcoin::secp256k1::SecretKey,
) -> Result<Trace> {
    let total_cols = column_offsets::total_cols();
    let constants = create_poseidon2_constants_and_params();

    // Build old state row
    let old_row = build_state_row(
        StateInfo {
            nonce: old_state.nonce,
            is_closed: false,
            sender_balance: old_state.sender_balance,
            receiver_balance: old_state.receiver_balance,
            sender_pubkey: &old_state.sender_pubkey,
            receiver_pubkey: &old_state.receiver_pubkey,
            metadata: Some(&old_state.metadata),
        },
        TraceContext { channel_id, amount: **transfer_amount, sender_sk: Some(*sender_sk) },
        &constants,
        |ch_id, state_hash, nonce| compute_channel_commitment(ch_id, *state_hash, nonce),
    )?;

    // Build new state row
    let new_row = build_state_row(
        StateInfo {
            nonce: new_state.nonce,
            is_closed: false,
            sender_balance: new_state.sender_balance,
            receiver_balance: new_state.receiver_balance,
            sender_pubkey: &new_state.sender_pubkey,
            receiver_pubkey: &new_state.receiver_pubkey,
            metadata: Some(&new_state.metadata),
        },
        TraceContext { channel_id, amount: **transfer_amount, sender_sk: Some(*sender_sk) },
        &constants,
        |ch_id, state_hash, nonce| compute_channel_commitment(ch_id, *state_hash, nonce),
    )?;

    Ok(build_trace_matrix(old_row, new_row, total_cols))
}

/// Build trace matrix for cooperative close transition (Open → CooperativeClosing).
///
/// Similar to `build_force_close_trace` but handles the transition from Open to CooperativeClosing.
///
/// For cooperative close, `auth_hash` is set to zero (8 zero field elements) since authentication
/// is handled at the Bitcoin transaction layer where both parties must sign. This allows either
/// party to generate proofs without requiring secret keys.
///
/// # Arguments
/// * `channel_id` - Channel identifier
/// * `old_state` - Previous Open state
/// * `closing_fee` - Closing fee that was deducted
/// * `new_state` - New CooperativeClosing state after transition
pub(super) fn build_cooperative_close_trace(
    channel_id: ChannelId,
    old_state: &Open,
    closing_fee: u64,
    new_state: &CooperativeClosing,
) -> Result<Trace> {
    let total_cols = column_offsets::total_cols();
    let constants = create_poseidon2_constants_and_params();

    // Build old state row (Open)
    let old_row = build_state_row(
        StateInfo {
            nonce: old_state.nonce,
            is_closed: false,
            sender_balance: old_state.sender_balance,
            receiver_balance: old_state.receiver_balance,
            sender_pubkey: &old_state.sender_pubkey,
            receiver_pubkey: &old_state.receiver_pubkey,
            metadata: Some(&old_state.metadata),
        },
        TraceContext {
            channel_id,
            amount: closing_fee,
            sender_sk: None, // auth_hash is zero for cooperative close
        },
        &constants,
        |ch_id, state_hash, nonce| compute_channel_commitment(ch_id, *state_hash, nonce),
    )?;

    // Build new state row (CooperativeClosing)
    let new_row = build_state_row(
        StateInfo {
            nonce: new_state.nonce,
            is_closed: true,
            sender_balance: new_state.sender_balance,
            receiver_balance: new_state.receiver_balance,
            sender_pubkey: &new_state.sender_pubkey,
            receiver_pubkey: &new_state.receiver_pubkey,
            metadata: None, // No metadata for closing states
        },
        TraceContext {
            channel_id,
            amount: closing_fee,
            sender_sk: None, // auth_hash is zero for cooperative close
        },
        &constants,
        |ch_id, state_hash, nonce| compute_channel_commitment(ch_id, *state_hash, nonce),
    )?;

    Ok(build_trace_matrix(old_row, new_row, total_cols))
}

/// Build trace matrix for force close transition (Open → ForceClosingPending).
///
/// Similar to `build_channel_trace` but handles the transition from Open to ForceClosingPending.
/// The old state is Open, the new state is ForceClosingPending.
///
/// # Arguments
/// * `channel_id` - Channel identifier
/// * `old_state` - Previous Open state
/// * `closing_fee` - Closing fee that was deducted
/// * `new_state` - New ForceClosingPending state after transition
/// * `sender_sk` - Optional sender's private key. If provided, auth_hash is computed to prove
///   sender authorization. If None, auth_hash is set to zero (for receiver-initiated force close).
pub(super) fn build_force_close_trace(
    channel_id: ChannelId,
    old_state: &Open,
    closing_fee: u64,
    new_state: &ForceClosingPending,
    sender_sk: Option<&bitcoin::secp256k1::SecretKey>,
) -> Result<Trace> {
    let total_cols = column_offsets::total_cols();
    let constants = create_poseidon2_constants_and_params();

    // Build old state row (Open)
    let old_row = build_state_row(
        StateInfo {
            nonce: old_state.nonce,
            is_closed: false,
            sender_balance: old_state.sender_balance,
            receiver_balance: old_state.receiver_balance,
            sender_pubkey: &old_state.sender_pubkey,
            receiver_pubkey: &old_state.receiver_pubkey,
            metadata: Some(&old_state.metadata),
        },
        TraceContext {
            channel_id,
            amount: closing_fee,
            sender_sk: sender_sk.copied(), // auth_hash depends on sender_sk
        },
        &constants,
        |ch_id, state_hash, nonce| compute_channel_commitment(ch_id, *state_hash, nonce),
    )?;

    // Build new state row (ForceClosingPending)
    let new_row = build_state_row(
        StateInfo {
            nonce: new_state.nonce,
            is_closed: true,
            sender_balance: new_state.sender_balance,
            receiver_balance: new_state.receiver_balance,
            sender_pubkey: &new_state.sender_pubkey,
            receiver_pubkey: &new_state.receiver_pubkey,
            metadata: None, // No metadata for closing states
        },
        TraceContext {
            channel_id,
            amount: closing_fee,
            sender_sk: sender_sk.copied(), // auth_hash depends on sender_sk
        },
        &constants,
        |ch_id, state_hash, nonce| compute_channel_commitment(ch_id, *state_hash, nonce),
    )?;

    Ok(build_trace_matrix(old_row, new_row, total_cols))
}

/// Build trace matrix for recover transition (ForceClosingPending → Closed).
///
/// Handles the transition from ForceClosingPending to Closed state.
pub(super) fn build_recover_trace(
    channel_id: ChannelId,
    old_state: &ForceClosingPending,
    new_state: &Closed,
) -> Result<Trace> {
    let total_cols = column_offsets::total_cols();
    let constants = create_poseidon2_constants_and_params();

    // Build old state row (ForceClosingPending)
    // For recover, the amount is 0 (no transfer, just state change)
    let old_row = build_state_row(
        StateInfo {
            nonce: old_state.nonce,
            is_closed: true,
            sender_balance: old_state.sender_balance,
            receiver_balance: old_state.receiver_balance,
            sender_pubkey: &old_state.sender_pubkey,
            receiver_pubkey: &old_state.receiver_pubkey,
            metadata: None, // No metadata for closing states
        },
        TraceContext {
            channel_id,
            amount: 0,       // No transfer amount
            sender_sk: None, // auth_hash is zero for recover
        },
        &constants,
        |ch_id, state_hash, nonce| compute_channel_commitment(ch_id, *state_hash, nonce),
    )?;

    // Build new state row (Closed)
    let new_row = build_state_row(
        StateInfo {
            nonce: new_state.nonce,
            is_closed: true,
            sender_balance: new_state.sender_balance,
            receiver_balance: new_state.receiver_balance,
            sender_pubkey: &new_state.sender_pubkey,
            receiver_pubkey: &new_state.receiver_pubkey,
            metadata: None, // No metadata for closing states
        },
        TraceContext {
            channel_id,
            amount: 0,       // No transfer amount
            sender_sk: None, // auth_hash is zero for recover
        },
        &constants,
        |ch_id, state_hash, nonce| compute_channel_commitment(ch_id, *state_hash, nonce),
    )?;

    Ok(build_trace_matrix(old_row, new_row, total_cols))
}

#[cfg(test)]
mod tests {
    use bitcoin::secp256k1::SecretKey;

    use super::*;
    use crate::channel::state::{
        Closed, CooperativeClosing, CooperativeClosingParams, ForceClosingPending,
        ForceClosingPendingParams, Open,
    };
    use crate::channel::test_utils::test_keys;
    use crate::TransferAmount;

    #[test]
    fn test_build_channel_trace() {
        let (sender_pubkey, receiver_pubkey) = test_keys();
        let sender_revocation_secret = SecretKey::from_secret_bytes([3u8; 32])
            .expect("sender revocation secret should always succeed");
        let receiver_revocation_secret = SecretKey::from_secret_bytes([4u8; 32])
            .expect("receiver revocation secret should always succeed");
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
            SecretKey::from_secret_bytes([1u8; 32]).expect("32-byte array should always be valid");

        let trace =
            build_channel_trace(channel_id, &old_state, &transfer_amount, &new_state, &sender_sk)
                .expect("trace generation should succeed");

        assert_eq!(trace.height(), 8);
        assert_eq!(trace.width(), column_offsets::total_cols());
    }

    #[test]
    fn test_build_cooperative_close_trace() {
        let (sender_pubkey, receiver_pubkey) = test_keys();
        let sender_revocation_secret = SecretKey::from_secret_bytes([3u8; 32])
            .expect("sender revocation secret should always succeed");
        let receiver_revocation_secret = SecretKey::from_secret_bytes([4u8; 32])
            .expect("receiver revocation secret should always succeed");
        let mut old_state = Open::new(
            sender_pubkey,
            receiver_pubkey,
            100,
            sender_revocation_secret,
            receiver_revocation_secret,
        );
        old_state.metadata = vec![];
        old_state.nonce = 0;
        let closing_fee = 5u64;
        let new_state_params = CooperativeClosingParams {
            sender_pubkey,
            receiver_pubkey,
            total_capacity: 100,
            sender_balance: 50,
            receiver_balance: 45,
            total_fee: closing_fee,
            sender_contribution: 3,
            receiver_contribution: 2,
            nonce: 1,
        };
        let new_state = CooperativeClosing::new(new_state_params);
        let channel_id = [0u8; 32];

        let trace = build_cooperative_close_trace(channel_id, &old_state, closing_fee, &new_state)
            .expect("trace generation should succeed");

        assert_eq!(trace.height(), 8);
        assert_eq!(trace.width(), column_offsets::total_cols());
    }

    #[test]
    fn test_build_force_close_trace() {
        let (sender_pubkey, receiver_pubkey) = test_keys();
        let sender_revocation_secret = SecretKey::from_secret_bytes([3u8; 32])
            .expect("sender revocation secret should always succeed");
        let receiver_revocation_secret = SecretKey::from_secret_bytes([4u8; 32])
            .expect("receiver revocation secret should always succeed");
        let mut old_state = Open::new(
            sender_pubkey,
            receiver_pubkey,
            100,
            sender_revocation_secret,
            receiver_revocation_secret,
        );
        old_state.metadata = vec![];
        old_state.nonce = 0;
        let closing_fee = 5u64;
        let new_state_params = ForceClosingPendingParams {
            sender_pubkey,
            receiver_pubkey,
            total_capacity: 100,
            sender_balance: 95,
            receiver_balance: 0,
            total_fee: closing_fee,
            nonce: 1,
            timeout_blocks: 10,
        };
        let new_state = ForceClosingPending::new(new_state_params);
        let channel_id = [0u8; 32];
        let sender_sk =
            SecretKey::from_secret_bytes([1u8; 32]).expect("32-byte array should always be valid");

        let trace = build_force_close_trace(
            channel_id,
            &old_state,
            closing_fee,
            &new_state,
            Some(&sender_sk),
        )
        .expect("trace generation should succeed");

        assert_eq!(trace.height(), 8);
        assert_eq!(trace.width(), column_offsets::total_cols());

        let (sender_pubkey, receiver_pubkey) = test_keys();
        let sender_revocation_secret = SecretKey::from_secret_bytes([3u8; 32])
            .expect("sender revocation secret should always succeed");
        let receiver_revocation_secret = SecretKey::from_secret_bytes([4u8; 32])
            .expect("receiver revocation secret should always succeed");
        let mut old_state = Open::new(
            sender_pubkey,
            receiver_pubkey,
            100,
            sender_revocation_secret,
            receiver_revocation_secret,
        );
        old_state.metadata = vec![];
        old_state.nonce = 0;
        let closing_fee = 5u64;
        let new_state_params = ForceClosingPendingParams {
            sender_pubkey,
            receiver_pubkey,
            total_capacity: 100,
            sender_balance: 95,
            receiver_balance: 0,
            total_fee: closing_fee,
            nonce: 1,
            timeout_blocks: 10,
        };
        let new_state = ForceClosingPending::new(new_state_params);
        let channel_id = [0u8; 32];

        let trace = build_force_close_trace(channel_id, &old_state, closing_fee, &new_state, None)
            .expect("trace generation should succeed");

        assert_eq!(trace.height(), 8);
        assert_eq!(trace.width(), column_offsets::total_cols());
    }

    #[test]
    fn test_build_recover_trace() {
        let (sender_pubkey, receiver_pubkey) = test_keys();
        let old_state_params = ForceClosingPendingParams {
            sender_pubkey,
            receiver_pubkey,
            total_capacity: 100,
            sender_balance: 95,
            receiver_balance: 0,
            total_fee: 5,
            nonce: 1,
            timeout_blocks: 10,
        };
        let old_state = ForceClosingPending::new(old_state_params);
        let new_state = Closed::new(sender_pubkey, receiver_pubkey, 100, 95, 0, 1);
        let channel_id = [0u8; 32];

        let trace = build_recover_trace(channel_id, &old_state, &new_state)
            .expect("trace generation should succeed");

        assert_eq!(trace.height(), 8);
        assert_eq!(trace.width(), column_offsets::total_cols());
    }
}
