//! Common Poseidon2 trace generation utilities
//!
//! This module provides shared functions for generating Poseidon2 hash traces
//! used in both wallet commitment and wallet transition proofs.

use p3_baby_bear::{GenericPoseidon2LinearLayersBabyBear, Poseidon2BabyBear};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::Matrix;
use p3_poseidon2_air::generate_trace_rows;
use p3_symmetric::Permutation;

use crate::zkp::poseidon2_common::{
    POSEIDON2_HALF_FULL_ROUNDS, POSEIDON2_OUTPUT_SIZE, POSEIDON2_PARTIAL_ROUNDS, POSEIDON2_RATE,
    POSEIDON2_SBOX_DEGREE, POSEIDON2_SBOX_REGISTERS, POSEIDON2_WIDTH,
};
use crate::zkp::types::Val;

/// Generate hash trace for a single input with specified constants
///
/// Returns a single row of the hash trace (all columns for one permutation).
///
/// # Arguments
/// * `input` - Input state array of POSEIDON2_WIDTH field elements
/// * `constants` - Poseidon2 round constants for trace generation
pub(super) fn generate_poseidon2_trace_row_with_constants(
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

/// Simulate sponge construction step-by-step to generate multi-permutation traces
///
/// Returns traces for each permutation needed to hash the input, and the final output.
/// This matches the behavior of the hash function implementation.
///
/// # Arguments
/// * `input_bytes` - Input bytes to hash
/// * `constants` - Poseidon2 round constants for trace generation
/// * `external_constants` - External layer constants for permutation
/// * `internal_constants` - Internal constants for permutation
pub(super) fn generate_multi_permutation_traces(
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

/// Copy traces into a row starting at the given offset.
///
/// # Arguments
/// * `row` - The row to copy traces into
/// * `traces` - Slice of trace vectors to copy
/// * `initial_offset` - Starting column offset in the row
pub(super) fn copy_traces_to_row(row: &mut [Val], traces: &[Vec<Val>], initial_offset: usize) {
    let mut offset = initial_offset;
    for trace in traces.iter() {
        if offset + trace.len() <= row.len() {
            row[offset..offset + trace.len()].copy_from_slice(trace);
            offset += trace.len();
        }
    }
}
