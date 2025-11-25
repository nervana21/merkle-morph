//! Trace generation for wallet commitment aggregation
//!
//! This module provides functions for generating execution traces
//! for wallet commitment proofs.

use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

use crate::types::{CHAIN_DOMAIN, MAX_CHANNELS, WALLET_HASH_DOMAIN, WALLET_INIT_DOMAIN};
use crate::wallet::state::WalletState;
use crate::zkp::poseidon2_hash_fixed;
use crate::zkp::types::{bytes32_to_fields, Trace, Val};
use crate::zkp::wallet::poseidon2_air::create_poseidon2_constants_and_params;
use crate::zkp::wallet::poseidon2_trace_common::{self, copy_traces_to_row};
use crate::{Bytes32, Result};

mod column_offsets {
    // Re-export from poseidon2_air for consistency
    pub(super) use crate::zkp::wallet::poseidon2_air::column_offsets::{
        total_cols, wallet_init_poseidon2_start, ACCUMULATOR_PERMUTATIONS,
        ACCUMULATOR_POSEIDON2_START, CHANNEL_COMMITMENT_END, CHANNEL_COMMITMENT_START,
        CHANNEL_ID_END, CHANNEL_ID_START, IS_ACTIVE_COL, NEXT_ACC_END, NEXT_ACC_START,
        PREV_ACC_END, PREV_ACC_START, WALLET_INIT_PERMUTATIONS,
    };
}

/// Build trace matrix for wallet commitment aggregation.
///
/// The trace contains multiple rows (one per channel, padded to power-of-2).
///
/// # Trace Structure
///
/// Each row represents one channel step with the following column layout:
/// * Columns 0-7: `prev_accumulator` (8 fields)
/// * Columns 8-15: `channel_id` (8 fields)
/// * Columns 16-23: `channel_commitment` (8 fields)
/// * Columns 24-31: `next_accumulator` (8 fields)
/// * Columns 32+: Hash trace columns for accumulator computation
///
/// Padding rows after the last channel have `channel_id = 0`, `channel_commitment = 0`,
/// and the accumulator remains stable (`prev_acc = next_acc`).
pub(super) fn build_wallet_trace(wallet: &WalletState) -> Result<Trace> {
    let total_cols = column_offsets::total_cols();
    const MIN_ROWS: usize = 8; // Minimum rows needed (power of 2)

    let mut sorted_channels: Vec<_> = wallet.channels.iter().collect();
    sorted_channels.sort_by_key(|(id, _)| *id);

    if sorted_channels.len() > MAX_CHANNELS {
        return Err(crate::Error::Zkp(crate::errors::ZkpError::TraceGenerationFailed(format!(
            "Wallet has {} channels, but maximum supported is {}",
            sorted_channels.len(),
            MAX_CHANNELS
        ))));
    }

    let num_active_channels = sorted_channels.len();
    let num_rows = num_active_channels.max(MIN_ROWS).next_power_of_two();

    let mut values = Vec::with_capacity(num_rows * total_cols);

    // Create constants and hash parameters from the same source
    // This ensures the constants match what will be used in trace generation AND hash computation
    let constants = create_poseidon2_constants_and_params();

    // Initialize accumulator with wallet_id
    let initial_accumulator: Bytes32 = poseidon2_hash_fixed(&[WALLET_INIT_DOMAIN, &wallet.id[..]]);
    let mut accumulator = initial_accumulator;

    // Generate hash trace for wallet_id initialization (used for verification)
    let mut wallet_init_input_bytes = Vec::new();
    wallet_init_input_bytes.extend_from_slice(WALLET_INIT_DOMAIN);
    wallet_init_input_bytes.extend_from_slice(&wallet.id[..]);

    let (wallet_init_traces, computed_wallet_init_output) =
        poseidon2_trace_common::generate_multi_permutation_traces(
            &wallet_init_input_bytes,
            &constants.round_constants,
            &constants.external_constants,
            &constants.internal_constants,
        );

    if wallet_init_traces.len() != column_offsets::WALLET_INIT_PERMUTATIONS {
        return Err(crate::Error::Zkp(crate::errors::ZkpError::TraceGenerationFailed(format!(
            "Wallet init trace count mismatch: expected {}, got {}",
            column_offsets::WALLET_INIT_PERMUTATIONS,
            wallet_init_traces.len()
        ))));
    }

    let expected_init_fields = bytes32_to_fields(initial_accumulator);
    if computed_wallet_init_output != expected_init_fields {
        return Err(crate::Error::Zkp(crate::errors::ZkpError::TraceGenerationFailed(
            "Wallet init output mismatch: computed hash does not match expected accumulator"
                .to_string(),
        )));
    }

    // Generate rows for active channels
    for (channel_id, channel_commitment) in sorted_channels.iter().take(num_active_channels) {
        let mut row = vec![Val::ZERO; total_cols];

        row[column_offsets::IS_ACTIVE_COL] = Val::ONE;

        let prev_accumulator = accumulator;
        let prev_acc_fields = bytes32_to_fields(prev_accumulator);
        row[column_offsets::PREV_ACC_START..column_offsets::PREV_ACC_END]
            .copy_from_slice(&prev_acc_fields);

        let channel_id_fields = bytes32_to_fields(**channel_id);
        row[column_offsets::CHANNEL_ID_START..column_offsets::CHANNEL_ID_END]
            .copy_from_slice(&channel_id_fields);

        let channel_commitment_fields = bytes32_to_fields(**channel_commitment);
        row[column_offsets::CHANNEL_COMMITMENT_START..column_offsets::CHANNEL_COMMITMENT_END]
            .copy_from_slice(&channel_commitment_fields);

        let channel_hash_bytes: Bytes32 =
            poseidon2_hash_fixed(&[WALLET_HASH_DOMAIN, &channel_id[..], &channel_commitment[..]]);

        accumulator =
            poseidon2_hash_fixed(&[CHAIN_DOMAIN, &prev_accumulator[..], &channel_hash_bytes[..]]);

        let next_acc_fields = bytes32_to_fields(accumulator);
        row[column_offsets::NEXT_ACC_START..column_offsets::NEXT_ACC_END]
            .copy_from_slice(&next_acc_fields);

        let mut accumulator_input_bytes = Vec::new();
        accumulator_input_bytes.extend_from_slice(CHAIN_DOMAIN);
        accumulator_input_bytes.extend_from_slice(&prev_accumulator[..]);
        accumulator_input_bytes.extend_from_slice(&channel_hash_bytes[..]);

        let (accumulator_traces, computed_output) =
            poseidon2_trace_common::generate_multi_permutation_traces(
                &accumulator_input_bytes,
                &constants.round_constants,
                &constants.external_constants,
                &constants.internal_constants,
            );

        if accumulator_traces.len() != column_offsets::ACCUMULATOR_PERMUTATIONS {
            return Err(crate::Error::Zkp(crate::errors::ZkpError::TraceGenerationFailed(
                format!(
                    "Accumulator trace count mismatch: expected {}, got {}",
                    column_offsets::ACCUMULATOR_PERMUTATIONS,
                    accumulator_traces.len()
                ),
            )));
        }

        let expected_fields = bytes32_to_fields(accumulator);
        if computed_output != expected_fields {
            return Err(crate::Error::Zkp(crate::errors::ZkpError::TraceGenerationFailed(
                "Accumulator output mismatch: computed hash does not match expected accumulator"
                    .to_string(),
            )));
        }

        copy_traces_to_row(
            &mut row,
            &accumulator_traces,
            column_offsets::ACCUMULATOR_POSEIDON2_START,
        );

        copy_traces_to_row(
            &mut row,
            &wallet_init_traces,
            column_offsets::wallet_init_poseidon2_start(),
        );

        values.extend_from_slice(&row);
    }

    // Generate padding rows (inactive channels)
    // For padding rows: is_active = 0, channel_id = 0, channel_commitment = 0, accumulator remains stable
    let num_padding = num_rows - num_active_channels;
    for _ in 0..num_padding {
        let mut row = vec![Val::ZERO; total_cols];

        row[column_offsets::IS_ACTIVE_COL] = Val::ZERO;

        let stable_acc_fields = bytes32_to_fields(accumulator);
        row[column_offsets::PREV_ACC_START..column_offsets::PREV_ACC_END]
            .copy_from_slice(&stable_acc_fields);
        row[column_offsets::NEXT_ACC_START..column_offsets::NEXT_ACC_END]
            .copy_from_slice(&stable_acc_fields);

        let mut dummy_accumulator_input = Vec::new();
        dummy_accumulator_input.extend_from_slice(CHAIN_DOMAIN);
        dummy_accumulator_input.extend_from_slice(&accumulator);
        dummy_accumulator_input.extend_from_slice(&[0u8; 32]); // zero channel_hash for inactive

        let (accumulator_traces, _) = poseidon2_trace_common::generate_multi_permutation_traces(
            &dummy_accumulator_input,
            &constants.round_constants,
            &constants.external_constants,
            &constants.internal_constants,
        );

        copy_traces_to_row(
            &mut row,
            &accumulator_traces,
            column_offsets::ACCUMULATOR_POSEIDON2_START,
        );

        copy_traces_to_row(
            &mut row,
            &wallet_init_traces,
            column_offsets::wallet_init_poseidon2_start(),
        );

        values.extend_from_slice(&row);
    }

    Ok(RowMajorMatrix::new(values, total_cols))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use p3_matrix::Matrix;

    use super::*;
    use crate::wallet::commitment::compute_commitment_from_channels;
    use crate::wallet::state::WalletState;
    use crate::zkp::wallet::public_inputs::WalletPublicInputs;
    use crate::zkp::wallet::{prove_wallet_commitment, verify_wallet_commitment};

    fn wallet(id: u8, channels: &[(u8, u8)]) -> WalletState {
        let mut map = BTreeMap::new();
        for (cid, comm) in channels.iter() {
            let mut channel_id = [0u8; 32];
            channel_id[31] = *cid;

            let mut channel_commitment = [0u8; 32];
            channel_commitment[31] = *comm;

            map.insert(channel_id, channel_commitment);
        }
        WalletState::from_channels([id; 32], map)
    }

    #[test]
    fn empty_wallet_trace() {
        let w = wallet(1, &[]);
        let trace = build_wallet_trace(&w).expect("failed to build wallet trace");
        assert!(trace.width() > 0);

        let expected =
            compute_commitment_from_channels(w.id, &w.channels).expect("should compute commitment");
        let pi = WalletPublicInputs { wallet_id: w.id, wallet_commitment: expected };
        let cfg = crate::zkp::types::create_config().expect("failed to create config");

        let proof = prove_wallet_commitment(&cfg, &w).expect("failed to prove wallet commitment");
        verify_wallet_commitment(&cfg, &pi, &proof).expect("failed to verify wallet commitment");
    }

    #[test]
    fn single_channel_trace() {
        let w = wallet(1, &[(2, 3)]);
        let trace = build_wallet_trace(&w).expect("failed to build wallet trace");
        assert!(trace.width() > 0);

        let expected =
            compute_commitment_from_channels(w.id, &w.channels).expect("should compute commitment");
        let pi = WalletPublicInputs { wallet_id: w.id, wallet_commitment: expected };
        let cfg = crate::zkp::types::create_config().expect("failed to create config");

        let proof = prove_wallet_commitment(&cfg, &w).expect("failed to prove wallet commitment");
        verify_wallet_commitment(&cfg, &pi, &proof).expect("failed to verify wallet commitment");
    }

    #[test]
    fn multiple_channels_trace() {
        let w = wallet(1, &[(2, 3), (4, 5), (6, 7)]);
        let trace = build_wallet_trace(&w).expect("failed to build wallet trace");
        assert!(trace.width() > 0);

        let expected =
            compute_commitment_from_channels(w.id, &w.channels).expect("should compute commitment");
        let pi = WalletPublicInputs { wallet_id: w.id, wallet_commitment: expected };
        let cfg = crate::zkp::types::create_config().expect("failed to create config");

        let proof = prove_wallet_commitment(&cfg, &w).expect("failed to prove wallet commitment");
        verify_wallet_commitment(&cfg, &pi, &proof).expect("failed to verify wallet commitment");
    }

    #[test]
    fn test_sorted_order() {
        let w = wallet(1, &[(10, 10), (5, 20), (15, 30)]);
        let trace = build_wallet_trace(&w).expect("failed to build wallet trace");
        assert!(trace.width() > 0);

        let expected =
            compute_commitment_from_channels(w.id, &w.channels).expect("should compute commitment");
        let pi = WalletPublicInputs { wallet_id: w.id, wallet_commitment: expected };
        let cfg = crate::zkp::types::create_config().expect("failed to create config");

        let proof = prove_wallet_commitment(&cfg, &w).expect("failed to prove wallet commitment");
        verify_wallet_commitment(&cfg, &pi, &proof).expect("failed to verify wallet commitment");
    }

    #[test]
    fn max_channels_trace() {
        let mut pairs = Vec::new();
        for i in 0..16u8 {
            pairs.push((i, i + 100));
        }
        let w = wallet(1, &pairs);

        let trace = build_wallet_trace(&w).expect("failed to build wallet trace");
        assert!(trace.width() > 0);

        let expected =
            compute_commitment_from_channels(w.id, &w.channels).expect("should compute commitment");
        let pi = WalletPublicInputs { wallet_id: w.id, wallet_commitment: expected };
        let cfg = crate::zkp::types::create_config().expect("failed to create config");

        let proof = prove_wallet_commitment(&cfg, &w).expect("failed to prove wallet commitment");
        verify_wallet_commitment(&cfg, &pi, &proof).expect("failed to verify wallet commitment");
    }

    #[test]
    fn too_many_channels_trace() {
        let mut pairs = Vec::new();
        for i in 0..(MAX_CHANNELS + 5) as u8 {
            pairs.push((i, i + 100));
        }
        let w = wallet(1, &pairs);

        // build_wallet_trace should fail with too many channels
        let result = build_wallet_trace(&w);
        assert!(result.is_err(), "Should fail when wallet has more than MAX_CHANNELS");

        // prove_wallet_commitment should also fail (it calls build_wallet_trace)
        let cfg = crate::zkp::types::create_config().expect("failed to create config");
        let result = prove_wallet_commitment(&cfg, &w);
        assert!(result.is_err(), "Should fail when wallet has more than MAX_CHANNELS");
    }

    #[test]
    fn wrong_wallet_id_fails() {
        let w = wallet(1, &[(2, 3)]);
        let expected =
            compute_commitment_from_channels(w.id, &w.channels).expect("should compute commitment");

        let mut wrong = [0u8; 32];
        wrong[31] = 99;

        let pi = WalletPublicInputs { wallet_id: wrong, wallet_commitment: expected };
        let cfg = crate::zkp::types::create_config().expect("failed to create config");
        let proof = prove_wallet_commitment(&cfg, &w).expect("failed to prove wallet commitment");

        assert!(verify_wallet_commitment(&cfg, &pi, &proof).is_err());
    }

    #[test]
    fn wrong_commitment_fails() {
        let w = wallet(1, &[(2, 3)]);
        let mut wrong_commit = [0u8; 32];
        wrong_commit[31] = 42;

        let pi = WalletPublicInputs { wallet_id: w.id, wallet_commitment: wrong_commit };
        let cfg = crate::zkp::types::create_config().expect("failed to create config");
        let proof = prove_wallet_commitment(&cfg, &w).expect("failed to prove wallet commitment");

        assert!(verify_wallet_commitment(&cfg, &pi, &proof).is_err());
    }

    #[test]
    fn consistency_same_wallet() {
        let w = wallet(1, &[(2, 3), (4, 5), (6, 7)]);
        let cfg = crate::zkp::types::create_config().expect("failed to create config");

        let p1 = prove_wallet_commitment(&cfg, &w).expect("failed to prove wallet commitment");
        let p2 = prove_wallet_commitment(&cfg, &w).expect("failed to prove wallet commitment");

        let expected =
            compute_commitment_from_channels(w.id, &w.channels).expect("should compute commitment");
        let pi = WalletPublicInputs { wallet_id: w.id, wallet_commitment: expected };

        verify_wallet_commitment(&cfg, &pi, &p1).expect("failed to verify wallet commitment");
        verify_wallet_commitment(&cfg, &pi, &p2).expect("failed to verify wallet commitment");
    }
}
