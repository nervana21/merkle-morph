//! Trace generation for wallet state transitions
//!
//! This module provides functions for generating execution traces
//! for wallet state transition proofs. The trace tracks both old and new
//! wallet accumulator chains in parallel, includes hash computation traces
//! for accumulator chains and wallet_id initialization, and padding rows
//! to ensure the trace has a power-of-2 height.

use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;

use crate::types::{
    ChannelCommitment, ChannelId, CHAIN_DOMAIN, MAX_CHANNELS, WALLET_HASH_DOMAIN,
    WALLET_INIT_DOMAIN,
};
use crate::wallet::commitment::compute_commitment_from_channels;
use crate::wallet::operation::WalletTransition;
use crate::wallet::state::WalletState;
use crate::zkp::poseidon2_hash_fixed;
use crate::zkp::types::{bytes32_to_fields, Trace, Val};
use crate::zkp::wallet::poseidon2_trace_common::{self, copy_traces_to_row};
use crate::zkp::wallet::transition_poseidon2_air::create_poseidon2_constants_and_params;
use crate::{Bytes32, Result};

mod column_offsets {
    // Re-export from transition_poseidon2_air for consistency
    pub(super) use crate::zkp::wallet::transition_poseidon2_air::column_offsets::{
        new_accumulator_poseidon2_start, total_cols, wallet_init_poseidon2_start,
        ACCUMULATOR_PERMUTATIONS, CHANNEL_COMMITMENT_END, CHANNEL_COMMITMENT_START, CHANNEL_ID_END,
        CHANNEL_ID_START, IS_IN_NEW_COL, IS_IN_OLD_COL, NEXT_NEW_ACC_END, NEXT_NEW_ACC_START,
        NEXT_OLD_ACC_END, NEXT_OLD_ACC_START, OLD_ACCUMULATOR_POSEIDON2_START, PREV_NEW_ACC_END,
        PREV_NEW_ACC_START, PREV_OLD_ACC_END, PREV_OLD_ACC_START, WALLET_INIT_PERMUTATIONS,
    };
}

/// Channel information tuple: (is_in_old, is_in_new, old_commitment, new_commitment)
type ChannelInfo = (bool, bool, ChannelCommitment, ChannelCommitment);

/// Channel entry: (channel_id, channel_info)
type ChannelEntry = (ChannelId, ChannelInfo);

/// Build trace matrix for wallet transition.
///
/// The trace contains multiple rows (padded to power-of-2):
/// - One row per channel in the union of old and new wallets
/// - Padding rows (inactive channels) with stable accumulators
///
/// # Trace Structure
///
/// Each row represents one channel with the following column layout:
/// * Columns 0-7: channel_id (8 fields) - channel identifier
/// * Columns 8-15: channel_commitment (8 fields) - channel commitment (from old or new wallet)
/// * Column 16: is_in_old (1 field) - flag indicating if channel exists in old wallet
/// * Column 17: is_in_new (1 field) - flag indicating if channel exists in new wallet
/// * Columns 18-25: prev_old_acc (8 fields) - old accumulator before processing this channel
/// * Columns 26-33: next_old_acc (8 fields) - old accumulator after processing this channel
/// * Columns 34-41: prev_new_acc (8 fields) - new accumulator before processing this channel
/// * Columns 42-49: next_new_acc (8 fields) - new accumulator after processing this channel
/// * Columns 50+: Poseidon2 AIR columns for old accumulator computation (3 permutations)
/// * Columns 50+poseidon2_cols*3+: Poseidon2 AIR columns for new accumulator computation (3 permutations)
/// * Columns 50+poseidon2_cols*6+: Poseidon2 AIR columns for wallet_id initialization (2 permutations)
pub(super) fn build_transition_trace(
    old_wallet: &WalletState,
    new_wallet: &WalletState,
) -> Result<Trace> {
    // Minimum rows needed (power of 2)
    const MIN_ROWS: usize = 8;
    let total_cols = column_offsets::total_cols();

    // Build union of channels from old and new wallets
    // Each entry: (channel_id, (is_in_old, is_in_new, old_commitment, new_commitment))
    let mut all_channels: Vec<ChannelEntry> = Vec::new();

    // Add channels from old wallet
    for (channel_id, commitment) in old_wallet.channels.iter() {
        all_channels.push((*channel_id, (true, false, *commitment, [0u8; 32])));
    }

    // Add channels from new wallet (update existing entries or add new ones)
    for (channel_id, commitment) in new_wallet.channels.iter() {
        if let Some((_, flags)) = all_channels.iter_mut().find(|(id, _)| id == channel_id) {
            // Channel exists in both wallets
            flags.1 = true;
            flags.3 = *commitment;
        } else {
            // Channel only in new wallet
            all_channels.push((*channel_id, (false, true, [0u8; 32], *commitment)));
        }
    }

    // Sort channels by channel_id for deterministic trace generation
    all_channels.sort_by_key(|(id, _)| *id);

    if all_channels.len() > MAX_CHANNELS {
        return Err(crate::Error::Zkp(crate::errors::ZkpError::TraceGenerationFailed(format!(
            "Wallet transition has {} channels, but maximum supported is {}",
            all_channels.len(),
            MAX_CHANNELS
        ))));
    }

    let num_active_channels = all_channels.len();
    let num_rows = num_active_channels.max(MIN_ROWS).next_power_of_two();

    let mut values = Vec::with_capacity(num_rows * total_cols);

    // Create constants and hash parameters from the same source
    // This ensures the constants match what will be used in trace generation AND hash computation
    let constants = create_poseidon2_constants_and_params();

    // Compute wallet commitments and verify they match expected values
    let old_wallet_commitment =
        compute_commitment_from_channels(old_wallet.id, &old_wallet.channels).map_err(|e| {
            crate::Error::Zkp(crate::errors::ZkpError::TraceGenerationFailed(format!(
                "Failed to compute old wallet commitment: {:?}",
                e
            )))
        })?;

    // Rebuild old accumulator chain to verify it matches old_wallet_commitment
    // This ensures trace generation matches the commitment computation
    let wallet_id_hash: Bytes32 = poseidon2_hash_fixed(&[WALLET_INIT_DOMAIN, &old_wallet.id[..]]);

    let mut old_accumulator_rebuilt = wallet_id_hash;
    for (channel_id, (is_in_old, _, old_commitment, _)) in all_channels.iter() {
        if *is_in_old {
            // Hash channel: hash(WALLET_HASH_DOMAIN || channel_id || channel_commitment)
            let channel_hash_bytes: Bytes32 =
                poseidon2_hash_fixed(&[WALLET_HASH_DOMAIN, &channel_id[..], &old_commitment[..]]);
            // Update accumulator: hash(CHAIN_DOMAIN || accumulator || channel_hash)
            old_accumulator_rebuilt = poseidon2_hash_fixed(&[
                CHAIN_DOMAIN,
                &old_accumulator_rebuilt[..],
                &channel_hash_bytes[..],
            ]);
        }
    }

    // Verify rebuilt accumulator matches expected commitment
    if old_accumulator_rebuilt != old_wallet_commitment {
        return Err(crate::Error::Zkp(crate::errors::ZkpError::TraceGenerationFailed(format!(
            "Rebuilt old accumulator ({:?}) does not match old wallet commitment ({:?})",
            old_accumulator_rebuilt, old_wallet_commitment
        ))));
    }

    // Rebuild new accumulator chain to verify it matches new_wallet_commitment
    let new_wallet_commitment =
        compute_commitment_from_channels(new_wallet.id, &new_wallet.channels).map_err(|e| {
            crate::Error::Zkp(crate::errors::ZkpError::TraceGenerationFailed(format!(
                "Failed to compute new wallet commitment: {:?}",
                e
            )))
        })?;

    let mut new_accumulator_rebuilt = wallet_id_hash;
    for (channel_id, (_, is_in_new, _, new_commitment)) in all_channels.iter() {
        if *is_in_new {
            // Hash channel: hash(WALLET_HASH_DOMAIN || channel_id || channel_commitment)
            let channel_hash_bytes: Bytes32 =
                poseidon2_hash_fixed(&[WALLET_HASH_DOMAIN, &channel_id[..], &new_commitment[..]]);
            // Update accumulator: hash(CHAIN_DOMAIN || accumulator || channel_hash)
            new_accumulator_rebuilt = poseidon2_hash_fixed(&[
                CHAIN_DOMAIN,
                &new_accumulator_rebuilt[..],
                &channel_hash_bytes[..],
            ]);
        }
    }

    // Verify rebuilt accumulator matches expected commitment
    if new_accumulator_rebuilt != new_wallet_commitment {
        return Err(crate::Error::Zkp(crate::errors::ZkpError::TraceGenerationFailed(format!(
            "Rebuilt new accumulator ({:?}) does not match new wallet commitment ({:?})",
            new_accumulator_rebuilt, new_wallet_commitment
        ))));
    }

    // Initialize accumulators for trace generation
    // Old accumulator starts from old_wallet_commitment (unchanged during transition)
    let mut old_accumulator = old_wallet_commitment;
    // New accumulator starts from wallet_id_hash (built from scratch)
    // This matches the rebuilding logic which starts from wallet_id_hash
    let mut new_accumulator = wallet_id_hash;

    let first_row_prev_acc = old_wallet_commitment;

    // Generate hash trace for wallet_id initialization (used for verification)
    let mut wallet_init_input_bytes = Vec::new();
    wallet_init_input_bytes.extend_from_slice(WALLET_INIT_DOMAIN);
    wallet_init_input_bytes.extend_from_slice(&old_wallet.id[..]);

    let (wallet_init_traces, computed_wallet_init_output) =
        poseidon2_trace_common::generate_multi_permutation_traces(
            &wallet_init_input_bytes,
            &constants.round_constants,
            &constants.external_constants,
            &constants.internal_constants,
        );

    // Verify wallet init trace count matches expected number of permutations
    if wallet_init_traces.len() != column_offsets::WALLET_INIT_PERMUTATIONS {
        return Err(crate::Error::Zkp(crate::errors::ZkpError::TraceGenerationFailed(format!(
            "Wallet init trace count mismatch: expected {}, got {}",
            column_offsets::WALLET_INIT_PERMUTATIONS,
            wallet_init_traces.len()
        ))));
    }

    // Verify computed wallet_id hash matches expected value
    // This ensures trace generation matches the hash computation implementation
    let wallet_id_hash: Bytes32 = poseidon2_hash_fixed(&[WALLET_INIT_DOMAIN, &old_wallet.id[..]]);
    let expected_init_fields = bytes32_to_fields(wallet_id_hash);
    if computed_wallet_init_output != expected_init_fields {
        return Err(crate::Error::Zkp(crate::errors::ZkpError::TraceGenerationFailed(
            "Wallet init output mismatch: computed hash does not match expected wallet_id hash"
                .to_string(),
        )));
    }

    // Generate rows for active channels
    // Each row represents one channel from the union of old and new wallets
    let mut is_first_channel = true;
    for (channel_id, (is_in_old, is_in_new, old_commitment, new_commitment)) in
        all_channels.iter().take(num_active_channels)
    {
        let mut row = vec![Val::ZERO; total_cols];

        row[column_offsets::IS_IN_OLD_COL] = if *is_in_old { Val::ONE } else { Val::ZERO };
        row[column_offsets::IS_IN_NEW_COL] = if *is_in_new { Val::ONE } else { Val::ZERO };

        // Set previous accumulators for this row
        // First channel: old_acc starts from old_wallet_commitment, new_acc starts from wallet_id_hash
        // Subsequent channels: both start from their respective current accumulator values
        let prev_old_acc = if is_first_channel { first_row_prev_acc } else { old_accumulator };
        let prev_new_acc = if is_first_channel { wallet_id_hash } else { new_accumulator };

        is_first_channel = false;

        let prev_old_acc_fields = bytes32_to_fields(prev_old_acc);
        row[column_offsets::PREV_OLD_ACC_START..column_offsets::PREV_OLD_ACC_END]
            .copy_from_slice(&prev_old_acc_fields);

        let prev_new_acc_fields = bytes32_to_fields(prev_new_acc);
        row[column_offsets::PREV_NEW_ACC_START..column_offsets::PREV_NEW_ACC_END]
            .copy_from_slice(&prev_new_acc_fields);

        let channel_id_fields = bytes32_to_fields(*channel_id);
        row[column_offsets::CHANNEL_ID_START..column_offsets::CHANNEL_ID_END]
            .copy_from_slice(&channel_id_fields);

        let trace_commitment = if *is_in_new { *new_commitment } else { *old_commitment };
        let channel_commitment_fields = bytes32_to_fields(trace_commitment);
        row[column_offsets::CHANNEL_COMMITMENT_START..column_offsets::CHANNEL_COMMITMENT_END]
            .copy_from_slice(&channel_commitment_fields);

        // Old accumulator remains unchanged (old wallet doesn't change in a transition)
        let next_old_acc = prev_old_acc;

        let next_old_acc_fields = bytes32_to_fields(next_old_acc);
        row[column_offsets::NEXT_OLD_ACC_START..column_offsets::NEXT_OLD_ACC_END]
            .copy_from_slice(&next_old_acc_fields);

        // Generate Poseidon2 trace for old accumulator computation
        // For old accumulator, channel_hash is always zero (old wallet doesn't change)
        let old_channel_hash_bytes: Bytes32 = [0u8; 32];
        let mut old_accumulator_input_bytes = Vec::new();
        old_accumulator_input_bytes.extend_from_slice(CHAIN_DOMAIN);
        old_accumulator_input_bytes.extend_from_slice(&prev_old_acc[..]);
        old_accumulator_input_bytes.extend_from_slice(&old_channel_hash_bytes[..]);

        let (old_accumulator_traces, _) = poseidon2_trace_common::generate_multi_permutation_traces(
            &old_accumulator_input_bytes,
            &constants.round_constants,
            &constants.external_constants,
            &constants.internal_constants,
        );

        // Verify old accumulator trace count matches expected number of permutations
        if old_accumulator_traces.len() != column_offsets::ACCUMULATOR_PERMUTATIONS {
            return Err(crate::Error::Zkp(crate::errors::ZkpError::TraceGenerationFailed(
                format!(
                    "Old accumulator trace count mismatch: expected {}, got {}",
                    column_offsets::ACCUMULATOR_PERMUTATIONS,
                    old_accumulator_traces.len()
                ),
            )));
        }

        copy_traces_to_row(
            &mut row,
            &old_accumulator_traces,
            column_offsets::OLD_ACCUMULATOR_POSEIDON2_START,
        );

        // Generate Poseidon2 trace for new accumulator computation
        // Channel hash is computed only if channel is in new wallet
        let new_channel_hash_bytes: Bytes32 = if *is_in_new {
            poseidon2_hash_fixed(&[WALLET_HASH_DOMAIN, &channel_id[..], &new_commitment[..]])
        } else {
            [0u8; 32]
        };
        let mut new_accumulator_input_bytes = Vec::new();
        new_accumulator_input_bytes.extend_from_slice(CHAIN_DOMAIN);
        new_accumulator_input_bytes.extend_from_slice(&prev_new_acc[..]);
        new_accumulator_input_bytes.extend_from_slice(&new_channel_hash_bytes[..]);

        let (new_accumulator_traces, computed_new_output) =
            poseidon2_trace_common::generate_multi_permutation_traces(
                &new_accumulator_input_bytes,
                &constants.round_constants,
                &constants.external_constants,
                &constants.internal_constants,
            );

        // Verify new accumulator trace count matches expected number of permutations
        if new_accumulator_traces.len() != column_offsets::ACCUMULATOR_PERMUTATIONS {
            return Err(crate::Error::Zkp(crate::errors::ZkpError::TraceGenerationFailed(
                format!(
                    "New accumulator trace count mismatch: expected {}, got {}",
                    column_offsets::ACCUMULATOR_PERMUTATIONS,
                    new_accumulator_traces.len()
                ),
            )));
        }

        // Compute next_new_acc from Poseidon2 output (only if channel is in new wallet)
        let next_new_acc = if *is_in_new {
            // Convert computed output back to Bytes32
            // This matches the hash computation: Poseidon2 output is 8 field elements = 32 bytes
            let mut next_new_acc_bytes = [0u8; 32];
            for (i, field) in computed_new_output.iter().enumerate() {
                let val = PrimeField32::as_canonical_u32(field);
                next_new_acc_bytes[i * 4..(i + 1) * 4].copy_from_slice(&val.to_le_bytes());
            }
            next_new_acc_bytes
        } else {
            // Channel not in new wallet: accumulator remains unchanged
            prev_new_acc
        };

        let next_new_acc_fields = bytes32_to_fields(next_new_acc);
        row[column_offsets::NEXT_NEW_ACC_START..column_offsets::NEXT_NEW_ACC_END]
            .copy_from_slice(&next_new_acc_fields);

        old_accumulator = next_old_acc;
        new_accumulator = next_new_acc;

        copy_traces_to_row(
            &mut row,
            &new_accumulator_traces,
            column_offsets::new_accumulator_poseidon2_start(),
        );

        copy_traces_to_row(
            &mut row,
            &wallet_init_traces,
            column_offsets::wallet_init_poseidon2_start(),
        );

        values.extend_from_slice(&row);
    }

    // Verify final accumulators match expected commitments
    // This ensures trace generation correctly computes the accumulator chains
    if old_accumulator != old_wallet_commitment {
        return Err(crate::Error::Zkp(crate::errors::ZkpError::TraceGenerationFailed(format!(
            "Final old accumulator ({:?}) does not match old wallet commitment ({:?})",
            old_accumulator, old_wallet_commitment
        ))));
    }

    if new_accumulator != new_wallet_commitment {
        return Err(crate::Error::Zkp(crate::errors::ZkpError::TraceGenerationFailed(format!(
            "Final new accumulator ({:?}) does not match new wallet commitment ({:?})",
            new_accumulator, new_wallet_commitment
        ))));
    }

    // Generate padding rows (inactive channels)
    // For padding rows: is_in_old=0, is_in_new=0, accumulators remain stable
    let num_padding = num_rows - num_active_channels;
    for _ in 0..num_padding {
        let mut row = vec![Val::ZERO; total_cols];

        row[column_offsets::IS_IN_OLD_COL] = Val::ZERO;
        row[column_offsets::IS_IN_NEW_COL] = Val::ZERO;

        let stable_old_acc_fields = bytes32_to_fields(old_accumulator);
        row[column_offsets::PREV_OLD_ACC_START..column_offsets::PREV_OLD_ACC_END]
            .copy_from_slice(&stable_old_acc_fields);
        row[column_offsets::NEXT_OLD_ACC_START..column_offsets::NEXT_OLD_ACC_END]
            .copy_from_slice(&stable_old_acc_fields);

        let stable_new_acc_fields = bytes32_to_fields(new_accumulator);
        row[column_offsets::PREV_NEW_ACC_START..column_offsets::PREV_NEW_ACC_END]
            .copy_from_slice(&stable_new_acc_fields);
        row[column_offsets::NEXT_NEW_ACC_START..column_offsets::NEXT_NEW_ACC_END]
            .copy_from_slice(&stable_new_acc_fields);

        // Generate dummy Poseidon2 traces for padding rows
        // These traces use zero channel_hash (inactive channel)
        let mut dummy_old_input = Vec::new();
        dummy_old_input.extend_from_slice(CHAIN_DOMAIN);
        dummy_old_input.extend_from_slice(&old_accumulator);
        dummy_old_input.extend_from_slice(&[0u8; 32]); // zero channel_hash for inactive

        let (old_accumulator_traces, _) = poseidon2_trace_common::generate_multi_permutation_traces(
            &dummy_old_input,
            &constants.round_constants,
            &constants.external_constants,
            &constants.internal_constants,
        );

        copy_traces_to_row(
            &mut row,
            &old_accumulator_traces,
            column_offsets::OLD_ACCUMULATOR_POSEIDON2_START,
        );

        let mut dummy_new_input = Vec::new();
        dummy_new_input.extend_from_slice(CHAIN_DOMAIN);
        dummy_new_input.extend_from_slice(&new_accumulator);
        dummy_new_input.extend_from_slice(&[0u8; 32]); // zero channel_hash for inactive

        let (new_accumulator_traces, _) = poseidon2_trace_common::generate_multi_permutation_traces(
            &dummy_new_input,
            &constants.round_constants,
            &constants.external_constants,
            &constants.internal_constants,
        );

        copy_traces_to_row(
            &mut row,
            &new_accumulator_traces,
            column_offsets::new_accumulator_poseidon2_start(),
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

/// Build trace matrix for a sequence of wallet transitions.
///
/// This function builds a trace by concatenating multiple single-transition traces.
/// It ensures continuity between transitions by setting prev_old_acc/prev_new_acc on
/// the first row of each subsequent transition to match the next_new_acc from the
/// previous transition.
///
/// # Arguments
/// * `wallets` - Sequence of wallet states (must have length = transitions.len() + 1)
/// * `transitions` - Sequence of wallet transitions (one per transition)
pub(super) fn build_sequence_trace(
    wallets: &[WalletState],
    transitions: &[WalletTransition],
) -> Result<Trace> {
    if wallets.is_empty() {
        return Err(crate::Error::Zkp(crate::errors::ZkpError::TraceGenerationFailed(
            "Empty wallet sequence".to_string(),
        )));
    }

    if wallets.len() != transitions.len() + 1 {
        return Err(crate::Error::Zkp(crate::errors::ZkpError::TraceGenerationFailed(format!(
            "Invalid sequence: {} wallets but {} transitions (expected {} transitions)",
            wallets.len(),
            transitions.len(),
            wallets.len() - 1
        ))));
    }

    let mut transition_traces = Vec::new();
    for i in 0..transitions.len() {
        let old_wallet = &wallets[i];
        let new_wallet = &wallets[i + 1];
        let trace = build_transition_trace(old_wallet, new_wallet)?;
        transition_traces.push(trace);
    }

    let total_cols = column_offsets::total_cols();
    let mut all_values = Vec::new();
    let mut total_rows = 0;

    for (trace_idx, trace) in transition_traces.iter().enumerate() {
        if trace.width() != total_cols {
            return Err(crate::Error::Zkp(crate::errors::ZkpError::TraceGenerationFailed(
                format!("Trace width mismatch: expected {}, got {}", total_cols, trace.width()),
            )));
        }

        let prev_accumulators = if trace_idx > 0 {
            let prev_trace = &transition_traces[trace_idx - 1];
            let prev_last_row =
                prev_trace.row_slice(prev_trace.height() - 1).expect("Prev last row should exist");
            let old_acc = prev_last_row
                [column_offsets::NEXT_OLD_ACC_START..column_offsets::NEXT_OLD_ACC_END]
                .to_vec();
            let new_acc = prev_last_row
                [column_offsets::NEXT_NEW_ACC_START..column_offsets::NEXT_NEW_ACC_END]
                .to_vec();
            Some((old_acc, new_acc))
        } else {
            None
        };

        for row_idx in 0..trace.height() {
            let mut row = trace.row_slice(row_idx).expect("Row should exist").to_vec();

            // Ensure continuity: old_wallet[i] == new_wallet[i-1], so use previous transition's NEXT_NEW_ACC.
            if trace_idx > 0 && row_idx == 0 {
                if let Some((_, ref prev_new)) = prev_accumulators {
                    row[column_offsets::PREV_OLD_ACC_START..column_offsets::PREV_OLD_ACC_END]
                        .copy_from_slice(prev_new);
                    row[column_offsets::PREV_NEW_ACC_START..column_offsets::PREV_NEW_ACC_END]
                        .copy_from_slice(prev_new);
                    row[column_offsets::NEXT_OLD_ACC_START..column_offsets::NEXT_OLD_ACC_END]
                        .copy_from_slice(prev_new);
                }
            }

            all_values.extend_from_slice(&row);
            total_rows += 1;
        }
    }

    // Pad to power of 2 by repeating the last row
    const MIN_ROWS: usize = 8; // Minimum rows needed (power of 2)
    let padded_rows = total_rows.max(MIN_ROWS).next_power_of_two();
    if padded_rows > total_rows {
        let last_trace = &transition_traces[transition_traces.len() - 1];
        let last_row_idx = last_trace.height() - 1;
        let last_row_slice = last_trace.row_slice(last_row_idx).expect("Last row should exist");

        // Add padding rows (repeating last row)
        let num_padding = padded_rows - total_rows;
        for _ in 0..num_padding {
            let mut padding_row = vec![Val::ZERO; total_cols];

            padding_row[column_offsets::PREV_OLD_ACC_START..column_offsets::PREV_OLD_ACC_END]
                .copy_from_slice(
                    &last_row_slice
                        [column_offsets::NEXT_OLD_ACC_START..column_offsets::NEXT_OLD_ACC_END],
                );
            padding_row[column_offsets::NEXT_OLD_ACC_START..column_offsets::NEXT_OLD_ACC_END]
                .copy_from_slice(
                    &last_row_slice
                        [column_offsets::NEXT_OLD_ACC_START..column_offsets::NEXT_OLD_ACC_END],
                );
            padding_row[column_offsets::PREV_NEW_ACC_START..column_offsets::PREV_NEW_ACC_END]
                .copy_from_slice(
                    &last_row_slice
                        [column_offsets::NEXT_NEW_ACC_START..column_offsets::NEXT_NEW_ACC_END],
                );
            padding_row[column_offsets::NEXT_NEW_ACC_START..column_offsets::NEXT_NEW_ACC_END]
                .copy_from_slice(
                    &last_row_slice
                        [column_offsets::NEXT_NEW_ACC_START..column_offsets::NEXT_NEW_ACC_END],
                );

            let poseidon2_start = column_offsets::OLD_ACCUMULATOR_POSEIDON2_START;
            let poseidon2_end = column_offsets::total_cols();
            padding_row[poseidon2_start..poseidon2_end]
                .copy_from_slice(&last_row_slice[poseidon2_start..poseidon2_end]);

            all_values.extend_from_slice(&padding_row);
        }
    }

    Ok(RowMajorMatrix::new(all_values, total_cols))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use p3_field::PrimeField32;
    use p3_matrix::Matrix;

    use super::*;
    use crate::wallet::commitment::compute_commitment_from_channels;
    use crate::wallet::operation::WalletTransition;
    use crate::wallet::state::WalletState;
    use crate::wallet::transition::apply_operation;

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

    /// Helper to extract Bytes32 from trace row fields
    fn fields_to_bytes32(row: &[Val], start: usize, end: usize) -> Bytes32 {
        let mut bytes = [0u8; 32];
        for (i, field) in row[start..end].iter().enumerate() {
            let val = PrimeField32::as_canonical_u32(field);
            bytes[i * 4..(i + 1) * 4].copy_from_slice(&val.to_le_bytes());
        }
        bytes
    }

    /// Helper to get row as Vec<Val> from trace
    fn get_row_vec(trace: &Trace, row_idx: usize) -> Vec<Val> {
        trace.row_slice(row_idx).expect("Row should exist").to_vec()
    }

    #[test]
    fn test_build_transition_trace() {
        // Test: Basic structure verification
        let old_w = wallet(1, &[]);
        let mut channel_id = [0u8; 32];
        channel_id[31] = 2;
        let mut channel_commitment = [0u8; 32];
        channel_commitment[31] = 3;
        let transition = WalletTransition::InsertChannel { channel_id, channel_commitment };

        let old_w_copy = WalletState {
            id: old_w.id,
            channels: old_w.channels.clone(),
            commitment: old_w.commitment,
        };
        let new_w = apply_operation(old_w_copy, &transition).expect("should apply transition");

        let trace =
            build_transition_trace(&old_w, &new_w).expect("failed to build transition trace");
        let expected_cols = column_offsets::total_cols();
        assert_eq!(trace.width(), expected_cols, "Trace should have correct width");
        assert!(trace.height() >= 8, "Trace should have at least 8 rows (power of 2)");
        assert!(
            trace.height().is_power_of_two(),
            "Trace height should be power of 2, got {}",
            trace.height()
        );

        // Test: Error case - too many channels
        let mut pairs = Vec::new();
        for i in 0..16u8 {
            pairs.push((i, i + 100));
        }
        let old_w_max = wallet(1, &pairs);
        let mut new_channels = old_w_max.channels.clone();
        let mut channel_id = [0u8; 32];
        channel_id[31] = 17;
        let mut channel_commitment = [0u8; 32];
        channel_commitment[31] = 117;
        new_channels.insert(channel_id, channel_commitment);

        let new_w_max =
            WalletState { id: old_w_max.id, channels: new_channels, commitment: [0u8; 32] };

        let result = build_transition_trace(&old_w_max, &new_w_max);
        assert!(result.is_err(), "Should fail when transition has more than MAX_CHANNELS");

        // Test: Trace content - channel IDs, commitments, flags
        let old_w = wallet(1, &[(2, 10), (4, 20)]);
        let mut channel_id = [0u8; 32];
        channel_id[31] = 6;
        let mut channel_commitment = [0u8; 32];
        channel_commitment[31] = 30;
        let transition = WalletTransition::InsertChannel { channel_id, channel_commitment };

        let old_w_copy = WalletState {
            id: old_w.id,
            channels: old_w.channels.clone(),
            commitment: old_w.commitment,
        };
        let new_w = apply_operation(old_w_copy, &transition).expect("should apply transition");

        let trace =
            build_transition_trace(&old_w, &new_w).expect("failed to build transition trace");

        let mut found_channels = Vec::new();
        for row_idx in 0..trace.height() {
            let row = get_row_vec(&trace, row_idx);
            let is_in_old = row[column_offsets::IS_IN_OLD_COL];
            let is_in_new = row[column_offsets::IS_IN_NEW_COL];

            if is_in_old == Val::ZERO && is_in_new == Val::ZERO {
                continue;
            }

            let row_channel_id = fields_to_bytes32(
                &row,
                column_offsets::CHANNEL_ID_START,
                column_offsets::CHANNEL_ID_END,
            );
            let row_commitment = fields_to_bytes32(
                &row,
                column_offsets::CHANNEL_COMMITMENT_START,
                column_offsets::CHANNEL_COMMITMENT_END,
            );

            found_channels.push((row_channel_id, is_in_old, is_in_new, row_commitment));
        }

        assert_eq!(found_channels.len(), 3, "Should have 3 active channels");

        let both = found_channels
            .iter()
            .find(|(id, _, _, _)| id[31] == 2)
            .expect("Channel 2 should exist");
        assert_eq!(both.1, Val::ONE, "Channel 2 should be in old wallet");
        assert_eq!(both.2, Val::ONE, "Channel 2 should be in new wallet");
        assert_eq!(both.3[31], 10, "Channel 2 should have commitment 10");

        let new_only = found_channels
            .iter()
            .find(|(id, _, _, _)| id[31] == 6)
            .expect("Channel 6 should exist");
        assert_eq!(new_only.1, Val::ZERO, "Channel 6 should not be in old wallet");
        assert_eq!(new_only.2, Val::ONE, "Channel 6 should be in new wallet");
        assert_eq!(new_only.3[31], 30, "Channel 6 should have commitment 30");

        // Test: Accumulator values verification
        let old_commitment = compute_commitment_from_channels(old_w.id, &old_w.channels)
            .expect("should compute commitment");
        let first_row = get_row_vec(&trace, 0);
        let first_prev_old_acc = fields_to_bytes32(
            &first_row,
            column_offsets::PREV_OLD_ACC_START,
            column_offsets::PREV_OLD_ACC_END,
        );
        if old_w.channels.is_empty() {
            assert_eq!(
                first_prev_old_acc, old_commitment,
                "First row prev_old_acc should match old_commitment for empty wallet"
            );
        }

        for row_idx in 0..trace.height() {
            let row = get_row_vec(&trace, row_idx);
            let is_in_old = row[column_offsets::IS_IN_OLD_COL];
            let is_in_new = row[column_offsets::IS_IN_NEW_COL];

            if is_in_old == Val::ZERO && is_in_new == Val::ZERO {
                continue;
            }

            let prev_old_acc = fields_to_bytes32(
                &row,
                column_offsets::PREV_OLD_ACC_START,
                column_offsets::PREV_OLD_ACC_END,
            );
            let next_old_acc = fields_to_bytes32(
                &row,
                column_offsets::NEXT_OLD_ACC_START,
                column_offsets::NEXT_OLD_ACC_END,
            );
            assert_eq!(
                prev_old_acc, next_old_acc,
                "Old accumulator should remain unchanged on row {}",
                row_idx
            );
        }

        // Test: Channel union - channel in both wallets
        let old_w_both = wallet(1, &[(2, 10)]);
        let new_w_both = wallet(1, &[(2, 20)]);
        let trace_both =
            build_transition_trace(&old_w_both, &new_w_both).expect("failed to build trace");

        let mut found_both = false;
        for row_idx in 0..trace_both.height() {
            let row = get_row_vec(&trace_both, row_idx);
            let is_in_old = row[column_offsets::IS_IN_OLD_COL];
            let is_in_new = row[column_offsets::IS_IN_NEW_COL];

            if is_in_old == Val::ONE && is_in_new == Val::ONE {
                found_both = true;
                let row_channel_id = fields_to_bytes32(
                    &row,
                    column_offsets::CHANNEL_ID_START,
                    column_offsets::CHANNEL_ID_END,
                );
                assert_eq!(row_channel_id[31], 2, "Channel should be channel 2");
                let row_commitment = fields_to_bytes32(
                    &row,
                    column_offsets::CHANNEL_COMMITMENT_START,
                    column_offsets::CHANNEL_COMMITMENT_END,
                );
                assert_eq!(row_commitment[31], 20, "Commitment should be from new wallet");
                break;
            }
        }
        assert!(found_both, "Should find channel in both wallets");

        // Test: Padding rows verification
        let old_w_pad = wallet(1, &[(2, 10)]);
        let new_w_pad = wallet(1, &[(2, 10)]);
        let trace_pad =
            build_transition_trace(&old_w_pad, &new_w_pad).expect("failed to build trace");
        let num_active = 1usize;
        let expected_rows = num_active.max(8).next_power_of_two();
        assert_eq!(trace_pad.height(), expected_rows, "Trace should be padded to power of 2");

        let mut padding_count = 0;
        let last_active_row_old_acc = {
            let row = get_row_vec(&trace_pad, 0);
            fields_to_bytes32(
                &row,
                column_offsets::NEXT_OLD_ACC_START,
                column_offsets::NEXT_OLD_ACC_END,
            )
        };
        let last_active_row_new_acc = {
            let row = get_row_vec(&trace_pad, 0);
            fields_to_bytes32(
                &row,
                column_offsets::NEXT_NEW_ACC_START,
                column_offsets::NEXT_NEW_ACC_END,
            )
        };

        for row_idx in 0..trace_pad.height() {
            let row = get_row_vec(&trace_pad, row_idx);
            let is_in_old = row[column_offsets::IS_IN_OLD_COL];
            let is_in_new = row[column_offsets::IS_IN_NEW_COL];

            if is_in_old == Val::ZERO && is_in_new == Val::ZERO {
                padding_count += 1;
                let prev_old_acc = fields_to_bytes32(
                    &row,
                    column_offsets::PREV_OLD_ACC_START,
                    column_offsets::PREV_OLD_ACC_END,
                );
                let next_old_acc = fields_to_bytes32(
                    &row,
                    column_offsets::NEXT_OLD_ACC_START,
                    column_offsets::NEXT_OLD_ACC_END,
                );
                let prev_new_acc = fields_to_bytes32(
                    &row,
                    column_offsets::PREV_NEW_ACC_START,
                    column_offsets::PREV_NEW_ACC_END,
                );
                let next_new_acc = fields_to_bytes32(
                    &row,
                    column_offsets::NEXT_NEW_ACC_START,
                    column_offsets::NEXT_NEW_ACC_END,
                );

                assert_eq!(
                    prev_old_acc, next_old_acc,
                    "Padding row old accumulator should be stable"
                );
                assert_eq!(
                    prev_new_acc, next_new_acc,
                    "Padding row new accumulator should be stable"
                );
                assert_eq!(
                    prev_old_acc, last_active_row_old_acc,
                    "Padding row should use last active old accumulator"
                );
                assert_eq!(
                    prev_new_acc, last_active_row_new_acc,
                    "Padding row should use last active new accumulator"
                );
            }
        }

        assert_eq!(
            padding_count,
            expected_rows - num_active,
            "Should have correct number of padding rows"
        );
    }

    #[test]
    fn test_build_sequence_trace() {
        // Test: Basic structure verification
        let old_w = wallet(1, &[]);
        let mut channel_id1 = [0u8; 32];
        channel_id1[31] = 2;
        let mut channel_commitment1 = [0u8; 32];
        channel_commitment1[31] = 10;
        let transition1 = WalletTransition::InsertChannel {
            channel_id: channel_id1,
            channel_commitment: channel_commitment1,
        };

        let old_w_copy = WalletState {
            id: old_w.id,
            channels: old_w.channels.clone(),
            commitment: old_w.commitment,
        };
        let mid_w = apply_operation(old_w_copy, &transition1).expect("should apply transition");

        let mut channel_id2 = [0u8; 32];
        channel_id2[31] = 4;
        let mut channel_commitment2 = [0u8; 32];
        channel_commitment2[31] = 20;
        let transition2 = WalletTransition::InsertChannel {
            channel_id: channel_id2,
            channel_commitment: channel_commitment2,
        };

        let mid_w_copy = WalletState {
            id: mid_w.id,
            channels: mid_w.channels.clone(),
            commitment: mid_w.commitment,
        };
        let new_w = apply_operation(mid_w_copy, &transition2).expect("should apply transition");

        let wallets = vec![
            WalletState {
                id: old_w.id,
                channels: old_w.channels.clone(),
                commitment: old_w.commitment,
            },
            WalletState {
                id: mid_w.id,
                channels: mid_w.channels.clone(),
                commitment: mid_w.commitment,
            },
            WalletState {
                id: new_w.id,
                channels: new_w.channels.clone(),
                commitment: new_w.commitment,
            },
        ];
        let transitions = vec![transition1.clone(), transition2.clone()];

        let trace =
            build_sequence_trace(&wallets, &transitions).expect("failed to build sequence trace");
        let expected_cols = column_offsets::total_cols();
        assert_eq!(trace.width(), expected_cols, "Sequence trace should have correct width");

        let trace1 = build_transition_trace(&old_w, &mid_w).expect("should build first transition");
        let trace2 =
            build_transition_trace(&mid_w, &new_w).expect("should build second transition");
        let expected_total_rows = trace1.height() + trace2.height();
        let expected_padded_rows = expected_total_rows.max(8).next_power_of_two();
        assert_eq!(
            trace.height(),
            expected_padded_rows,
            "Sequence trace should be padded to power of 2"
        );

        // Test: Error cases
        let result = build_sequence_trace(&[], &[]);
        assert!(result.is_err(), "Should fail with empty wallets");

        let wallets_invalid = vec![WalletState {
            id: old_w.id,
            channels: old_w.channels.clone(),
            commitment: old_w.commitment,
        }];
        let transitions_invalid = vec![transition1.clone(), transition2.clone()];
        let result = build_sequence_trace(&wallets_invalid, &transitions_invalid);
        assert!(result.is_err(), "Should fail when wallets.len() != transitions.len() + 1");

        // Test: Continuity between transitions
        let trace_seq =
            build_sequence_trace(&wallets, &transitions).expect("should build sequence trace");
        let trace1_height = trace1.height();
        let first_row_second_transition = get_row_vec(&trace_seq, trace1_height);
        let last_row_first_transition = get_row_vec(&trace_seq, trace1_height - 1);

        let prev_old_acc_second = fields_to_bytes32(
            &first_row_second_transition,
            column_offsets::PREV_OLD_ACC_START,
            column_offsets::PREV_OLD_ACC_END,
        );
        let prev_new_acc_second = fields_to_bytes32(
            &first_row_second_transition,
            column_offsets::PREV_NEW_ACC_START,
            column_offsets::PREV_NEW_ACC_END,
        );
        let next_new_acc_first = fields_to_bytes32(
            &last_row_first_transition,
            column_offsets::NEXT_NEW_ACC_START,
            column_offsets::NEXT_NEW_ACC_END,
        );

        assert_eq!(
            prev_old_acc_second, next_new_acc_first,
            "prev_old_acc on first row of second transition should match next_new_acc from first transition"
        );
        assert_eq!(
            prev_new_acc_second, next_new_acc_first,
            "prev_new_acc on first row of second transition should match next_new_acc from first transition"
        );

        // Test: Multiple transitions
        let old_w3 = wallet(1, &[]);
        let mut channel_id3 = [0u8; 32];
        channel_id3[31] = 6;
        let mut channel_commitment3 = [0u8; 32];
        channel_commitment3[31] = 30;
        let transition3 = WalletTransition::InsertChannel {
            channel_id: channel_id3,
            channel_commitment: channel_commitment3,
        };

        let old_w3_copy = WalletState {
            id: old_w3.id,
            channels: old_w3.channels.clone(),
            commitment: old_w3.commitment,
        };
        let mid_w3 = apply_operation(old_w3_copy, &transition3).expect("should apply transition");

        let mid_w3_copy = WalletState {
            id: mid_w3.id,
            channels: mid_w3.channels.clone(),
            commitment: mid_w3.commitment,
        };
        let final_w3 = apply_operation(mid_w3_copy, &transition1).expect("should apply transition");

        let wallets3 = vec![
            WalletState {
                id: old_w3.id,
                channels: old_w3.channels.clone(),
                commitment: old_w3.commitment,
            },
            WalletState {
                id: mid_w3.id,
                channels: mid_w3.channels.clone(),
                commitment: mid_w3.commitment,
            },
            WalletState {
                id: final_w3.id,
                channels: final_w3.channels.clone(),
                commitment: final_w3.commitment,
            },
        ];
        let transitions3 = vec![transition3.clone(), transition1.clone()];

        let trace3 = build_sequence_trace(&wallets3, &transitions3)
            .expect("should build 3-transition trace");
        let trace3_1 =
            build_transition_trace(&old_w3, &mid_w3).expect("should build first transition");
        let trace3_2 =
            build_transition_trace(&mid_w3, &final_w3).expect("should build second transition");
        let expected_rows3 = trace3_1.height() + trace3_2.height();
        let expected_padded_rows3 = expected_rows3.max(8).next_power_of_two();
        assert_eq!(
            trace3.height(),
            expected_padded_rows3,
            "3-transition trace should have correct padded height"
        );

        // Test: Padding verification
        let trace_padded =
            build_sequence_trace(&wallets, &transitions).expect("should build sequence trace");
        let num_active_rows = trace1.height() + trace2.height();
        let expected_padded = num_active_rows.max(8).next_power_of_two();
        assert_eq!(
            trace_padded.height(),
            expected_padded,
            "Sequence trace should be padded to power of 2"
        );

        if expected_padded > num_active_rows {
            let last_active_row = get_row_vec(&trace_padded, num_active_rows - 1);
            let first_padding_row = get_row_vec(&trace_padded, num_active_rows);

            let last_prev_old = fields_to_bytes32(
                &last_active_row,
                column_offsets::NEXT_OLD_ACC_START,
                column_offsets::NEXT_OLD_ACC_END,
            );
            let last_prev_new = fields_to_bytes32(
                &last_active_row,
                column_offsets::NEXT_NEW_ACC_START,
                column_offsets::NEXT_NEW_ACC_END,
            );

            let pad_prev_old = fields_to_bytes32(
                &first_padding_row,
                column_offsets::PREV_OLD_ACC_START,
                column_offsets::PREV_OLD_ACC_END,
            );
            let pad_next_old = fields_to_bytes32(
                &first_padding_row,
                column_offsets::NEXT_OLD_ACC_START,
                column_offsets::NEXT_OLD_ACC_END,
            );
            let pad_prev_new = fields_to_bytes32(
                &first_padding_row,
                column_offsets::PREV_NEW_ACC_START,
                column_offsets::PREV_NEW_ACC_END,
            );
            let pad_next_new = fields_to_bytes32(
                &first_padding_row,
                column_offsets::NEXT_NEW_ACC_START,
                column_offsets::NEXT_NEW_ACC_END,
            );

            assert_eq!(
                pad_prev_old, last_prev_old,
                "Padding row prev_old_acc should match last active next_old_acc"
            );
            assert_eq!(
                pad_next_old, last_prev_old,
                "Padding row next_old_acc should match last active next_old_acc"
            );
            assert_eq!(
                pad_prev_new, last_prev_new,
                "Padding row prev_new_acc should match last active next_new_acc"
            );
            assert_eq!(
                pad_next_new, last_prev_new,
                "Padding row next_new_acc should match last active next_new_acc"
            );
        }
    }
}
