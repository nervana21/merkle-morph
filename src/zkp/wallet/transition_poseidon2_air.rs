//! Poseidon2 AIR integration for wallet transition verification
//!
//! This module provides the infrastructure for full in-circuit Poseidon2 hash verification
//! for wallet state transitions. It implements Poseidon2 AIR columns and constraints for
//! verifying both old and new wallet commitment aggregation in parallel.

// Re-export for convenience
pub(crate) use crate::zkp::poseidon2_common::create_poseidon2_constants_and_params;
use crate::zkp::poseidon2_common::{
    create_poseidon2_air as create_common_poseidon2_air, CommonPoseidon2Air,
};

/// Poseidon2 AIR type for wallet transitions (reuses wallet commitment AIR)
pub(super) type WalletTransitionPoseidon2Air = CommonPoseidon2Air;

/// Create Poseidon2 AIR instance for wallet transitions
pub(super) fn create_poseidon2_air() -> WalletTransitionPoseidon2Air {
    create_common_poseidon2_air()
}

/// Column offsets for Poseidon2 AIR columns in the wallet transition trace
///
/// The trace structure supports proving arbitrary numbers of transitions (0, 1, or 1+):
/// - 0 transitions: Use `prove_wallet_commitment` to prove a wallet state without transitions
/// - 1+ transitions: Use `prove_wallet_transition_sequence` for any number of transitions (1, 2, N)
///   - The single-transition functions (`prove_wallet_transition`, `verify_wallet_transition`) are
///     just convenience wrappers that call the sequence functions internally
///   - The number of transitions is private and verified implicitly through the trace structure
///
/// The trace structure is multi-row (one row per channel in the union of old and new wallets):
/// - Each row contains the same columns regardless of transition count:
///   - Columns 0-7: channel_id (8 fields) - channel identifier
///   - Columns 8-15: channel_commitment (8 fields) - channel commitment (from old or new wallet)
///   - Column 16: is_in_old (1 field) - flag indicating if channel exists in old wallet
///   - Column 17: is_in_new (1 field) - flag indicating if channel exists in new wallet
///   - Columns 18-25: prev_old_acc (8 fields) - old accumulator before processing this channel
///   - Columns 26-33: next_old_acc (8 fields) - old accumulator after processing this channel
///   - Columns 34-41: prev_new_acc (8 fields) - new accumulator before processing this channel
///   - Columns 42-49: next_new_acc (8 fields) - new accumulator after processing this channel
///   - Columns 50+: Poseidon2 AIR columns for old accumulator computation (3 permutations)
///   - Columns 50+poseidon2_cols*3+: Poseidon2 AIR columns for new accumulator computation (3 permutations)
///   - Columns 50+poseidon2_cols*6+: Poseidon2 AIR columns for wallet_id initialization (2 permutations)
///
/// For sequences of transitions, the trace builder:
/// 1. Builds each transition trace independently using `build_transition_trace`
/// 2. Concatenates them row-by-row (so 2 transitions = 2x the rows, same columns per row)
/// 3. Ensures continuity between transitions by setting prev_old_acc/prev_new_acc on the
///    first row of each subsequent transition to match the next_new_acc from the previous transition
pub(super) mod column_offsets {
    use crate::zkp::poseidon2_common::poseidon2_air_num_cols;

    /// Column offsets within a row (same for all rows)
    /// Starting column index for the channel ID (8 fields)
    pub(crate) const CHANNEL_ID_START: usize = 0;
    /// Ending column index (exclusive) for the channel ID
    pub(crate) const CHANNEL_ID_END: usize = 8;
    /// Starting column index for the channel commitment (8 fields)
    pub(crate) const CHANNEL_COMMITMENT_START: usize = 8;
    /// Ending column index (exclusive) for the channel commitment
    pub(crate) const CHANNEL_COMMITMENT_END: usize = 16;
    /// Column index for the is_in_old flag (1 field)
    pub(crate) const IS_IN_OLD_COL: usize = 16;
    /// Column index for the is_in_new flag (1 field)
    pub(crate) const IS_IN_NEW_COL: usize = 17;
    /// Starting column index for the previous old accumulator (8 fields)
    pub(crate) const PREV_OLD_ACC_START: usize = 18;
    /// Ending column index (exclusive) for the previous old accumulator
    pub(crate) const PREV_OLD_ACC_END: usize = 26;
    /// Starting column index for the next old accumulator (8 fields)
    pub(crate) const NEXT_OLD_ACC_START: usize = 26;
    /// Ending column index (exclusive) for the next old accumulator
    pub(crate) const NEXT_OLD_ACC_END: usize = 34;
    /// Starting column index for the previous new accumulator (8 fields)
    pub(crate) const PREV_NEW_ACC_START: usize = 34;
    /// Ending column index (exclusive) for the previous new accumulator
    pub(crate) const PREV_NEW_ACC_END: usize = 42;
    /// Starting column index for the next new accumulator (8 fields)
    pub(crate) const NEXT_NEW_ACC_START: usize = 42;
    /// Ending column index (exclusive) for the next new accumulator
    pub(crate) const NEXT_NEW_ACC_END: usize = 50;
    /// Starting column index for Poseidon2 AIR columns for old accumulator computation
    pub(crate) const OLD_ACCUMULATOR_POSEIDON2_START: usize = 50;

    /// Number of Poseidon2 permutations needed for accumulator (77 bytes = 19.25 elements -> 3 permutations)
    /// Input: CHAIN_DOMAIN (13 bytes) + prev_accumulator (32 bytes) + channel_hash_bytes (32 bytes) = 77 bytes
    /// With RATE = 8 (32 bytes per permutation): 32 + 32 + 13 = 3 permutations
    pub(crate) const ACCUMULATOR_PERMUTATIONS: usize = 3;

    /// Offset for new accumulator Poseidon2 columns
    pub(crate) fn new_accumulator_poseidon2_start() -> usize {
        let poseidon2_cols = poseidon2_air_num_cols();
        OLD_ACCUMULATOR_POSEIDON2_START + ACCUMULATOR_PERMUTATIONS * poseidon2_cols
    }

    /// Offset for wallet_id initialization Poseidon2 columns
    /// These columns are used to verify that the wallet_id hash is computed correctly.
    /// Note: prev_old_acc and prev_new_acc on the first row equal the initial wallet commitment
    /// (which may be just wallet_id_hash for empty wallets, or include channels for non-empty wallets).
    /// The wallet_id hash is used as the base for accumulator chain computation.
    pub(crate) fn wallet_init_poseidon2_start() -> usize {
        let poseidon2_cols = poseidon2_air_num_cols();
        new_accumulator_poseidon2_start() + ACCUMULATOR_PERMUTATIONS * poseidon2_cols
    }

    /// Number of Poseidon2 permutations needed for wallet_id initialization
    /// Input: WALLET_INIT_DOMAIN (14 bytes) + wallet_id (32 bytes) = 46 bytes = 11.5 elements
    /// With RATE = 8 (32 bytes per permutation): 32 + 14 = 2 permutations
    pub(crate) const WALLET_INIT_PERMUTATIONS: usize = 2;

    /// Total number of columns per row
    pub(crate) fn total_cols() -> usize {
        let poseidon2_cols = poseidon2_air_num_cols();
        // Base columns: is_in_old (1) + is_in_new (1) + prev_old_acc (8) + prev_new_acc (8) +
        //               channel_id (8) + channel_commitment (8) + next_old_acc (8) + next_new_acc (8) = 50
        // Plus Poseidon2 trace for old accumulator (3 permutations)
        // Plus Poseidon2 trace for new accumulator (3 permutations)
        // Plus Poseidon2 trace for wallet_id initialization (2 permutations)
        const BASE_COLS: usize = 50;
        BASE_COLS
            + ACCUMULATOR_PERMUTATIONS * poseidon2_cols
            + ACCUMULATOR_PERMUTATIONS * poseidon2_cols
            + WALLET_INIT_PERMUTATIONS * poseidon2_cols
    }
}
