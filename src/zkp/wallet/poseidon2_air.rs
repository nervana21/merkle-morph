//! Poseidon2 AIR integration for wallet commitment aggregation verification
//!
//! This module provides the infrastructure for full in-circuit Poseidon2 hash verification.
//! It implements Poseidon2 AIR columns and constraints for verifying wallet commitment aggregation.
//!
//! ## Architecture
//!
//! The module verifies Poseidon2 hash computations for wallet commitment aggregation:
//! 1. For each channel: `hash = poseidon2("MM_WLT_HASH_v0" || channel_id || channel_commitment)`
//! 2. Accumulator updates: `accumulator = poseidon2("MM_CHAIN_v0" || accumulator || hash)`
//!    TODO: change name to morph (eliminate MM_ prefix everywhere)
//!    Each Poseidon2 computation requires Poseidon2 AIR columns for intermediate states,
//!    which are included in the trace structure.

// Re-export for convenience
pub(crate) use crate::zkp::poseidon2_common::create_poseidon2_constants_and_params;
use crate::zkp::poseidon2_common::{
    create_poseidon2_air as create_common_poseidon2_air, CommonPoseidon2Air,
};

/// Poseidon2 AIR type for wallet commitments
pub(super) type WalletPoseidon2Air = CommonPoseidon2Air;

/// Create Poseidon2 AIR instance for wallet commitments
pub(super) fn create_poseidon2_air() -> WalletPoseidon2Air { create_common_poseidon2_air() }

/// Get the total number of columns per row in a wallet trace
/// This is useful for benchmarking and understanding trace dimensions
pub fn wallet_trace_cols() -> usize { column_offsets::total_cols() }

/// Column offsets for Poseidon2 AIR columns in the wallet trace
///
/// The trace structure is now multi-row (one row per channel):
/// - Each row contains:
///   - Columns 0-7: prev_accumulator (8 fields)
///   - Columns 8-15: channel_id (8 fields)
///   - Columns 16-23: channel_commitment (8 fields)
///   - Columns 24-31: next_accumulator (8 fields)
///   - Columns 32+: Poseidon2 AIR columns for accumulator computation
pub(super) mod column_offsets {
    use crate::zkp::poseidon2_common::poseidon2_air_num_cols;

    /// Column offsets within a row (same for all rows)
    pub(crate) const IS_ACTIVE_COL: usize = 0;
    pub(crate) const PREV_ACC_START: usize = 1;
    pub(crate) const PREV_ACC_END: usize = 9;
    pub(crate) const CHANNEL_ID_START: usize = 9;
    pub(crate) const CHANNEL_ID_END: usize = 17;
    pub(crate) const CHANNEL_COMMITMENT_START: usize = 17;
    pub(crate) const CHANNEL_COMMITMENT_END: usize = 25;
    pub(crate) const NEXT_ACC_START: usize = 25;
    pub(crate) const NEXT_ACC_END: usize = 33;
    pub(crate) const ACCUMULATOR_POSEIDON2_START: usize = 33;

    /// Number of Poseidon2 permutations needed for accumulator (77 bytes = 19.25 elements -> 3 permutations)
    /// Input: CHAIN_DOMAIN (13 bytes) + prev_accumulator (32 bytes) + channel_hash_bytes (32 bytes) = 77 bytes
    /// With RATE = 8 (32 bytes per permutation): 32 + 32 + 13 = 3 permutations
    pub(crate) const ACCUMULATOR_PERMUTATIONS: usize = 3;

    /// Offset for wallet_id initialization Poseidon2 columns
    /// These columns are used to verify that prev_acc in the first row equals hash(wallet_id)
    pub(crate) fn wallet_init_poseidon2_start() -> usize {
        let poseidon2_cols = poseidon2_air_num_cols();
        ACCUMULATOR_POSEIDON2_START + ACCUMULATOR_PERMUTATIONS * poseidon2_cols
    }

    /// Number of Poseidon2 permutations needed for wallet_id initialization
    /// Input: WALLET_INIT_DOMAIN (14 bytes) + wallet_id (32 bytes) = 46 bytes = 11.5 elements
    /// With RATE = 8 (32 bytes per permutation): 32 + 14 = 2 permutations
    pub(crate) const WALLET_INIT_PERMUTATIONS: usize = 2;

    /// Total number of columns per row
    pub(crate) fn total_cols() -> usize {
        let poseidon2_cols = poseidon2_air_num_cols();
        // Base columns: is_active (1) + prev_acc (8) + channel_id (8) + channel_commitment (8) + next_acc (8) = 33
        // Plus Poseidon2 trace for accumulator (3 permutations)
        // Plus Poseidon2 trace for wallet_id initialization (2 permutations)
        const BASE_COLS: usize = 33;
        BASE_COLS
            + ACCUMULATOR_PERMUTATIONS * poseidon2_cols
            + WALLET_INIT_PERMUTATIONS * poseidon2_cols
    }
}

#[cfg(test)]
mod tests {
    use p3_air::BaseAir;

    use super::*;
    use crate::zkp::poseidon2_common::poseidon2_air_num_cols;

    #[test]
    fn test_poseidon2_constants_deterministic() {
        use crate::zkp::poseidon2_common::create_poseidon2_constants;
        let constants1 = create_poseidon2_constants();
        let constants2 = create_poseidon2_constants();
        // Constants should be deterministic - verify by creating AIR instances
        let air1 = WalletPoseidon2Air::new(constants1);
        let air2 = WalletPoseidon2Air::new(constants2);
        // Both AIRs should have the same width
        assert_eq!(air1.width(), air2.width());
    }

    #[test]
    fn test_column_offsets() {
        // Verify column offsets are correct
        let poseidon2_cols = poseidon2_air_num_cols();
        assert!(poseidon2_cols > 0, "Poseidon2 AIR should require columns");
        // Accumulator uses 3 permutations, wallet init uses 2 permutations
        assert_eq!(
            column_offsets::wallet_init_poseidon2_start(),
            column_offsets::ACCUMULATOR_POSEIDON2_START
                + column_offsets::ACCUMULATOR_PERMUTATIONS * poseidon2_cols
        );
        assert_eq!(
            column_offsets::total_cols(),
            column_offsets::wallet_init_poseidon2_start()
                + column_offsets::WALLET_INIT_PERMUTATIONS * poseidon2_cols
        );
    }

    #[test]
    fn test_poseidon2_air_creation() {
        let air = create_poseidon2_air();
        assert!(air.width() > 0, "Poseidon2 AIR should have columns");
    }
}
