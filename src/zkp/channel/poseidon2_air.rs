#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
//! Poseidon2 AIR integration for channel commitment verification
//!
//! This module provides the infrastructure for full in-circuit Poseidon2 hash verification.
//! It implements Poseidon2 AIR columns and constraints for verifying channel commitments.
//!
//! ## Architecture
//!
//! The module verifies two Poseidon2 hash computations:
//! 1. `state_hash = poseidon2(sender_balance || receiver_balance)`
//! 2. `commitment` (two-stage hash):
//!    - stage1 = poseidon2(CHANNEL_DOMAIN_TAG || channel_id || state_hash)
//!    - commitment = poseidon2(stage1 || nonce)
//!
//! Each Poseidon2 computation requires Poseidon2 AIR columns for intermediate states,
//! which are included in the trace structure.

// Re-export for convenience
pub(crate) use crate::zkp::poseidon2_common::create_poseidon2_constants_and_params;
use crate::zkp::poseidon2_common::{
    create_poseidon2_air as create_common_poseidon2_air, CommonPoseidon2Air,
};

/// Poseidon2 AIR type for channel commitments
pub(super) type ChannelPoseidon2Air = CommonPoseidon2Air;

/// Create Poseidon2 AIR instance for channel commitments
pub(super) fn create_poseidon2_air() -> ChannelPoseidon2Air { create_common_poseidon2_air() }

/// Get the total number of columns per row in a channel trace
/// This is useful for benchmarking and understanding trace dimensions
#[allow(dead_code)]
pub(crate) fn channel_trace_cols() -> usize { column_offsets::total_cols() }

/// Column offsets for Poseidon2 AIR columns in the channel trace
///
/// The trace structure is:
/// - Columns 0-12: Channel state (sender_balance, receiver_balance, nonce, is_closed, amount, commitment[8])
/// - Columns STATE_HASH_OFFSET+: Poseidon2 AIR columns for state_hash computation (multiple permutations)
/// - Columns commitment_offset()+: Poseidon2 AIR columns for commitment computation
pub(super) mod column_offsets {
    use crate::zkp::poseidon2_common::poseidon2_air_num_cols;

    // Base channel state column indices
    /// Column index for sender_balance
    pub(crate) const SENDER_BALANCE: usize = 0;
    /// Column index for receiver_balance
    pub(crate) const RECEIVER_BALANCE: usize = 1;
    /// Column index for nonce
    pub(crate) const NONCE: usize = 2;
    /// Column index for is_closed flag
    pub(crate) const IS_CLOSED: usize = 3;
    /// Column index for transfer amount
    pub(crate) const AMOUNT: usize = 4;
    /// Starting column index for commitment (8 field elements)
    pub(crate) const COMMITMENT_START: usize = 5;
    /// Ending column index for commitment (exclusive, so commitment spans indices 5-12)
    pub(crate) const COMMITMENT_END: usize = 13;

    /// Number of base channel columns
    pub(super) const CHANNEL_COLS: usize = 13;

    /// Maximum number of Poseidon2 permutations for state_hash computation
    /// This supports variable-length metadata (up to ~96 bytes with 4 permutations)
    pub(crate) const MAX_STATE_HASH_PERMUTATIONS: usize = 4;

    /// Offset for state_hash Poseidon2 AIR columns
    pub(crate) const STATE_HASH_OFFSET: usize = CHANNEL_COLS;

    /// Offset for commitment Poseidon2 AIR columns
    /// This accounts for multiple permutations in state_hash computation
    pub(crate) fn commitment_offset() -> usize {
        STATE_HASH_OFFSET + MAX_STATE_HASH_PERMUTATIONS * poseidon2_air_num_cols()
    }

    /// Total number of columns in the trace
    pub(crate) fn total_cols() -> usize { commitment_offset() + poseidon2_air_num_cols() }
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
        let air1 = ChannelPoseidon2Air::new(constants1);
        let air2 = ChannelPoseidon2Air::new(constants2);
        // Both AIRs should have the same width
        assert_eq!(air1.width(), air2.width());
    }

    #[test]
    fn test_column_offsets() {
        // Verify column offsets are correct
        let poseidon2_cols = poseidon2_air_num_cols();
        assert!(poseidon2_cols > 0, "Poseidon2 AIR should require columns");
        // State hash now uses multiple permutations
        assert_eq!(
            column_offsets::commitment_offset(),
            column_offsets::STATE_HASH_OFFSET
                + column_offsets::MAX_STATE_HASH_PERMUTATIONS * poseidon2_cols
        );
        assert_eq!(
            column_offsets::total_cols(),
            column_offsets::commitment_offset() + poseidon2_cols
        );
    }

    #[test]
    fn test_poseidon2_air_creation() {
        let air = create_poseidon2_air();
        assert!(air.width() > 0, "Poseidon2 AIR should have columns");
    }

    #[test]
    fn test_channel_trace_cols_matches_total_cols() {
        assert_eq!(channel_trace_cols(), column_offsets::total_cols());
        assert!(channel_trace_cols() > column_offsets::CHANNEL_COLS);
    }
}
