//! Poseidon2 AIR integration for channel commitment verification
//!
//! This module provides the infrastructure for full in-circuit Poseidon2 hash verification.
//! It implements Poseidon2 AIR columns and constraints for verifying channel commitments.
//!
//! ## Architecture
//!
//! The module verifies two Poseidon2 hash computations:
//! 1. `state_hash = poseidon2(sender_balance || receiver_balance || sender_pubkey || receiver_pubkey || metadata || is_closed)`
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
/// - Columns 0-4: Channel state (sender_balance, receiver_balance, nonce, is_closed, amount)
/// - Columns 5-12: commitment[8] (8 field elements)
/// - Columns 13-20: auth_hash[8] (8 field elements for sender authentication hash)
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
    /// Starting column index for auth_hash (8 field elements)
    pub(crate) const AUTH_HASH_START: usize = 13;
    /// Ending column index for auth_hash (exclusive, so auth_hash spans indices 13-20)
    pub(crate) const AUTH_HASH_END: usize = 21;

    /// Number of base channel columns (including commitment and auth_hash)
    pub(super) const CHANNEL_COLS: usize = 21;

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
