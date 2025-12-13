// SPDX-License-Identifier: CC0-1.0

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
/// - Columns 0-4: Channel state (nonce, is_closed, sender_balance, receiver_balance, amount)
/// - Columns STATE_HASH_OFFSET+: Poseidon2 AIR columns for state_hash computation (multiple permutations)
/// - Columns COMMITMENT_START..COMMITMENT_END: commitment[8] (8 field elements, computed from state_hash)
/// - Columns commitment_offset()+: Poseidon2 AIR columns for commitment computation
/// - Columns AUTH_HASH_START..AUTH_HASH_END: auth_hash[8] (8 field elements, computed from commitment)
pub(super) mod column_offsets {
    use crate::zkp::poseidon2_common::poseidon2_air_num_cols;

    // Base channel state column indices
    /// Column index for nonce (state identifier)
    pub(crate) const NONCE: usize = 0;
    /// Column index for is_closed flag (state type)
    pub(crate) const IS_CLOSED: usize = 1;
    /// Column index for sender_balance (core financial state)
    pub(crate) const SENDER_BALANCE: usize = 2;
    /// Column index for receiver_balance (core financial state)
    pub(crate) const RECEIVER_BALANCE: usize = 3;
    /// Column index for transfer amount (transaction data)
    pub(crate) const AMOUNT: usize = 4;

    /// Number of base channel state columns
    const BASE_STATE_COLS: usize = 5;

    /// Maximum number of Poseidon2 permutations for state_hash computation
    /// This supports variable-length metadata up to MAX_METADATA_SIZE (256 bytes).
    /// With POSEIDON2_RATE=8, we need 11 permutations to handle:
    /// - 22 field elements (88 bytes) for fixed fields (balances, pubkeys, is_closed)
    /// - 64 field elements (256 bytes) for metadata
    ///   Total: 86 field elements = ceil(86/8) = 11 permutations
    pub(crate) const MAX_STATE_HASH_PERMUTATIONS: usize = 11;

    /// Offset for state_hash Poseidon2 AIR columns
    pub(crate) const STATE_HASH_OFFSET: usize = BASE_STATE_COLS;

    /// Starting column index for commitment (8 field elements)
    /// Placed after state_hash trace columns since commitment depends on state_hash
    pub(crate) fn commitment_start() -> usize {
        STATE_HASH_OFFSET + MAX_STATE_HASH_PERMUTATIONS * poseidon2_air_num_cols()
    }
    /// Ending column index for commitment (exclusive)
    pub(crate) fn commitment_end() -> usize { commitment_start() + 8 }

    /// Offset for commitment Poseidon2 AIR columns
    pub(crate) fn commitment_offset() -> usize { commitment_end() }

    /// Starting column index for auth_hash (8 field elements)
    pub(crate) fn auth_hash_start() -> usize { commitment_offset() + poseidon2_air_num_cols() }
    /// Ending column index for auth_hash (exclusive)
    pub(crate) fn auth_hash_end() -> usize { auth_hash_start() + 8 }

    /// Total number of columns in the trace
    pub(crate) fn total_cols() -> usize { auth_hash_end() }
}
