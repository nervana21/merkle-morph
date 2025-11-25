#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
//! Channel commitment computation
//!
//! This module provides functions for computing cryptographic commitments
//! over channel state using Poseidon2 hashing.

use crate::channel::state::ChannelState;
use crate::types::{Bytes32, ChannelCommitment, ChannelId, CHANNEL_DOMAIN_TAG};
use crate::zkp::{poseidon2_hash_bytes, poseidon2_hash_fixed};

/// Computes a deterministic commitment over channel state
///
/// The commitment is computed using a two-stage hash to preserve all data:
/// 1. Stage 1: `poseidon2(CHANNEL_DOMAIN_TAG || channel_id || state_hash)` -> 32 bytes
/// 2. Stage 2: `poseidon2(stage1_result || nonce)` -> 32 bytes
///
/// where `state_hash = poseidon2(balance || is_closed)`
pub fn compute_commitment(channel_id: ChannelId, state: &ChannelState) -> ChannelCommitment {
    // Compute state hash (balance and is_closed, excluding nonce)
    let state_hash = compute_state_hash(state);

    // Compute final commitment with domain separation
    compute_channel_commitment(channel_id, state_hash, state.nonce)
}

/// Computes the hash of channel state (balances, metadata, and closure status)
///
/// This includes sender_balance, receiver_balance, metadata, and `is_closed` flag,
/// but excludes the nonce and commitment, which are included in the final commitment.
fn compute_state_hash(state: &ChannelState) -> Bytes32 {
    let is_closed_u64 = if state.is_closed { 1u64 } else { 0u64 };
    poseidon2_hash_fixed(&[
        &state.sender_balance.to_le_bytes(),
        &state.receiver_balance.to_le_bytes(),
        &state.metadata,
        &is_closed_u64.to_le_bytes(),
    ])
}

/// Computes the channel-specific commitment from `channel_id`, `state_hash`,
/// and `nonce` using Poseidon2.
///
/// The `state_hash` represents hash(sender_wallet_id||receiver_wallet_id||sender_balance||is_closed)
/// and excludes `channel_id` and `nonce`. The final channel commitment is a
/// hashed combination of all three components, but first appended with the
/// domain separation tag `CHANNEL_DOMAIN_TAG`.
///
/// Uses a two-stage hash to preserve all data:
/// 1. Stage 1: `poseidon2(CHANNEL_DOMAIN_TAG || channel_id || state_hash)` -> 32 bytes
/// 2. Stage 2: `poseidon2(stage1_result || nonce)` -> 32 bytes
pub fn compute_channel_commitment(
    channel_id: ChannelId,
    state_hash: Bytes32,
    nonce: u32,
) -> ChannelCommitment {
    // Stage 1: Hash domain_tag || channel_id || state_hash (72 bytes -> 32 bytes)
    let mut stage1_input = Vec::new();
    stage1_input.extend_from_slice(CHANNEL_DOMAIN_TAG);
    stage1_input.extend_from_slice(&channel_id);
    stage1_input.extend_from_slice(&state_hash);
    let stage1_hash = poseidon2_hash_bytes(&stage1_input);

    // Stage 2: Hash stage1_result || nonce (40 bytes -> 32 bytes)
    let mut stage2_input = Vec::new();
    stage2_input.extend_from_slice(&stage1_hash);
    stage2_input.extend_from_slice(&nonce.to_le_bytes());
    poseidon2_hash_bytes(&stage2_input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_state_hash() {
        let state1 = ChannelState::new(100);
        let state2 = ChannelState::new(100);
        let state3 = ChannelState::new(200);

        let hash1 = compute_state_hash(&state1);
        let hash2 = compute_state_hash(&state2);
        let hash3 = compute_state_hash(&state3);

        // Same state produces same hash
        assert_eq!(hash1, hash2);

        // Different balances produce different hash
        assert_ne!(hash1, hash3);

        // Test that is_closed affects the hash
        let mut state_open = ChannelState::new(100);
        state_open.is_closed = false;

        let mut state_closed = ChannelState::new(100);
        state_closed.is_closed = true;

        let hash_open = compute_state_hash(&state_open);
        let hash_closed = compute_state_hash(&state_closed);

        // Same balance but different is_closed produce different hash
        assert_ne!(hash_open, hash_closed);

        // Test different metadata produces different hashes
        let mut state_metadata1 = ChannelState::new(100);
        state_metadata1.metadata = vec![1, 2, 3];
        let hash_metadata1 = compute_state_hash(&state_metadata1);

        let mut state_metadata2 = ChannelState::new(100);
        state_metadata2.metadata = vec![4, 5, 6];
        let hash_metadata2 = compute_state_hash(&state_metadata2);

        assert_ne!(hash1, hash_metadata1);
        assert_ne!(hash_metadata1, hash_metadata2);

        // Test that nonce does NOT affect state hash (nonce is excluded)
        let mut state_nonce1 = ChannelState::new(100);
        state_nonce1.nonce = 1;
        let hash_nonce1 = compute_state_hash(&state_nonce1);

        let mut state_nonce2 = ChannelState::new(100);
        state_nonce2.nonce = 2;
        let hash_nonce2 = compute_state_hash(&state_nonce2);

        // Same state hash regardless of nonce
        assert_eq!(hash1, hash_nonce1);
        assert_eq!(hash_nonce1, hash_nonce2);

        // Test that commitment does NOT affect state hash (commitment is excluded)
        let mut state_commitment1 = ChannelState::new(100);
        state_commitment1.commitment = [1u8; 32];
        let hash_commitment1 = compute_state_hash(&state_commitment1);

        let mut state_commitment2 = ChannelState::new(100);
        state_commitment2.commitment = [2u8; 32];
        let hash_commitment2 = compute_state_hash(&state_commitment2);

        // Same state hash regardless of commitment
        assert_eq!(hash1, hash_commitment1);
        assert_eq!(hash_commitment1, hash_commitment2);
    }

    #[test]
    fn test_compute_commitment() {
        let channel_id = [0u8; 32];
        let state = ChannelState::new(100);

        let commitment1 = compute_commitment(channel_id, &state);
        let commitment2 = compute_commitment(channel_id, &state);

        // Same state produces same commitment
        assert_eq!(commitment1, commitment2);

        // Different channel ID produces different commitment
        let different_id = [1u8; 32];
        let commitment3 = compute_commitment(different_id, &state);
        assert_ne!(commitment1, commitment3);

        // Different nonce produces different commitment
        let mut state2 = state.clone();
        state2.nonce = 1;
        let commitment4 = compute_commitment(channel_id, &state2);
        assert_ne!(commitment1, commitment4);

        // Test that is_closed affects the commitment
        use crate::channel::transition::apply_close;

        let state = ChannelState::new(100);
        // Open channel commitment
        let open_commitment = compute_commitment(channel_id, &state);

        // Closed channel commitment (same balance, but nonce increments on close)
        let closed_state = apply_close(&state).expect("close should succeed");
        let closed_commitment = compute_commitment(channel_id, &closed_state);

        // Commitments should be different because is_closed changed
        // (even though balance is the same, nonce increments on close)
        assert_ne!(open_commitment, closed_commitment);

        // Test that is_closed affects commitment even with same nonce
        let mut state_open = ChannelState::new(100);
        state_open.is_closed = false;

        let mut state_closed = ChannelState::new(100);
        state_closed.is_closed = true;
        // Set nonce to same value to isolate is_closed effect
        state_closed.nonce = state_open.nonce;

        let commitment_open = compute_commitment(channel_id, &state_open);
        let commitment_closed = compute_commitment(channel_id, &state_closed);

        // Commitments must be different because is_closed is in the hash
        assert_ne!(commitment_open, commitment_closed);
    }

    #[test]
    fn test_compute_channel_commitment() {
        let channel_id = [0u8; 32];
        let state_hash = [0u8; 32];
        let nonce = 0;

        let base_commitment = compute_channel_commitment(channel_id, state_hash, nonce);

        // Test same inputs produce same output
        let same_commitment = compute_channel_commitment(channel_id, state_hash, nonce);
        assert_eq!(base_commitment, same_commitment);

        // Test parameter sensitivity
        let different_id = compute_channel_commitment([1u8; 32], state_hash, nonce);
        let different_hash = compute_channel_commitment(channel_id, [1u8; 32], nonce);
        let different_nonce = compute_channel_commitment(channel_id, state_hash, 1);

        assert_ne!(base_commitment, different_id);
        assert_ne!(base_commitment, different_hash);
        assert_ne!(base_commitment, different_nonce);

        // Test nonce progression
        let nonce_1 = compute_channel_commitment(channel_id, state_hash, 1);
        let nonce_2 = compute_channel_commitment(channel_id, state_hash, 2);
        assert_ne!(nonce_1, nonce_2);
    }
}
