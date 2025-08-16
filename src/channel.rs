//! Channel state management and operations
//!
//! This module provides functionality for managing payment channel states,
//! including balance updates, nonce management, and channel commitment computation.

use crate::utils::Bytes32;
use sha2::{Digest, Sha256};

/// Type alias for channel identifiers
pub type ChannelId = [u8; 32];

/// Represents the state of a payment channel between two parties
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelState {
    /// Current balances for both parties [party0_balance, party1_balance]
    pub balances: [u64; 2],
    /// Additional metadata associated with the channel
    pub metadata: Vec<u8>,
    /// Current nonce value
    pub nonce: u64,
    /// The channel commitment representing the current channel state
    pub commitment: Bytes32,
}

impl ChannelState {
    /// Creates a new channel state with the given initial balances
    pub fn new(balances: [u64; 2]) -> Self {
        Self {
            balances,
            metadata: vec![],
            nonce: 0,
            commitment: [0u8; 32],
        }
    }
}

/// Computes a deterministic commitment over balances and metadata
pub fn hash_state(channel_id: ChannelId, ch: &ChannelState) -> Bytes32 {
    let mut hasher = Sha256::new();
    hasher.update(channel_id);
    hasher.update(ch.balances[0].to_le_bytes());
    hasher.update(ch.balances[1].to_le_bytes());
    hasher.update(ch.metadata.as_slice());
    hasher.update(ch.nonce.to_le_bytes());
    let out = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&out);
    result
}

/// Transfers an amount from party 0 to party 1. This operation updates the balances
/// by transferring the specified amount from party 0 to party 1, increments the nonce
/// to ensure state uniqueness and prevent replay attacks, and recomputes the channel
/// commitment with the new state including the updated nonce.
pub fn transfer(channel_id: ChannelId, current_state: &ChannelState, amount: u64) -> ChannelState {
    let mut next_state = current_state.clone();

    // Checked math; reject underflow/overflow
    let b0 = next_state.balances[0]
        .checked_sub(amount)
        .expect("insufficient balance");
    let b1 = next_state.balances[1]
        .checked_add(amount)
        .expect("balance overflow");
    next_state.balances = [b0, b1];

    // Nonce +1 invariant
    next_state.nonce = current_state.nonce + 1;

    // Recompute channel commitment
    let state_commitment = hash_state(channel_id, &next_state);
    next_state.commitment =
        compute_channel_commitment(channel_id, state_commitment, next_state.nonce);
    next_state
}

/// Computes the channel-specific commitment from channel ID, commitment, and nonce.
/// Uses domain separation with tag "MM_CHANNEL_v1" for future-proofing.
pub fn compute_channel_commitment(
    channel_id: ChannelId,
    commitment: Bytes32,
    nonce: u64,
) -> Bytes32 {
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"MM_CHANNEL_v1");
    hasher.update(channel_id);
    hasher.update(commitment);
    hasher.update(nonce.to_le_bytes());
    let out = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&out);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_state_new() {
        let balances = [100, 200];

        let channel = ChannelState::new(balances);

        // Verify all fields are set correctly
        assert_eq!(channel.balances, balances);
        assert_eq!(channel.metadata, vec![]);
        assert_eq!(channel.nonce, 0);
        assert_eq!(channel.commitment, [0u8; 32]);
    }

    #[test]
    fn test_hash_state() {
        let channel_id = [0u8; 32];
        let balances = [100, 200];

        // Test same input produces same output
        let channel1 = ChannelState::new(balances);
        let hash1 = hash_state(channel_id, &channel1);
        let hash2 = hash_state(channel_id, &channel1);
        assert_eq!(hash1, hash2);

        // Test different inputs produce different outputs
        let different_channel_id = [1u8; 32];
        let hash3 = hash_state(different_channel_id, &channel1);
        assert_ne!(hash1, hash3);

        // Test all fields affect the hash
        let mut channel2 = ChannelState::new(balances);
        channel2.balances = [200, 100]; // Different balances
        let hash4 = hash_state(channel_id, &channel2);
        assert_ne!(hash1, hash4);

        let mut channel3 = ChannelState::new(balances);
        channel3.metadata = vec![1, 2, 3]; // Different metadata
        let hash5 = hash_state(channel_id, &channel3);
        assert_ne!(hash1, hash5);

        let mut channel4 = ChannelState::new(balances);
        channel4.nonce = 1; // Different nonce
        let hash6 = hash_state(channel_id, &channel4);
        assert_ne!(hash1, hash6);
    }

    #[test]
    fn test_transfer() {
        let channel_id = [0u8; 32];
        let initial_state = ChannelState::new([100, 50]);

        // Test successful transfer
        let next_state = transfer(channel_id, &initial_state, 30);

        // Verify balances updated correctly
        assert_eq!(next_state.balances, [70, 80]);
        assert_eq!(next_state.nonce, initial_state.nonce + 1);
        assert_eq!(next_state.metadata, vec![]);

        // Verify commitment was recomputed
        let expected_state_hash = hash_state(channel_id, &next_state);
        let expected_commitment =
            compute_channel_commitment(channel_id, expected_state_hash, next_state.nonce);
        assert_eq!(next_state.commitment, expected_commitment);

        // Same transfer applied to same initial state produces consistent output
        let same_state = transfer(channel_id, &initial_state, 30);
        assert_eq!(next_state.commitment, same_state.commitment);
        assert_eq!(next_state.nonce, same_state.nonce);

        // Test zero transfer
        let zero_transfer = transfer(channel_id, &initial_state, 0);
        assert_eq!(zero_transfer.balances, initial_state.balances);
        assert_eq!(zero_transfer.nonce, initial_state.nonce + 1);
        assert_ne!(zero_transfer.commitment, initial_state.commitment); // Commitment should change due to nonce

        // Test maximum transfer
        let max_transfer = transfer(channel_id, &initial_state, 100);
        assert_eq!(max_transfer.balances, [0, 150]);
        assert_eq!(max_transfer.nonce, initial_state.nonce + 1);

        // Test small transfer
        let small_transfer = transfer(channel_id, &initial_state, 1);
        assert_eq!(small_transfer.balances, [99, 51]);
        assert_eq!(small_transfer.nonce, initial_state.nonce + 1);
    }

    #[test]
    #[should_panic(expected = "insufficient balance")]
    fn test_transfer_panics_on_insufficient_balance() {
        let channel_id = [0u8; 32];
        let initial_state = ChannelState::new([10, 10]);

        // This should panic because it would make party0's balance negative
        transfer(channel_id, &initial_state, 11);
    }

    #[test]
    #[should_panic(expected = "balance overflow")]
    fn test_transfer_panics_on_balance_overflow() {
        let channel_id = [0u8; 32];
        let initial_state = ChannelState::new([u64::MAX, u64::MAX]);

        // This should panic because it would overflow party1's balance
        transfer(channel_id, &initial_state, 1);
    }

    #[test]
    fn test_transfer_with_metadata_preservation() {
        let channel_id = [0u8; 32];
        let mut initial_state = ChannelState::new([100, 50]);
        initial_state.metadata = vec![1, 2, 3, 4, 5];

        let next_state = transfer(channel_id, &initial_state, 25);

        // Metadata should be preserved
        assert_eq!(next_state.metadata, vec![1, 2, 3, 4, 5]);

        // Balances should be updated
        assert_eq!(next_state.balances, [75, 75]);

        // Nonce should be incremented
        assert_eq!(next_state.nonce, initial_state.nonce + 1);
    }

    #[test]
    fn test_compute_channel_commitment() {
        let id1 = [0u8; 32];
        let id2 = [1u8; 32];
        let commit1 = [3u8; 32];
        let commit2 = [4u8; 32];

        // Test uniqueness across all parameters
        let commitment1 = compute_channel_commitment(id1, commit1, 1);
        let commitment2 = compute_channel_commitment(id2, commit1, 1);
        let commitment3 = compute_channel_commitment(id1, commit2, 1);
        let commitment4 = compute_channel_commitment(id1, commit1, 2);

        assert_ne!(commitment1, commitment2); // different channel_id
        assert_ne!(commitment1, commitment3); // different commitment
        assert_ne!(commitment1, commitment4); // different nonce
        assert_ne!(commitment1, [0u8; 32]); // not default
    }
}
