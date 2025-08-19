//! Channel state management and operations
//!
//! This module provides functionality for managing unilateral state channels

use sha2::{Digest, Sha256};

use crate::errors::ChannelError;
use crate::types::Bytes32;
use crate::types::ChannelId;

/// Represents the state of a unilateral state channel
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelState {
    /// Balance of the sender
    pub sender_balance: u64,
    /// Balance of the receiver
    pub receiver_balance: u64,
    /// Additional metadata associated with the channel
    pub metadata: Vec<u8>,
    /// Current nonce value
    pub nonce: u64,
    /// Commitment over channel state
    pub commitment: Bytes32,
}

/// Computes a deterministic commitment over `channel_id`, channel
/// balances, and channel metadata.
pub fn hash(channel_id: ChannelId, channel: &ChannelState) -> Bytes32 {
    let mut hasher = Sha256::new();
    hasher.update(channel_id);
    hasher.update(channel.sender_balance.to_le_bytes());
    hasher.update(channel.receiver_balance.to_le_bytes());
    hasher.update(channel.metadata.as_slice());
    let out = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&out);
    hash
}

/// Computes the channel-specific commitment from `channel_id`, `state_hash`,
/// and `nonce`.
///
/// The `state_hash` represents hash(sender_balance||receiver_balance||metadata)
/// and excludes `channel_id` and `nonce`. The final channel commitment is a
/// hashed combination of all three components, but first appended with the
/// domain separation tag "MM_CHANNEL_v0":
/// hash("MM_CHANNEL_v0"||`channel_id`||`state_hash`||`nonce`).
pub fn compute_channel_commitment(
    channel_id: ChannelId,
    state_hash: Bytes32,
    nonce: u64,
) -> Bytes32 {
    let mut hasher = Sha256::new();
    hasher.update(b"MM_CHANNEL_v0");
    hasher.update(channel_id);
    hasher.update(state_hash);
    hasher.update(nonce.to_le_bytes());
    let out = hasher.finalize();
    let mut channel_commitment = [0u8; 32];
    channel_commitment.copy_from_slice(&out);
    channel_commitment
}

impl ChannelState {
    /// Creates a new `ChannelState` with the given initial `sender_balance`.
    /// The receiver starts at 0 as a constructor invariant.
    pub fn new(sender_balance: u64) -> Self {
        Self {
            sender_balance,
            receiver_balance: 0,
            metadata: vec![],
            nonce: 0,
            commitment: [0u8; 32],
        }
    }

    /// Transfers `amount` from sender to receiver.
    /// This function does NOT update the nonce or commitment.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The transfer amount is zero (`InvalidZeroTransfer`)
    /// - The sender has insufficient balance (`InsufficientBalance`)
    /// - The receiver's balance would overflow (`BalanceOverflow`)
    ///
    ///   Otherwise, returns a new `ChannelState` with the updated balances.
    fn transfer(&self, amount: u64) -> Result<Self, ChannelError> {
        if amount == 0 {
            return Err(ChannelError::InvalidZeroTransfer);
        }

        let mut next_state = self.clone();

        let next_sender_balance = self
            .sender_balance
            .checked_sub(amount)
            .ok_or(ChannelError::InsufficientBalance)?;
        let next_receiver_balance = self
            .receiver_balance
            .checked_add(amount)
            .ok_or(ChannelError::BalanceOverflow)?;

        next_state.sender_balance = next_sender_balance;
        next_state.receiver_balance = next_receiver_balance;

        Ok(next_state)
    }

    /// Apply a transfer and finalize a new enforceable state.
    /// The function transfers a balance, increments the nonce,
    /// and recomputes the commitment.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The transfer amount is zero (`InvalidZeroTransfer`)
    /// - The sender has insufficient balance (`InsufficientBalance`)
    /// - The receiver's balance would overflow (`BalanceOverflow`)
    /// - The nonce would overflow (`ChannelNonceOverflow`)
    pub fn apply_transfer(&self, channel_id: ChannelId, amount: u64) -> Result<Self, ChannelError> {
        let mut next_state = self.transfer(amount)?;

        next_state.nonce = self
            .nonce
            .checked_add(1)
            .ok_or(ChannelError::ChannelNonceOverflow)?;

        let state_hash = hash(channel_id, &next_state);
        next_state.commitment =
            compute_channel_commitment(channel_id, state_hash, next_state.nonce);
        Ok(next_state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash() {
        let channel_id = [0u8; 32];
        let sender_balance = 100;

        // Test same input produces same output
        let channel = ChannelState::new(sender_balance);
        let hash_0 = hash(channel_id, &channel);
        let same_inputs = hash(channel_id, &channel);
        assert_eq!(hash_0, same_inputs);

        // Test different inputs produce different outputs
        let different_channel_id = [1u8; 32];
        let different_id = hash(different_channel_id, &channel);
        assert_ne!(hash_0, different_id);

        // Test different balances produce different hashes
        let channel_balance = ChannelState::new(21);
        let different_balance = hash(channel_id, &channel_balance);
        assert_ne!(hash_0, different_balance);

        // Test different metadata produces different hashes
        let mut channel_metadata = ChannelState::new(sender_balance);
        channel_metadata.metadata = vec![1, 2, 3];
        let different_metadata = hash(channel_id, &channel_metadata);
        assert_ne!(hash_0, different_metadata);

        // Test different nonce produces the same hash
        let mut channel_nonce = ChannelState::new(sender_balance);
        channel_nonce.nonce = 21;
        let different_nonce = hash(channel_id, &channel_nonce);
        assert_eq!(hash_0, different_nonce);

        // Test different commitment produces the same hash
        let mut channel_commitment = ChannelState::new(sender_balance);
        channel_commitment.commitment = [1u8; 32];
        let different_commitment = hash(channel_id, &channel_commitment);
        assert_eq!(hash_0, different_commitment);

        // Test different nonce and commitment produce the same hash
        let mut nonce_1_commitment_1 = ChannelState::new(sender_balance);
        nonce_1_commitment_1.nonce = 1;
        nonce_1_commitment_1.commitment = [1u8; 32];

        let mut nonce_2_commitment_2 = ChannelState::new(sender_balance);
        nonce_2_commitment_2.nonce = 2;
        nonce_2_commitment_2.commitment = [2u8; 32];

        // Test that only balances and metadata are used in the hash function
        let hash1 = hash(channel_id, &nonce_1_commitment_1);
        let hash2 = hash(channel_id, &nonce_2_commitment_2);
        assert_eq!(hash1, hash2);

        // But different balances should produce different hashes
        let mut different_balance = ChannelState::new(21);
        different_balance.nonce = 1;
        different_balance.commitment = [1u8; 32];
        let different_balance = hash(channel_id, &different_balance);
        assert_ne!(hash1, different_balance);
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

    #[test]
    fn test_new() {
        let sender_balance = 100;
        let channel = ChannelState::new(sender_balance);

        // Test constructor
        assert_eq!(channel.sender_balance, sender_balance);
        assert_eq!(channel.receiver_balance, 0);
        assert_eq!(channel.metadata, vec![]);
        assert_eq!(channel.nonce, 0);
        assert_eq!(channel.commitment, [0u8; 32]);
    }

    #[test]
    fn test_transfer() {
        let initial_state = ChannelState::new(100);

        // Test successful transfer
        let next_state = initial_state.transfer(30).unwrap();

        // Verify balances updated correctly
        assert_eq!(next_state.sender_balance, 70);
        assert_eq!(next_state.receiver_balance, 30);
        assert_eq!(next_state.nonce, initial_state.nonce); // nonce is not updated by transfer
        assert_eq!(next_state.metadata, vec![]);
        assert_eq!(next_state.commitment, initial_state.commitment); // commitment is not updated by transfer

        // Same transfer applied to same initial state produces consistent output
        let same_state = initial_state.transfer(30).unwrap();
        assert_eq!(next_state.commitment, same_state.commitment);
        assert_eq!(next_state.nonce, same_state.nonce);

        // Test zero transfer should fail with correct error type
        let zero_transfer = initial_state.transfer(0);
        assert!(matches!(
            zero_transfer,
            Err(ChannelError::InvalidZeroTransfer)
        ));

        // Test full transfer
        let full_transfer = initial_state.transfer(100).unwrap();
        assert_eq!(full_transfer.sender_balance, 0);
        assert_eq!(full_transfer.receiver_balance, 100);
        assert_eq!(full_transfer.nonce, initial_state.nonce); // nonce is not updated by transfer

        // Test transfer with metadata preservation
        let mut initial_state_with_metadata = ChannelState::new(100);
        initial_state_with_metadata.metadata = vec![1, 2, 3, 4, 5];

        let next_state_with_metadata = initial_state_with_metadata.transfer(21).unwrap();

        // Metadata should be preserved
        assert_eq!(next_state_with_metadata.metadata, vec![1, 2, 3, 4, 5]);

        // Balances should be updated
        assert_eq!(next_state_with_metadata.sender_balance, 79);
        assert_eq!(next_state_with_metadata.receiver_balance, 21);

        // Nonce should not be incremented by transfer
        assert_eq!(
            next_state_with_metadata.nonce,
            initial_state_with_metadata.nonce
        );

        // Test error cases
        // Insufficient balance
        let small_initial_state = ChannelState::new(10);
        let transfer_result = small_initial_state.transfer(21);
        assert!(matches!(
            transfer_result,
            Err(ChannelError::InsufficientBalance)
        ));

        // Balance overflow
        let mut overflow_state = ChannelState::new(100);
        overflow_state.receiver_balance = u64::MAX;
        let transfer_result = overflow_state.transfer(1);
        assert!(matches!(
            transfer_result,
            Err(ChannelError::BalanceOverflow)
        ));

        // Test that original state is preserved on failure
        let mut original_state = ChannelState::new(100);
        original_state.metadata = vec![1, 2, 3, 4, 5];

        // Attempt zero transfer (should fail)
        let transfer_result = original_state.transfer(0);
        assert!(matches!(
            transfer_result,
            Err(ChannelError::InvalidZeroTransfer)
        ));

        // Verify original state is unchanged
        assert_eq!(original_state.metadata, vec![1, 2, 3, 4, 5]);
        assert_eq!(original_state.sender_balance, 100);
        assert_eq!(original_state.receiver_balance, 0);
        assert_eq!(original_state.nonce, 0);
    }

    #[test]
    fn test_apply_transfer() {
        let channel_id = [0u8; 32];
        let initial_state = ChannelState::new(100);

        // Test that each successful apply_transfer increments nonce by exactly 1
        let state1 = initial_state.apply_transfer(channel_id, 10).unwrap();
        assert_eq!(state1.nonce, 1);

        let state2 = state1.apply_transfer(channel_id, 20).unwrap();
        assert_eq!(state2.nonce, 2);

        let state3 = state2.apply_transfer(channel_id, 30).unwrap();
        assert_eq!(state3.nonce, 3);

        // Verify the progression is strictly monotonic
        assert!(state1.nonce < state2.nonce);
        assert!(state2.nonce < state3.nonce);

        // Test nonce overflow scenario
        let mut overflow_state = ChannelState::new(100);
        overflow_state.nonce = u64::MAX; // Set nonce to maximum value

        let overflow_result = overflow_state.apply_transfer(channel_id, 10);
        assert!(matches!(
            overflow_result,
            Err(ChannelError::ChannelNonceOverflow)
        ));
    }
}
