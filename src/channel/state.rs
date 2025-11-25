#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
//! Channel state representation
//!
//! This module defines the state structure for a unidirectional state channel.
//! A channel is between a sender and a receiver, where the sender can make
//! transfers unilaterally to the receiver.

use crate::types::ChannelCommitment;

/// Channel state structure
///
/// Represents the state of a unidirectional state channel. A unidirectional channel is between
/// a sender and a receiver. The sender can make transfers to the receiver unilaterally
/// (without requiring the receiver's participation). The channel maintains both sender and
/// receiver balances, where transfers move funds from sender to receiver.
///
/// The nonce is incremented on each state transition for replay protection.
/// The `is_closed` flag indicates whether the channel has been closed and prevents further operations.
#[derive(Debug, Clone)]
pub struct ChannelState {
    /// Balance of the sender
    pub sender_balance: u64,
    /// Balance of the receiver
    pub receiver_balance: u64,
    /// Additional metadata associated with the channel
    pub metadata: Vec<u8>,
    /// Current nonce value for replay protection
    pub nonce: u32,
    /// Whether the channel is closed (prevents further operations)
    pub is_closed: bool,
    /// Commitment over channel state
    pub commitment: ChannelCommitment,
}

impl PartialEq for ChannelState {
    fn eq(&self, other: &Self) -> bool {
        self.sender_balance == other.sender_balance
            && self.receiver_balance == other.receiver_balance
            && self.metadata == other.metadata
            && self.nonce == other.nonce
            && self.is_closed == other.is_closed
            && self.commitment == other.commitment
    }
}

impl Eq for ChannelState {}

impl ChannelState {
    /// Creates a new channel state with the given initial sender balance.
    /// The receiver starts at 0 as a constructor invariant.
    ///
    /// # Arguments
    /// * `sender_balance` - Initial balance for the sender
    pub fn new(sender_balance: u64) -> Self {
        Self {
            sender_balance,
            receiver_balance: 0,
            metadata: vec![],
            nonce: 0,
            is_closed: false,
            commitment: ChannelCommitment::default(),
        }
    }

    /// Gets the sender's balance
    pub fn sender_balance(&self) -> u64 { self.sender_balance }

    /// Gets the receiver's balance
    pub fn receiver_balance(&self) -> u64 { self.receiver_balance }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_state_new() {
        let state = ChannelState::new(100);

        assert_eq!(state.sender_balance, 100);
        assert_eq!(state.receiver_balance, 0);
        assert!(state.metadata.is_empty());
        assert_eq!(state.nonce, 0);
        assert!(!state.is_closed);
        assert_eq!(state.commitment, [0u8; 32]);
    }

    #[test]
    fn test_channel_state_balances() {
        let state = ChannelState::new(100);
        assert_eq!(state.sender_balance(), 100);
        assert_eq!(state.receiver_balance(), 0);
    }

    #[test]
    fn test_channel_state_equality() {
        let state1 = ChannelState::new(100);
        let state2 = ChannelState::new(100);
        let state3 = ChannelState::new(200);

        // Same values should be equal
        assert_eq!(state1, state2);

        // Different balances should not be equal
        assert_ne!(state1, state3);

        // Test equality with different metadata
        let mut state_meta1 = ChannelState::new(100);
        state_meta1.metadata = vec![1, 2, 3];
        let mut state_meta2 = ChannelState::new(100);
        state_meta2.metadata = vec![4, 5, 6];
        assert_ne!(state_meta1, state_meta2);

        // Test equality with different nonce
        let mut state_nonce1 = ChannelState::new(100);
        state_nonce1.nonce = 1;
        let mut state_nonce2 = ChannelState::new(100);
        state_nonce2.nonce = 2;
        assert_ne!(state_nonce1, state_nonce2);

        // Test equality with different is_closed
        let mut state_open = ChannelState::new(100);
        state_open.is_closed = false;
        let mut state_closed = ChannelState::new(100);
        state_closed.is_closed = true;
        assert_ne!(state_open, state_closed);

        // Test equality with different commitment
        let mut state_commit1 = ChannelState::new(100);
        state_commit1.commitment = [1u8; 32];
        let mut state_commit2 = ChannelState::new(100);
        state_commit2.commitment = [2u8; 32];
        assert_ne!(state_commit1, state_commit2);
    }
}
