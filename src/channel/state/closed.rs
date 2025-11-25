//! Closed state
//!
//! This state represents a permanently closed channel between a fixed
//! sender and receiver. No further transitions are allowed from this
//! state and all values are final.
//!
//! # Invariants
//!
//! - State is immutable and final
//! - No new transitions allowed
//! - Channel has been fully settled

use bitcoin::secp256k1::XOnlyPublicKey;

use crate::types::ChannelCommitment;

/// Permanently closed channel state representing the terminal state with final balances and commitment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Closed {
    /// Sender's public key
    pub sender_pubkey: XOnlyPublicKey,
    /// Receiver's public key
    pub receiver_pubkey: XOnlyPublicKey,
    /// Total channel capacity
    pub total_capacity: u64,
    /// Final sender balance
    pub sender_balance: u64,
    /// Final receiver balance
    pub receiver_balance: u64,
    /// Final nonce value
    pub nonce: u32,
    /// Final commitment
    pub commitment: ChannelCommitment,
}

impl Closed {
    /// Creates a new Closed state
    ///
    /// # Arguments
    /// * `sender_pubkey` - Sender's public key
    /// * `receiver_pubkey` - Receiver's public key
    /// * `total_capacity` - Total channel capacity
    /// * `sender_balance` - Final sender balance
    /// * `receiver_balance` - Final receiver balance
    /// * `nonce` - Final nonce value
    pub fn new(
        sender_pubkey: XOnlyPublicKey,
        receiver_pubkey: XOnlyPublicKey,
        total_capacity: u64,
        sender_balance: u64,
        receiver_balance: u64,
        nonce: u32,
    ) -> Self {
        Self {
            sender_pubkey,
            receiver_pubkey,
            total_capacity,
            sender_balance,
            receiver_balance,
            nonce,
            commitment: ChannelCommitment::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::test_utils::test_keys;

    #[test]
    fn test_new() {
        let (sender_pubkey, receiver_pubkey) = test_keys();
        let total_capacity = 100u64;
        let sender_balance = 60u64;
        let receiver_balance = 40u64;
        let nonce = 5u32;
        let state = Closed::new(
            sender_pubkey,
            receiver_pubkey,
            total_capacity,
            sender_balance,
            receiver_balance,
            nonce,
        );

        assert_eq!(state.sender_pubkey, sender_pubkey);
        assert_eq!(state.receiver_pubkey, receiver_pubkey);
        assert_eq!(state.total_capacity, total_capacity);
        assert_eq!(state.sender_balance, sender_balance);
        assert_eq!(state.receiver_balance, receiver_balance);
        assert_eq!(state.nonce, nonce);
        assert_eq!(state.commitment, ChannelCommitment::default());
    }
}
