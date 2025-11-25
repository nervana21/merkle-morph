//! ForceClosingPending state
//!
//! This state represents a channel that is being force closed between a
//! fixed sender and receiver. A force close transaction has been
//! broadcast and is waiting for the CSV timelock to expire or for a
//! recovery transaction.
//!
//! # Invariants
//!
//! - Timeout or recovery paths are active
//! - Force close transaction has been broadcast
//! - Channel cannot process new transfers
//! - Recovery transaction can be created if an older state is detected

use bitcoin::secp256k1::XOnlyPublicKey;

use crate::types::ChannelCommitment;

/// ForceClosingPending state for a force-closed channel with a broadcast commitment,
/// awaiting CSV timelock expiry or possible recovery on outdated states.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForceClosingPending {
    /// Sender's public key
    pub sender_pubkey: XOnlyPublicKey,
    /// Receiver's public key
    pub receiver_pubkey: XOnlyPublicKey,
    /// Total channel capacity
    pub total_capacity: u64,
    /// Sender balance after fee deduction (funder pays fees)
    pub sender_balance: u64,
    /// Receiver balance (unchanged)
    pub receiver_balance: u64,
    /// Total closing fee (paid by funder/sender)
    pub total_fee: u64,
    /// Current nonce value
    pub nonce: u32,
    /// Commitment over the force close state
    pub commitment: ChannelCommitment,
    /// Timeout in blocks for CSV timelock
    pub timeout_blocks: u16,
}

/// Parameters required to construct a `ForceClosingPending` state.
///
/// Using a struct instead of a long positional argument list makes it much
/// harder to mix up balances, fees and capacity, which are all `u64`s.
#[derive(Debug, Clone, Copy)]
pub struct ForceClosingPendingParams {
    /// Sender's public key
    pub sender_pubkey: XOnlyPublicKey,
    /// Receiver's public key
    pub receiver_pubkey: XOnlyPublicKey,
    /// Total channel capacity
    pub total_capacity: u64,
    /// Sender balance after fee deduction (funder pays fees)
    pub sender_balance: u64,
    /// Receiver balance (unchanged)
    pub receiver_balance: u64,
    /// Total closing fee (paid by funder/sender)
    pub total_fee: u64,
    /// Current nonce value
    pub nonce: u32,
    /// Timeout in blocks for CSV timelock
    pub timeout_blocks: u16,
}

impl ForceClosingPending {
    /// Creates a new ForceClosingPending state
    ///
    /// # Arguments
    /// * `params` - All fields required to describe the force-closing state
    pub fn new(params: ForceClosingPendingParams) -> Self {
        Self {
            sender_pubkey: params.sender_pubkey,
            receiver_pubkey: params.receiver_pubkey,
            total_capacity: params.total_capacity,
            sender_balance: params.sender_balance,
            receiver_balance: params.receiver_balance,
            total_fee: params.total_fee,
            nonce: params.nonce,
            commitment: ChannelCommitment::default(),
            timeout_blocks: params.timeout_blocks,
        }
    }

    /// Validates that balances and fees sum to total capacity
    pub fn validate_balances(&self) -> bool {
        self.sender_balance
            .checked_add(self.receiver_balance)
            .and_then(|sum| sum.checked_add(self.total_fee))
            .map(|total| total == self.total_capacity)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::test_utils::test_keys;

    #[test]
    fn test_new() {
        let (sender_pubkey, receiver_pubkey) = test_keys();

        let params = ForceClosingPendingParams {
            sender_pubkey,
            receiver_pubkey,
            total_capacity: 105,
            sender_balance: 60,
            receiver_balance: 40,
            total_fee: 5,
            nonce: 1,
            timeout_blocks: 10,
        };

        let state = ForceClosingPending::new(params);

        assert_eq!(state.sender_balance, 60);
        assert_eq!(state.receiver_balance, 40);
        assert_eq!(state.total_fee, 5);
        assert_eq!(state.total_capacity, 105);
        assert_eq!(state.nonce, 1);
        assert_eq!(state.timeout_blocks, 10);
        assert_eq!(state.sender_pubkey, sender_pubkey);
        assert_eq!(state.receiver_pubkey, receiver_pubkey);
        assert_eq!(state.commitment, ChannelCommitment::default());
    }

    #[test]
    fn test_validate_balances() {
        let (sender_pubkey, receiver_pubkey) = test_keys();

        let params_valid = ForceClosingPendingParams {
            sender_pubkey,
            receiver_pubkey,
            total_capacity: 100,
            sender_balance: 60,
            receiver_balance: 30,
            total_fee: 10,
            nonce: 1,
            timeout_blocks: 10,
        };
        let params_unequal = ForceClosingPendingParams { total_capacity: 90, ..params_valid };
        let params_overflow = ForceClosingPendingParams {
            sender_balance: u64::MAX,
            receiver_balance: 1,
            total_fee: 0,
            total_capacity: 0,
            ..params_valid
        };

        let state_valid = ForceClosingPending::new(params_valid);
        let state_unequal = ForceClosingPending::new(params_unequal);
        let state_overflow = ForceClosingPending::new(params_overflow);

        assert!(state_valid.validate_balances());
        assert!(!state_unequal.validate_balances());
        assert!(!state_overflow.validate_balances());
    }
}
