//! CooperativeClosing state
//!
//! This state represents a channel that is being closed cooperatively
//! between a sender and receiver. Both parties have agreed to
//! close the channel and signatures for the cooperative close
//! transaction are ready.
//!
//! # Invariants
//!
//! - Signatures for cooperative closure are ready
//! - Final balances are determined (after fee contributions)
//! - Channel cannot process new transfers
//! - Transition to Closed happens when transaction confirms

use bitcoin::secp256k1::XOnlyPublicKey;

use crate::types::ChannelCommitment;

/// Represents the finalized cooperative close state with agreed balances,
/// fee contributions, and corresponding commitment after the cooperative
/// close transaction has been confirmed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CooperativeClosing {
    /// Sender's public key
    pub sender_pubkey: XOnlyPublicKey,
    /// Receiver's public key
    pub receiver_pubkey: XOnlyPublicKey,
    /// Total channel capacity
    pub total_capacity: u64,
    /// Final sender balance after fee deduction
    pub sender_balance: u64,
    /// Final receiver balance after fee deduction
    pub receiver_balance: u64,
    /// Total closing fee
    pub total_fee: u64,
    /// Sender's contribution to closing fees
    pub sender_contribution: u64,
    /// Receiver's contribution to closing fees
    pub receiver_contribution: u64,
    /// Current nonce value
    pub nonce: u32,
    /// Commitment over the closing state
    pub commitment: ChannelCommitment,
}

/// Parameters required to construct a `CooperativeClosing` state.
///
/// Using a struct instead of a long positional argument list makes it much
/// harder to mix up amounts and contributions, which are all `u64`s.
#[derive(Debug, Clone, Copy)]
pub struct CooperativeClosingParams {
    /// Sender's public key
    pub sender_pubkey: XOnlyPublicKey,
    /// Receiver's public key
    pub receiver_pubkey: XOnlyPublicKey,
    /// Total channel capacity
    pub total_capacity: u64,
    /// Final sender balance after fee deduction
    pub sender_balance: u64,
    /// Final receiver balance after fee deduction
    pub receiver_balance: u64,
    /// Total closing fee
    pub total_fee: u64,
    /// Sender's contribution to closing fees
    pub sender_contribution: u64,
    /// Receiver's contribution to closing fees
    pub receiver_contribution: u64,
    /// Current nonce value
    pub nonce: u32,
}

impl CooperativeClosing {
    /// Creates a new CooperativeClosing state
    ///
    /// # Arguments
    /// * `params` - All fields required to describe the cooperative closing state
    pub fn new(params: CooperativeClosingParams) -> Self {
        Self {
            sender_pubkey: params.sender_pubkey,
            receiver_pubkey: params.receiver_pubkey,
            total_capacity: params.total_capacity,
            sender_balance: params.sender_balance,
            receiver_balance: params.receiver_balance,
            total_fee: params.total_fee,
            sender_contribution: params.sender_contribution,
            receiver_contribution: params.receiver_contribution,
            nonce: params.nonce,
            commitment: ChannelCommitment::default(),
        }
    }

    /// Validates that fee contributions are sufficient
    pub fn validate_fee_contributions(&self) -> bool {
        self.sender_contribution
            .checked_add(self.receiver_contribution)
            .map(|sum| sum >= self.total_fee)
            .unwrap_or(false)
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
        let params = CooperativeClosingParams {
            sender_pubkey,
            receiver_pubkey,
            total_capacity: 100,
            sender_balance: 60,
            receiver_balance: 30,
            total_fee: 10,
            sender_contribution: 6,
            receiver_contribution: 4,
            nonce: 5,
        };

        let state = CooperativeClosing::new(params);

        assert_eq!(state.sender_pubkey, sender_pubkey);
        assert_eq!(state.receiver_pubkey, receiver_pubkey);
        assert_eq!(state.total_capacity, 100);
        assert_eq!(state.sender_balance, 60);
        assert_eq!(state.receiver_balance, 30);
        assert_eq!(state.total_fee, 10);
        assert_eq!(state.sender_contribution, 6);
        assert_eq!(state.receiver_contribution, 4);
        assert_eq!(state.nonce, 5);
        assert_eq!(state.commitment, ChannelCommitment::default());
    }

    #[test]
    fn test_validate_fee_contributions() {
        let (sender_pubkey, receiver_pubkey) = test_keys();
        let params_overflow = CooperativeClosingParams {
            sender_pubkey,
            receiver_pubkey,
            total_capacity: 100,
            sender_balance: 50,
            receiver_balance: 50,
            total_fee: 10,
            sender_contribution: u64::MAX,
            receiver_contribution: 1,
            nonce: 0,
        };

        let state_overflow = CooperativeClosing::new(params_overflow);

        assert!(!state_overflow.validate_fee_contributions());

        let params_sufficient = CooperativeClosingParams {
            sender_pubkey,
            receiver_pubkey,
            total_capacity: 100,
            sender_balance: 50,
            receiver_balance: 50,
            total_fee: 10,
            sender_contribution: 6,
            receiver_contribution: 4,
            nonce: 0,
        };

        let state_sufficient = CooperativeClosing::new(params_sufficient);

        assert!(state_sufficient.validate_fee_contributions());

        let params_insufficient = CooperativeClosingParams {
            sender_pubkey,
            receiver_pubkey,
            total_capacity: 100,
            sender_balance: 50,
            receiver_balance: 50,
            total_fee: 10,
            sender_contribution: 4,
            receiver_contribution: 4,
            nonce: 0,
        };

        let state_insufficient = CooperativeClosing::new(params_insufficient);

        assert!(!state_insufficient.validate_fee_contributions());
    }

    #[test]
    fn test_validate_balances() {
        let (sender_pubkey, receiver_pubkey) = test_keys();
        let params_first_overflow = CooperativeClosingParams {
            sender_pubkey,
            receiver_pubkey,
            total_capacity: 100,
            sender_balance: u64::MAX,
            receiver_balance: 1,
            total_fee: 10,
            sender_contribution: 5,
            receiver_contribution: 5,
            nonce: 0,
        };

        let state_first_overflow = CooperativeClosing::new(params_first_overflow);

        assert!(!state_first_overflow.validate_balances());

        let params_second_overflow = CooperativeClosingParams {
            sender_pubkey,
            receiver_pubkey,
            total_capacity: 100,
            sender_balance: u64::MAX - 10,
            receiver_balance: 1,
            total_fee: 20,
            sender_contribution: 5,
            receiver_contribution: 5,
            nonce: 0,
        };
        let state_second_overflow = CooperativeClosing::new(params_second_overflow);

        assert!(!state_second_overflow.validate_balances());

        let params_equal = CooperativeClosingParams {
            sender_pubkey,
            receiver_pubkey,
            total_capacity: 100,
            sender_balance: 60,
            receiver_balance: 30,
            total_fee: 10,
            sender_contribution: 5,
            receiver_contribution: 5,
            nonce: 0,
        };

        let state_equal = CooperativeClosing::new(params_equal);

        assert!(state_equal.validate_balances());

        let params_not_equal = CooperativeClosingParams {
            sender_pubkey,
            receiver_pubkey,
            total_capacity: 100,
            sender_balance: 60,
            receiver_balance: 30,
            total_fee: 5,
            sender_contribution: 5,
            receiver_contribution: 5,
            nonce: 0,
        };

        let state_not_equal = CooperativeClosing::new(params_not_equal);

        assert!(!state_not_equal.validate_balances());
    }
}
