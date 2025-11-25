//! Close output calculation utilities
//!
//! This module provides shared utilities for calculating close outputs
//! for both cooperative and force close operations.

use crate::errors::ChannelError::{
    InsufficientCombinedFeeContribution, InsufficientReceiverFeeContribution,
    InsufficientSenderFeeContribution, TotalFeeContributionMismatch,
};
use crate::{Error, Result};

/// Parameters for calculating close outputs
///
/// Groups all the parameters needed to calculate the final balances
/// after deducting fees from both parties.
#[derive(Debug, Clone, Copy)]
pub struct CloseOutputsParams {
    /// Sender's current balance
    pub sender_balance: u64,
    /// Receiver's current balance
    pub receiver_balance: u64,
    /// Sender's contribution to the closing fee
    pub sender_contribution: u64,
    /// Receiver's contribution to the closing fee
    pub receiver_contribution: u64,
    /// Total closing fee required
    pub total_fee: u64,
}

/// Calculate close outputs with fee payment policy
///
/// Implements the funder-pays fee policy where the sender (funder) pays all closing fees.
/// The fee is deducted from the sender's balance, and the receiver's balance remains unchanged.
///
/// # Arguments
/// * `sender_balance` - Balance of the sender (funder)
/// * `receiver_balance` - Balance of the receiver
/// * `closing_fee` - Total closing fee in satoshis
///
/// # Returns
/// * `Ok((sender_output, receiver_output))` - Tuple of outputs after fee deduction
/// * `Err(ChannelError::InsufficientSenderFeeContribution)` - If the sender cannot afford the fee
///
/// # Note
/// If the sender cannot afford the closing fee, consider using
/// `calculate_close_outputs_with_contributions` to allow the receiver
/// to contribute to the closing fee.
pub fn calculate_close_outputs(
    sender_balance: u64,
    receiver_balance: u64,
    closing_fee: u64,
) -> Result<(u64, u64)> {
    if sender_balance >= closing_fee {
        Ok((sender_balance - closing_fee, receiver_balance))
    } else {
        Err(Error::Channel(InsufficientSenderFeeContribution {
            balance: sender_balance,
            contribution: closing_fee,
        }))
    }
}

/// Calculate close outputs with dual-party fee contributions
///
/// Implements a fee payment policy where both parties contribute to the closing fees,
/// following the collaborative transaction construction pattern from BOLT #2 where both
/// peers can contribute inputs/fees to a transaction.
///
/// Parties specify their contributions as **absolute values in satoshis**.
///
/// This helper performs **only arithmetic and affordability checks**:
/// 1. Both parties can afford their respective contributions
/// 2. Combined contributions equal or exceed the total fee
///
/// It intentionally **does not** enforce policy-level invariants about how
/// the contributions relate to `total_fee` beyond being sufficient (for
/// example, it does not require that individual contributions are ≤
/// `total_fee`, or that their sum is exactly equal to `total_fee`).
///
/// Those higher-level invariants are enforced by transition functions such
/// as [`crate::channel::transition::cooperative_close::apply_cooperative_close_with_fee_contributions`],
/// which define the cooperative-close fee split policy.
///
/// If any affordability or sufficiency validation fails, an appropriate
/// error is returned.
///
/// # Arguments
/// * `params` - Parameters containing balances, total fee, and fee contributions
///
/// # Returns
/// * `Ok((sender_output, receiver_output))` - Tuple of outputs after fee deduction
/// * `Err(ChannelError::InsufficientSenderFeeContribution)` - If sender cannot afford their contribution
/// * `Err(ChannelError::InsufficientReceiverFeeContribution)` - If receiver cannot afford their contribution
/// * `Err(ChannelError::InsufficientCombinedFeeContribution)` - If combined contributions are insufficient (sum < required)
/// * `Err(ChannelError::TotalFeeContributionMismatch)` - If combined contributions overflow or exceed the required fee
pub fn calculate_close_outputs_with_contributions(
    params: CloseOutputsParams,
) -> Result<(u64, u64)> {
    if params.sender_balance < params.sender_contribution {
        return Err(Error::Channel(InsufficientSenderFeeContribution {
            balance: params.sender_balance,
            contribution: params.sender_contribution,
        }));
    }

    if params.receiver_balance < params.receiver_contribution {
        return Err(Error::Channel(InsufficientReceiverFeeContribution {
            balance: params.receiver_balance,
            contribution: params.receiver_contribution,
        }));
    }

    let total_contribution = params
        .sender_contribution
        .checked_add(params.receiver_contribution)
        .ok_or(Error::Channel(TotalFeeContributionMismatch {
        sender_contribution: params.sender_contribution,
        receiver_contribution: params.receiver_contribution,
        total_contribution: u64::MAX, // represents overflowed sum
        required_fee: params.total_fee,
    }))?;
    if total_contribution < params.total_fee {
        return Err(Error::Channel(InsufficientCombinedFeeContribution {
            sender_contribution: params.sender_contribution,
            receiver_contribution: params.receiver_contribution,
            total_contribution,
            required_fee: params.total_fee,
        }));
    }

    if total_contribution > params.total_fee {
        return Err(Error::Channel(TotalFeeContributionMismatch {
            sender_contribution: params.sender_contribution,
            receiver_contribution: params.receiver_contribution,
            total_contribution,
            required_fee: params.total_fee,
        }));
    }

    let sender_output = params.sender_balance - params.sender_contribution;
    let receiver_output = params.receiver_balance - params.receiver_contribution;

    Ok((sender_output, receiver_output))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::ChannelError;

    #[test]
    fn test_calculate_close_outputs() {
        let (sender_ok, receiver_ok) =
            calculate_close_outputs(100, 50, 10).expect("sender should cover closing fee");
        assert_eq!(sender_ok, 90);
        assert_eq!(receiver_ok, 50);

        let error = calculate_close_outputs(5, 50, 10)
            .expect_err("should fail with insufficient sender fee contribution");
        match error {
            Error::Channel(ChannelError::InsufficientSenderFeeContribution {
                balance,
                contribution,
            }) => {
                assert_eq!(balance, 5);
                assert_eq!(contribution, 10);
            }
            _ => panic!("unexpected error variant"),
        }
    }

    #[test]
    fn test_calculate_close_outputs_with_contributions() {
        let params_sender_insufficient = CloseOutputsParams {
            sender_balance: 5,
            receiver_balance: 50,
            sender_contribution: 10,
            receiver_contribution: 0,
            total_fee: 10,
        };
        let error_sender = calculate_close_outputs_with_contributions(params_sender_insufficient)
            .expect_err("should fail with insufficient sender fee contribution");
        match error_sender {
            Error::Channel(ChannelError::InsufficientSenderFeeContribution {
                balance,
                contribution,
            }) => {
                assert_eq!(balance, 5);
                assert_eq!(contribution, 10);
            }
            _ => panic!("unexpected error variant for sender insufficient"),
        }

        let params_receiver_insufficient = CloseOutputsParams {
            sender_balance: 50,
            receiver_balance: 5,
            sender_contribution: 10,
            receiver_contribution: 10,
            total_fee: 10,
        };
        let error_receiver =
            calculate_close_outputs_with_contributions(params_receiver_insufficient)
                .expect_err("should fail with insufficient receiver fee contribution");
        match error_receiver {
            Error::Channel(ChannelError::InsufficientReceiverFeeContribution {
                balance,
                contribution,
            }) => {
                assert_eq!(balance, 5);
                assert_eq!(contribution, 10);
            }
            _ => panic!("unexpected error variant for receiver insufficient"),
        }

        let params_overflow = CloseOutputsParams {
            sender_balance: u64::MAX,
            receiver_balance: u64::MAX,
            sender_contribution: u64::MAX,
            receiver_contribution: 1,
            total_fee: 10,
        };
        let error_overflow = calculate_close_outputs_with_contributions(params_overflow)
            .expect_err("should fail with fee contribution overflow");
        match error_overflow {
            Error::Channel(ChannelError::TotalFeeContributionMismatch {
                sender_contribution,
                receiver_contribution,
                total_contribution,
                required_fee,
            }) => {
                assert_eq!(sender_contribution, u64::MAX);
                assert_eq!(receiver_contribution, 1);
                // Overflow case: we record u64::MAX as a sentinel total
                assert_eq!(total_contribution, u64::MAX);
                assert_eq!(required_fee, 10);
            }
            _ => panic!("unexpected error variant for overflow"),
        }

        let params_insufficient_combined = CloseOutputsParams {
            sender_balance: 10,
            receiver_balance: 10,
            sender_contribution: 5,
            receiver_contribution: 4,
            total_fee: 20,
        };
        let error_combined =
            calculate_close_outputs_with_contributions(params_insufficient_combined)
                .expect_err("should fail with insufficient combined fee contribution");
        match error_combined {
            Error::Channel(ChannelError::InsufficientCombinedFeeContribution {
                sender_contribution,
                receiver_contribution,
                total_contribution,
                required_fee,
            }) => {
                assert_eq!(sender_contribution, 5);
                assert_eq!(receiver_contribution, 4);
                assert_eq!(total_contribution, 9);
                assert_eq!(required_fee, 20);
            }
            _ => panic!("unexpected error variant for insufficient combined"),
        }

        let params_success = CloseOutputsParams {
            sender_balance: 10,
            receiver_balance: 10,
            sender_contribution: 4,
            receiver_contribution: 4,
            total_fee: 8,
        };
        let (sender_out, receiver_out) =
            calculate_close_outputs_with_contributions(params_success).expect("success path");
        assert_eq!(sender_out, 6);
        assert_eq!(receiver_out, 6);
    }
}
