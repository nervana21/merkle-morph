// SPDX-License-Identifier: CC0-1.0

//! Close output calculation utilities
//!
//! This module provides shared utilities for calculating close outputs
//! for both cooperative and force close operations.

use crate::errors::ChannelError::{
    BalanceOverflow, InsufficientCombinedFeeContribution, InsufficientReceiverFeeContribution,
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
/// * `Err(ChannelError::BalanceOverflow)` - If combined contributions would overflow (sum > u64::MAX)
/// * `Err(ChannelError::TotalFeeContributionMismatch)` - If combined contributions exceed the required fee (sum > required)
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
        .ok_or(Error::Channel(BalanceOverflow))?;

    match total_contribution.cmp(&params.total_fee) {
        std::cmp::Ordering::Less => {
            return Err(Error::Channel(InsufficientCombinedFeeContribution {
                sender_contribution: params.sender_contribution,
                receiver_contribution: params.receiver_contribution,
                total_contribution,
                required_fee: params.total_fee,
            }));
        }
        std::cmp::Ordering::Greater => {
            return Err(Error::Channel(TotalFeeContributionMismatch {
                sender_contribution: params.sender_contribution,
                receiver_contribution: params.receiver_contribution,
                total_contribution,
                required_fee: params.total_fee,
            }));
        }
        std::cmp::Ordering::Equal => {
            // Continue with calculation
        }
    }

    let sender_output = params.sender_balance - params.sender_contribution;
    let receiver_output = params.receiver_balance - params.receiver_contribution;

    Ok((sender_output, receiver_output))
}

/// Computes total channel capacity with overflow checking
///
/// Calculates the sum of sender and receiver balances with overflow protection.
/// Returns an error if the addition would overflow.
///
/// # Arguments
/// * `sender_balance` - Sender's balance
/// * `receiver_balance` - Receiver's balance
///
/// # Returns
/// * `Ok(u64)` - Total capacity
/// * `Err(ChannelError::BalanceOverflow)` - If addition would overflow
pub fn compute_total_capacity_checked(sender_balance: u64, receiver_balance: u64) -> Result<u64> {
    sender_balance.checked_add(receiver_balance).ok_or(Error::Channel(BalanceOverflow))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::ChannelError;

    #[test]
    fn test_calculate_close_outputs() {
        let (sender_ok, receiver_ok) = calculate_close_outputs(10, 5, 5).expect("valid inputs");

        assert_eq!(sender_ok, 5);
        assert_eq!(receiver_ok, 5);
        assert!(matches!(
            calculate_close_outputs(5, 10, 10),
            Err(Error::Channel(ChannelError::InsufficientSenderFeeContribution { .. }))
        ));
    }

    #[test]
    fn test_calculate_close_outputs_with_contributions() {
        let params_sender_insufficient = CloseOutputsParams {
            sender_balance: 5,
            receiver_balance: 10,
            sender_contribution: 10,
            receiver_contribution: 0,
            total_fee: 10,
        };

        assert!(matches!(
            calculate_close_outputs_with_contributions(params_sender_insufficient),
            Err(Error::Channel(ChannelError::InsufficientSenderFeeContribution { .. }))
        ));

        let params_receiver_insufficient = CloseOutputsParams {
            sender_balance: 10,
            receiver_balance: 5,
            sender_contribution: 0,
            receiver_contribution: 10,
            total_fee: 10,
        };

        assert!(matches!(
            calculate_close_outputs_with_contributions(params_receiver_insufficient),
            Err(Error::Channel(ChannelError::InsufficientReceiverFeeContribution { .. }))
        ));

        let params_overflow = CloseOutputsParams {
            sender_balance: u64::MAX,
            receiver_balance: u64::MAX,
            sender_contribution: u64::MAX,
            receiver_contribution: 1,
            total_fee: 10,
        };

        assert!(matches!(
            calculate_close_outputs_with_contributions(params_overflow),
            Err(Error::Channel(ChannelError::BalanceOverflow))
        ));

        let params_insufficient_combined = CloseOutputsParams {
            sender_balance: 10,
            receiver_balance: 10,
            sender_contribution: 5,
            receiver_contribution: 4,
            total_fee: 10,
        };

        assert!(matches!(
            calculate_close_outputs_with_contributions(params_insufficient_combined),
            Err(Error::Channel(ChannelError::InsufficientCombinedFeeContribution { .. }))
        ));

        let params_exceeds = CloseOutputsParams {
            sender_balance: 10,
            receiver_balance: 10,
            sender_contribution: 5,
            receiver_contribution: 6,
            total_fee: 10,
        };

        assert!(matches!(
            calculate_close_outputs_with_contributions(params_exceeds),
            Err(Error::Channel(ChannelError::TotalFeeContributionMismatch { .. }))
        ));

        let params_success = CloseOutputsParams {
            sender_balance: 10,
            receiver_balance: 10,
            sender_contribution: 5,
            receiver_contribution: 5,
            total_fee: 10,
        };

        let (sender_out, receiver_out) =
            calculate_close_outputs_with_contributions(params_success).expect("valid inputs");

        assert_eq!(sender_out, 5);
        assert_eq!(receiver_out, 5);
    }

    #[test]
    fn test_compute_total_capacity_checked() {
        assert_eq!(compute_total_capacity_checked(10, 5).expect("valid inputs"), 15);

        assert!(matches!(
            compute_total_capacity_checked(u64::MAX, 1),
            Err(Error::Channel(ChannelError::BalanceOverflow))
        ));
    }
}
