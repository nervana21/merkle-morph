// SPDX-License-Identifier: CC0-1.0

//! Cooperative close transition
//!
//! This transition transforms a channel from Open to CooperativeClosing state.
//!
//! This transition specifies:
//! - Valid source and target states: Open → CooperativeClosing
//! - Preconditions that must hold before the transition can be applied
//! - Postconditions that are guaranteed after a successful transition
//! - Input requirements and validation rules
//! - Nonce progression rules (strict +1 increment)
//! - Fee semantics and allocation policies

use std::fmt;

use crate::channel::close_utils::{
    calculate_close_outputs, calculate_close_outputs_with_contributions,
    compute_total_capacity_checked, CloseOutputsParams,
};
use crate::channel::commitment::state_commitment::compute_cooperative_closing_commitment;
use crate::channel::state::{CooperativeClosing, Open};
use crate::errors::ChannelError::{BalanceOverflow, ChannelNonceOverflow};
use crate::types::{ChannelCommitment, ChannelId};
use crate::zkp::prove_cooperative_close_transition;
use crate::{Error, Proof, Result, StarkConfig};

/// Result of a cooperative close operation
///
/// Contains the new state, commitment, and proof for the transition.
pub struct CooperativeCloseResult {
    /// New channel state after transition
    pub new_state: CooperativeClosing,
    /// Commitment to the new state
    pub commitment: ChannelCommitment,
    /// Proof for the transition
    pub proof: Proof,
}

impl fmt::Debug for CooperativeCloseResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CooperativeCloseResult")
            .field("new_state", &"<hidden>")
            .field("commitment", &"<hidden>")
            .field("proof", &"<hidden>")
            .finish()
    }
}

/// Apply a cooperative close operation with fee deduction
///
/// Implements the closing method where the sender (funder) pays all closing fees.
/// The fee is deducted from the sender's balance, and the receiver's balance remains unchanged.
/// If the sender cannot afford the fee, the close operation fails.
///
/// To avoid this situation, transfers should maintain a minimum reserve balance
/// for the sender to cover closing fees. If the sender cannot afford the fee,
/// use `apply_cooperative_close_with_fee_contributions` to allow the receiver
/// to contribute to the closing fee.
///
/// # Arguments
/// * `state` - Current Open state
/// * `closing_fee` - Total closing fee in satoshis
/// * `channel_id` - Channel identifier
/// * `config` - Proof system configuration
///
/// # Returns
/// * `Ok(CooperativeCloseResult)` - Contains new state, commitment, and proof
/// * `Err(ChannelError::InsufficientSenderFeeContribution)` - Error if sender cannot afford the fee
/// * `Err(ChannelError::ChannelNonceOverflow)` - Error if nonce would overflow
///
/// # Note
/// If the sender cannot afford the closing fee, consider using
/// `apply_cooperative_close_with_fee_contributions` to allow the receiver
/// to contribute to the closing fee.
pub fn apply_cooperative_close(
    state: &Open,
    closing_fee: u64,
    channel_id: ChannelId,
    config: &StarkConfig,
) -> Result<CooperativeCloseResult> {
    let (sender_output, receiver_output) =
        calculate_close_outputs(state.sender_balance, state.receiver_balance, closing_fee)?;

    let new_nonce = state.nonce.checked_add(1).ok_or(ChannelNonceOverflow)?;

    let total_capacity =
        compute_total_capacity_checked(state.sender_balance, state.receiver_balance)?;

    let mut closing_state =
        CooperativeClosing::new(crate::channel::state::CooperativeClosingParams {
            sender_pubkey: state.sender_pubkey,
            receiver_pubkey: state.receiver_pubkey,
            total_capacity,
            sender_balance: sender_output,
            receiver_balance: receiver_output,
            total_fee: closing_fee,
            sender_contribution: closing_fee,
            receiver_contribution: 0,
            nonce: new_nonce,
        });

    closing_state.commitment = compute_cooperative_closing_commitment(channel_id, &closing_state);
    let commitment = closing_state.commitment;

    let proof =
        prove_cooperative_close_transition(channel_id, state, closing_fee, &closing_state, config)?;

    Ok(CooperativeCloseResult { new_state: closing_state, commitment, proof })
}

/// Apply a cooperative close operation with dual-party fee contributions
///
/// Implements a closing method where both parties contribute to the closing fees,
/// following the collaborative transaction construction pattern from BOLT #2.
///
/// The fee contributions are deducted from each party's balance. If either party
/// cannot afford their contribution, or if the combined contributions are insufficient,
/// the close operation fails.
///
/// # Arguments
/// * `state` - Current Open state
/// * `closing_fee` - Total closing fee in satoshis
/// * `sender_contribution` - Sender's contribution to the closing fee in satoshis
/// * `receiver_contribution` - Receiver's contribution to the closing fee in satoshis
/// * `channel_id` - Channel identifier
/// * `config` - Proof system configuration
///
/// # Returns
/// * `Ok(CooperativeCloseResult)` - Contains new state, commitment, and proof
/// * `Err(ChannelError::InsufficientSenderFeeContribution)` - Error if sender cannot afford their contribution
/// * `Err(ChannelError::InsufficientReceiverFeeContribution)` - Error if receiver cannot afford their contribution
/// * `Err(ChannelError::InsufficientCombinedFeeContribution)` - Error if combined contributions are insufficient (sum < required)
/// * `Err(ChannelError::BalanceOverflow)` - Error if combined contributions would overflow (sum > u64::MAX)
/// * `Err(ChannelError::TotalFeeContributionMismatch)` - Error if combined contributions exceed the required fee (sum > required)
/// * `Err(ChannelError::ChannelNonceOverflow)` - Error if nonce would overflow
pub fn apply_cooperative_close_with_fee_contributions(
    state: &Open,
    closing_fee: u64,
    sender_contribution: u64,
    receiver_contribution: u64,
    channel_id: ChannelId,
    config: &StarkConfig,
) -> Result<CooperativeCloseResult> {
    // Check overflow early to ensure it's reported even if affordability checks would fail first.
    sender_contribution
        .checked_add(receiver_contribution)
        .ok_or(Error::Channel(BalanceOverflow))?;

    let params = CloseOutputsParams {
        sender_balance: state.sender_balance,
        receiver_balance: state.receiver_balance,
        sender_contribution,
        receiver_contribution,
        total_fee: closing_fee,
    };
    let (sender_output, receiver_output) = calculate_close_outputs_with_contributions(params)?;

    let new_nonce = state.nonce.checked_add(1).ok_or(ChannelNonceOverflow)?;
    let total_capacity =
        compute_total_capacity_checked(state.sender_balance, state.receiver_balance)?;

    let mut closing_state =
        CooperativeClosing::new(crate::channel::state::CooperativeClosingParams {
            sender_pubkey: state.sender_pubkey,
            receiver_pubkey: state.receiver_pubkey,
            total_capacity,
            sender_balance: sender_output,
            receiver_balance: receiver_output,
            total_fee: closing_fee,
            sender_contribution,
            receiver_contribution,
            nonce: new_nonce,
        });

    closing_state.commitment = compute_cooperative_closing_commitment(channel_id, &closing_state);
    let commitment = closing_state.commitment;

    let proof =
        prove_cooperative_close_transition(channel_id, state, closing_fee, &closing_state, config)?;

    Ok(CooperativeCloseResult { new_state: closing_state, commitment, proof })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::test_utils;
    use crate::errors::ChannelError;
    use crate::types::ChannelCommitment;

    #[test]
    fn test_apply_cooperative_close() {
        let (sender_pubkey, receiver_pubkey) = test_utils::test_keys();
        let (sender_revocation_secret, receiver_revocation_secret) =
            test_utils::revocation_secrets();
        let channel_id = [0u8; 32];
        let config = crate::zkp::types::create_config().expect("should create config");

        let state_ok = Open::new(
            sender_pubkey,
            receiver_pubkey,
            100,
            sender_revocation_secret,
            receiver_revocation_secret,
        );

        let ok = apply_cooperative_close(&state_ok, 10, channel_id, &config).expect("ok");

        assert_eq!(ok.new_state.sender_balance, 90);
        assert_eq!(ok.new_state.receiver_balance, 0);
        assert_eq!(ok.new_state.nonce, 1);

        let err_insufficient =
            apply_cooperative_close(&state_ok, 150, channel_id, &config).expect_err("insufficient");

        match err_insufficient {
            Error::Channel(ChannelError::InsufficientSenderFeeContribution {
                balance,
                contribution,
            }) => {
                assert_eq!(balance, 100);
                assert_eq!(contribution, 150);
            }
            other => panic!("{other:?}"),
        }

        let nonce_overflow = Open {
            sender_pubkey,
            receiver_pubkey,
            sender_revocation_pubkey: sender_pubkey,
            receiver_revocation_pubkey: receiver_pubkey,
            sender_revocation_secret: [0u8; 32],
            receiver_revocation_secret: [0u8; 32],
            sender_balance: 50,
            receiver_balance: 0,
            nonce: u32::MAX,
            commitment: ChannelCommitment::default(),
            metadata: vec![],
            timeout_blocks: 144,
        };

        let err_nonce = apply_cooperative_close(&nonce_overflow, 0, channel_id, &config)
            .expect_err("nonce overflow");

        match err_nonce {
            Error::Channel(ChannelError::ChannelNonceOverflow) => {}
            other => panic!("{other:?}"),
        }

        let balance_overflow = Open {
            sender_pubkey,
            receiver_pubkey,
            sender_revocation_pubkey: sender_pubkey,
            receiver_revocation_pubkey: receiver_pubkey,
            sender_revocation_secret: [0u8; 32],
            receiver_revocation_secret: [0u8; 32],
            sender_balance: u64::MAX,
            receiver_balance: 1,
            nonce: 0,
            commitment: ChannelCommitment::default(),
            metadata: vec![],
            timeout_blocks: 144,
        };

        let err_balance = apply_cooperative_close(&balance_overflow, 0, channel_id, &config)
            .expect_err("balance overflow");

        match err_balance {
            Error::Channel(ChannelError::BalanceOverflow) => {}
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn test_apply_cooperative_close_with_fee_contributions() {
        let (sender_pubkey, receiver_pubkey) = test_utils::test_keys();
        let (sender_revocation_secret, receiver_revocation_secret) =
            test_utils::revocation_secrets();
        let channel_id = [0u8; 32];
        let config = crate::zkp::types::create_config().expect("should create config");
        let base_state = Open {
            sender_pubkey,
            receiver_pubkey,
            sender_revocation_pubkey: sender_pubkey,
            receiver_revocation_pubkey: receiver_pubkey,
            sender_revocation_secret: sender_revocation_secret.to_secret_bytes(),
            receiver_revocation_secret: receiver_revocation_secret.to_secret_bytes(),
            sender_balance: 100,
            receiver_balance: 100,
            nonce: 0,
            commitment: ChannelCommitment::default(),
            metadata: vec![],
            timeout_blocks: 144,
        };

        let ok = apply_cooperative_close_with_fee_contributions(
            &base_state,
            10,
            6,
            4,
            channel_id,
            &config,
        )
        .expect("ok");

        assert_eq!(ok.new_state.sender_balance, 94);
        assert_eq!(ok.new_state.receiver_balance, 96);
        assert_eq!(ok.new_state.nonce, 1);

        let overflow_sum = apply_cooperative_close_with_fee_contributions(
            &base_state,
            1,
            u64::MAX,
            1,
            channel_id,
            &config,
        )
        .expect_err("sum overflow");

        match overflow_sum {
            Error::Channel(ChannelError::BalanceOverflow) => {}
            other => panic!("expected BalanceOverflow, got {other:?}"),
        }

        // When a party contributes more than the required fee, the exact match check
        // (total_contribution == total_fee) catches it and returns TotalFeeContributionMismatch
        let over_party = apply_cooperative_close_with_fee_contributions(
            &base_state,
            10,
            11,
            0,
            channel_id,
            &config,
        )
        .expect_err("party over fee");

        match over_party {
            Error::Channel(ChannelError::TotalFeeContributionMismatch {
                sender_contribution,
                receiver_contribution,
                total_contribution,
                required_fee,
            }) => {
                assert_eq!(sender_contribution, 11);
                assert_eq!(receiver_contribution, 0);
                assert_eq!(total_contribution, 11);
                assert_eq!(required_fee, 10);
            }
            other => panic!("{other:?}"),
        }

        let under_total = apply_cooperative_close_with_fee_contributions(
            &base_state,
            10,
            4,
            5,
            channel_id,
            &config,
        )
        .expect_err("under total");

        match under_total {
            Error::Channel(ChannelError::InsufficientCombinedFeeContribution {
                total_contribution,
                required_fee,
                ..
            }) => {
                assert_eq!(total_contribution, 9);
                assert_eq!(required_fee, 10);
            }
            other => panic!("{other:?}"),
        }

        let over_total = apply_cooperative_close_with_fee_contributions(
            &base_state,
            10,
            6,
            5,
            channel_id,
            &config,
        )
        .expect_err("over total");

        match over_total {
            Error::Channel(ChannelError::TotalFeeContributionMismatch {
                total_contribution,
                required_fee,
                ..
            }) => {
                assert_eq!(total_contribution, 11);
                assert_eq!(required_fee, 10);
            }
            other => panic!("{other:?}"),
        }

        let sender_small = Open {
            sender_pubkey,
            receiver_pubkey,
            sender_revocation_pubkey: sender_pubkey,
            receiver_revocation_pubkey: receiver_pubkey,
            sender_revocation_secret: [0u8; 32],
            receiver_revocation_secret: [0u8; 32],
            sender_balance: 50,
            receiver_balance: 50,
            nonce: 0,
            commitment: ChannelCommitment::default(),
            metadata: vec![],
            timeout_blocks: 144,
        };

        let sender_afford = apply_cooperative_close_with_fee_contributions(
            &sender_small,
            60,
            60,
            0,
            channel_id,
            &config,
        )
        .expect_err("sender affordability");

        match sender_afford {
            Error::Channel(ChannelError::InsufficientSenderFeeContribution {
                balance,
                contribution,
            }) => {
                assert_eq!(balance, 50);
                assert_eq!(contribution, 60);
            }
            other => panic!("{other:?}"),
        }

        let receiver_small = Open {
            sender_pubkey,
            receiver_pubkey,
            sender_revocation_pubkey: sender_pubkey,
            receiver_revocation_pubkey: receiver_pubkey,
            sender_revocation_secret: [0u8; 32],
            receiver_revocation_secret: [0u8; 32],
            sender_balance: 50,
            receiver_balance: 50,
            nonce: 0,
            commitment: ChannelCommitment::default(),
            metadata: vec![],
            timeout_blocks: 144,
        };

        let receiver_afford = apply_cooperative_close_with_fee_contributions(
            &receiver_small,
            60,
            0,
            60,
            channel_id,
            &config,
        )
        .expect_err("receiver affordability");

        match receiver_afford {
            Error::Channel(ChannelError::InsufficientReceiverFeeContribution {
                balance,
                contribution,
            }) => {
                assert_eq!(balance, 50);
                assert_eq!(contribution, 60);
            }
            other => panic!("{other:?}"),
        }

        let nonce_overflow = Open {
            sender_pubkey,
            receiver_pubkey,
            sender_revocation_pubkey: sender_pubkey,
            receiver_revocation_pubkey: receiver_pubkey,
            sender_revocation_secret: [0u8; 32],
            receiver_revocation_secret: [0u8; 32],
            sender_balance: 50,
            receiver_balance: 50,
            nonce: u32::MAX,
            commitment: ChannelCommitment::default(),
            metadata: vec![],
            timeout_blocks: 144,
        };

        let err_nonce = apply_cooperative_close_with_fee_contributions(
            &nonce_overflow,
            10,
            5,
            5,
            channel_id,
            &config,
        )
        .expect_err("nonce overflow");

        match err_nonce {
            Error::Channel(ChannelError::ChannelNonceOverflow) => {}
            other => panic!("{other:?}"),
        }

        let capacity_overflow = Open {
            sender_pubkey,
            receiver_pubkey,
            sender_revocation_pubkey: sender_pubkey,
            receiver_revocation_pubkey: receiver_pubkey,
            sender_revocation_secret: [0u8; 32],
            receiver_revocation_secret: [0u8; 32],
            sender_balance: u64::MAX,
            receiver_balance: 1,
            nonce: 0,
            commitment: ChannelCommitment::default(),
            metadata: vec![],
            timeout_blocks: 144,
        };

        let err_capacity = apply_cooperative_close_with_fee_contributions(
            &capacity_overflow,
            0,
            0,
            0,
            channel_id,
            &config,
        )
        .expect_err("capacity overflow");

        match err_capacity {
            Error::Channel(ChannelError::BalanceOverflow) => {}
            other => panic!("{other:?}"),
        }
    }
}
