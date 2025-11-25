// SPDX-License-Identifier: CC0-1.0

//! Force close transition
//!
//! This transition moves a channel from Open to ForceClosingPending state.
//!
//! # State Flow
//! Open → ForceClosingPending
//!
//! # Preconditions
//! - Channel is in Open state
//! - Funder (sender) can afford the closing fee
//!
//! # Postconditions
//! - Channel is in ForceClosingPending state
//! - Final balances are determined (funder pays fees)
//! - Nonce incremented by exactly +1
//! - Commitment updated
//! - Timeout blocks set
//!
//! # Fee Semantics
//! - Funder (sender) always pays all fees for force closes (BOLT3-compliant)

use std::fmt;

use bitcoin::secp256k1::XOnlyPublicKey;

use crate::channel::close_utils::{calculate_close_outputs, compute_total_capacity_checked};
use crate::channel::commitment::state_commitment::compute_force_closing_pending_commitment;
use crate::channel::state::{ForceClosingPending, ForceClosingPendingParams, Open};
use crate::errors::ChannelError;
use crate::errors::ChannelError::{ChannelNonceOverflow, FunderCannotAffordFee};
use crate::types::{ChannelCommitment, ChannelId};
use crate::zkp::prove_force_close_transition;
use crate::{Error, Proof, Result, StarkConfig};

/// Result of a force close operation
///
/// Contains the new state, commitment, and proof for the transition.
pub struct ForceCloseResult {
    /// New channel state after transition
    pub new_state: ForceClosingPending,
    /// Commitment to the new state
    pub commitment: ChannelCommitment,
    /// Proof for the transition
    pub proof: Proof,
}

impl fmt::Debug for ForceCloseResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ForceCloseResult")
            .field("new_state", &"<hidden>")
            .field("commitment", &"<hidden>")
            .field("proof", &"<hidden>")
            .finish()
    }
}

/// Apply a force close operation with fee deduction
///
/// This function closes a channel and applies the BOLT3-compliant fee payment policy where the
/// funder (channel opener/sender) pays all fees for force close transactions,
/// regardless of who broadcasts the transaction. If the funder can't pay the fee, the close
/// operation fails.
///
/// The CSV timelock duration is read from the channel state's `timeout_blocks` field, which
/// allows per-channel configuration.
///
/// # Arguments
/// * `state` - Current Open state (contains `timeout_blocks` configuration)
/// * `closing_fee` - Total closing fee in satoshis
/// * `channel_id` - Channel identifier
/// * `config` - Proof system configuration
/// * `sender_sk` - Optional sender's private key. If provided (sender-initiated force close),
///   auth_hash is computed to prove sender authorization. If None (receiver-initiated),
///   auth_hash is set to zero and authentication is handled at the Bitcoin transaction layer.
///
/// # Returns
/// * `Ok(ForceCloseResult)` - Contains new state, commitment, and proof
/// * `Err(ChannelError::FunderCannotAffordFee)` - Error if funder cannot afford the fee
/// * `Err(ChannelError::ChannelNonceOverflow)` - Error if nonce would overflow
pub fn apply_force_close(
    state: &Open,
    closing_fee: u64,
    channel_id: ChannelId,
    config: &StarkConfig,
    sender_sk: Option<&bitcoin::secp256k1::SecretKey>,
) -> Result<ForceCloseResult> {
    // Check if funder can afford the fee upfront to construct the correct error type
    if state.sender_balance < closing_fee {
        return Err(Error::Channel(FunderCannotAffordFee {
            balance: state.sender_balance,
            fee: closing_fee,
        }));
    }

    let (sender_output, receiver_output) =
        calculate_close_outputs(state.sender_balance, state.receiver_balance, closing_fee)?;

    let new_nonce = state.nonce.checked_add(1).ok_or(ChannelNonceOverflow)?;

    let total_capacity =
        compute_total_capacity_checked(state.sender_balance, state.receiver_balance)?;

    let mut force_closing_state = ForceClosingPending::new(ForceClosingPendingParams {
        sender_pubkey: state.sender_pubkey,
        receiver_pubkey: state.receiver_pubkey,
        total_capacity,
        sender_balance: sender_output,
        receiver_balance: receiver_output,
        total_fee: closing_fee,
        nonce: new_nonce,
        timeout_blocks: state.timeout_blocks,
    });

    force_closing_state.commitment =
        compute_force_closing_pending_commitment(channel_id, &force_closing_state);
    let commitment = force_closing_state.commitment;

    let proof = prove_force_close_transition(
        channel_id,
        state,
        closing_fee,
        &force_closing_state,
        config,
        sender_sk,
    )?;

    Ok(ForceCloseResult { new_state: force_closing_state, commitment, proof })
}

/// Validates that a channel state is valid for force close
///
/// This function ensures that:
/// 1. The channel state's public keys match the expected public keys
/// 2. The state nonce is at least as high as the latest known nonce (if provided)
///
/// # Arguments
/// * `state` - Channel state to validate
/// * `expected_sender_pubkey` - Expected sender public key
/// * `expected_receiver_pubkey` - Expected receiver public key
/// * `latest_nonce` - Optional latest known nonce for the channel
///
/// # Returns
/// * `Ok(())` - State is valid for force close
/// * `Err(ChannelError::InvalidForceCloseTransaction)` - Public keys don't match expected
/// * `Err(ChannelError::InvalidForceCloseState)` - State nonce is older than latest known
pub fn validate_force_close_state(
    state: &Open,
    expected_sender_pubkey: XOnlyPublicKey,
    expected_receiver_pubkey: XOnlyPublicKey,
    latest_nonce: Option<u32>,
) -> Result<()> {
    if state.sender_pubkey != expected_sender_pubkey
        || state.receiver_pubkey != expected_receiver_pubkey
    {
        return Err(Error::Channel(ChannelError::InvalidForceCloseTransaction {
            reason: "force close state public keys do not match expected values".to_string(),
        }));
    }

    if let Some(latest) = latest_nonce {
        if state.nonce < latest {
            return Err(Error::Channel(ChannelError::InvalidForceCloseState {
                provided_nonce: state.nonce,
                latest_nonce: latest,
            }));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::test_utils::*;
    use crate::errors::ChannelError;

    #[test]
    fn test_apply_force_close() {
        let (sender_pubkey, receiver_pubkey) = test_keys();
        let (sender_revocation_secret, receiver_revocation_secret) = revocation_secrets();
        let channel_id = [0u8; 32];
        let config = crate::zkp::types::create_config().expect("should create config");
        let state_success = Open::new(
            sender_pubkey,
            receiver_pubkey,
            100,
            sender_revocation_secret,
            receiver_revocation_secret,
        );

        let result_success = apply_force_close(&state_success, 10, channel_id, &config, None)
            .expect("success branch");

        assert_eq!(result_success.new_state.sender_balance, 90);
        assert_eq!(result_success.new_state.receiver_balance, 0);
        assert_eq!(result_success.new_state.nonce, 1);
        assert_eq!(result_success.new_state.timeout_blocks, state_success.timeout_blocks);

        let state_fee_shortfall = Open::new(
            sender_pubkey,
            receiver_pubkey,
            5,
            sender_revocation_secret,
            receiver_revocation_secret,
        );

        let error_fee = apply_force_close(&state_fee_shortfall, 10, channel_id, &config, None)
            .expect_err("fee contribution branch");

        match error_fee {
            Error::Channel(ChannelError::FunderCannotAffordFee { balance, fee }) => {
                assert_eq!(balance, 5);
                assert_eq!(fee, 10);
            }
            other => panic!("unexpected error for fee: {other:?}"),
        }

        let state_nonce_overflow = Open { nonce: u32::MAX, ..state_success.clone() };

        let error_nonce = apply_force_close(&state_nonce_overflow, 0, channel_id, &config, None)
            .expect_err("nonce overflow branch");

        match error_nonce {
            Error::Channel(ChannelError::ChannelNonceOverflow) => {}
            other => panic!("unexpected error for nonce: {other:?}"),
        }

        let state_balance_overflow =
            Open { sender_balance: u64::MAX, receiver_balance: 1, ..state_success };

        let error_balance =
            apply_force_close(&state_balance_overflow, 0, channel_id, &config, None)
                .expect_err("balance overflow branch");

        match error_balance {
            Error::Channel(ChannelError::BalanceOverflow) => {}
            other => panic!("unexpected error for balance: {other:?}"),
        }
    }

    #[test]
    fn test_validate_force_close_state() {
        let (sender_pubkey, receiver_pubkey) = test_keys();
        let (different_sender_pubkey, different_receiver_pubkey) = different_test_keys();
        let (sender_revocation_secret, receiver_revocation_secret) = revocation_secrets();
        let mut state = Open::new(
            sender_pubkey,
            receiver_pubkey,
            100,
            sender_revocation_secret,
            receiver_revocation_secret,
        );

        let error_keys = validate_force_close_state(
            &state,
            different_sender_pubkey,
            different_receiver_pubkey,
            None,
        )
        .expect_err("mismatched keys branch");

        match error_keys {
            Error::Channel(ChannelError::InvalidForceCloseTransaction { reason }) => {
                assert_eq!(reason, "force close state public keys do not match expected values");
            }
            other => panic!("unexpected error for keys: {other:?}"),
        }

        validate_force_close_state(&state, sender_pubkey, receiver_pubkey, None)
            .expect("no latest nonce branch");

        let error_old_nonce = validate_force_close_state(
            &state,
            sender_pubkey,
            receiver_pubkey,
            Some(state.nonce + 1),
        )
        .expect_err("stale nonce branch");

        match error_old_nonce {
            Error::Channel(ChannelError::InvalidForceCloseState {
                provided_nonce,
                latest_nonce,
            }) => {
                assert_eq!(provided_nonce, state.nonce);
                assert_eq!(latest_nonce, state.nonce + 1);
            }
            other => panic!("unexpected error for nonce: {other:?}"),
        }

        state.nonce = 2;

        validate_force_close_state(&state, sender_pubkey, receiver_pubkey, Some(1))
            .expect("latest nonce provided branch");
    }
}
