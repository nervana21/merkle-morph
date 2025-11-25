// SPDX-License-Identifier: CC0-1.0

//! Cooperative close transaction builders
//!
//! This module provides Bitcoin transaction builders for cooperative
//! close transactions. These builders translate channel state transitions
//! into Bitcoin transaction format.

use bitcoin::absolute::LockTime;
use bitcoin::address::NetworkUnchecked;
use bitcoin::script::ScriptSigBuf;
use bitcoin::transaction::Version;
use bitcoin::{Address, Sequence, Transaction, TxIn, TxOut, Witness};

use crate::channel::close_utils::{calculate_close_outputs_with_contributions, CloseOutputsParams};
use crate::channel::funding::ChannelFunding;
use crate::channel::state::Open;
use crate::errors::{ChannelError, Result};

/// Builds a cooperative close transaction with fee contributions
///
/// Creates a transaction that spends the funding UTXO without a time lock.
/// Both parties must sign this transaction for it to be valid.
///
/// This function allows both sender and receiver to contribute to the closing fees,
/// following the collaborative transaction construction pattern from BOLT #2.
///
/// For the common case where the sender (funder) pays all fees, pass `closing_fee`
/// as `sender_contribution` and `0` as `receiver_contribution`.
///
/// # Arguments
/// * `funding` - Channel funding information
/// * `channel_state` - Current channel state
/// * `closing_fee` - Total closing transaction fee
/// * `sender_contribution` - Sender's contribution to the closing fee in satoshis
/// * `receiver_contribution` - Receiver's contribution to the closing fee in satoshis
/// * `sender_address` - Address for sender's output
/// * `receiver_address` - Address for receiver's output
///
/// # Returns
/// A Bitcoin transaction ready for both parties to sign
///
/// # Errors
/// * `ChannelError::InvalidFundingScript` - If public keys don't match
/// * `ChannelError::InsufficientSenderFeeContribution` - If sender cannot afford their contribution
/// * `ChannelError::InsufficientReceiverFeeContribution` - If receiver cannot afford their contribution
/// * `ChannelError::InsufficientCombinedFeeContribution` - If combined contributions are insufficient
/// * `ChannelError::TotalFeeContributionMismatch` - If total contribution doesn't equal required fee
pub fn build_cooperative_close_transaction(
    funding: &ChannelFunding,
    channel_state: &Open,
    closing_fee: u64,
    sender_contribution: u64,
    receiver_contribution: u64,
    sender_address: Address<NetworkUnchecked>,
    receiver_address: Address<NetworkUnchecked>,
) -> Result<Transaction> {
    let funding_sender_bytes: [u8; 32] = funding.sender_pubkey.serialize();
    let funding_receiver_bytes: [u8; 32] = funding.receiver_pubkey.serialize();
    let funding_sender = bitcoin::secp256k1::XOnlyPublicKey::from_byte_array(funding_sender_bytes)
        .map_err(|_| {
            ChannelError::InvalidFundingScript("Failed to convert sender pubkey".to_string())
        })?;
    let funding_receiver =
        bitcoin::secp256k1::XOnlyPublicKey::from_byte_array(funding_receiver_bytes).map_err(
            |_| ChannelError::InvalidFundingScript("Failed to convert receiver pubkey".to_string()),
        )?;
    if channel_state.sender_pubkey != funding_sender
        || channel_state.receiver_pubkey != funding_receiver
    {
        return Err(ChannelError::InvalidFundingScript(
            "Channel state public keys do not match funding public keys".to_string(),
        )
        .into());
    }

    let params = CloseOutputsParams {
        sender_balance: channel_state.sender_balance,
        receiver_balance: channel_state.receiver_balance,
        sender_contribution,
        receiver_contribution,
        total_fee: closing_fee,
    };
    let (sender_output_value, receiver_output_value) =
        calculate_close_outputs_with_contributions(params)?;

    let input = TxIn {
        previous_output: funding.funding_utxo.outpoint(),
        script_sig: ScriptSigBuf::new(), // Empty for SegWit
        sequence: Sequence::MAX,         // No CSV time lock
        witness: Witness::new(),         // Will be populated with signatures
    };

    let sender_script = sender_address.assume_checked_ref().script_pubkey().to_owned();
    let receiver_script = receiver_address.assume_checked_ref().script_pubkey().to_owned();

    let sender_output = TxOut {
        amount: bitcoin::Amount::from_sat(sender_output_value)
            .expect("sender output value out of range"),
        script_pubkey: sender_script,
    };

    let receiver_output = TxOut {
        amount: bitcoin::Amount::from_sat(receiver_output_value)
            .expect("receiver output value out of range"),
        script_pubkey: receiver_script,
    };

    let transaction = Transaction {
        version: Version::THREE, // TRUC v3 enables package relay for reliable fee-bumping via CPFP
        lock_time: LockTime::ZERO,
        inputs: vec![input],
        outputs: vec![sender_output, receiver_output],
    };

    Ok(transaction)
}

#[cfg(test)]
mod tests {
    use bitcoin::{Address, Network};

    use super::*;
    use crate::channel::test_utils::{
        different_test_keys, revocation_secrets, test_keys_miniscript, to_secp_xonly,
    };

    #[test]
    fn test_build_cooperative_close_transaction() {
        let (sender_pubkey, receiver_pubkey) = test_keys_miniscript();
        let (sender_revocation_secret, receiver_revocation_secret) = revocation_secrets();
        let funding = ChannelFunding::new(
            sender_pubkey,
            receiver_pubkey,
            sender_revocation_secret,
            receiver_revocation_secret,
            Network::Regtest,
        )
        .expect("channel funding creation should succeed");
        let channel_state = Open::new(
            to_secp_xonly(sender_pubkey),
            to_secp_xonly(receiver_pubkey),
            100,
            sender_revocation_secret,
            receiver_revocation_secret,
        );
        let sender_address: Address<NetworkUnchecked> =
            "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080".parse().expect("valid address");
        let receiver_address: Address<NetworkUnchecked> =
            "bcrt1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqc8gma6"
                .parse()
                .expect("valid address");
        let (different_sender_pubkey, _) = different_test_keys();
        let (sender_revocation_secret2, receiver_revocation_secret2) = revocation_secrets();
        let mismatched_state = Open::new(
            different_sender_pubkey,
            to_secp_xonly(receiver_pubkey),
            100,
            sender_revocation_secret2,
            receiver_revocation_secret2,
        );

        let mismatch_error = build_cooperative_close_transaction(
            &funding,
            &mismatched_state,
            10,
            10,
            0,
            sender_address,
            receiver_address,
        )
        .expect_err("should fail with mismatched keys");

        match mismatch_error {
            crate::errors::Error::Channel(ChannelError::InvalidFundingScript(_)) => {}
            _ => panic!("unexpected error variant for mismatched keys"),
        }

        let mut state_sender_insufficient = channel_state.clone();
        state_sender_insufficient.sender_balance = 5;
        let sender_error = build_cooperative_close_transaction(
            &funding,
            &state_sender_insufficient,
            10,
            10,
            0,
            sender_address,
            receiver_address,
        )
        .expect_err("should fail with insufficient sender contribution");

        match sender_error {
            crate::errors::Error::Channel(ChannelError::InsufficientSenderFeeContribution {
                balance,
                contribution,
            }) => {
                assert_eq!(balance, 5);
                assert_eq!(contribution, 10);
            }
            _ => panic!("unexpected error variant for sender insufficient"),
        }

        let mut state_receiver_insufficient = channel_state.clone();
        state_receiver_insufficient.receiver_balance = 5;

        let receiver_error = build_cooperative_close_transaction(
            &funding,
            &state_receiver_insufficient,
            10,
            0,
            10,
            sender_address,
            receiver_address,
        )
        .expect_err("should fail with insufficient receiver contribution");

        match receiver_error {
            crate::errors::Error::Channel(ChannelError::InsufficientReceiverFeeContribution {
                balance,
                contribution,
            }) => {
                assert_eq!(balance, 5);
                assert_eq!(contribution, 10);
            }
            _ => panic!("unexpected error variant for receiver insufficient"),
        }

        let mut state_overflow = channel_state.clone();
        state_overflow.sender_balance = u64::MAX;
        state_overflow.receiver_balance = u64::MAX;

        let overflow_error = build_cooperative_close_transaction(
            &funding,
            &state_overflow,
            10,
            u64::MAX,
            1,
            sender_address,
            receiver_address,
        )
        .expect_err("should fail with contribution overflow");

        match overflow_error {
            crate::errors::Error::Channel(ChannelError::BalanceOverflow) => {}
            _ => panic!("unexpected error variant for overflow"),
        }

        let mut state_insufficient_combined = channel_state.clone();
        state_insufficient_combined.receiver_balance = 1;

        let combined_error = build_cooperative_close_transaction(
            &funding,
            &state_insufficient_combined,
            10,
            1,
            1,
            sender_address,
            receiver_address,
        )
        .expect_err("should fail with insufficient combined contribution");

        match combined_error {
            crate::errors::Error::Channel(ChannelError::InsufficientCombinedFeeContribution {
                sender_contribution,
                receiver_contribution,
                total_contribution,
                required_fee,
            }) => {
                assert_eq!(sender_contribution, 1);
                assert_eq!(receiver_contribution, 1);
                assert_eq!(total_contribution, 2);
                assert_eq!(required_fee, 10);
            }
            _ => panic!("unexpected error variant for insufficient combined"),
        }

        let mut state_exceeds = channel_state.clone();
        state_exceeds.sender_balance = 100;
        state_exceeds.receiver_balance = 100;

        let exceeds_error = build_cooperative_close_transaction(
            &funding,
            &state_exceeds,
            10,
            6,
            6,
            sender_address,
            receiver_address,
        )
        .expect_err("should fail with contribution exceeding required fee");

        match exceeds_error {
            crate::errors::Error::Channel(ChannelError::TotalFeeContributionMismatch {
                sender_contribution,
                receiver_contribution,
                total_contribution,
                required_fee,
            }) => {
                assert_eq!(sender_contribution, 6);
                assert_eq!(receiver_contribution, 6);
                assert_eq!(total_contribution, 12);
                assert_eq!(required_fee, 10);
            }
            _ => panic!("unexpected error variant for exceeds"),
        }

        let transaction = build_cooperative_close_transaction(
            &funding,
            &channel_state,
            10,
            10,
            0,
            sender_address,
            receiver_address,
        )
        .expect("should succeed with valid inputs");

        assert_eq!(transaction.version, Version::THREE);
        assert_eq!(transaction.lock_time, LockTime::ZERO);
        assert_eq!(transaction.inputs.len(), 1);
        assert_eq!(transaction.outputs.len(), 2);
        assert_eq!(transaction.inputs[0].sequence, Sequence::MAX);
        assert_eq!(transaction.outputs[0].amount.to_sat(), 90);
        assert_eq!(transaction.outputs[1].amount.to_sat(), 0);
    }
}
