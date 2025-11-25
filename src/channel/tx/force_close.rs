// SPDX-License-Identifier: CC0-1.0

//! Force close transaction builders
//!
//! This module provides Bitcoin transaction builders for force close transactions.
//! These builders translate channel state transitions into Bitcoin transactions.

use bdk_sp::encoding::SilentPaymentCode;
use bitcoin::absolute::LockTime;
use bitcoin::script::{ScriptPubKeyBuf, ScriptSigBuf};
use bitcoin::secp256k1::SecretKey;
use bitcoin::transaction::Version;
use bitcoin::{Amount, Transaction, TxIn, TxOut, Witness};

use crate::btx::timelock::compute_sequence_for_blocks;
use crate::channel::anchor::build_anchor_output_default;
use crate::channel::close_utils::calculate_close_outputs;
use crate::channel::funding::ChannelFunding;
use crate::channel::silent_payment::{
    create_taproot_scriptpubkey, generate_silent_payment_scriptpubkeys, get_silent_payment_key,
};
use crate::channel::state::Open;
use crate::errors::{ChannelError, Result};

/// Spending path for force close transactions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpendingPath {
    /// Sender unilateral: sender signs after timelock
    SenderUnilateral,
    /// Receiver unilateral: receiver signs after timelock
    ReceiverUnilateral,
}

/// Builds a force close transaction
///
/// Creates a transaction that spends the funding UTXO. Force closes are always unilateral -
/// one party closes without the other's cooperation. Only one signature is required after
/// the timelock expires.
///
/// The CSV timelock duration is read from the channel state's `timeout_blocks` field, which
/// allows per-channel configuration.
///
/// # Arguments
/// * `funding` - Channel funding information
/// * `channel_state` - Current channel state (contains `timeout_blocks` configuration)
/// * `closing_fee` - Total closing transaction fee
/// * `sender_sp_code` - Silent payment code for sender's output
/// * `receiver_sp_code` - Silent payment code for receiver's output
/// * `funding_input_script_pubkey` - ScriptPubKey of the funding UTXO input
/// * `closing_party_private_key` - Private key of the party performing the unilateral close
///
/// # Returns
/// A Bitcoin transaction with appropriate sequence and witness structure
///
/// # Errors
/// * `ChannelError::InvalidFundingScript` - If public keys don't match
/// * `ChannelError::SilentPaymentError` - If silent payment computation fails
#[allow(clippy::too_many_arguments)]
pub fn build_force_close_transaction(
    funding: &ChannelFunding,
    channel_state: &Open,
    closing_fee: u64,
    sender_sp_code: SilentPaymentCode,
    receiver_sp_code: SilentPaymentCode,
    funding_input_script_pubkey: ScriptPubKeyBuf,
    closing_party_private_key: SecretKey,
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

    let (sender_output_value, receiver_output_value) = calculate_close_outputs(
        channel_state.sender_balance,
        channel_state.receiver_balance,
        closing_fee,
    )?;

    let sequence = compute_sequence_for_blocks(channel_state.timeout_blocks);

    let funding_outpoint = funding.funding_utxo.outpoint();

    let input = TxIn {
        previous_output: funding_outpoint,
        script_sig: ScriptSigBuf::new(), // Empty for SegWit
        sequence,
        witness: Witness::new(), // Will be populated with signatures
    };

    let script_pubkeys_map = generate_silent_payment_scriptpubkeys(
        &[funding_outpoint],
        &[(funding_input_script_pubkey.clone(), closing_party_private_key)],
        &[sender_sp_code.clone(), receiver_sp_code.clone()],
    )?;

    let sender_sp_pubkey = get_silent_payment_key(
        &script_pubkeys_map,
        &sender_sp_code,
        "Failed to generate sender silent payment scriptPubKey",
    )?;

    let receiver_sp_pubkey = get_silent_payment_key(
        &script_pubkeys_map,
        &receiver_sp_code,
        "Failed to generate receiver silent payment scriptPubKey",
    )?;

    let sender_script_pubkey = create_taproot_scriptpubkey(sender_sp_pubkey);
    let receiver_script_pubkey = create_taproot_scriptpubkey(receiver_sp_pubkey);

    let sender_output = TxOut {
        amount: Amount::from_sat(sender_output_value).expect("sender output value out of range"),
        script_pubkey: sender_script_pubkey,
    };

    let receiver_output = TxOut {
        amount: Amount::from_sat(receiver_output_value)
            .expect("receiver output value out of range"),
        script_pubkey: receiver_script_pubkey,
    };

    let mut outputs = vec![sender_output, receiver_output];
    outputs.push(build_anchor_output_default());
    outputs.push(build_anchor_output_default());

    let transaction = Transaction {
        version: Version::THREE,
        lock_time: LockTime::ZERO,
        inputs: vec![input],
        outputs,
    };

    Ok(transaction)
}

#[cfg(test)]
mod tests {
    use bitcoin::Network;

    use super::*;
    use crate::channel::test_utils::{
        different_test_keys_miniscript, receiver_silent_payment_code, revocation_secrets,
        silent_payment_setup, test_keys_miniscript, to_secp_xonly,
    };

    #[test]
    fn test_build_force_close_transaction() {
        let (sender_pubkey, receiver_pubkey) = test_keys_miniscript();
        let (different_sender_pubkey, different_receiver_pubkey) = different_test_keys_miniscript();
        let (sender_revocation_secret, receiver_revocation_secret) = revocation_secrets();
        let funding = ChannelFunding::new(
            sender_pubkey,
            receiver_pubkey,
            sender_revocation_secret,
            receiver_revocation_secret,
            Network::Regtest,
        )
        .expect("channel funding creation should succeed");
        let closing_fee = 10u64;
        let (sender_sp_code, closing_party_private_key, funding_input_script_pubkey) =
            silent_payment_setup();
        let receiver_sp_code = receiver_silent_payment_code();

        let sender_mismatch_state = Open::new(
            to_secp_xonly(different_sender_pubkey),
            to_secp_xonly(receiver_pubkey),
            100,
            sender_revocation_secret,
            receiver_revocation_secret,
        );

        let sender_mismatch_error = build_force_close_transaction(
            &funding,
            &sender_mismatch_state,
            closing_fee,
            sender_sp_code.clone(),
            receiver_sp_code.clone(),
            funding_input_script_pubkey.clone(),
            closing_party_private_key,
        )
        .expect_err("sender mismatch should fail");

        match sender_mismatch_error {
            crate::errors::Error::Channel(ChannelError::InvalidFundingScript(_)) => {}
            _ => panic!("unexpected error variant"),
        }

        let receiver_mismatch_state = Open::new(
            to_secp_xonly(sender_pubkey),
            to_secp_xonly(different_receiver_pubkey),
            100,
            sender_revocation_secret,
            receiver_revocation_secret,
        );
        let receiver_mismatch_error = build_force_close_transaction(
            &funding,
            &receiver_mismatch_state,
            closing_fee,
            sender_sp_code.clone(),
            receiver_sp_code.clone(),
            funding_input_script_pubkey.clone(),
            closing_party_private_key,
        )
        .expect_err("receiver mismatch should fail");

        match receiver_mismatch_error {
            crate::errors::Error::Channel(ChannelError::InvalidFundingScript(_)) => {}
            _ => panic!("unexpected error variant"),
        }

        let channel_state = Open::new(
            to_secp_xonly(sender_pubkey),
            to_secp_xonly(receiver_pubkey),
            100,
            sender_revocation_secret,
            receiver_revocation_secret,
        );

        let transaction = build_force_close_transaction(
            &funding,
            &channel_state,
            closing_fee,
            sender_sp_code,
            receiver_sp_code,
            funding_input_script_pubkey,
            closing_party_private_key,
        )
        .expect("valid inputs should succeed");

        assert_eq!(transaction.version, Version::THREE);
        assert_eq!(transaction.lock_time, LockTime::ZERO);
        assert_eq!(transaction.inputs.len(), 1);
        assert_eq!(transaction.outputs.len(), 4);
    }
}
