//! Force close transaction builders
//!
//! This module provides Bitcoin transaction builders for force close transactions.
//! These builders translate channel state transitions into Bitcoin transactions.

use bdk_sp::encoding::SilentPaymentCode;
use bitcoin::absolute::LockTime;
use bitcoin::secp256k1::SecretKey;
use bitcoin::transaction::Version;
use bitcoin::{Amount, ScriptBuf, Transaction, TxIn, TxOut, Witness};

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
    funding_input_script_pubkey: ScriptBuf,
    closing_party_private_key: SecretKey,
) -> Result<Transaction> {
    if channel_state.sender_pubkey != funding.sender_pubkey
        || channel_state.receiver_pubkey != funding.receiver_pubkey
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
        script_sig: ScriptBuf::new(), // Empty for SegWit
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

    let sender_output =
        TxOut { value: Amount::from_sat(sender_output_value), script_pubkey: sender_script_pubkey };

    let receiver_output = TxOut {
        value: Amount::from_sat(receiver_output_value),
        script_pubkey: receiver_script_pubkey,
    };

    let mut outputs = vec![sender_output, receiver_output];
    outputs.push(build_anchor_output_default());
    outputs.push(build_anchor_output_default());

    let transaction = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![input],
        output: outputs,
    };

    Ok(transaction)
}

#[cfg(test)]
mod tests {
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    use bitcoin::Network;

    use super::*;
    use crate::channel::test_utils::*;

    #[test]
    fn test_build_force_close_transaction() {
        let (sender_pubkey, receiver_pubkey) = test_keys();
        let (different_sender_pubkey, different_receiver_pubkey) = different_test_keys();
        let funding = ChannelFunding::new(sender_pubkey, receiver_pubkey, Network::Regtest)
            .expect("channel funding creation should succeed");
        let (sender_revocation_secret, receiver_revocation_secret) = revocation_secrets();
        let closing_fee = 10u64;
        let (sender_sp_code, closing_party_private_key, funding_input_script_pubkey) =
            silent_payment_setup();
        let secp = Secp256k1::new();
        let receiver_scan_sk =
            SecretKey::from_slice(&[5u8; 32]).expect("valid receiver scan secret key");
        let receiver_spend_sk =
            SecretKey::from_slice(&[6u8; 32]).expect("valid receiver spend secret key");
        let receiver_scan_pk = PublicKey::from_secret_key(&secp, &receiver_scan_sk);
        let receiver_spend_pk = PublicKey::from_secret_key(&secp, &receiver_spend_sk);
        let receiver_sp_code =
            SilentPaymentCode::new_v0(receiver_scan_pk, receiver_spend_pk, Network::Regtest);

        let sender_mismatch_state = Open::new(
            different_sender_pubkey,
            receiver_pubkey,
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
            sender_pubkey,
            different_receiver_pubkey,
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
            sender_pubkey,
            receiver_pubkey,
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

        assert_eq!(transaction.version, Version::TWO);
        assert_eq!(transaction.lock_time, LockTime::ZERO);
        assert_eq!(transaction.input.len(), 1);
        assert_eq!(transaction.output.len(), 4);
    }
}
