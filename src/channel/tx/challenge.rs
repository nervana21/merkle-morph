//! Challenge transaction builders
//!
//! This module provides Bitcoin transaction builders for challenge transactions.
//! These builders translate channel state transitions into Bitcoin transaction format.

use bdk_sp::encoding::SilentPaymentCode;
use bitcoin::absolute::LockTime;
use bitcoin::secp256k1::SecretKey;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

use crate::channel::funding::ChannelFunding;
use crate::channel::silent_payment::{
    create_taproot_scriptpubkey, generate_silent_payment_scriptpubkeys, get_silent_payment_key,
};
use crate::errors::{ChannelError, Result};

/// Builds all challenge transactions for an old force close transaction.
///
/// Primary entry point for the per-output challenge flow: validates parameters,
/// filters out dust outputs, and delegates to the per-output builder.
pub fn build_all_challenge_transactions(
    old_force_close_tx: &Transaction,
    challenge_fee_per_tx: u64,
    dust_limit: u64,
    challenge_recipient_sp_code: SilentPaymentCode,
    input_private_keys: Vec<SecretKey>,
    input_script_pubkeys: Vec<ScriptBuf>,
) -> Result<Vec<Transaction>> {
    if old_force_close_tx.output.is_empty() {
        return Err(ChannelError::InvalidForceCloseTransaction {
            reason: "force close transaction has no outputs".to_string(),
        }
        .into());
    }

    if input_private_keys.len() != old_force_close_tx.output.len() {
        return Err(ChannelError::InvalidChallengeParameters {
            reason: format!(
                "input_private_keys length {} does not match number of outputs {}",
                input_private_keys.len(),
                old_force_close_tx.output.len()
            ),
        }
        .into());
    }

    if input_script_pubkeys.len() != old_force_close_tx.output.len() {
        return Err(ChannelError::InvalidChallengeParameters {
            reason: format!(
                "input_script_pubkeys length {} does not match number of outputs {}",
                input_script_pubkeys.len(),
                old_force_close_tx.output.len()
            ),
        }
        .into());
    }

    // Build challenge transactions for all outputs, filtering out dust outputs
    let challenge_txs: Result<Vec<_>> = (0..old_force_close_tx.output.len())
        .map(|output_index| {
            build_challenge_transaction_for_output(
                old_force_close_tx,
                output_index,
                challenge_fee_per_tx,
                dust_limit,
                challenge_recipient_sp_code.clone(),
                input_private_keys[output_index],
                input_script_pubkeys[output_index].clone(),
            )
        })
        .filter_map(|result| match result {
            Ok(tx) => Some(Ok(tx)),
            Err(crate::Error::Channel(ChannelError::OutputBelowDustLimit { .. })) => None,
            Err(e) => Some(Err(e)),
        })
        .collect();

    let challenge_txs = challenge_txs?;

    if challenge_txs.is_empty() {
        return Err(ChannelError::NoChallengeableOutputs { dust_limit }.into());
    }

    Ok(challenge_txs)
}

/// Builds a challenge transaction for a single output from an old force close transaction.
///
/// Lower-level helper that handles validation and silent payment construction for
/// a specific output.
pub fn build_challenge_transaction_for_output(
    old_force_close_tx: &Transaction,
    output_index: usize,
    challenge_fee: u64,
    dust_limit: u64,
    challenge_recipient_sp_code: SilentPaymentCode,
    input_private_key: SecretKey,
    input_script_pubkey: ScriptBuf,
) -> Result<Transaction> {
    if output_index >= old_force_close_tx.output.len() {
        return Err(ChannelError::InvalidForceCloseTransaction {
            reason: format!(
                "output index {} out of bounds (transaction has {} outputs)",
                output_index,
                old_force_close_tx.output.len()
            ),
        }
        .into());
    }

    let output = &old_force_close_tx.output[output_index];
    let output_value = output.value.to_sat();

    let challenge_value = output_value.saturating_sub(challenge_fee);

    if challenge_value < dust_limit {
        return Err(ChannelError::OutputBelowDustLimit {
            output_index,
            output_value,
            fee: challenge_fee,
            dust_limit,
        }
        .into());
    }

    let old_txid = old_force_close_tx.compute_txid();
    let input_outpoint = OutPoint { txid: old_txid, vout: output_index as u32 };

    let script_pubkeys_map = generate_silent_payment_scriptpubkeys(
        &[input_outpoint],
        &[(input_script_pubkey, input_private_key)],
        std::slice::from_ref(&challenge_recipient_sp_code),
    )?;

    let sp_x_only_pubkey = get_silent_payment_key(
        &script_pubkeys_map,
        &challenge_recipient_sp_code,
        "Failed to generate silent payment scriptPubKey",
    )?;

    let sp_script_pubkey = create_taproot_scriptpubkey(sp_x_only_pubkey);

    let input = TxIn {
        previous_output: input_outpoint,
        script_sig: ScriptBuf::new(), // Empty for SegWit
        sequence: Sequence::MAX,
        witness: Witness::new(), // Will be populated with signatures
    };

    let challenge_output =
        TxOut { value: Amount::from_sat(challenge_value), script_pubkey: sp_script_pubkey };

    let transaction = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![input],
        output: vec![challenge_output],
    };

    Ok(transaction)
}

/// Builds a single revocation sweep transaction that spends the funding output via the
/// revocation branch and pays the honest party using silent payments.
pub fn build_revocation_sweep_transaction(
    funding: &ChannelFunding,
    revocation_secret: SecretKey,
    challenge_recipient_sp_code: SilentPaymentCode,
    challenge_fee: u64,
    dust_limit: u64,
) -> Result<Transaction> {
    let funding_value = funding.funding_value();
    let sweep_value = funding_value.saturating_sub(challenge_fee);

    if sweep_value < dust_limit {
        return Err(ChannelError::OutputBelowDustLimit {
            output_index: 0,
            output_value: funding_value,
            fee: challenge_fee,
            dust_limit,
        }
        .into());
    }

    let input_outpoint = funding.funding_outpoint();
    let funding_script_pubkey = funding.funding_script_pubkey();

    let script_pubkeys_map = generate_silent_payment_scriptpubkeys(
        &[input_outpoint],
        &[(funding_script_pubkey, revocation_secret)],
        std::slice::from_ref(&challenge_recipient_sp_code),
    )?;

    let sp_x_only_pubkey = get_silent_payment_key(
        &script_pubkeys_map,
        &challenge_recipient_sp_code,
        "Failed to generate silent payment scriptPubKey for revocation sweep",
    )?;

    let sp_script_pubkey = create_taproot_scriptpubkey(sp_x_only_pubkey);

    let input = TxIn {
        previous_output: input_outpoint,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::MAX,
        witness: Witness::new(), // Witness will be populated with penalty signature + control block
    };

    let output = TxOut { value: Amount::from_sat(sweep_value), script_pubkey: sp_script_pubkey };

    let transaction = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![input],
        output: vec![output],
    };

    Ok(transaction)
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{Secp256k1, XOnlyPublicKey};
    use bitcoin::{Amount, Transaction, TxOut};

    use super::*;
    use crate::channel::funding::ChannelFunding;
    use crate::channel::test_utils::*;

    // One test per public function
    #[test]
    fn test_build_all_challenge_transactions() {
        let (sp_code, input_sk1, input_spk1) = silent_payment_setup();
        let (input_sk2, input_spk2) = second_input_key_pair();

        let empty_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        let empty =
            build_all_challenge_transactions(&empty_tx, 1, 1, sp_code.clone(), vec![], vec![]);

        assert!(matches!(
            empty,
            Err(crate::Error::Channel(ChannelError::InvalidForceCloseTransaction { .. }))
        ));

        let one_output = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut { value: Amount::from_sat(3), script_pubkey: ScriptBuf::new() }],
        };

        let key_len_mismatch = build_all_challenge_transactions(
            &one_output,
            1,
            1,
            sp_code.clone(),
            vec![],
            vec![input_spk1.clone()],
        );

        assert!(matches!(
            key_len_mismatch,
            Err(crate::Error::Channel(ChannelError::InvalidChallengeParameters { .. }))
        ));

        let spk_len_mismatch = build_all_challenge_transactions(
            &one_output,
            1,
            1,
            sp_code.clone(),
            vec![input_sk1],
            vec![],
        );

        assert!(matches!(
            spk_len_mismatch,
            Err(crate::Error::Channel(ChannelError::InvalidChallengeParameters { .. }))
        ));

        let dust_only = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut { value: Amount::from_sat(10), script_pubkey: ScriptBuf::new() }],
        };

        let filtered_out = build_all_challenge_transactions(
            &dust_only,
            9,
            2,
            sp_code.clone(),
            vec![input_sk1],
            vec![input_spk1.clone()],
        );

        assert!(matches!(
            filtered_out,
            Err(crate::Error::Channel(ChannelError::NoChallengeableOutputs { .. }))
        ));

        let two_output = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![
                TxOut { value: Amount::from_sat(50_000), script_pubkey: ScriptBuf::new() },
                TxOut { value: Amount::from_sat(75_000), script_pubkey: ScriptBuf::new() },
            ],
        };

        let success = build_all_challenge_transactions(
            &two_output,
            1_000,
            500,
            sp_code,
            vec![input_sk1, input_sk2],
            vec![input_spk1, input_spk2],
        )
        .expect("challenge transactions");

        assert_eq!(success.len(), 2);
        assert_eq!(success[0].output[0].value, Amount::from_sat(49_000));
        assert_eq!(success[1].output[0].value, Amount::from_sat(74_000));
    }

    #[test]
    fn test_build_challenge_transaction_for_output() {
        let (sp_code, input_sk, input_spk) = silent_payment_setup();
        let old_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let invalid_index = build_challenge_transaction_for_output(
            &old_tx,
            2,
            1,
            1,
            sp_code.clone(),
            input_sk,
            input_spk.clone(),
        );

        assert!(matches!(
            invalid_index,
            Err(crate::Error::Channel(ChannelError::InvalidForceCloseTransaction { .. }))
        ));

        let dust = build_challenge_transaction_for_output(
            &old_tx,
            0,
            99_900,
            200,
            sp_code.clone(),
            SecretKey::from_slice(&[7u8; 32]).expect("valid secret key"),
            input_spk,
        );

        assert!(matches!(
            dust,
            Err(crate::Error::Channel(ChannelError::OutputBelowDustLimit { .. }))
        ));

        let secp = Secp256k1::new();
        let input_sk = SecretKey::from_slice(&[8u8; 32]).expect("valid secret key");
        let input_x_only_pk = XOnlyPublicKey::from_keypair(&input_sk.keypair(&secp)).0;
        let output_key = bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(input_x_only_pk);
        let input_spk = ScriptBuf::new_p2tr_tweaked(output_key);
        let success = build_challenge_transaction_for_output(
            &old_tx, 0, 1_000, 500, sp_code, input_sk, input_spk,
        )
        .expect("challenge transaction");

        assert_eq!(success.output[0].value, Amount::from_sat(99_000));
        assert_eq!(success.input.len(), 1);
    }

    #[test]
    fn test_build_revocation_sweep_transaction() {
        let (sp_code, _, _) = silent_payment_setup();
        let (sender_pubkey, receiver_pubkey) = test_keys();
        let (sender_revocation_secret, receiver_revocation_secret) = revocation_secrets();
        let mut funding =
            ChannelFunding::new(sender_pubkey, receiver_pubkey, bitcoin::Network::Regtest)
                .expect("funding");
        funding.update_funding_utxo(
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
                [1u8; 32],
            )),
            0,
            100_000,
        );

        let too_small = build_revocation_sweep_transaction(
            &funding,
            sender_revocation_secret,
            sp_code.clone(),
            99_700,
            400,
        );

        assert!(matches!(
            too_small,
            Err(crate::Error::Channel(ChannelError::OutputBelowDustLimit { .. }))
        ));

        let sweep = build_revocation_sweep_transaction(
            &funding,
            receiver_revocation_secret,
            sp_code,
            1_000,
            400,
        )
        .expect("sweep");

        assert_eq!(sweep.output[0].value, Amount::from_sat(99_000));
        assert_eq!(sweep.input.len(), 1);
    }
}
