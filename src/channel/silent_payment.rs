// SPDX-License-Identifier: CC0-1.0

//! Silent payment utilities for transaction builders
//!
//! This module provides shared helper functions for generating silent payment
//! scriptPubKeys according to BIP-0352. These utilities are used across all
//! transaction builders that support silent payments.

use bdk_sp::encoding::SilentPaymentCode;
use bdk_sp::send::{create_silentpayment_partial_secret, create_silentpayment_scriptpubkeys};
use bdk_sp::LexMin;
use bitcoin::key::XOnlyPublicKey;
use bitcoin::script::{ScriptPubKeyBuf, ScriptPubKeyBufExt};
use bitcoin::secp256k1::SecretKey;
use bitcoin::OutPoint;

use crate::errors::{ChannelError, Result};

/// Generates silent payment scriptPubKeys for one or more recipients
///
/// This function implements the core silent payment logic according to BIP-0352:
/// 1. Finds the lexicographically smallest outpoint from the inputs
/// 2. Creates a partial secret from the input keys
/// 3. Generates unique scriptPubKeys for each recipient's silent payment code
///
/// # Arguments
/// * `input_outpoints` - OutPoints from all inputs in the transaction
/// * `input_keys` - Tuples of (script_pubkey, private_key) for each input
/// * `recipient_codes` - Silent payment codes for all recipients
///
/// # Returns
/// A map from SilentPaymentCode to a vector of XOnlyPublicKey (typically one per code)
///
/// # Errors
/// * `ChannelError::SilentPaymentError` - If silent payment computation fails
pub fn generate_silent_payment_scriptpubkeys(
    input_outpoints: &[OutPoint],
    input_keys: &[(ScriptPubKeyBuf, SecretKey)],
    recipient_codes: &[SilentPaymentCode],
) -> Result<std::collections::HashMap<SilentPaymentCode, Vec<XOnlyPublicKey>>> {
    let mut lex_min = LexMin::default();
    for outpoint in input_outpoints {
        lex_min.update(outpoint);
    }
    let smallest_outpoint_bytes =
        lex_min.bytes().map_err(|e| ChannelError::SilentPaymentError {
            reason: format!("Failed to compute smallest outpoint: {}", e),
        })?;

    // bdk_sp expects bitcoin::script::ScriptPubKeyBuf and bitcoin::secp256k1::SecretKey directly
    let input_keys_vec: Vec<(ScriptPubKeyBuf, SecretKey)> =
        input_keys.iter().map(|(spk, sk)| (spk.clone(), *sk)).collect();

    let partial_secret =
        create_silentpayment_partial_secret(&smallest_outpoint_bytes, input_keys_vec.as_slice())
            .map_err(|e| ChannelError::SilentPaymentError {
                reason: format!("Failed to create silent payment partial secret: {}", e),
            })?;

    let script_pubkeys_map = create_silentpayment_scriptpubkeys(partial_secret, recipient_codes);

    let converted_map: std::collections::HashMap<_, Vec<_>> = script_pubkeys_map
        .into_iter()
        .map(|(code, keys)| {
            let converted_keys: Vec<XOnlyPublicKey> = keys.into_iter().collect();
            (code, converted_keys)
        })
        .collect();

    Ok(converted_map)
}

/// Creates a Taproot scriptPubKey from a silent payment XOnlyPublicKey
///
/// # Arguments
/// * `sp_x_only_pubkey` - The XOnlyPublicKey generated from a silent payment code
///
/// # Returns
/// A P2TR scriptPubKey
pub fn create_taproot_scriptpubkey(sp_x_only_pubkey: XOnlyPublicKey) -> ScriptPubKeyBuf {
    let output_key = bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(sp_x_only_pubkey);
    ScriptPubKeyBuf::new_p2tr_tweaked(output_key)
}

/// Gets the first (and typically only) XOnlyPublicKey for a silent payment code
///
/// # Arguments
/// * `script_pubkeys_map` - Map from SilentPaymentCode to XOnlyPublicKey vectors
/// * `sp_code` - The silent payment code to look up
/// * `error_message` - Custom error message if the key is not found
///
/// # Returns
/// The first XOnlyPublicKey for the given silent payment code
///
/// # Errors
/// * `ChannelError::SilentPaymentError` - If the key is not found
pub fn get_silent_payment_key(
    script_pubkeys_map: &std::collections::HashMap<SilentPaymentCode, Vec<XOnlyPublicKey>>,
    sp_code: &SilentPaymentCode,
    error_message: &str,
) -> Result<XOnlyPublicKey> {
    script_pubkeys_map
        .get(sp_code)
        .and_then(|v| v.first().copied())
        .ok_or_else(|| ChannelError::SilentPaymentError { reason: error_message.to_string() })
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use bitcoin::script::ScriptPubKeyExt;

    use super::*;
    use crate::channel::test_utils::silent_payment_setup;

    #[test]
    fn test_generate_silent_payment_scriptpubkeys() {
        let (sp_code, input_sk, input_spk) = silent_payment_setup();
        let outpoint = OutPoint { txid: bitcoin::Txid::from_byte_array([1u8; 32]), vout: 0 };
        let input_outpoints = vec![outpoint];
        let input_keys = vec![(input_spk, input_sk)];
        let recipient_codes = vec![sp_code.clone()];

        let result =
            generate_silent_payment_scriptpubkeys(&input_outpoints, &input_keys, &recipient_codes);

        assert!(result.is_ok());
        let map = result.expect("should succeed with valid inputs");
        assert!(map.contains_key(&sp_code));
        assert!(!map.get(&sp_code).expect("should contain sp_code").is_empty());
    }

    #[test]
    fn test_create_taproot_scriptpubkey() {
        let sk = bitcoin::secp256k1::SecretKey::from_secret_bytes([1u8; 32])
            .expect("32-byte array should always be a valid SecretKey");
        let keypair = sk.keypair();
        let (x_only_pubkey_secp, _) = bitcoin::secp256k1::XOnlyPublicKey::from_keypair(&keypair);
        let x_only_pubkey = XOnlyPublicKey::from(x_only_pubkey_secp);

        let script_pubkey = create_taproot_scriptpubkey(x_only_pubkey);

        assert!(!script_pubkey.is_empty());
        assert!(script_pubkey.is_p2tr());
    }

    #[test]
    fn test_get_silent_payment_key() {
        let sk = bitcoin::secp256k1::SecretKey::from_secret_bytes([1u8; 32])
            .expect("32-byte array should always be a valid SecretKey");
        let keypair = sk.keypair();
        let (x_only_pubkey_secp, _) = bitcoin::secp256k1::XOnlyPublicKey::from_keypair(&keypair);
        let x_only_pubkey = XOnlyPublicKey::from(x_only_pubkey_secp);
        let (sp_code, _, _) = silent_payment_setup();
        // Use different secret keys (10 and 11) instead of 8 and 9 to ensure other_sp_code is different
        let other_scan_sk = bitcoin::secp256k1::SecretKey::from_secret_bytes([10u8; 32])
            .expect("32-byte array should always be a valid SecretKey");
        let other_spend_sk = bitcoin::secp256k1::SecretKey::from_secret_bytes([11u8; 32])
            .expect("32-byte array should always be a valid SecretKey");
        let other_sp_code =
            crate::channel::test_utils::create_silent_payment_code(other_scan_sk, other_spend_sk);
        let mut map = HashMap::new();
        map.insert(sp_code.clone(), vec![x_only_pubkey]);

        let success_result = get_silent_payment_key(&map, &sp_code, "not found");

        assert!(success_result.is_ok());
        assert_eq!(success_result.expect("should succeed"), x_only_pubkey);

        let not_found_result = get_silent_payment_key(&map, &other_sp_code, "not found");

        assert!(not_found_result.is_err());

        let mut empty_map = HashMap::new();
        empty_map.insert(sp_code.clone(), vec![]);

        let empty_vec_result = get_silent_payment_key(&empty_map, &sp_code, "empty");

        assert!(empty_vec_result.is_err());
    }
}
