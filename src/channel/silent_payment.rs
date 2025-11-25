//! Silent payment utilities for transaction builders
//!
//! This module provides shared helper functions for generating silent payment
//! scriptPubKeys according to BIP 352. These utilities are used across all
//! transaction builders that support silent payments.

use bdk_sp::encoding::SilentPaymentCode;
use bdk_sp::send::{create_silentpayment_partial_secret, create_silentpayment_scriptpubkeys};
use bdk_sp::LexMin;
use bitcoin::secp256k1::SecretKey;
use bitcoin::{OutPoint, ScriptBuf};

use crate::errors::{ChannelError, Result};

/// Generates silent payment scriptPubKeys for one or more recipients
///
/// This function implements the core silent payment logic according to BIP 352:
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
    input_keys: &[(ScriptBuf, SecretKey)],
    recipient_codes: &[SilentPaymentCode],
) -> Result<std::collections::HashMap<SilentPaymentCode, Vec<bitcoin::secp256k1::XOnlyPublicKey>>> {
    let mut lex_min = LexMin::default();
    for outpoint in input_outpoints {
        lex_min.update(outpoint);
    }
    let smallest_outpoint_bytes =
        lex_min.bytes().map_err(|e| ChannelError::SilentPaymentError {
            reason: format!("Failed to compute smallest outpoint: {}", e),
        })?;

    let partial_secret = create_silentpayment_partial_secret(&smallest_outpoint_bytes, input_keys)
        .map_err(|e| ChannelError::SilentPaymentError {
            reason: format!("Failed to create silent payment partial secret: {}", e),
        })?;

    let script_pubkeys_map = create_silentpayment_scriptpubkeys(partial_secret, recipient_codes);

    Ok(script_pubkeys_map)
}

/// Creates a Taproot scriptPubKey from a silent payment XOnlyPublicKey
///
/// # Arguments
/// * `sp_x_only_pubkey` - The XOnlyPublicKey generated from a silent payment code
///
/// # Returns
/// A P2TR scriptPubKey
pub fn create_taproot_scriptpubkey(
    sp_x_only_pubkey: bitcoin::secp256k1::XOnlyPublicKey,
) -> ScriptBuf {
    let output_key = bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(sp_x_only_pubkey);
    ScriptBuf::new_p2tr_tweaked(output_key)
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
    script_pubkeys_map: &std::collections::HashMap<
        SilentPaymentCode,
        Vec<bitcoin::secp256k1::XOnlyPublicKey>,
    >,
    sp_code: &SilentPaymentCode,
    error_message: &str,
) -> Result<bitcoin::secp256k1::XOnlyPublicKey> {
    script_pubkeys_map
        .get(sp_code)
        .and_then(|v| v.first().copied())
        .ok_or_else(|| ChannelError::SilentPaymentError { reason: error_message.to_string() })
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{Secp256k1, XOnlyPublicKey};
    use bitcoin::{Network, Txid};

    use super::*;
    use crate::channel::test_utils::silent_payment_setup;

    #[test]
    fn test_generate_silent_payment_scriptpubkeys() {
        let (sp_code, input_sk, input_spk) = silent_payment_setup();
        let outpoint = OutPoint { txid: Txid::from_byte_array([1u8; 32]), vout: 0 };
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
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[1u8; 32])
            .expect("32-byte array should always be a valid SecretKey");
        let x_only_pubkey = XOnlyPublicKey::from_keypair(&sk.keypair(&secp)).0;

        let script_pubkey = create_taproot_scriptpubkey(x_only_pubkey);

        assert!(!script_pubkey.is_empty());
        assert!(script_pubkey.is_p2tr());
    }

    #[test]
    fn test_get_silent_payment_key() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[1u8; 32])
            .expect("32-byte array should always be a valid SecretKey");
        let x_only_pubkey = XOnlyPublicKey::from_keypair(&sk.keypair(&secp)).0;
        let (sp_code, _, _) = silent_payment_setup();
        // Use different secret keys (10 and 11) instead of 8 and 9 to ensure other_sp_code is different
        let other_scan_sk = SecretKey::from_slice(&[10u8; 32])
            .expect("32-byte array should always be a valid SecretKey");
        let other_spend_sk = SecretKey::from_slice(&[11u8; 32])
            .expect("32-byte array should always be a valid SecretKey");
        let other_scan_pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &other_scan_sk);
        let other_spend_pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &other_spend_sk);
        let other_sp_code =
            SilentPaymentCode::new_v0(other_scan_pk, other_spend_pk, Network::Regtest);
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
