// SPDX-License-Identifier: CC0-1.0

//! Shared test utilities for channel module tests
//!
//! This module provides common helper functions used across all channel module tests.

use bdk_sp::encoding::SilentPaymentCode;
use bitcoin::key::{TweakedPublicKey, XOnlyPublicKey};
use bitcoin::script::{ScriptPubKeyBuf, ScriptPubKeyBufExt};
use bitcoin::secp256k1::{PublicKey, SecretKey, XOnlyPublicKey as SecpXOnlyPublicKey};

/// Deterministically derive a secret key from a single byte (tests only)
fn deterministic_secret(byte: u8) -> SecretKey {
    bitcoin::secp256k1::SecretKey::from_secret_bytes([byte; 32])
        .expect("32-byte array should always be a valid SecretKey")
}

/// Converts a secp256k1 PublicKey to miniscript PublicKey
fn to_miniscript_pubkey(pk: PublicKey) -> miniscript::bitcoin::secp256k1::PublicKey {
    let pk_bytes = pk.serialize();
    miniscript::bitcoin::secp256k1::PublicKey::from_slice(&pk_bytes)
        .expect("serialized public key should always be valid")
}

/// Converts `bitcoin::key::XOnlyPublicKey` to `bitcoin::secp256k1::XOnlyPublicKey`
///
/// This is needed when converting between the bitcoin crate's key types and secp256k1 types.
/// The conversion is infallible for valid X-only public keys.
pub fn to_secp_xonly(pubkey: XOnlyPublicKey) -> SecpXOnlyPublicKey {
    SecpXOnlyPublicKey::from_byte_array(pubkey.serialize()).expect("pubkey should always be valid")
}

/// Helper function to generate test public keys
pub fn test_keys() -> (SecpXOnlyPublicKey, SecpXOnlyPublicKey) {
    let sender_sk = deterministic_secret(1);
    let receiver_sk = deterministic_secret(2);
    let sender_keypair = sender_sk.keypair();
    let (sender_pubkey, _) = SecpXOnlyPublicKey::from_keypair(&sender_keypair);
    let receiver_keypair = receiver_sk.keypair();
    let (receiver_pubkey, _) = SecpXOnlyPublicKey::from_keypair(&receiver_keypair);
    (sender_pubkey, receiver_pubkey)
}

/// Helper function to generate test public keys
///
/// Returns `bitcoin::key::XOnlyPublicKey` for use with ChannelFunding and other APIs.
pub fn test_keys_miniscript() -> (XOnlyPublicKey, XOnlyPublicKey) {
    let (sender_pubkey_secp, receiver_pubkey_secp) = test_keys();
    let sender_pubkey = XOnlyPublicKey::from(sender_pubkey_secp);
    let receiver_pubkey = XOnlyPublicKey::from(receiver_pubkey_secp);
    (sender_pubkey, receiver_pubkey)
}

/// Helper function to generate different test public keys
pub fn different_test_keys() -> (SecpXOnlyPublicKey, SecpXOnlyPublicKey) {
    let different_sender_sk = deterministic_secret(3);
    let different_receiver_sk = deterministic_secret(4);
    let different_sender_keypair = different_sender_sk.keypair();
    let (different_sender_pubkey, _) = SecpXOnlyPublicKey::from_keypair(&different_sender_keypair);
    let different_receiver_keypair = different_receiver_sk.keypair();
    let (different_receiver_pubkey, _) =
        SecpXOnlyPublicKey::from_keypair(&different_receiver_keypair);
    (different_sender_pubkey, different_receiver_pubkey)
}

/// Helper function to generate different test public keys
///
/// Returns `bitcoin::key::XOnlyPublicKey` for use with ChannelFunding and other APIs.
pub fn different_test_keys_miniscript() -> (XOnlyPublicKey, XOnlyPublicKey) {
    let (different_sender_pubkey_secp, different_receiver_pubkey_secp) = different_test_keys();
    let different_sender_pubkey = XOnlyPublicKey::from(different_sender_pubkey_secp);
    let different_receiver_pubkey = XOnlyPublicKey::from(different_receiver_pubkey_secp);
    (different_sender_pubkey, different_receiver_pubkey)
}

/// Helper function to generate deterministic revocation secrets for tests
pub fn revocation_secrets() -> (SecretKey, SecretKey) {
    let sender_revocation_secret = deterministic_secret(5);
    let receiver_revocation_secret = deterministic_secret(6);
    (sender_revocation_secret, receiver_revocation_secret)
}

/// Helper function to generate challenge pubkeys from revocation secrets
///
/// Returns `bitcoin::key::XOnlyPublicKey` for use with ChannelFunding and other APIs.
pub fn challenge_pubkeys_miniscript(
    sender_revocation_sk: SecretKey,
    receiver_revocation_sk: SecretKey,
) -> (XOnlyPublicKey, XOnlyPublicKey) {
    let sender_keypair = sender_revocation_sk.keypair();
    let (sender_challenge_pubkey_raw, _) =
        bitcoin::secp256k1::XOnlyPublicKey::from_keypair(&sender_keypair);
    let sender_challenge_pubkey = XOnlyPublicKey::from(sender_challenge_pubkey_raw);

    let receiver_keypair = receiver_revocation_sk.keypair();
    let (receiver_challenge_pubkey_raw, _) =
        bitcoin::secp256k1::XOnlyPublicKey::from_keypair(&receiver_keypair);
    let receiver_challenge_pubkey = XOnlyPublicKey::from(receiver_challenge_pubkey_raw);

    (sender_challenge_pubkey, receiver_challenge_pubkey)
}

/// Helper function to generate a deterministic Taproot input keypair for tests
pub fn test_taproot_input_keypair() -> (SecretKey, ScriptPubKeyBuf) {
    let input_sk = deterministic_secret(7);
    let input_keypair = input_sk.keypair();
    let (input_x_only_pk, _) = XOnlyPublicKey::from_keypair(&input_keypair);
    let output_key = TweakedPublicKey::dangerous_assume_tweaked(input_x_only_pk);
    let input_spk = ScriptPubKeyBuf::new_p2tr_tweaked(output_key);
    (input_sk, input_spk)
}

/// Creates a SilentPaymentCode from scan and spend secret keys
///
/// This is a generic helper that can be used to create SilentPaymentCode instances
/// from any pair of secret keys.
pub fn create_silent_payment_code(scan_sk: SecretKey, spend_sk: SecretKey) -> SilentPaymentCode {
    let scan_pk = PublicKey::from_secret_key(&scan_sk);
    let spend_pk = PublicKey::from_secret_key(&spend_sk);
    SilentPaymentCode::new_v0(
        to_miniscript_pubkey(scan_pk),
        to_miniscript_pubkey(spend_pk),
        miniscript::bitcoin::Network::Regtest,
    )
}

/// Helper function to generate test silent payment code and input key material
pub fn silent_payment_setup() -> (SilentPaymentCode, SecretKey, ScriptPubKeyBuf) {
    let scan_sk = deterministic_secret(8);
    let spend_sk = deterministic_secret(9);
    let sp_code = create_silent_payment_code(scan_sk, spend_sk);
    let input_sk = deterministic_secret(10);
    let input_keypair = input_sk.keypair();
    let (input_x_only_pk, _) = XOnlyPublicKey::from_keypair(&input_keypair);
    let output_key = TweakedPublicKey::dangerous_assume_tweaked(input_x_only_pk);
    let input_spk = ScriptPubKeyBuf::new_p2tr_tweaked(output_key);
    (sp_code, input_sk, input_spk)
}

/// Helper function to generate a receiver silent payment code for tests
///
/// Uses deterministic keys (11 and 12) to avoid conflicts with other test utilities.
pub fn receiver_silent_payment_code() -> SilentPaymentCode {
    let receiver_scan_sk = deterministic_secret(11);
    let receiver_spend_sk = deterministic_secret(12);
    create_silent_payment_code(receiver_scan_sk, receiver_spend_sk)
}
