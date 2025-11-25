//! Shared test utilities for channel module tests
//!
//! This module provides common helper functions used across all channel module tests.

use bdk_sp::encoding::SilentPaymentCode;
use bitcoin::key::TweakedPublicKey;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::{Network, ScriptBuf};

/// Deterministically derive a secret key from a single byte (tests only)
fn deterministic_secret(byte: u8) -> SecretKey {
    SecretKey::from_slice(&[byte; 32]).expect("32-byte array should always be a valid SecretKey")
}

/// Helper function to generate test public keys
pub fn test_keys() -> (XOnlyPublicKey, XOnlyPublicKey) {
    let secp = Secp256k1::new();
    let sender_sk = deterministic_secret(1);
    let receiver_sk = deterministic_secret(2);
    let sender_pubkey = XOnlyPublicKey::from_keypair(&sender_sk.keypair(&secp)).0;
    let receiver_pubkey = XOnlyPublicKey::from_keypair(&receiver_sk.keypair(&secp)).0;
    (sender_pubkey, receiver_pubkey)
}

/// Helper function to generate different test public keys
pub fn different_test_keys() -> (XOnlyPublicKey, XOnlyPublicKey) {
    let secp = Secp256k1::new();
    let different_sender_sk = deterministic_secret(3);
    let different_receiver_sk = deterministic_secret(4);
    let different_sender_pubkey =
        XOnlyPublicKey::from_keypair(&different_sender_sk.keypair(&secp)).0;
    let different_receiver_pubkey =
        XOnlyPublicKey::from_keypair(&different_receiver_sk.keypair(&secp)).0;
    (different_sender_pubkey, different_receiver_pubkey)
}

/// Helper function to generate deterministic revocation secrets for tests
pub fn revocation_secrets() -> (SecretKey, SecretKey) {
    let sender_revocation_secret = deterministic_secret(5);
    let receiver_revocation_secret = deterministic_secret(6);
    (sender_revocation_secret, receiver_revocation_secret)
}

/// Helper function to generate a second input key pair for challenge transactions
pub fn second_input_key_pair() -> (SecretKey, ScriptBuf) {
    let secp = Secp256k1::new();
    let input_sk = deterministic_secret(7);
    let input_x_only_pk = XOnlyPublicKey::from_keypair(&input_sk.keypair(&secp)).0;
    let output_key = TweakedPublicKey::dangerous_assume_tweaked(input_x_only_pk);
    let input_spk = ScriptBuf::new_p2tr_tweaked(output_key);
    (input_sk, input_spk)
}

/// Helper function to generate test silent payment code and input key material
pub fn silent_payment_setup() -> (SilentPaymentCode, SecretKey, ScriptBuf) {
    let secp = Secp256k1::new();
    let scan_sk = deterministic_secret(8);
    let spend_sk = deterministic_secret(9);
    let scan_pk = PublicKey::from_secret_key(&secp, &scan_sk);
    let spend_pk = PublicKey::from_secret_key(&secp, &spend_sk);
    let sp_code = SilentPaymentCode::new_v0(scan_pk, spend_pk, Network::Regtest);
    let input_sk = deterministic_secret(10);
    let input_x_only_pk = XOnlyPublicKey::from_keypair(&input_sk.keypair(&secp)).0;
    let output_key = TweakedPublicKey::dangerous_assume_tweaked(input_x_only_pk);
    let input_spk = ScriptBuf::new_p2tr_tweaked(output_key);
    (sp_code, input_sk, input_spk)
}
