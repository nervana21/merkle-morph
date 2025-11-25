// SPDX-License-Identifier: CC0-1.0

//! P2A (Pay-to-Anchor) Taproot utilities
//!
//! Functions for deriving P2A addresses, scripts, and transaction outputs
//! using Bitcoin Taproot.

use bitcoin::key::XOnlyPublicKey;
use bitcoin::script::ScriptPubKeyBuf;
use bitcoin::taproot::{TapNodeHash, TaprootSpendInfo};
use bitcoin::{Address, Amount, Network, TxOut};

use crate::global::anchor::commitment::compute_commitment_hash;
use crate::types::{Bytes32, P2A_DEFAULT_INTERNAL_KEY_BYTES};

/// Derive the default x-only internal key from the baked constant.
pub fn derive_default_p2a_internal_key() -> Result<XOnlyPublicKey, String> {
    XOnlyPublicKey::from_byte_array(&P2A_DEFAULT_INTERNAL_KEY_BYTES)
        .map_err(|e| format!("invalid default P2A internal key: {e}"))
}

/// Compute domain-separated hash used as taproot tweak for P2A.
fn derive_p2a_tweak(global_root: Bytes32, nonce: u32) -> TapNodeHash {
    let commitment_hash = compute_commitment_hash(global_root, nonce);
    TapNodeHash::assume_hidden(commitment_hash)
}

/// Build taproot spend info for anchoring the global root via P2A.
pub fn derive_p2a_spend_info(
    global_root: Bytes32,
    nonce: u32,
    internal_key: XOnlyPublicKey,
) -> TaprootSpendInfo {
    let tweak = derive_p2a_tweak(global_root, nonce);
    TaprootSpendInfo::new_key_spend(internal_key, Some(tweak))
}

/// Derive a P2A taproot address for a global root + nonce pair.
pub fn derive_p2a_address(
    global_root: Bytes32,
    nonce: u32,
    internal_key: XOnlyPublicKey,
    network: Network,
) -> Address {
    let spend_info = derive_p2a_spend_info(global_root, nonce, internal_key);
    Address::p2tr_tweaked(spend_info.output_key(), network)
}

/// Derive a P2A taproot scriptPubKey for anchoring.
pub fn derive_p2a_script(
    global_root: Bytes32,
    nonce: u32,
    internal_key: XOnlyPublicKey,
    network: Network,
) -> ScriptPubKeyBuf {
    derive_p2a_address(global_root, nonce, internal_key, network).script_pubkey()
}

/// Build a TxOut carrying the P2A anchor commitment.
pub fn build_p2a_txout(
    global_root: Bytes32,
    nonce: u32,
    internal_key: XOnlyPublicKey,
    value_sats: u64,
    network: Network,
) -> Result<TxOut, bitcoin::amount::OutOfRangeError> {
    Ok(TxOut {
        amount: Amount::from_sat(value_sats)?,
        script_pubkey: derive_p2a_script(global_root, nonce, internal_key, network),
    })
}

/// Verify a script_pubkey matches the expected P2A commitment.
pub fn verify_p2a_script(
    script_pubkey: &ScriptPubKeyBuf,
    global_root: Bytes32,
    nonce: u32,
    internal_key: XOnlyPublicKey,
    network: Network,
) -> bool {
    script_pubkey == &derive_p2a_script(global_root, nonce, internal_key, network)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_default_p2a_internal_key() {
        let result = derive_default_p2a_internal_key();

        assert!(result.is_ok());
        let key = result.expect("default key should be valid");
        let serialized = key.serialize();
        assert_eq!(serialized.len(), 32);
    }

    #[test]
    fn test_derive_p2a_spend_info() {
        let global_root = [1u8; 32];
        let nonce = 42u32;
        let internal_key = derive_default_p2a_internal_key().expect("default key should be valid");

        let spend_info = derive_p2a_spend_info(global_root, nonce, internal_key);

        let output_key = spend_info.output_key();
        assert_eq!(output_key.serialize().len(), 32);
    }

    #[test]
    fn test_derive_p2a_address() {
        let global_root = [2u8; 32];
        let nonce = 100u32;
        let internal_key = derive_default_p2a_internal_key().expect("default key should be valid");
        let network = Network::Regtest;

        let address = derive_p2a_address(global_root, nonce, internal_key, network);

        let script = address.script_pubkey();
        let expected_script = derive_p2a_script(global_root, nonce, internal_key, network);
        assert_eq!(script, expected_script);
    }

    #[test]
    fn test_derive_p2a_script() {
        let global_root = [3u8; 32];
        let nonce = 200u32;
        let internal_key = derive_default_p2a_internal_key().expect("default key should be valid");
        let network = Network::Regtest;

        let script = derive_p2a_script(global_root, nonce, internal_key, network);

        assert!(!script.is_empty());
        let address = derive_p2a_address(global_root, nonce, internal_key, network);
        assert_eq!(script, address.script_pubkey());
    }

    #[test]
    fn test_build_p2a_txout() {
        let global_root = [4u8; 32];
        let nonce = 300u32;
        let internal_key = derive_default_p2a_internal_key().expect("default key should be valid");
        let value_sats = 1000u64;
        let network = Network::Regtest;

        let txout = build_p2a_txout(global_root, nonce, internal_key, value_sats, network)
            .expect("should build valid txout");

        assert_eq!(txout.amount, Amount::from_sat(value_sats).expect("should create valid amount"));
        let expected_script = derive_p2a_script(global_root, nonce, internal_key, network);
        assert_eq!(txout.script_pubkey, expected_script);
    }

    #[test]
    fn test_verify_p2a_script() {
        let global_root = [5u8; 32];
        let nonce = 400u32;
        let internal_key = derive_default_p2a_internal_key().expect("default key should be valid");
        let network = Network::Regtest;
        let valid_script = derive_p2a_script(global_root, nonce, internal_key, network);

        assert!(verify_p2a_script(&valid_script, global_root, nonce, internal_key, network));

        let different_script = derive_p2a_script(global_root, nonce + 1, internal_key, network);

        assert!(!verify_p2a_script(&different_script, global_root, nonce, internal_key, network));
    }
}
