// SPDX-License-Identifier: CC0-1.0

//! Bitcoin script validation utilities
//!
//! This module provides utilities for script type detection, validation,
//! and building common script types.

use std::str::FromStr;

use bitcoin::key::XOnlyPublicKey;
use bitcoin::script::{ScriptPubKeyBuf, TapScriptBuf};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::{Address, Network, Witness};
use miniscript::descriptor::{Descriptor, TrSpendInfo};
use miniscript::policy::Concrete;
use miniscript::Translator;
use rand::random;

use crate::errors::{BtxError, Result};
use crate::types::{
    OP_1, P2A_MARKER_BYTE_1, P2A_MARKER_BYTE_2, P2A_SCRIPT_LEN, P2TR_SCRIPT_LEN, PUSH_2_BYTES,
    PUSH_32_BYTES,
};

/// Script type classification
///
/// This module supports Pay-to-Taproot (P2TR) and Pay-to-Anchor (P2A) scripts.
/// P2TR is the standard Taproot format (OP_1 <32 bytes>).
/// P2A is the anchor output format (OP_1 <0x4e 0x73>).
/// All other script types are classified as Unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptType {
    /// Pay-to-Anchor (P2A)
    P2A,
    /// Pay-to-Taproot (P2TR)
    P2TR,
    /// Unknown or unsupported script type
    Unknown,
}

/// Miniscript funding script information
///
/// Contains all three spending paths (cooperative, sender unilateral, receiver unilateral)
/// and the Taproot spend info needed to construct witnesses.
pub struct MiniscriptFundingInfo {
    /// Cooperative close script (both parties sign, no timelock)
    pub cooperative_script: TapScriptBuf,
    /// Sender unilateral close script (sender signs after timelock)
    pub sender_unilateral_script: TapScriptBuf,
    /// Receiver unilateral close script (receiver signs after timelock)
    pub receiver_unilateral_script: TapScriptBuf,
    /// Sender challenge script (counterparty can spend immediately if sender revocation secret revealed)
    pub sender_challenge_script: TapScriptBuf,
    /// Receiver challenge script (counterparty can spend immediately if receiver revocation secret revealed)
    pub receiver_challenge_script: TapScriptBuf,
    /// Taproot spend info for witness construction (wrapped in Arc for sharing)
    pub spend_info: std::sync::Arc<TrSpendInfo<XOnlyPublicKey>>,
    /// The Taproot address
    pub address: Address<bitcoin::address::NetworkUnchecked>,
}

/// Detects the script type from a scriptPubkey
///
/// Detects P2TR (standard Taproot) and P2A (anchor output) scripts.
/// All other scripts are classified as Unknown.
///
/// # Arguments
/// * `script` - The script to analyze
///
/// # Returns
/// The detected script type (P2TR, P2A, or Unknown)
pub fn detect_script_type(script: &ScriptPubKeyBuf) -> ScriptType {
    let bytes = script.as_bytes();

    if bytes.len() == P2TR_SCRIPT_LEN && bytes[0] == OP_1 && bytes[1] == PUSH_32_BYTES {
        return ScriptType::P2TR;
    }

    if bytes.len() == P2A_SCRIPT_LEN
        && bytes[0] == OP_1
        && bytes[1] == PUSH_2_BYTES
        && bytes[2] == P2A_MARKER_BYTE_1
        && bytes[3] == P2A_MARKER_BYTE_2
    {
        return ScriptType::P2A;
    }

    ScriptType::Unknown
}

/// Validates a Taproot multisig spend
///
/// This validates the witness structure for a Taproot script path spend.
/// Supports both cooperative (2-of-2) and unilateral (1-of-1) spending paths.
///
/// # Arguments
/// * `witness` - The witness data
/// * `script_pubkey` - The scriptPubkey (should be P2TR or P2A)
///
/// # Returns
/// * `Ok(())` - Witness structure is valid
/// * `Err(BtxError::InvalidWitness)` - Witness structure is invalid
pub fn validate_taproot_multisig_spend(
    witness: &Witness,
    script_pubkey: &ScriptPubKeyBuf,
) -> Result<()> {
    // Verify script_pubkey is P2TR or P2A
    let script_type = detect_script_type(script_pubkey);
    match script_type {
        ScriptType::P2TR | ScriptType::P2A => {
            // Both P2TR and P2A are Taproot scripts
        }
        _ => {
            return Err(BtxError::InvalidScriptPubkey(format!(
                "Expected P2TR or P2A script type for Taproot multisig spend, but detected {:?} (script length: {} bytes)",
                script_type,
                script_pubkey.len()
            ))
            .into());
        }
    }

    // For Taproot script path spending:
    // - Cooperative (2-of-2): script, control_block, sig1, sig2 (4 items)
    // - Unilateral (1-of-1): script, control_block, sig1 (3 items)
    // Minimum 3 items (script + control + at least 1 sig)
    if witness.len() < 3 {
        return Err(BtxError::InvalidWitness(
            0,
            format!(
                "Taproot witness should have at least 3 items (script, control, sig), got {}",
                witness.len()
            ),
        )
        .into());
    }

    Ok(())
}

/// Validates a P2TR or P2A spend
///
/// This is a simplified validation that checks witness structure.
/// Full validation requires script execution which is done by
/// Bitcoin Core's consensus validation.
///
/// # Arguments
/// * `witness` - The witness data
/// * `script_pubkey` - The scriptPubkey (locking script, must be P2TR or P2A)
///
/// # Returns
/// * `Ok(())` - Witness structure is valid
/// * `Err(BtxError::InvalidWitness)` - Witness structure is invalid
/// * `Err(BtxError::InvalidScriptPubkey)` - Script is not P2TR or P2A
pub fn validate_segwit_spend(witness: &Witness, script_pubkey: &ScriptPubKeyBuf) -> Result<()> {
    let script_type = detect_script_type(script_pubkey);

    match script_type {
        ScriptType::P2TR | ScriptType::P2A => {
            // Both P2TR and P2A are Taproot scripts and use the same witness validation
        }
        _ => {
            return Err(BtxError::InvalidScriptPubkey(format!(
                "Expected P2TR or P2A script type, but detected {:?} (script length: {} bytes)",
                script_type,
                script_pubkey.len()
            ))
            .into());
        }
    }

    // P2TR key-path spend: single signature in witness is acceptable
    if witness.is_empty() {
        return Err(BtxError::InvalidWitness(
            0,
            format!("{:?} witness is empty (expected at least one witness item)", script_type),
        )
        .into());
    }

    if witness.len() > 1 {
        // Script-path spend (e.g., multisig/miniscript) should have control block + script + sig(s)
        validate_taproot_multisig_spend(witness, script_pubkey)?;
    }

    Ok(())
}

/// Builds miniscript funding scripts with multiple spending paths
///
/// Creates miniscript policies with five spending paths:
/// 1. Cooperative: both parties sign immediately (no timelock)
/// 2. Sender unilateral: sender signs after CSV timelock expires
/// 3. Receiver unilateral: receiver signs after CSV timelock expires
/// 4. Sender challenge: counterparty can spend immediately with revocation key
/// 5. Receiver challenge: counterparty can spend immediately with revocation key
///
/// # Arguments
/// * `sender_pubkey` - Sender's X-only public key
/// * `receiver_pubkey` - Receiver's X-only public key
/// * `timeout_blocks` - Number of blocks for CSV timelock
/// * `sender_challenge_pubkey` - Sender's challenge (revocation) key
/// * `receiver_challenge_pubkey` - Receiver's challenge (revocation) key
///
/// # Returns
/// A MiniscriptFundingInfo containing all scripts
pub fn build_miniscript_funding_script(
    sender_pubkey: XOnlyPublicKey,
    receiver_pubkey: XOnlyPublicKey,
    timeout_blocks: u16,
    sender_challenge_pubkey: XOnlyPublicKey,
    receiver_challenge_pubkey: XOnlyPublicKey,
) -> Result<MiniscriptFundingInfo> {
    let _secp = Secp256k1::new();

    // Generate a fresh, random internal key for this Taproot output
    let sk_bytes: [u8; 32] = random();
    let internal_sk = SecretKey::from_secret_bytes(sk_bytes).map_err(|_| {
        BtxError::InvalidScriptPubkey("Failed to generate internal key".to_string())
    })?;
    let keypair = internal_sk.keypair();
    let (internal_key_raw, _parity) = bitcoin::secp256k1::XOnlyPublicKey::from_keypair(&keypair);
    let internal_key_bytes = internal_key_raw.serialize();
    let internal_key = XOnlyPublicKey::from_byte_array(&internal_key_bytes)
        .map_err(|_| BtxError::InvalidScriptPubkey("Failed to convert internal key".to_string()))?;

    // Create policy string with five spending paths
    // Cooperative: both parties sign immediately (no timelock)
    // Sender unilateral: sender signs after CSV timelock expires
    // Receiver unilateral: receiver signs after CSV timelock expires
    // Sender challenge: counterparty (receiver) can spend immediately with revocation key
    // Receiver challenge: counterparty (sender) can spend immediately with revocation key
    // Note: Using unique key names to avoid "duplicate keys" error in Taproot compiler
    // They will be translated to the same actual keys
    let policy_str = format!(
        "or(thresh(2,pk(sender1),pk(receiver1)),or(and(pk(sender2),older({})),or(and(pk(receiver2),older({})),or(pk(sender_challenge),pk(receiver_challenge)))))",
        timeout_blocks, timeout_blocks
    );

    // Parse and compile policy to Taproot descriptor
    let policy = Concrete::<String>::from_str(&policy_str)
        .map_err(|e| BtxError::InvalidScriptPubkey(format!("Failed to parse policy: {}", e)))?;

    let descriptor = policy.compile_tr(Some("internal_key".to_string())).map_err(|e| {
        BtxError::InvalidScriptPubkey(format!("Failed to compile policy to Taproot: {}", e))
    })?;

    // Translate string keys to real XOnlyPublicKey
    let mut translator = XOnlyKeyTranslator {
        sender: sender_pubkey,
        receiver: receiver_pubkey,
        internal: internal_key,
        sender_challenge: sender_challenge_pubkey,
        receiver_challenge: receiver_challenge_pubkey,
    };

    let real_descriptor = descriptor.translate_pk(&mut translator).map_err(|e| {
        BtxError::InvalidScriptPubkey(format!("Failed to translate keys in descriptor: {:?}", e))
    })?;

    // Extract descriptor and get spend info
    let tr_descriptor = match real_descriptor {
        Descriptor::Tr(tr) => tr,
        _ =>
            return Err(
                BtxError::InvalidScriptPubkey("Expected Taproot descriptor".to_string()).into()
            ),
    };

    // Get spend info (computes Taproot tree and output key)
    let spend_info = tr_descriptor.spend_info();

    // Extract scripts from leaves, identified by structure
    let mut cooperative_script = None;
    let mut sender_unilateral_script = None;
    let mut receiver_unilateral_script = None;
    let mut sender_challenge_script = None;
    let mut receiver_challenge_script = None;

    let sender_hex = sender_pubkey.to_string();
    let receiver_hex = receiver_pubkey.to_string();
    let sender_challenge_hex = sender_challenge_pubkey.to_string();
    let receiver_challenge_hex = receiver_challenge_pubkey.to_string();

    for leaf in tr_descriptor.leaves() {
        let script_bytes = leaf.miniscript().encode().into_bytes();
        let script: TapScriptBuf = TapScriptBuf::from_bytes(script_bytes);
        let miniscript_str = leaf.miniscript().to_string();

        // Cooperative: contains both sender and receiver keys, but no "older" and no challenge keys
        if miniscript_str.contains(&sender_hex)
            && miniscript_str.contains(&receiver_hex)
            && !miniscript_str.contains("older")
            && !miniscript_str.contains(&sender_challenge_hex)
            && !miniscript_str.contains(&receiver_challenge_hex)
        {
            cooperative_script = Some(script.clone());
        }

        // Unilateral: contains "older" (timelock) + specific key
        if miniscript_str.contains("older") && miniscript_str.contains(&sender_hex) {
            sender_unilateral_script = Some(script.clone());
        }
        if miniscript_str.contains("older") && miniscript_str.contains(&receiver_hex) {
            receiver_unilateral_script = Some(script.clone());
        }

        // Challenge: contains challenge keys (may be in separate leaves or merged)
        if miniscript_str.contains(&sender_challenge_hex) {
            sender_challenge_script = Some(script.clone());
        }
        if miniscript_str.contains(&receiver_challenge_hex) {
            receiver_challenge_script = Some(script.clone());
        }

        // If a leaf contains both challenge keys, use it for both
        if miniscript_str.contains(&sender_challenge_hex)
            && miniscript_str.contains(&receiver_challenge_hex)
        {
            sender_challenge_script = Some(script.clone());
            receiver_challenge_script = Some(script.clone());
        }
    }

    // If only one challenge script is found, use it for both
    if sender_challenge_script.is_some() && receiver_challenge_script.is_none() {
        receiver_challenge_script = sender_challenge_script.clone();
    }
    if receiver_challenge_script.is_some() && sender_challenge_script.is_none() {
        sender_challenge_script = receiver_challenge_script.clone();
    }

    let cooperative_script = cooperative_script.ok_or_else(|| {
        BtxError::InvalidScriptPubkey("Failed to find cooperative script".to_string())
    })?;
    let sender_unilateral_script = sender_unilateral_script.ok_or_else(|| {
        BtxError::InvalidScriptPubkey("Failed to find sender unilateral script".to_string())
    })?;
    let receiver_unilateral_script = receiver_unilateral_script.ok_or_else(|| {
        BtxError::InvalidScriptPubkey("Failed to find receiver unilateral script".to_string())
    })?;
    let sender_challenge_script = sender_challenge_script.ok_or_else(|| {
        BtxError::InvalidScriptPubkey("Failed to find sender challenge script".to_string())
    })?;
    let receiver_challenge_script = receiver_challenge_script.ok_or_else(|| {
        BtxError::InvalidScriptPubkey("Failed to find receiver challenge script".to_string())
    })?;

    let output_key_raw = spend_info.output_key();
    let output_key_bytes = output_key_raw.serialize();
    let output_key_xonly = bitcoin::key::XOnlyPublicKey::from_byte_array(&output_key_bytes)
        .map_err(|_| BtxError::InvalidScriptPubkey("Failed to convert output key".to_string()))?;
    let output_key = bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(output_key_xonly);
    let address = Address::p2tr_tweaked(output_key, Network::Regtest);

    Ok(MiniscriptFundingInfo {
        cooperative_script,
        sender_unilateral_script,
        receiver_unilateral_script,
        sender_challenge_script,
        receiver_challenge_script,
        spend_info,
        address: *address.as_unchecked(),
    })
}

/// Builds funding information with multiple spending paths
///
/// This creates a P2TR address with three spending paths embedded in a Taproot script tree.
///
/// # Arguments
/// * `sender_pubkey` - Sender's X-only public key
/// * `receiver_pubkey` - Receiver's X-only public key
/// * `timeout_blocks` - Number of blocks for CSV timelock
/// * `network` - Bitcoin network
///
/// # Returns
/// A MiniscriptFundingInfo containing all scripts, spend info, and address
pub fn build_funding_info(
    sender_pubkey: XOnlyPublicKey,
    receiver_pubkey: XOnlyPublicKey,
    timeout_blocks: u16,
    network: Network,
    sender_challenge_pubkey: XOnlyPublicKey,
    receiver_challenge_pubkey: XOnlyPublicKey,
) -> Result<MiniscriptFundingInfo> {
    let mut funding_info = build_miniscript_funding_script(
        sender_pubkey,
        receiver_pubkey,
        timeout_blocks,
        sender_challenge_pubkey,
        receiver_challenge_pubkey,
    )?;

    let output_key_raw = funding_info.spend_info.output_key();
    let output_key_bytes = output_key_raw.serialize();
    let output_key_xonly = bitcoin::key::XOnlyPublicKey::from_byte_array(&output_key_bytes)
        .map_err(|_| BtxError::InvalidScriptPubkey("Failed to convert output key".to_string()))?;
    let output_key = bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(output_key_xonly);
    let address = Address::p2tr_tweaked(output_key, network);
    funding_info.address = *address.as_unchecked();

    Ok(funding_info)
}

/// Key translator for converting string keys in miniscript policies to XOnlyPublicKey
struct XOnlyKeyTranslator {
    sender: XOnlyPublicKey,
    receiver: XOnlyPublicKey,
    internal: XOnlyPublicKey,
    sender_challenge: XOnlyPublicKey,
    receiver_challenge: XOnlyPublicKey,
}

impl Translator<String> for XOnlyKeyTranslator {
    type TargetPk = XOnlyPublicKey;
    type Error = ();
    /// Translates a string key to an XOnlyPublicKey
    ///
    /// # Arguments
    /// * `pk` - The string key to translate
    ///
    /// # Returns
    /// The translated XOnlyPublicKey
    fn pk(&mut self, pk: &String) -> std::result::Result<XOnlyPublicKey, Self::Error> {
        match pk.as_str() {
            "sender" | "sender1" | "sender2" => Ok(self.sender),
            "receiver" | "receiver1" | "receiver2" => Ok(self.receiver),
            "internal_key" => Ok(self.internal),
            "sender_challenge" => Ok(self.sender_challenge),
            "receiver_challenge" => Ok(self.receiver_challenge),
            _ => Err(()),
        }
    }

    /// Hash-based keys are not supported.
    fn sha256(
        &mut self,
        _sha256: &<String as miniscript::MiniscriptKey>::Sha256,
    ) -> std::result::Result<<XOnlyPublicKey as miniscript::MiniscriptKey>::Sha256, Self::Error>
    {
        Err(())
    }

    /// Hash-based keys are not supported.
    fn hash256(
        &mut self,
        _hash256: &<String as miniscript::MiniscriptKey>::Hash256,
    ) -> std::result::Result<<XOnlyPublicKey as miniscript::MiniscriptKey>::Hash256, Self::Error>
    {
        Err(())
    }

    /// Hash-based keys are not supported.
    fn hash160(
        &mut self,
        _hash160: &<String as miniscript::MiniscriptKey>::Hash160,
    ) -> std::result::Result<<XOnlyPublicKey as miniscript::MiniscriptKey>::Hash160, Self::Error>
    {
        Err(())
    }

    /// Hash-based keys are not supported.
    fn ripemd160(
        &mut self,
        _ripemd160: &<String as miniscript::MiniscriptKey>::Ripemd160,
    ) -> std::result::Result<<XOnlyPublicKey as miniscript::MiniscriptKey>::Ripemd160, Self::Error>
    {
        Err(())
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::key::TweakedPublicKey;
    use bitcoin::script::ScriptPubKeyBufExt;

    use super::*;
    use crate::channel::test_utils::{
        challenge_pubkeys_miniscript, revocation_secrets, test_keys, test_keys_miniscript,
    };

    #[test]
    fn test_detect_script_type() {
        let (sender_pubkey_secp, _) = test_keys();
        let sender_pubkey = bitcoin::key::XOnlyPublicKey::from(sender_pubkey_secp);
        let output_key = TweakedPublicKey::dangerous_assume_tweaked(sender_pubkey);
        let p2tr_script = ScriptPubKeyBuf::new_p2tr_tweaked(output_key);

        let result_p2tr = detect_script_type(&p2tr_script);

        assert_eq!(result_p2tr, ScriptType::P2TR);

        let p2a_script = ScriptPubKeyBuf::new_p2a();

        let result_p2a = detect_script_type(&p2a_script);

        assert_eq!(result_p2a, ScriptType::P2A);

        let unknown_script = ScriptPubKeyBuf::from_bytes(vec![0x00u8, 0x01u8, 0x02u8]);

        let result_unknown = detect_script_type(&unknown_script);

        assert_eq!(result_unknown, ScriptType::Unknown);
    }

    #[test]
    fn test_validate_taproot_multisig_spend() -> Result<()> {
        let (sender_pubkey_secp, _) = test_keys();
        let sender_pubkey = bitcoin::key::XOnlyPublicKey::from(sender_pubkey_secp);
        let output_key = TweakedPublicKey::dangerous_assume_tweaked(sender_pubkey);
        let p2tr_script = ScriptPubKeyBuf::new_p2tr_tweaked(output_key);
        let mut witness = Witness::new();
        witness.push(vec![0u8; 32]);
        witness.push(vec![0u8; 33]);
        witness.push(vec![0u8; 64]);

        let result = validate_taproot_multisig_spend(&witness, &p2tr_script);

        assert!(result.is_ok());

        let p2a_script = ScriptPubKeyBuf::new_p2a();
        let mut witness_p2a = Witness::new();
        witness_p2a.push(vec![0u8; 32]);
        witness_p2a.push(vec![0u8; 33]);
        witness_p2a.push(vec![0u8; 64]);

        let result_p2a = validate_taproot_multisig_spend(&witness_p2a, &p2a_script);

        assert!(result_p2a.is_ok());

        let unknown_script = ScriptPubKeyBuf::from_bytes(vec![0x00u8, 0x01u8, 0x02u8]);
        let mut witness_unknown = Witness::new();
        witness_unknown.push(vec![0u8; 32]);
        witness_unknown.push(vec![0u8; 33]);
        witness_unknown.push(vec![0u8; 64]);

        let result_unknown = validate_taproot_multisig_spend(&witness_unknown, &unknown_script);

        assert!(result_unknown.is_err());

        let mut witness_short = Witness::new();
        witness_short.push(vec![0u8; 32]);
        witness_short.push(vec![0u8; 33]);

        let result_short = validate_taproot_multisig_spend(&witness_short, &p2tr_script);

        assert!(result_short.is_err());
        Ok(())
    }

    #[test]
    fn test_validate_segwit_spend() -> Result<()> {
        let (sender_pubkey_secp, _) = test_keys();
        let sender_pubkey = bitcoin::key::XOnlyPublicKey::from(sender_pubkey_secp);
        let output_key = TweakedPublicKey::dangerous_assume_tweaked(sender_pubkey);
        let p2tr_script = ScriptPubKeyBuf::new_p2tr_tweaked(output_key);
        let empty_witness = Witness::new();

        let result_empty = validate_segwit_spend(&empty_witness, &p2tr_script);

        assert!(result_empty.is_err());

        let mut witness_len1 = Witness::new();
        witness_len1.push(vec![0u8; 64]);

        let result_len1 = validate_segwit_spend(&witness_len1, &p2tr_script);

        assert!(result_len1.is_ok());

        let mut witness_len2 = Witness::new();
        witness_len2.push(vec![0u8; 32]);
        witness_len2.push(vec![0u8; 33]);
        witness_len2.push(vec![0u8; 64]);

        let result_len2 = validate_segwit_spend(&witness_len2, &p2tr_script);

        assert!(result_len2.is_ok());

        let p2a_script = ScriptPubKeyBuf::new_p2a();
        let mut witness_p2a = Witness::new();
        witness_p2a.push(vec![0u8; 64]);

        let result_p2a = validate_segwit_spend(&witness_p2a, &p2a_script);

        assert!(result_p2a.is_ok());

        let unknown_script = ScriptPubKeyBuf::from_bytes(vec![0x00u8, 0x01u8, 0x02u8]);
        let mut witness_unknown = Witness::new();
        witness_unknown.push(vec![0u8; 64]);

        let result_unknown = validate_segwit_spend(&witness_unknown, &unknown_script);

        assert!(result_unknown.is_err());
        Ok(())
    }

    #[test]
    fn test_build_miniscript_funding_script() -> Result<()> {
        let (sender_pubkey, receiver_pubkey) = test_keys_miniscript();
        let (sender_revocation_sk, receiver_revocation_sk) = revocation_secrets();
        let (sender_challenge_pubkey, receiver_challenge_pubkey) =
            challenge_pubkeys_miniscript(sender_revocation_sk, receiver_revocation_sk);
        let timeout_blocks = 144u16;

        let result = build_miniscript_funding_script(
            sender_pubkey,
            receiver_pubkey,
            timeout_blocks,
            sender_challenge_pubkey,
            receiver_challenge_pubkey,
        )?;

        assert!(!result.cooperative_script.is_empty());
        assert!(!result.sender_unilateral_script.is_empty());
        assert!(!result.receiver_unilateral_script.is_empty());
        assert!(!result.sender_challenge_script.is_empty());
        assert!(!result.receiver_challenge_script.is_empty());
        Ok(())
    }

    #[test]
    fn test_build_funding_info() -> Result<()> {
        let (sender_pubkey, receiver_pubkey) = test_keys_miniscript();
        let (sender_revocation_sk, receiver_revocation_sk) = revocation_secrets();
        let (sender_challenge_pubkey, receiver_challenge_pubkey) =
            challenge_pubkeys_miniscript(sender_revocation_sk, receiver_revocation_sk);
        let timeout_blocks = 144u16;
        let network = Network::Regtest;

        let result = build_funding_info(
            sender_pubkey,
            receiver_pubkey,
            timeout_blocks,
            network,
            sender_challenge_pubkey,
            receiver_challenge_pubkey,
        )?;

        assert!(!result.cooperative_script.is_empty());
        assert!(!result.sender_unilateral_script.is_empty());
        assert!(!result.receiver_unilateral_script.is_empty());
        assert!(!result.sender_challenge_script.is_empty());
        assert!(!result.receiver_challenge_script.is_empty());

        let network_mainnet = Network::Bitcoin;

        let result_mainnet = build_funding_info(
            sender_pubkey,
            receiver_pubkey,
            timeout_blocks,
            network_mainnet,
            sender_challenge_pubkey,
            receiver_challenge_pubkey,
        )?;

        assert!(!result_mainnet.cooperative_script.is_empty());
        assert_ne!(result.address, result_mainnet.address);
        Ok(())
    }
}
