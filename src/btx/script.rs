//! Bitcoin script validation utilities
//!
//! This module provides utilities for script type detection, validation,
//! and building common script types.

use bitcoin::ScriptBuf;

use crate::errors::{BtxError, Result};

/// Script type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptType {
    /// Pay-to-Public-Key-Hash (P2PKH)
    P2PKH,
    /// Pay-to-Script-Hash (P2SH)
    P2SH,
    /// Pay-to-Witness-Public-Key-Hash (P2WPKH)
    P2WPKH,
    /// Pay-to-Witness-Script-Hash (P2WSH)
    P2WSH,
    /// Pay-to-Taproot (P2TR)
    P2TR,
    /// Unknown or unsupported script type
    Unknown,
}

/// Detects the script type from a scriptPubkey
///
/// # Arguments
/// * `script` - The script to analyze
///
/// # Returns
/// The detected script type
pub fn detect_script_type(script: &ScriptBuf) -> ScriptType {
    let bytes = script.as_bytes();
    if bytes.is_empty() {
        return ScriptType::Unknown;
    }

    // P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    if bytes.len() == 25
        && bytes[0] == 0x76 // OP_DUP
        && bytes[1] == 0xa9 // OP_HASH160
        && bytes[2] == 0x14 // Push 20 bytes
        && bytes[23] == 0x88 // OP_EQUALVERIFY
        && bytes[24] == 0xac
    // OP_CHECKSIG
    {
        return ScriptType::P2PKH;
    }

    // P2SH: OP_HASH160 <20 bytes> OP_EQUAL
    if bytes.len() == 23
        && bytes[0] == 0xa9 // OP_HASH160
        && bytes[1] == 0x14 // Push 20 bytes
        && bytes[22] == 0x87
    // OP_EQUAL
    {
        return ScriptType::P2SH;
    }

    // P2WPKH: OP_0 <20 bytes>
    if bytes.len() == 22 && bytes[0] == 0x00 && bytes[1] == 0x14 {
        return ScriptType::P2WPKH;
    }

    // P2WSH: OP_0 <32 bytes>
    if bytes.len() == 34 && bytes[0] == 0x00 && bytes[1] == 0x20 {
        return ScriptType::P2WSH;
    }

    // P2TR: OP_1 <32 bytes>
    if bytes.len() == 34 && bytes[0] == 0x51 && bytes[1] == 0x20 {
        return ScriptType::P2TR;
    }

    ScriptType::Unknown
}

/// Validates a P2PKH spend
///
/// This is a simplified validation that checks script structure.
/// Full validation requires signature verification which is done by
/// Bitcoin Core's consensus validation.
///
/// # Arguments
/// * `script_sig` - The scriptSig (unlocking script)
/// * `script_pubkey` - The scriptPubkey (locking script)
///
/// # Returns
/// * `Ok(())` - Script structure is valid
/// * `Err(BtxError::InvalidScriptSig)` - Script structure is invalid
pub fn validate_p2pkh_spend(script_sig: &ScriptBuf, script_pubkey: &ScriptBuf) -> Result<()> {
    // Verify script_pubkey is P2PKH
    if detect_script_type(script_pubkey) != ScriptType::P2PKH {
        return Err(BtxError::InvalidScriptPubkey(format!(
            "Expected P2PKH script, got {:?}",
            detect_script_type(script_pubkey)
        ))
        .into());
    }

    // scriptSig should contain signature and public key
    // Structure: <sig> <pubkey>
    let script_sig_bytes = script_sig.as_bytes();
    if script_sig_bytes.len() < 2 {
        return Err(BtxError::InvalidScriptSig(0, "P2PKH scriptSig too short".to_string()).into());
    }

    Ok(())
}

/// Validates a P2SH spend
///
/// This is a simplified validation that checks script structure.
/// Full validation requires script execution which is done by
/// Bitcoin Core's consensus validation.
///
/// # Arguments
/// * `script_sig` - The scriptSig (unlocking script)
/// * `script_pubkey` - The scriptPubkey (locking script)
///
/// # Returns
/// * `Ok(())` - Script structure is valid
/// * `Err(BtxError::InvalidScriptSig)` - Script structure is invalid
pub fn validate_p2sh_spend(script_sig: &ScriptBuf, script_pubkey: &ScriptBuf) -> Result<()> {
    // Verify script_pubkey is P2SH
    if detect_script_type(script_pubkey) != ScriptType::P2SH {
        return Err(BtxError::InvalidScriptPubkey(format!(
            "Expected P2SH script, got {:?}",
            detect_script_type(script_pubkey)
        ))
        .into());
    }

    // scriptSig should contain redeem script and unlocking data
    let script_sig_bytes = script_sig.as_bytes();
    if script_sig_bytes.is_empty() {
        return Err(BtxError::InvalidScriptSig(0, "P2SH scriptSig is empty".to_string()).into());
    }

    Ok(())
}

/// Validates a SegWit spend
///
/// This is a simplified validation that checks witness structure.
/// Full validation requires script execution which is done by
/// Bitcoin Core's consensus validation.
///
/// # Arguments
/// * `witness` - The witness data
/// * `script_pubkey` - The scriptPubkey (locking script)
///
/// # Returns
/// * `Ok(())` - Witness structure is valid
/// * `Err(BtxError::InvalidWitness)` - Witness structure is invalid
pub fn validate_segwit_spend(witness: &bitcoin::Witness, script_pubkey: &ScriptBuf) -> Result<()> {
    let script_type = detect_script_type(script_pubkey);
    match script_type {
        ScriptType::P2WPKH => {
            // P2WPKH witness should have 2 items: signature and public key
            if witness.len() != 2 {
                return Err(BtxError::InvalidWitness(
                    0,
                    format!("P2WPKH witness should have 2 items, got {}", witness.len()),
                )
                .into());
            }
        }
        ScriptType::P2WSH => {
            // P2WSH witness should have at least 1 item (the witness script)
            if witness.is_empty() {
                return Err(
                    BtxError::InvalidWitness(0, "P2WSH witness is empty".to_string()).into()
                );
            }
        }
        ScriptType::P2TR => {
            // P2TR witness should have at least 1 item (the control block and/or script path)
            if witness.is_empty() {
                return Err(BtxError::InvalidWitness(0, "P2TR witness is empty".to_string()).into());
            }
        }
        _ => {
            return Err(BtxError::InvalidScriptPubkey(format!(
                "Expected SegWit script type, got {:?}",
                script_type
            ))
            .into());
        }
    }

    Ok(())
}

/// Extracts script_pubkey from an address
///
/// # Arguments
/// * `address` - The Bitcoin address
///
/// # Returns
/// The script_pubkey for the address
pub fn script_pubkey_from_address(
    address: &bitcoin::Address<bitcoin::address::NetworkUnchecked>,
) -> ScriptBuf {
    address.assume_checked_ref().script_pubkey().to_owned()
}
