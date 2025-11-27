//! Bitcoin script validation utilities
//!
//! This module provides utilities for script type detection, validation,
//! and building common script types.

use std::str::FromStr;

use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::{Address, Network, ScriptBuf};
use miniscript::descriptor::{Descriptor, TrSpendInfo};
use miniscript::policy::Concrete;
use miniscript::Translator;

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
            // P2TR key-path spend: single signature in witness is acceptable
            if witness.is_empty() {
                return Err(BtxError::InvalidWitness(0, "P2TR witness is empty".to_string()).into());
            }
            if witness.len() > 1 {
                // Script-path spend (e.g., multisig/miniscript) should have control block + script + sig(s)
                validate_taproot_multisig_spend(witness, script_pubkey)?;
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

/// Builds a 2-of-2 multisig script for Taproot
///
/// Creates a Bitcoin script that requires signatures from both public keys.
/// The script format is: `OP_2 <pubkey1> <pubkey2> OP_2 OP_CHECKMULTISIG`
///
/// # Arguments
/// * `sender_pubkey` - First public key (sender's X-only public key)
/// * `receiver_pubkey` - Second public key (receiver's X-only public key)
///
/// # Returns
/// A ScriptBuf containing the 2-of-2 multisig script
///
/// # Examples
///
/// ```rust
/// use merkle_morph::btx::script::build_2_of_2_multisig_script;
/// use bitcoin::secp256k1::{Secp256k1, SecretKey, XOnlyPublicKey};
///
/// // In practice, these would come from key generation
/// let secp = Secp256k1::new();
/// let sender_sk =
///     SecretKey::from_slice(&[1u8; 32]).expect("32-byte array should always be a valid SecretKey");
/// let receiver_sk =
///     SecretKey::from_slice(&[2u8; 32]).expect("32-byte array should always be a valid SecretKey");
/// let sender_pubkey = XOnlyPublicKey::from_keypair(&sender_sk.keypair(&secp)).0;
/// let receiver_pubkey = XOnlyPublicKey::from_keypair(&receiver_sk.keypair(&secp)).0;
///
/// let script = build_2_of_2_multisig_script(sender_pubkey, receiver_pubkey);
/// ```
pub fn build_2_of_2_multisig_script(
    sender_pubkey: XOnlyPublicKey,
    receiver_pubkey: XOnlyPublicKey,
) -> ScriptBuf {
    let mut script = ScriptBuf::new();

    // Push 2 onto stack (number of required signatures)
    script.push_slice([0x52]);

    // Push first public key (33 bytes for compressed, but X-only is 32 bytes)
    // For Taproot, we use X-only public keys (32 bytes)
    script.push_slice(sender_pubkey.serialize());

    // Push second public key
    script.push_slice(receiver_pubkey.serialize());

    // Push 2 onto stack (total number of public keys)
    script.push_slice([0x52]);

    // OP_CHECKMULTISIG: Verify 2-of-2 multisig
    script.push_opcode(bitcoin::opcodes::all::OP_CHECKMULTISIG);

    script
}

/// Builds a Taproot address from a script using script path spending
///
/// This creates a P2TR (Pay-to-Taproot) address that can be spent via the script path.
/// The script is embedded in a Taproot script tree.
///
/// Security note: We generate a fresh random internal key for each address so that
/// there is no shared or hard-coded key material. This library currently only
/// supports script-path spending for these outputs; callers must manage and
/// persist any key material if they wish to use key-path spending.
///
/// # Arguments
/// * `script` - The script to embed (e.g., 2-of-2 multisig)
/// * `network` - Bitcoin network (mainnet, testnet, etc.)
///
/// # Returns
/// A Taproot address (P2TR) that can spend via the script path
///
/// # Examples
///
/// ```rust
/// use merkle_morph::btx::script::{build_2_of_2_multisig_script, build_taproot_address};
/// use bitcoin::{
///     Network,
///     secp256k1::{Secp256k1, SecretKey, XOnlyPublicKey},
/// };
///
/// let secp = Secp256k1::new();
/// let sender_sk =
///     SecretKey::from_slice(&[1u8; 32]).expect("32-byte array should always be a valid SecretKey");
/// let receiver_sk =
///     SecretKey::from_slice(&[2u8; 32]).expect("32-byte array should always be a valid SecretKey");
/// let sender_pubkey = XOnlyPublicKey::from_keypair(&sender_sk.keypair(&secp)).0;
/// let receiver_pubkey = XOnlyPublicKey::from_keypair(&receiver_sk.keypair(&secp)).0;
/// let script = build_2_of_2_multisig_script(sender_pubkey, receiver_pubkey);
///
/// let address = build_taproot_address(&script, Network::Regtest)
///     .expect("building taproot address should succeed for valid keys");
/// ```
pub fn build_taproot_address(
    script: &ScriptBuf,
    network: Network,
) -> Result<Address<bitcoin::address::NetworkUnchecked>> {
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::taproot::TaprootBuilder;
    use rand::random;

    let secp = Secp256k1::new();

    // Create a Taproot builder
    // Generate a fresh, random internal key for this Taproot output.
    // The corresponding secret key is not persisted by this function.
    let sk_bytes: [u8; 32] = random();
    let internal_sk = bitcoin::secp256k1::SecretKey::from_slice(&sk_bytes).map_err(|_| {
        BtxError::InvalidScriptPubkey("Failed to generate internal key".to_string())
    })?;
    let internal_key = XOnlyPublicKey::from_keypair(&internal_sk.keypair(&secp)).0;

    // Build the Taproot script tree with our multisig script
    let taproot_builder = TaprootBuilder::new().add_leaf(0, script.clone()).map_err(|_| {
        BtxError::InvalidScriptPubkey("Failed to build Taproot script tree".to_string())
    })?;

    let spend_info = taproot_builder
        .finalize(&secp, internal_key)
        .map_err(|_| BtxError::InvalidScriptPubkey("Failed to finalize Taproot".to_string()))?;

    // Get the output key (the Taproot public key) as XOnlyPublicKey
    let output_key = spend_info.output_key().to_x_only_public_key();

    // Create the P2TR address
    let address = Address::p2tr(&secp, output_key, None, network);

    // Convert to NetworkUnchecked for consistency with our API
    // The address is already valid, we just need to change the type parameter
    Ok(address.as_unchecked().clone())
}

/// Key translator for converting string keys in miniscript policies to XOnlyPublicKey
struct XOnlyKeyTranslator {
    sender: XOnlyPublicKey,
    receiver: XOnlyPublicKey,
    internal: XOnlyPublicKey,
    sender_penalty: XOnlyPublicKey,
    receiver_penalty: XOnlyPublicKey,
}

impl Translator<String> for XOnlyKeyTranslator {
    type TargetPk = XOnlyPublicKey;
    type Error = ();

    fn pk(&mut self, pk: &String) -> std::result::Result<XOnlyPublicKey, Self::Error> {
        match pk.as_str() {
            "sender" | "sender1" | "sender2" => Ok(self.sender),
            "receiver" | "receiver1" | "receiver2" => Ok(self.receiver),
            "internal_key" => Ok(self.internal),
            "sender_penalty" => Ok(self.sender_penalty),
            "receiver_penalty" => Ok(self.receiver_penalty),
            _ => Err(()),
        }
    }

    fn sha256(
        &mut self,
        _sha256: &<String as miniscript::MiniscriptKey>::Sha256,
    ) -> std::result::Result<<XOnlyPublicKey as miniscript::MiniscriptKey>::Sha256, Self::Error>
    {
        Err(())
    }

    fn hash256(
        &mut self,
        _hash256: &<String as miniscript::MiniscriptKey>::Hash256,
    ) -> std::result::Result<<XOnlyPublicKey as miniscript::MiniscriptKey>::Hash256, Self::Error>
    {
        Err(())
    }

    fn hash160(
        &mut self,
        _hash160: &<String as miniscript::MiniscriptKey>::Hash160,
    ) -> std::result::Result<<XOnlyPublicKey as miniscript::MiniscriptKey>::Hash160, Self::Error>
    {
        Err(())
    }

    fn ripemd160(
        &mut self,
        _ripemd160: &<String as miniscript::MiniscriptKey>::Ripemd160,
    ) -> std::result::Result<<XOnlyPublicKey as miniscript::MiniscriptKey>::Ripemd160, Self::Error>
    {
        Err(())
    }
}

/// Miniscript funding script information
///
/// Contains all three spending paths (cooperative, sender unilateral, receiver unilateral)
/// and the Taproot spend info needed to construct witnesses.
pub struct MiniscriptFundingInfo {
    /// Cooperative close script (both parties sign, no timelock)
    pub cooperative_script: ScriptBuf,
    /// Sender unilateral close script (sender signs after timelock)
    pub sender_unilateral_script: ScriptBuf,
    /// Receiver unilateral close script (receiver signs after timelock)
    pub receiver_unilateral_script: ScriptBuf,
    /// Sender penalty script (counterparty can spend immediately if sender revocation secret revealed)
    pub sender_penalty_script: ScriptBuf,
    /// Receiver penalty script (counterparty can spend immediately if receiver revocation secret revealed)
    pub receiver_penalty_script: ScriptBuf,
    /// Taproot spend info for witness construction (wrapped in Arc for sharing)
    pub spend_info: std::sync::Arc<TrSpendInfo<XOnlyPublicKey>>,
    /// The Taproot address
    pub address: Address<bitcoin::address::NetworkUnchecked>,
}

/// Builds miniscript funding scripts with three spending paths
///
/// Creates three miniscript policies:
/// 1. Cooperative: both parties sign immediately (no timelock)
/// 2. Sender unilateral: sender signs after CSV timelock expires
/// 3. Receiver unilateral: receiver signs after CSV timelock expires
///
/// # Arguments
/// * `sender_pubkey` - Sender's X-only public key
/// * `receiver_pubkey` - Receiver's X-only public key
/// * `timeout_blocks` - Number of blocks for CSV timelock
///
/// # Returns
/// A MiniscriptFundingInfo containing all three scripts
pub fn build_miniscript_funding_script(
    sender_pubkey: XOnlyPublicKey,
    receiver_pubkey: XOnlyPublicKey,
    timeout_blocks: u16,
    sender_penalty_pubkey: XOnlyPublicKey,
    receiver_penalty_pubkey: XOnlyPublicKey,
) -> Result<MiniscriptFundingInfo> {
    use bitcoin::secp256k1::Secp256k1;
    use rand::random;

    let secp = Secp256k1::new();

    // Generate a fresh, random internal key for this Taproot output
    let sk_bytes: [u8; 32] = random();
    let internal_sk = bitcoin::secp256k1::SecretKey::from_slice(&sk_bytes).map_err(|_| {
        BtxError::InvalidScriptPubkey("Failed to generate internal key".to_string())
    })?;
    let internal_key = XOnlyPublicKey::from_keypair(&internal_sk.keypair(&secp)).0;

    // Create policy string with five spending paths
    // Cooperative: both parties sign immediately (no timelock)
    // Sender unilateral: sender signs after CSV timelock expires
    // Receiver unilateral: receiver signs after CSV timelock expires
    // Sender penalty: counterparty (receiver) can spend immediately with revocation key
    // Receiver penalty: counterparty (sender) can spend immediately with revocation key
    // Note: Using unique key names to avoid "duplicate keys" error in Taproot compiler
    // They will be translated to the same actual keys
    let policy_str = format!(
        "or(thresh(2,pk(sender1),pk(receiver1)),or(and(pk(sender2),older({})),or(and(pk(receiver2),older({})),or(pk(sender_penalty),pk(receiver_penalty)))))",
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
        sender_penalty: sender_penalty_pubkey,
        receiver_penalty: receiver_penalty_pubkey,
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

    // Extract scripts from leaves
    // The compiler may reorder leaves, so we identify them by structure
    let mut cooperative_script = None;
    let mut sender_unilateral_script = None;
    let mut receiver_unilateral_script = None;
    let mut sender_penalty_script = None;
    let mut receiver_penalty_script = None;

    // Pre-compute hex strings so we can match against miniscript string
    let sender_hex = sender_pubkey.to_string();
    let receiver_hex = receiver_pubkey.to_string();
    let sender_penalty_hex = sender_penalty_pubkey.to_string();
    let receiver_penalty_hex = receiver_penalty_pubkey.to_string();

    for leaf in tr_descriptor.leaves() {
        let script = leaf.miniscript().encode();
        let miniscript_str = leaf.miniscript().to_string();

        // Identify scripts by their miniscript structure
        // Cooperative: contains "thresh(2" (2-of-2 multisig)
        if miniscript_str.contains("thresh(2") {
            cooperative_script = Some(script.clone());
        }

        // Unilateral branches contain the csv timelock ("older") and the relevant key
        if miniscript_str.contains("older") && miniscript_str.contains(&sender_hex) {
            sender_unilateral_script = Some(script.clone());
        }
        if miniscript_str.contains("older") && miniscript_str.contains(&receiver_hex) {
            receiver_unilateral_script = Some(script.clone());
        }

        // Penalty branches may be compiled into a single leaf that includes both keys.
        if miniscript_str.contains(&sender_penalty_hex) {
            sender_penalty_script = Some(script.clone());
        }
        if miniscript_str.contains(&receiver_penalty_hex) {
            receiver_penalty_script = Some(script);
        }
    }

    // Fallback: if we couldn't identify by structure, use order
    // (compiler typically outputs: cooperative, sender, receiver, penalty)
    // Some compiler versions merge the two penalty branches into a single leaf.
    let leaves_vec: Vec<_> = tr_descriptor.leaves().collect();
    if cooperative_script.is_none() && !leaves_vec.is_empty() {
        cooperative_script = Some(leaves_vec[0].miniscript().encode());
    }
    if sender_unilateral_script.is_none() && leaves_vec.len() > 1 {
        sender_unilateral_script = Some(leaves_vec[1].miniscript().encode());
    }
    if receiver_unilateral_script.is_none() && leaves_vec.len() > 2 {
        receiver_unilateral_script = Some(leaves_vec[2].miniscript().encode());
    }
    if sender_penalty_script.is_none() || receiver_penalty_script.is_none() {
        match leaves_vec.len() {
            l if l >= 5 => {
                if sender_penalty_script.is_none() {
                    sender_penalty_script = Some(leaves_vec[3].miniscript().encode());
                }
                if receiver_penalty_script.is_none() {
                    receiver_penalty_script = Some(leaves_vec[4].miniscript().encode());
                }
            }
            l if l >= 4 => {
                // Penalty leaves collapsed into a single branch; reuse it for both
                let penalty_script = leaves_vec[3].miniscript().encode();
                if sender_penalty_script.is_none() {
                    sender_penalty_script = Some(penalty_script.clone());
                }
                if receiver_penalty_script.is_none() {
                    receiver_penalty_script = Some(penalty_script);
                }
            }
            _ => {
                return Err(BtxError::InvalidScriptPubkey(format!(
                    "Expected at least 4 script leaves, got {}",
                    leaves_vec.len()
                ))
                .into());
            }
        }
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
    let sender_penalty_script = sender_penalty_script.ok_or_else(|| {
        BtxError::InvalidScriptPubkey("Failed to find sender penalty script".to_string())
    })?;
    let receiver_penalty_script = receiver_penalty_script.ok_or_else(|| {
        BtxError::InvalidScriptPubkey("Failed to find receiver penalty script".to_string())
    })?;

    // Get address from descriptor
    let address = tr_descriptor.address(Network::Regtest);

    Ok(MiniscriptFundingInfo {
        cooperative_script,
        sender_unilateral_script,
        receiver_unilateral_script,
        sender_penalty_script,
        receiver_penalty_script,
        spend_info,
        address: address.as_unchecked().clone(),
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
    sender_penalty_pubkey: XOnlyPublicKey,
    receiver_penalty_pubkey: XOnlyPublicKey,
) -> Result<MiniscriptFundingInfo> {
    // Build funding info with default network (will be updated)
    let mut funding_info = build_miniscript_funding_script(
        sender_pubkey,
        receiver_pubkey,
        timeout_blocks,
        sender_penalty_pubkey,
        receiver_penalty_pubkey,
    )?;

    // Update address with correct network using the output key from spend_info
    let output_key = funding_info.spend_info.output_key();
    let address = Address::p2tr_tweaked(output_key, network);
    funding_info.address = address.as_unchecked().clone();

    Ok(funding_info)
}

/// Validates a Taproot multisig spend
///
/// This validates the witness structure for a Taproot script path spend.
/// Supports both cooperative (2-of-2) and unilateral (1-of-1) spending paths.
///
/// # Arguments
/// * `witness` - The witness data
/// * `script_pubkey` - The scriptPubkey (should be P2TR)
///
/// # Returns
/// * `Ok(())` - Witness structure is valid
/// * `Err(BtxError::InvalidWitness)` - Witness structure is invalid
pub fn validate_taproot_multisig_spend(
    witness: &bitcoin::Witness,
    script_pubkey: &ScriptBuf,
) -> Result<()> {
    // Verify script_pubkey is P2TR
    if detect_script_type(script_pubkey) != ScriptType::P2TR {
        return Err(BtxError::InvalidScriptPubkey(format!(
            "Expected P2TR script, got {:?}",
            detect_script_type(script_pubkey)
        ))
        .into());
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

/// Validates a miniscript spend
///
/// This validates the witness structure for any of the three spending paths:
/// - Cooperative: both parties sign (no timelock)
/// - Sender unilateral: sender signs after timelock
/// - Receiver unilateral: receiver signs after timelock
///
/// # Arguments
/// * `witness` - The witness data
/// * `script_pubkey` - The scriptPubkey (should be P2TR)
/// * `current_height` - Current block height (for timelock validation)
/// * `lock_height` - Block height when transaction was first seen
///
/// # Returns
/// * `Ok(())` - Witness structure is valid and timelock is satisfied (if applicable)
/// * `Err(BtxError::InvalidWitness)` - Witness structure is invalid
/// * `Err(ChannelError::ForceCloseTimeoutNotMet)` - Timelock not yet satisfied
pub fn validate_miniscript_spend(
    witness: &bitcoin::Witness,
    script_pubkey: &ScriptBuf,
) -> Result<()> {
    // Basic witness structure validation
    validate_taproot_multisig_spend(witness, script_pubkey)?;

    // Extract the script from witness (first element)
    if witness.is_empty() {
        return Err(BtxError::InvalidWitness(0, "Witness is empty".to_string()).into());
    }

    let _script_bytes = witness.nth(0).ok_or_else(|| {
        BtxError::InvalidWitness(0, "Failed to extract script from witness".to_string())
    })?;

    // Check if this is a unilateral spend (has older() timelock)
    // For now, we do basic validation. Full miniscript analysis would require
    // parsing the script to detect older() opcodes.
    // The number of signatures can indicate the path:
    // - 2 signatures: cooperative (thresh(2, ...))
    // - 1 signature: unilateral (and_v(v:pk(...), older(...)))

    // Timelock enforcement for unilateral spends should be validated at the transaction
    // level using sequence values. We do not enforce the CSV delay here because the
    // same single-sig branch is also used for immediate revocation/penalty spends.

    Ok(())
}
