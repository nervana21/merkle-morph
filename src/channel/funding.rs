// SPDX-License-Identifier: CC0-1.0

//! Channel funding utilities
//!
//! This module provides utilities for creating and managing channel funding transactions
//! using miniscript-based Taproot scripts with three spending paths:
//! 1. Cooperative close: both parties sign immediately (no timelock)
//! 2. Sender unilateral: sender signs after CSV timelock expires
//! 3. Receiver unilateral: receiver signs after CSV timelock expires

use std::sync::Arc;

use bitcoin::address::NetworkUnchecked;
use bitcoin::key::XOnlyPublicKey;
use bitcoin::script::{ScriptPubKeyBuf, TapScriptBuf};
use bitcoin::secp256k1::SecretKey;
use bitcoin::{Address, Network, Txid};
use miniscript::descriptor::TrSpendInfo;

use crate::btx::script::build_funding_info;
use crate::btx::state::Utxo;
use crate::btx::timelock::FORCE_CLOSE_TIMEOUT_BLOCKS;
use crate::Result;

/// Channel funding information
///
/// Contains all information needed to manage a channel's funding UTXO.
/// The funding UTXO is locked with a miniscript-based Taproot script that supports
/// three spending paths: cooperative close, sender unilateral, and receiver unilateral.
pub struct ChannelFunding {
    /// The funding UTXO
    pub funding_utxo: Utxo,
    /// Sender's public key
    pub sender_pubkey: XOnlyPublicKey,
    /// Receiver's public key
    pub receiver_pubkey: XOnlyPublicKey,
    /// Revocation/challenge pubkey the receiver controls to slash a misbehaving sender
    pub sender_challenge_pubkey: XOnlyPublicKey,
    /// Revocation/challenge pubkey the sender controls to slash a misbehaving receiver
    pub receiver_challenge_pubkey: XOnlyPublicKey,
    /// Transaction ID of the funding transaction
    pub funding_txid: Txid,
    /// Cooperative close script (both parties sign, no timelock)
    pub cooperative_script: TapScriptBuf,
    /// Sender unilateral close script (sender signs after timelock)
    pub sender_unilateral_script: TapScriptBuf,
    /// Receiver unilateral close script (receiver signs after timelock)
    pub receiver_unilateral_script: TapScriptBuf,
    /// Sender challenge script (revocation spend controlled by receiver)
    pub sender_challenge_script: TapScriptBuf,
    /// Receiver challenge script (revocation spend controlled by sender)
    pub receiver_challenge_script: TapScriptBuf,
    /// Taproot spend info for witness construction (wrapped in Arc for sharing)
    pub spend_info: Arc<TrSpendInfo<XOnlyPublicKey>>,
    /// The Taproot address for the funding output
    pub funding_address: Address<NetworkUnchecked>,
    /// Timeout in blocks for unilateral close
    pub timeout_blocks: u16,
}

/// Revocation branch spend data needed to build sweep transactions
#[derive(Clone)]
pub struct RevocationSpendData {
    /// Script paying the receiver when the sender misbehaves
    pub sender_challenge_script: TapScriptBuf,
    /// Script paying the sender when the receiver misbehaves
    pub receiver_challenge_script: TapScriptBuf,
    /// Taproot spend info (used to derive control block for challenge leaves)
    pub spend_info: Arc<TrSpendInfo<XOnlyPublicKey>>,
}

impl ChannelFunding {
    /// Creates a new ChannelFunding from public keys and revocation secrets
    ///
    /// This generates the funding script and address but does not create
    /// the actual funding transaction. Use `build_funding_transaction()`
    /// to create the transaction.
    ///
    /// # Arguments
    /// * `sender_pubkey` - Sender's X-only public key
    /// * `receiver_pubkey` - Receiver's X-only public key
    /// * `sender_revocation_secret` - Sender's revocation secret (used to derive challenge pubkey)
    /// * `receiver_revocation_secret` - Receiver's revocation secret (used to derive challenge pubkey)
    /// * `network` - Bitcoin network
    ///
    /// # Returns
    /// A ChannelFunding struct with script and address prepared
    ///
    /// # Examples
    ///
    /// ```rust
    /// use merkle_morph::channel::ChannelFunding;
    /// use bitcoin::{
    ///     Network,
    ///     key::XOnlyPublicKey,
    ///     secp256k1::SecretKey,
    /// };
    ///
    /// let sender_sk =
    ///     SecretKey::from_secret_bytes([1u8; 32]).expect("32-byte array should always be a valid SecretKey");
    /// let receiver_sk =
    ///     SecretKey::from_secret_bytes([2u8; 32]).expect("32-byte array should always be a valid SecretKey");
    /// let sender_keypair = sender_sk.keypair();
    /// let (sender_pubkey_raw, _) = bitcoin::secp256k1::XOnlyPublicKey::from_keypair(&sender_keypair);
    /// let sender_pubkey = XOnlyPublicKey::from(sender_pubkey_raw);
    /// let receiver_keypair = receiver_sk.keypair();
    /// let (receiver_pubkey_raw, _) = bitcoin::secp256k1::XOnlyPublicKey::from_keypair(&receiver_keypair);
    /// let receiver_pubkey = XOnlyPublicKey::from(receiver_pubkey_raw);
    ///
    /// let sender_revocation_secret =
    ///     SecretKey::from_secret_bytes([3u8; 32]).expect("32-byte array should always be a valid SecretKey");
    /// let receiver_revocation_secret =
    ///     SecretKey::from_secret_bytes([4u8; 32]).expect("32-byte array should always be a valid SecretKey");
    ///
    /// let funding = ChannelFunding::new(
    ///     sender_pubkey,
    ///     receiver_pubkey,
    ///     sender_revocation_secret,
    ///     receiver_revocation_secret,
    ///     Network::Regtest,
    /// )
    /// .expect("channel funding creation should succeed for valid keys");
    /// ```
    pub fn new(
        sender_pubkey: XOnlyPublicKey,
        receiver_pubkey: XOnlyPublicKey,
        sender_revocation_secret: SecretKey,
        receiver_revocation_secret: SecretKey,
        network: Network,
    ) -> Result<Self> {
        Self::with_timeout(
            sender_pubkey,
            receiver_pubkey,
            sender_revocation_secret,
            receiver_revocation_secret,
            FORCE_CLOSE_TIMEOUT_BLOCKS,
            network,
        )
    }

    /// Creates a new ChannelFunding with a custom timeout
    ///
    /// # Arguments
    /// * `sender_pubkey` - Sender's X-only public key
    /// * `receiver_pubkey` - Receiver's X-only public key
    /// * `sender_revocation_secret` - Sender's revocation secret (used to derive challenge pubkey)
    /// * `receiver_revocation_secret` - Receiver's revocation secret (used to derive challenge pubkey)
    /// * `timeout_blocks` - Number of blocks for CSV timelock
    /// * `network` - Bitcoin network
    ///
    /// # Returns
    /// A ChannelFunding struct with miniscript-based scripts and address prepared
    pub fn with_timeout(
        sender_pubkey: XOnlyPublicKey,
        receiver_pubkey: XOnlyPublicKey,
        sender_revocation_secret: SecretKey,
        receiver_revocation_secret: SecretKey,
        timeout_blocks: u16,
        network: Network,
    ) -> Result<Self> {
        // Derive challenge pubkeys from revocation secrets
        let sender_challenge_pubkey = {
            let (xonly, _) = bitcoin::secp256k1::XOnlyPublicKey::from_keypair(
                &sender_revocation_secret.keypair(),
            );
            XOnlyPublicKey::from(xonly)
        };
        let receiver_challenge_pubkey = {
            let (xonly, _) = bitcoin::secp256k1::XOnlyPublicKey::from_keypair(
                &receiver_revocation_secret.keypair(),
            );
            XOnlyPublicKey::from(xonly)
        };

        let funding_info = build_funding_info(
            sender_pubkey,
            receiver_pubkey,
            timeout_blocks,
            network,
            sender_challenge_pubkey,
            receiver_challenge_pubkey,
        )?;

        let placeholder_utxo =
            Utxo::new(Txid::from_byte_array([0u8; 32]), 0, 0, funding_info.address);

        Ok(Self {
            funding_utxo: placeholder_utxo,
            sender_pubkey,
            receiver_pubkey,
            sender_challenge_pubkey,
            receiver_challenge_pubkey,
            funding_txid: Txid::from_byte_array([0u8; 32]), // Placeholder
            cooperative_script: funding_info.cooperative_script,
            sender_unilateral_script: funding_info.sender_unilateral_script,
            receiver_unilateral_script: funding_info.receiver_unilateral_script,
            sender_challenge_script: funding_info.sender_challenge_script,
            receiver_challenge_script: funding_info.receiver_challenge_script,
            spend_info: funding_info.spend_info,
            funding_address: funding_info.address,
            timeout_blocks,
        })
    }

    /// Updates the funding UTXO after the funding transaction is confirmed
    ///
    /// # Arguments
    /// * `txid` - Transaction ID of the funding transaction
    /// * `vout` - Output index of the funding output
    /// * `value` - Value of the funding UTXO in satoshis
    pub fn update_funding_utxo(&mut self, txid: Txid, vout: u32, value: u64) {
        self.funding_txid = txid;
        self.funding_utxo = Utxo::new(txid, vout, value, self.funding_address);
    }

    /// Returns the funding outpoint
    pub fn funding_outpoint(&self) -> bitcoin::OutPoint { self.funding_utxo.outpoint() }

    /// Returns the funding output value in satoshis
    pub fn funding_value(&self) -> u64 { self.funding_utxo.value }

    /// Returns the scriptPubKey locking the funding output
    pub fn funding_script_pubkey(&self) -> ScriptPubKeyBuf { self.funding_utxo.script_pubkey() }

    /// Returns the revocation spend data (scripts + spend info) for sweeps
    pub fn revocation_spend_data(&self) -> RevocationSpendData {
        RevocationSpendData {
            sender_challenge_script: self.sender_challenge_script.clone(),
            receiver_challenge_script: self.receiver_challenge_script.clone(),
            spend_info: self.spend_info.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::test_utils::{revocation_secrets, test_keys_miniscript};

    #[test]
    fn test_new() {
        let (sender_pubkey, receiver_pubkey) = test_keys_miniscript();
        let (sender_revocation_secret, receiver_revocation_secret) = revocation_secrets();

        let funding = ChannelFunding::new(
            sender_pubkey,
            receiver_pubkey,
            sender_revocation_secret,
            receiver_revocation_secret,
            Network::Regtest,
        )
        .expect("channel funding creation should succeed");

        assert_eq!(funding.timeout_blocks, FORCE_CLOSE_TIMEOUT_BLOCKS);
    }

    #[test]
    fn test_with_timeout() {
        let (sender_pubkey, receiver_pubkey) = test_keys_miniscript();
        let (sender_revocation_secret, receiver_revocation_secret) = revocation_secrets();
        let timeout_blocks = 5u16;

        let funding = ChannelFunding::with_timeout(
            sender_pubkey,
            receiver_pubkey,
            sender_revocation_secret,
            receiver_revocation_secret,
            timeout_blocks,
            Network::Regtest,
        )
        .expect("channel funding creation should succeed");

        assert_eq!(funding.timeout_blocks, timeout_blocks);
    }

    #[test]
    fn test_update_funding_utxo() {
        let (sender_pubkey, receiver_pubkey) = test_keys_miniscript();
        let (sender_revocation_secret, receiver_revocation_secret) = revocation_secrets();
        let mut funding = ChannelFunding::with_timeout(
            sender_pubkey,
            receiver_pubkey,
            sender_revocation_secret,
            receiver_revocation_secret,
            1,
            Network::Regtest,
        )
        .expect("channel funding creation should succeed");
        let txid = Txid::from_byte_array([1u8; 32]);
        let vout = 0u32;
        let value = 1000u64;

        funding.update_funding_utxo(txid, vout, value);

        assert_eq!(funding.funding_txid, txid);
        assert_eq!(funding.funding_utxo.txid, txid);
        assert_eq!(funding.funding_utxo.index, vout);
        assert_eq!(funding.funding_utxo.value, value);
    }

    #[test]
    fn test_funding_outpoint() {
        let (sender_pubkey, receiver_pubkey) = test_keys_miniscript();
        let (sender_revocation_secret, receiver_revocation_secret) = revocation_secrets();
        let funding = ChannelFunding::with_timeout(
            sender_pubkey,
            receiver_pubkey,
            sender_revocation_secret,
            receiver_revocation_secret,
            1,
            Network::Regtest,
        )
        .expect("channel funding creation should succeed");

        let outpoint = funding.funding_outpoint();

        assert_eq!(outpoint.txid, Txid::from_byte_array([0u8; 32]));
        assert_eq!(outpoint.vout, 0u32);
    }

    #[test]
    fn test_funding_value() {
        let (sender_pubkey, receiver_pubkey) = test_keys_miniscript();
        let (sender_revocation_secret, receiver_revocation_secret) = revocation_secrets();

        let funding = ChannelFunding::with_timeout(
            sender_pubkey,
            receiver_pubkey,
            sender_revocation_secret,
            receiver_revocation_secret,
            1,
            Network::Regtest,
        )
        .expect("channel funding creation should succeed");

        assert_eq!(funding.funding_value(), 0u64);
    }

    #[test]
    fn test_funding_script_pubkey() {
        let (sender_pubkey, receiver_pubkey) = test_keys_miniscript();
        let (sender_revocation_secret, receiver_revocation_secret) = revocation_secrets();
        let funding = ChannelFunding::with_timeout(
            sender_pubkey,
            receiver_pubkey,
            sender_revocation_secret,
            receiver_revocation_secret,
            1,
            Network::Regtest,
        )
        .expect("channel funding creation should succeed");

        let script_pubkey = funding.funding_script_pubkey();

        assert_eq!(script_pubkey, funding.funding_utxo.script_pubkey());
    }

    #[test]
    fn test_revocation_spend_data() {
        let (sender_pubkey, receiver_pubkey) = test_keys_miniscript();
        let (sender_revocation_secret, receiver_revocation_secret) = revocation_secrets();
        let funding = ChannelFunding::with_timeout(
            sender_pubkey,
            receiver_pubkey,
            sender_revocation_secret,
            receiver_revocation_secret,
            1,
            Network::Regtest,
        )
        .expect("channel funding creation should succeed");

        let data = funding.revocation_spend_data();

        assert_eq!(data.sender_challenge_script, funding.sender_challenge_script);
        assert_eq!(data.receiver_challenge_script, funding.receiver_challenge_script);
    }
}
