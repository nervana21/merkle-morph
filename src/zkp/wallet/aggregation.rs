//! Wallet-level proof aggregation
//!
//! This module provides functions for aggregating channel proofs
//! at the wallet level. It verifies that channel commitments are correctly
//! aggregated into wallet commitments.

use std::collections::BTreeMap;

use bitcoin::secp256k1::XOnlyPublicKey;

use crate::errors::ZkpError::InvalidAir;
use crate::types::{ChannelId, WalletCommitment};
use crate::wallet::commitment::compute_commitment_from_channels;
use crate::wallet::WalletState;
use crate::zkp::types::{Proof, StarkConfig};
use crate::zkp::{verify_channel_transition, ChannelPublicInputs};
use crate::Result;

/// Verify channel proofs and aggregate them into wallet commitment
///
/// This function:
/// 1. Verifies that every channel proof is for a channel that exists in the wallet
/// 2. Verifies that every channel in the wallet has a corresponding proof
/// 3. For each channel in the wallet (and its corresponding proof):
///    - Verifies the proof using [`verify_channel_transition`], which ensures:
///      - The proof is valid for the channel_id (the map key)
///      - The proof's commitment matches the wallet's stored channel commitment
///      - The proof's sender authentication is valid
///
/// This function verifies that channel proofs are valid and correctly aggregate.
/// To verify that the wallet commitment matches an expected value (e.g., from global state),
/// use [`verify_channel_aggregation_commitment`] instead.
///
/// # Arguments
/// * `config` - STARK configuration for proof verification
/// * `wallet` - Wallet containing channel commitments
/// * `proofs` - Map of channel IDs to their proofs
/// * `sender_pubkeys` - Map of channel IDs to sender public keys for authentication verification
///
/// # Returns
/// Ok if all verifications pass, Err otherwise
pub fn verify_channel_aggregation(
    config: &StarkConfig,
    wallet: &WalletState,
    proofs: &BTreeMap<ChannelId, Proof>,
    sender_pubkeys: &BTreeMap<ChannelId, XOnlyPublicKey>,
) -> Result<()> {
    // Verify that all channel proofs correspond to channels in the wallet
    for channel_id in proofs.keys() {
        if !wallet.channels.contains_key(channel_id) {
            return Err(InvalidAir.into());
        }
    }

    // Verify that all channels in the wallet have proofs
    for channel_id in wallet.channels.keys() {
        if !proofs.contains_key(channel_id) {
            return Err(InvalidAir.into());
        }
        if !sender_pubkeys.contains_key(channel_id) {
            return Err(InvalidAir.into());
        }
    }

    // Verify each proof individually
    for channel_id in wallet.channels.keys() {
        let proof = proofs.get(channel_id).ok_or(InvalidAir)?;
        let channel_commitment = wallet.channels.get(channel_id).ok_or(InvalidAir)?;
        let sender_pubkey = sender_pubkeys.get(channel_id).ok_or(InvalidAir)?;

        let public_inputs = ChannelPublicInputs {
            channel_id: *channel_id,
            channel_commitment: *channel_commitment,
            sender_pubkey: *sender_pubkey,
        };

        verify_channel_transition(config, &public_inputs, proof)?;
    }

    Ok(())
}

/// Verify channel proofs and check wallet commitment against expected value
///
/// This is a convenience wrapper around [`verify_channel_aggregation`] that also
/// verifies the computed wallet commitment matches an expected value. This is useful
/// when verifying wallet proofs in the context of global state, where the wallet
/// commitment must match what's stored in the global state registry.
///
/// # Arguments
/// * `config` - STARK configuration for proof verification
/// * `wallet` - Wallet containing channel commitments
/// * `proofs` - Map of channel IDs to their proofs
/// * `sender_pubkeys` - Map of channel IDs to sender public keys for authentication verification
/// * `expected_wallet_commitment` - Expected wallet commitment to verify against
///
/// # Returns
/// Ok if all verifications pass, Err otherwise
pub fn verify_channel_aggregation_commitment(
    config: &StarkConfig,
    wallet: &WalletState,
    proofs: &BTreeMap<ChannelId, Proof>,
    sender_pubkeys: &BTreeMap<ChannelId, XOnlyPublicKey>,
    expected_wallet_commitment: WalletCommitment,
) -> Result<()> {
    verify_channel_aggregation(config, wallet, proofs, sender_pubkeys)?;

    // Verify wallet commitment matches expected value
    let computed = compute_commitment_from_channels(wallet.id, &wallet.channels)?;
    if computed != expected_wallet_commitment {
        return Err(InvalidAir.into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use bitcoin::secp256k1::SecretKey;

    use super::*;
    use crate::channel::commitment::state_commitment::compute_open_commitment;
    use crate::channel::state::Open;
    use crate::channel::test_utils::{revocation_secrets, test_keys};
    use crate::channel::transition::transfer::apply_transfer_state_only;
    use crate::channel::TransferAmount;
    use crate::wallet::state::WalletState;
    use crate::zkp::prove_channel_transition;
    use crate::zkp::types::create_config;

    #[test]
    fn test_verify_channel_aggregation() {
        let config = create_config().expect("Should create config");
        let (sender_pubkey, receiver_pubkey) = test_keys();
        let sender_sk = SecretKey::from_slice(&[1u8; 32])
            .expect("32-byte array should always be a valid SecretKey");
        let wallet_id = [1u8; 32];
        let channel_id = [0u8; 32];
        let (sender_revocation_secret, receiver_revocation_secret) = revocation_secrets();
        let old_state = Open::new(
            sender_pubkey,
            receiver_pubkey,
            1000,
            sender_revocation_secret,
            receiver_revocation_secret,
        );
        let amount = TransferAmount::new(100).expect("valid transfer");
        let new_state =
            apply_transfer_state_only(&old_state, &amount).expect("Valid transfer should succeed");
        let channel_commitment = compute_open_commitment(channel_id, &new_state);
        let mut channels = BTreeMap::new();
        channels.insert(channel_id, channel_commitment);
        let wallet = WalletState::from_channels(wallet_id, channels);
        let mut sender_pubkeys = BTreeMap::new();
        sender_pubkeys.insert(channel_id, sender_pubkey);
        let empty_wallet = WalletState::new([2u8; 32]);
        let empty_proofs = BTreeMap::new();
        let empty_sender_pubkeys = BTreeMap::new();

        assert!(verify_channel_aggregation(
            &config,
            &empty_wallet,
            &empty_proofs,
            &empty_sender_pubkeys
        )
        .is_ok());

        let nonexistent_channel_id = [255u8; 32];
        let proof_nonexistent = prove_channel_transition(
            nonexistent_channel_id,
            &old_state,
            &amount,
            &new_state,
            &sender_sk,
            &config,
        )
        .expect("Should generate proof");
        let mut proofs_with_nonexistent = BTreeMap::new();
        proofs_with_nonexistent.insert(nonexistent_channel_id, proof_nonexistent);
        let mut sender_pubkeys_with_nonexistent = BTreeMap::new();
        sender_pubkeys_with_nonexistent.insert(nonexistent_channel_id, sender_pubkey);

        assert!(verify_channel_aggregation(
            &config,
            &wallet,
            &proofs_with_nonexistent,
            &sender_pubkeys_with_nonexistent
        )
        .is_err());

        let proofs_missing = BTreeMap::new();

        assert!(
            verify_channel_aggregation(&config, &wallet, &proofs_missing, &sender_pubkeys).is_err()
        );

        let sender_pubkeys_missing = BTreeMap::new();
        let proof_missing_pubkey = prove_channel_transition(
            channel_id, &old_state, &amount, &new_state, &sender_sk, &config,
        )
        .expect("Should generate proof");
        let mut proofs_for_missing_pubkey = BTreeMap::new();
        proofs_for_missing_pubkey.insert(channel_id, proof_missing_pubkey);

        assert!(verify_channel_aggregation(
            &config,
            &wallet,
            &proofs_for_missing_pubkey,
            &sender_pubkeys_missing
        )
        .is_err());

        let mut channels_wrong = BTreeMap::new();
        channels_wrong.insert(channel_id, [255u8; 32]);
        let wallet_wrong_commitment = WalletState::from_channels(wallet_id, channels_wrong);

        let proof_wrong_commitment = prove_channel_transition(
            channel_id, &old_state, &amount, &new_state, &sender_sk, &config,
        )
        .expect("Should generate proof");

        let mut proofs_for_wrong_commitment = BTreeMap::new();
        proofs_for_wrong_commitment.insert(channel_id, proof_wrong_commitment);

        assert!(verify_channel_aggregation(
            &config,
            &wallet_wrong_commitment,
            &proofs_for_wrong_commitment,
            &sender_pubkeys
        )
        .is_err());

        let proof_valid = prove_channel_transition(
            channel_id, &old_state, &amount, &new_state, &sender_sk, &config,
        )
        .expect("Should generate proof");
        let mut proofs_valid = BTreeMap::new();
        proofs_valid.insert(channel_id, proof_valid);

        assert!(
            verify_channel_aggregation(&config, &wallet, &proofs_valid, &sender_pubkeys).is_ok()
        );
    }

    #[test]
    fn test_verify_channel_aggregation_commitment() {
        let config = create_config().expect("Should create config");
        let (sender_pubkey, receiver_pubkey) = test_keys();
        let sender_sk = SecretKey::from_slice(&[1u8; 32])
            .expect("32-byte array should always be a valid SecretKey");
        let wallet_id = [1u8; 32];
        let channel_id = [0u8; 32];
        let (sender_revocation_secret, receiver_revocation_secret) = revocation_secrets();
        let old_state = Open::new(
            sender_pubkey,
            receiver_pubkey,
            1000,
            sender_revocation_secret,
            receiver_revocation_secret,
        );
        let amount = TransferAmount::new(100).expect("valid transfer");
        let new_state =
            apply_transfer_state_only(&old_state, &amount).expect("Valid transfer should succeed");
        let channel_commitment = compute_open_commitment(channel_id, &new_state);
        let proof = prove_channel_transition(
            channel_id, &old_state, &amount, &new_state, &sender_sk, &config,
        )
        .expect("Should generate proof");
        let mut channels = BTreeMap::new();
        channels.insert(channel_id, channel_commitment);
        let wallet = WalletState::from_channels(wallet_id, channels);
        let mut proofs = BTreeMap::new();
        proofs.insert(channel_id, proof);
        let mut sender_pubkeys = BTreeMap::new();
        sender_pubkeys.insert(channel_id, sender_pubkey);
        let expected_commitment = compute_commitment_from_channels(wallet.id, &wallet.channels)
            .expect("should compute commitment");
        let proofs_missing = BTreeMap::new();

        assert!(verify_channel_aggregation_commitment(
            &config,
            &wallet,
            &proofs_missing,
            &sender_pubkeys,
            expected_commitment
        )
        .is_err());

        let wrong_commitment = [255u8; 32];

        assert!(verify_channel_aggregation_commitment(
            &config,
            &wallet,
            &proofs,
            &sender_pubkeys,
            wrong_commitment
        )
        .is_err());

        assert!(verify_channel_aggregation_commitment(
            &config,
            &wallet,
            &proofs,
            &sender_pubkeys,
            expected_commitment
        )
        .is_ok());
    }
}
