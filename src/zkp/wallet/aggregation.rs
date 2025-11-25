#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
//! Wallet-level proof aggregation
//!
//! This module provides functions for aggregating channel proofs
//! at the wallet level. It verifies that channel commitments are correctly
//! aggregated into wallet commitments.

use std::collections::BTreeMap;

use crate::errors::Result;
use crate::errors::ZkpError::InvalidAir;
use crate::types::{ChannelId, WalletCommitment};
use crate::wallet::{compute_commitment, WalletState};
use crate::zkp::types::{Proof, StarkConfig};
use crate::zkp::{verify_channel_transition, ChannelPublicInputs};

/// Verify channel proofs and aggregate them into wallet commitment
///
/// This function:
/// 1. Verifies that every channel proof is for a channel that exists in the wallet
/// 2. Verifies that every channel in the wallet has a corresponding proof
/// 3. For each channel in the wallet (and its corresponding proof):
///    - Verifies the proof using [`verify_channel_transition`], which ensures:
///      - The proof is valid for the channel_id (the map key)
///      - The proof's commitment matches the wallet's stored channel commitment
///
/// This function verifies that channel proofs are valid and correctly aggregate.
/// To verify that the wallet commitment matches an expected value (e.g., from global state),
/// use [`verify_channel_aggregation_commitment`] instead.
///
/// # Arguments
/// * `config` - STARK configuration for proof verification
/// * `wallet` - Wallet containing channel commitments
/// * `proofs` - Map of channel IDs to their proofs
///
/// # Returns
/// Ok if all verifications pass, Err otherwise
pub fn verify_channel_aggregation(
    config: &StarkConfig,
    wallet: &WalletState,
    proofs: &BTreeMap<ChannelId, Proof>,
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
    }

    // Verify each proof individually
    for channel_id in wallet.channels.keys() {
        let proof = proofs.get(channel_id).ok_or(InvalidAir)?;
        let channel_commitment = wallet.channels.get(channel_id).ok_or(InvalidAir)?;

        let public_inputs = ChannelPublicInputs {
            channel_id: *channel_id,
            channel_commitment: *channel_commitment,
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
/// * `expected_wallet_commitment` - Expected wallet commitment to verify against
///
/// # Returns
/// Ok if all verifications pass, Err otherwise
pub fn verify_channel_aggregation_commitment(
    config: &StarkConfig,
    wallet: &WalletState,
    proofs: &BTreeMap<ChannelId, Proof>,
    expected_wallet_commitment: WalletCommitment,
) -> Result<()> {
    verify_channel_aggregation(config, wallet, proofs)?;

    // Verify wallet commitment matches expected value
    let computed = compute_commitment(wallet)?;
    if computed != expected_wallet_commitment {
        return Err(InvalidAir.into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::channel::commitment::compute_commitment as compute_channel_commitment;
    use crate::channel::state::ChannelState;
    use crate::channel::transition::apply_transfer_state_only;
    use crate::channel::TransferAmount;
    use crate::wallet::state::WalletState;
    use crate::zkp::prove_channel_transition;
    use crate::zkp::types::create_config;

    /// Helper function to create a wallet with channels and their proofs
    fn create_test_wallet_with_proofs(
        config: &StarkConfig,
        num_channels: usize,
    ) -> (WalletState, BTreeMap<ChannelId, Proof>, BTreeMap<ChannelId, ChannelState>) {
        let wallet_id = [1u8; 32];
        let mut channels = BTreeMap::new();
        let mut proofs = BTreeMap::new();
        let mut channel_states = BTreeMap::new();

        for i in 0..num_channels {
            let channel_id = {
                let mut id = [0u8; 32];
                id[0] = i as u8;
                id
            };

            // Create initial state and apply a transfer
            let old_state = ChannelState::new(1000);
            let amount = TransferAmount::new(100 + i as u64).expect("valid transfer");
            let new_state = apply_transfer_state_only(&old_state, &amount)
                .expect("Valid transfer should succeed");

            // Compute channel commitment
            let channel_commitment = compute_channel_commitment(channel_id, &new_state);

            // Generate proof
            let proof =
                prove_channel_transition(config, channel_id, &old_state, &amount, &new_state)
                    .expect("Should generate proof");

            channels.insert(channel_id, channel_commitment);
            proofs.insert(channel_id, proof);
            channel_states.insert(channel_id, new_state);
        }

        let wallet = WalletState::from_channels(wallet_id, channels);
        (wallet, proofs, channel_states)
    }

    #[test]
    fn test_verify_channel_aggregation_single_channel() {
        let config = create_config().expect("Should create config");
        let (wallet, proofs, _) = create_test_wallet_with_proofs(&config, 1);

        let result = verify_channel_aggregation(&config, &wallet, &proofs);
        assert!(result.is_ok(), "Single channel aggregation should succeed");
    }

    #[test]
    fn test_verify_channel_aggregation_multiple_channels() {
        let config = create_config().expect("Should create config");
        let (wallet, proofs, _) = create_test_wallet_with_proofs(&config, 3);

        let result = verify_channel_aggregation(&config, &wallet, &proofs);
        assert!(result.is_ok(), "Multiple channel aggregation should succeed");
    }

    #[test]
    fn test_verify_channel_aggregation_empty_wallet() {
        let config = create_config().expect("Should create config");
        let wallet = WalletState::new([1u8; 32]);
        let proofs = BTreeMap::new();

        let result = verify_channel_aggregation(&config, &wallet, &proofs);
        assert!(result.is_ok(), "Empty wallet should succeed");
    }

    #[test]
    fn test_verify_channel_aggregation_proof_for_nonexistent_channel() {
        let config = create_config().expect("Should create config");
        let (wallet, mut proofs, _) = create_test_wallet_with_proofs(&config, 2);

        // Add a proof for a channel that doesn't exist in the wallet
        // We'll create a fake proof by generating one for a different channel
        let nonexistent_channel_id = [255u8; 32];
        let fake_old_state = ChannelState::new(500);
        let fake_amount = TransferAmount::new(50).expect("valid transfer");
        let fake_new_state = apply_transfer_state_only(&fake_old_state, &fake_amount)
            .expect("Valid transfer should succeed");
        let fake_proof = prove_channel_transition(
            &config,
            nonexistent_channel_id,
            &fake_old_state,
            &fake_amount,
            &fake_new_state,
        )
        .expect("Should generate proof");
        proofs.insert(nonexistent_channel_id, fake_proof);

        let result = verify_channel_aggregation(&config, &wallet, &proofs);
        assert!(result.is_err(), "Should fail when proof exists for channel not in wallet");
        assert!(matches!(
            result.expect_err("Expected error for nonexistent channel"),
            crate::errors::Error::Zkp(crate::errors::ZkpError::InvalidAir)
        ));
    }

    #[test]
    fn test_verify_channel_aggregation_missing_proof() {
        let config = create_config().expect("Should create config");
        let (wallet, mut proofs, _) = create_test_wallet_with_proofs(&config, 3);

        // Remove one proof
        let first_channel_id =
            *wallet.channels.keys().next().expect("Wallet should have at least one channel");
        proofs.remove(&first_channel_id);

        let result = verify_channel_aggregation(&config, &wallet, &proofs);
        assert!(result.is_err(), "Should fail when channel in wallet has no proof");
        assert!(matches!(
            result.expect_err("Expected error for missing proof"),
            crate::errors::Error::Zkp(crate::errors::ZkpError::InvalidAir)
        ));
    }

    #[test]
    fn test_verify_channel_aggregation_wrong_proof_channel_id() {
        let config = create_config().expect("Should create config");
        let (wallet, mut proofs, _) = create_test_wallet_with_proofs(&config, 2);

        // Get channel IDs
        let channel_ids: Vec<_> = wallet.channels.keys().collect();
        let channel_id_1 = *channel_ids[0];
        let channel_id_2 = *channel_ids[1];

        // Remove the correct proof for channel_2
        proofs.remove(&channel_id_2);

        // Create a proof for channel_1 (with channel_1's commitment from wallet)
        // but try to use it for channel_2 (wrong channel_id)
        // We'll create a proof that matches channel_1's state but use it for channel_2
        let _channel_1_commitment =
            *wallet.channels.get(&channel_id_1).expect("Channel 1 should exist in wallet");
        // We need to create a state that produces this commitment
        // For simplicity, let's just create a proof for channel_1 and use it incorrectly
        let old_state_1 = ChannelState::new(1000);
        let amount_1 = TransferAmount::new(100).expect("valid transfer");
        let new_state_1 = apply_transfer_state_only(&old_state_1, &amount_1)
            .expect("Valid transfer should succeed");
        // Generate proof for channel_1
        let proof_for_channel_1 =
            prove_channel_transition(&config, channel_id_1, &old_state_1, &amount_1, &new_state_1)
                .expect("Should generate proof");
        // Use it for channel_2 (wrong channel_id) - this should fail
        proofs.insert(channel_id_2, proof_for_channel_1);

        let result = verify_channel_aggregation(&config, &wallet, &proofs);
        assert!(result.is_err(), "Should fail when proof is for wrong channel_id");
    }

    #[test]
    fn test_verify_channel_aggregation_wrong_proof_commitment() {
        let config = create_config().expect("Should create config");
        let (mut wallet, proofs, _) = create_test_wallet_with_proofs(&config, 2);

        // Change a channel commitment in the wallet to mismatch the proof
        let first_channel_id =
            *wallet.channels.keys().next().expect("Wallet should have at least one channel");
        wallet.channels.insert(first_channel_id, [255u8; 32]);

        let result = verify_channel_aggregation(&config, &wallet, &proofs);
        assert!(result.is_err(), "Should fail when wallet commitment doesn't match proof");
    }

    #[test]
    fn test_verify_channel_aggregation_commitment_success() {
        let config = create_config().expect("Should create config");
        let (wallet, proofs, _) = create_test_wallet_with_proofs(&config, 2);

        let expected_commitment =
            crate::wallet::compute_commitment(&wallet).expect("should compute commitment");

        let result =
            verify_channel_aggregation_commitment(&config, &wallet, &proofs, expected_commitment);
        assert!(result.is_ok(), "Should succeed when proofs are valid and commitment matches");
    }

    #[test]
    fn test_verify_channel_aggregation_commitment_wrong_commitment() {
        let config = create_config().expect("Should create config");
        let (wallet, proofs, _) = create_test_wallet_with_proofs(&config, 2);

        let wrong_commitment = [255u8; 32];

        let result =
            verify_channel_aggregation_commitment(&config, &wallet, &proofs, wrong_commitment);
        assert!(result.is_err(), "Should fail when commitment doesn't match expected value");
        assert!(matches!(
            result.expect_err("Expected error for wrong commitment"),
            crate::errors::Error::Zkp(crate::errors::ZkpError::InvalidAir)
        ));
    }

    #[test]
    fn test_verify_channel_aggregation_commitment_invalid_proofs() {
        let config = create_config().expect("Should create config");
        let (mut wallet, proofs, _) = create_test_wallet_with_proofs(&config, 2);

        // Corrupt wallet to make proofs invalid
        let first_channel_id =
            *wallet.channels.keys().next().expect("Wallet should have at least one channel");
        wallet.channels.insert(first_channel_id, [255u8; 32]);

        let expected_commitment =
            crate::wallet::compute_commitment(&wallet).expect("should compute commitment");

        // Should fail at proof verification stage, before checking commitment
        let result =
            verify_channel_aggregation_commitment(&config, &wallet, &proofs, expected_commitment);
        assert!(result.is_err(), "Should fail when proofs are invalid, even if commitment matches");
    }

    #[test]
    fn test_verify_channel_aggregation_large_wallet() {
        let config = create_config().expect("Should create config");
        // Test with a larger number of channels
        let (wallet, proofs, _) = create_test_wallet_with_proofs(&config, 5);

        let result = verify_channel_aggregation(&config, &wallet, &proofs);
        assert!(result.is_ok(), "Large wallet aggregation should succeed");
    }

    #[test]
    fn test_verify_channel_aggregation_all_channels_verified() {
        let config = create_config().expect("Should create config");
        let (wallet, proofs, _) = create_test_wallet_with_proofs(&config, 4);

        // Verify that all channels are checked
        let result = verify_channel_aggregation(&config, &wallet, &proofs);
        assert!(result.is_ok());

        // Verify that the number of proofs matches the number of channels
        assert_eq!(wallet.channels.len(), proofs.len());

        // Verify that all channel IDs in wallet have corresponding proofs
        for channel_id in wallet.channels.keys() {
            assert!(proofs.contains_key(channel_id), "Every channel in wallet should have a proof");
        }

        // Verify that all proofs correspond to channels in wallet
        for channel_id in proofs.keys() {
            assert!(
                wallet.channels.contains_key(channel_id),
                "Every proof should correspond to a channel in wallet"
            );
        }
    }

    #[test]
    fn test_verify_channel_aggregation_commitment_computed_correctly() {
        let config = create_config().expect("Should create config");
        let (wallet, proofs, _) = create_test_wallet_with_proofs(&config, 3);

        // Compute commitment directly
        let computed =
            crate::wallet::compute_commitment(&wallet).expect("should compute commitment");

        // Verify with the computed commitment
        let result = verify_channel_aggregation_commitment(&config, &wallet, &proofs, computed);
        assert!(result.is_ok(), "Computed commitment should match");

        // Verify with a different commitment fails
        let mut wrong_commitment = computed;
        wrong_commitment[0] ^= 1;
        let result =
            verify_channel_aggregation_commitment(&config, &wallet, &proofs, wrong_commitment);
        assert!(result.is_err(), "Wrong commitment should fail");
    }
}
