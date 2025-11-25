#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
//! Wallet commitment computation
//!
//! This module provides functions for computing wallet commitments as hash chains
//! from channel commitments. Wallet commitments aggregate multiple channel commitments
//! under a single wallet identifier, enabling efficient verification of wallet state.
//!
//! The commitment computation uses a deterministic hash chain:
//! 1. Initialize with wallet ID: `poseidon2("MM_WLT_INIT_v0" || wallet_id)`
//! 2. For each channel (in sorted order): hash channel ID and commitment
//! 3. Accumulate using chain domain: `poseidon2("MM_CHAIN_v0" || accumulator || hash)`
//!
//! This ensures that:
//! - Empty wallets have a deterministic commitment based on wallet ID
//! - Channel order is deterministic (sorted by channel ID)
//! - The commitment can be verified in zero-knowledge proofs

use std::collections::BTreeMap;

use crate::errors::Result;
use crate::types::{
    Bytes32, ChannelCommitment, ChannelId, WalletCommitment, WalletId, CHAIN_DOMAIN,
    WALLET_HASH_DOMAIN, WALLET_INIT_DOMAIN,
};
use crate::wallet::state::WalletState;
use crate::zkp::{poseidon2_hash_fixed, MAX_CHANNELS};

/// Computes commitment from wallet_id and a map of channel commitments
///
/// Channels are processed in sorted order by channel_id to match trace generation.
/// Returns an error if the wallet has more than MAX_CHANNELS channels.
///
/// The commitment is computed by:
/// 1. Initialize accumulator with:
///    poseidon2("MM_WLT_INIT_v0" || wallet_id)
///
/// 2. For each channel compute:
///    poseidon2("MM_WLT_HASH_v0" || channel_id || channel_commitment)
///
/// 3. Accumulate all hashes using:
///    poseidon2("MM_CHAIN_v0" || accumulator || hash)
///
/// Empty wallets have commitment = poseidon2("MM_WLT_INIT_v0" || wallet_id).
pub fn compute_commitment_from_channels(
    wallet_id: WalletId,
    channels: &BTreeMap<ChannelId, ChannelCommitment>,
) -> Result<WalletCommitment> {
    // Initialize accumulator with wallet_id
    let mut accumulator: Bytes32 = poseidon2_hash_fixed(&[WALLET_INIT_DOMAIN, &wallet_id[..]]);

    let mut sorted_channels: Vec<_> = channels.iter().collect();
    sorted_channels.sort_by_key(|(id, _)| *id);

    if sorted_channels.len() > MAX_CHANNELS {
        return Err(crate::errors::Error::Zkp(crate::errors::ZkpError::TraceGenerationFailed(
            format!(
                "Wallet has {} channels, but maximum supported is {}",
                sorted_channels.len(),
                MAX_CHANNELS
            ),
        )));
    }

    for (channel_id, channel_commitment) in sorted_channels.iter() {
        let hash: Bytes32 =
            poseidon2_hash_fixed(&[WALLET_HASH_DOMAIN, &channel_id[..], &channel_commitment[..]]);
        accumulator = compute_update(accumulator, &hash);
    }

    Ok(accumulator)
}

/// Computes the wallet commitment (hash chain) from channel commitments
///
/// This is a convenience function that delegates to `compute_commitment_from_channels`.
pub fn compute_commitment(wallet: &WalletState) -> Result<WalletCommitment> {
    compute_commitment_from_channels(wallet.id, &wallet.channels)
}

/// Computes the next accumulator state given prior state and new input
/// Uses domain separation with tag "MM_CHAIN_v0"
pub(crate) fn compute_update(prior_state: Bytes32, new_input: &Bytes32) -> Bytes32 {
    poseidon2_hash_fixed(&[CHAIN_DOMAIN, &prior_state[..], &new_input[..]])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zkp::MAX_CHANNELS;

    #[test]
    fn test_compute_commitment_empty() {
        let wallet = WalletState::default();
        let commitment = compute_commitment(&wallet).expect("should compute commitment");
        // Empty wallet commitment is hash(wallet_id), not zero
        let expected = poseidon2_hash_fixed(&[WALLET_INIT_DOMAIN, &wallet.id[..]]);
        assert_eq!(commitment, expected);
    }

    #[test]
    fn test_compute_commitment_single_channel() {
        let mut channels = BTreeMap::new();
        channels.insert([1u8; 32], [2u8; 32]);
        let wallet = WalletState::from_channels([0u8; 32], channels);

        let commitment = compute_commitment(&wallet).expect("should compute commitment");
        assert_ne!(commitment, [0u8; 32]);
    }

    #[test]
    fn test_compute_commitment_multiple_channels() {
        let mut channels1 = BTreeMap::new();
        channels1.insert([1u8; 32], [2u8; 32]);
        let wallet1 = WalletState::from_channels([0u8; 32], channels1);

        let mut channels2 = BTreeMap::new();
        channels2.insert([1u8; 32], [2u8; 32]);
        channels2.insert([3u8; 32], [4u8; 32]);
        let wallet2 = WalletState::from_channels([0u8; 32], channels2);

        let commitment1 = compute_commitment(&wallet1).expect("should compute commitment");
        let commitment2 = compute_commitment(&wallet2).expect("should compute commitment");

        // Different number of channels produces different commitment
        assert_ne!(commitment1, commitment2);
    }

    #[test]
    fn test_compute_update() {
        // Test basic functionality
        let prior_state = [0u8; 32];
        let new_input = &[1u8; 32];
        let updated_state = compute_update(prior_state, new_input);

        // New state should be different from old state
        assert_ne!(updated_state, prior_state);

        // Test same inputs produce same output
        let same_inputs = compute_update(prior_state, new_input);
        assert_eq!(updated_state, same_inputs);

        // Test a different input produces a different output
        let different_input = &[2u8; 32];
        let different_result = compute_update(prior_state, different_input);
        assert_ne!(updated_state, different_result);

        // Test different prior state produces a different output
        let different_prior_state = [1u8; 32];
        let different_prior_result = compute_update(different_prior_state, new_input);
        assert_ne!(updated_state, different_prior_result);

        // Test with zero input (should still produce different output)
        let zero_input = &[0u8; 32];
        let zero_result = compute_update(prior_state, zero_input);
        assert_ne!(updated_state, zero_result);
    }

    #[test]
    fn test_compute_commitment() {
        let wallet_id = [0u8; 32];

        // Test empty wallet - commitment should be hash(wallet_id)
        let empty = WalletState::from_channels(wallet_id, BTreeMap::new());
        let expected_empty = poseidon2_hash_fixed(&[WALLET_INIT_DOMAIN, &wallet_id[..]]);
        assert_eq!(compute_commitment(&empty).expect("should compute commitment"), expected_empty);

        // Test wallet with a single channel
        let mut channels = BTreeMap::new();
        channels.insert([1u8; 32], [2u8; 32]);
        let single_channel = WalletState::from_channels(wallet_id, channels);
        assert_ne!(
            compute_commitment(&single_channel).expect("should compute commitment"),
            [0u8; 32]
        );

        // Test wallet with multiple channels
        let mut channels = BTreeMap::new();
        channels.insert([1u8; 32], [2u8; 32]);
        channels.insert([3u8; 32], [4u8; 32]);
        let multi_channel = WalletState::from_channels(wallet_id, channels);
        assert_ne!(
            compute_commitment(&multi_channel).expect("should compute commitment"),
            [0u8; 32]
        );
        assert_ne!(
            compute_commitment(&multi_channel).expect("should compute commitment"),
            compute_commitment(&single_channel).expect("should compute commitment")
        );
    }

    #[test]
    fn test_compute_commitment_from_channels_rejects_excess_channels() {
        let wallet_id = [0u8; 32];
        let mut channels = BTreeMap::new();
        for idx in 0..=MAX_CHANNELS {
            let mut channel_id = [0u8; 32];
            channel_id[31] = idx as u8;
            let mut commitment = [0u8; 32];
            commitment[31] = idx as u8;
            channels.insert(channel_id, commitment);
        }

        let result = compute_commitment_from_channels(wallet_id, &channels);
        assert!(matches!(
            result,
            Err(crate::errors::Error::Zkp(crate::errors::ZkpError::TraceGenerationFailed(_)))
        ));
    }
}
