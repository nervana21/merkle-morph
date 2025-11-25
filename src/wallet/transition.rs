#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
//! Wallet state transition logic
//!
//! This module provides pure functions for applying state transitions to wallets.
//! All transition logic is deterministic and side-effect free.

use crate::errors::{Result, WalletError};
use crate::types::{ChannelCommitment, ChannelId};
use crate::wallet::commitment::compute_commitment;
use crate::wallet::input::WalletInput;
use crate::wallet::state::WalletState;

/// Inserts or updates a channel commitment in a wallet
///
/// Returns a new wallet with the updated channel commitment and recomputed wallet commitment.
///
/// # Arguments
/// * `wallet` - The wallet to update
/// * `channel_id` - The channel identifier
/// * `channel_commitment` - The channel commitment to insert or update
///
/// # Returns
/// * `Ok(WalletState)` - Updated wallet with the new channel commitment
pub fn insert_channel(
    wallet: WalletState,
    channel_id: ChannelId,
    channel_commitment: ChannelCommitment,
) -> Result<WalletState> {
    let mut wallet = wallet;
    wallet.channels.insert(channel_id, channel_commitment);
    wallet.commitment = compute_commitment(&wallet)?;
    Ok(wallet)
}

/// Removes a channel from a wallet
///
/// Returns the wallet without the specified channel and with recomputed wallet commitment.
///
/// # Arguments
/// * `wallet` - The wallet to update
/// * `channel_id` - The channel identifier to remove
///
/// # Returns
/// * `Ok(WalletState)` - Updated wallet without the specified channel
/// * `Err(WalletError::ChannelNotFound)` - If the channel does not exist in the wallet
///
/// # Errors
/// This function will return an error if the channel is not found in the wallet.
pub fn remove_channel(wallet: WalletState, channel_id: &ChannelId) -> Result<WalletState> {
    if !wallet.channels.contains_key(channel_id) {
        return Err(WalletError::ChannelNotFound(*channel_id).into());
    }
    let mut wallet = wallet;
    wallet.channels.remove(channel_id);
    wallet.commitment = compute_commitment(&wallet)?;
    Ok(wallet)
}

/// Gets a channel commitment from a wallet
pub fn get_channel(wallet: &WalletState, channel_id: &ChannelId) -> Option<ChannelCommitment> {
    wallet.channels.get(channel_id).copied()
}

/// Applies a wallet operation, returning the updated wallet.
///
/// This is a convenience function that transforms a wallet by applying the given operation.
///
/// # Arguments
/// * `wallet` - The wallet to update
/// * `input` - The wallet operation to apply
///
/// # Returns
/// * `Ok(WalletState)` - Updated wallet
/// * `Err(Error)` - Error if the operation fails (e.g., channel not found)
///
/// # Errors
/// This function will return an error if:
/// - The operation is `RemoveChannel` and the channel does not exist in the wallet
pub fn apply_input(wallet: WalletState, input: &WalletInput) -> Result<WalletState> {
    match input {
        WalletInput::InsertChannel { channel_id, channel_commitment } =>
            insert_channel(wallet, *channel_id, *channel_commitment),
        WalletInput::RemoveChannel { channel_id } => remove_channel(wallet, channel_id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_channel() {
        let wallet = WalletState::default();
        let channel_id = [1u8; 32];
        let commitment = [2u8; 32];

        let new_wallet =
            insert_channel(wallet, channel_id, commitment).expect("insert should succeed");

        assert_eq!(new_wallet.channels.len(), 1);
        assert_eq!(new_wallet.channels.get(&channel_id), Some(&commitment));
        // Verify commitment is recomputed
        let expected_commitment =
            compute_commitment(&new_wallet).expect("should compute commitment");
        assert_eq!(new_wallet.commitment, expected_commitment);
    }

    #[test]
    fn test_update_channel() {
        let mut channels = std::collections::BTreeMap::new();
        channels.insert([1u8; 32], [2u8; 32]);
        let wallet = WalletState::from_channels([0u8; 32], channels);

        let new_commitment = [3u8; 32];
        let new_wallet =
            insert_channel(wallet, [1u8; 32], new_commitment).expect("update should succeed");

        assert_eq!(new_wallet.channels.len(), 1);
        assert_eq!(new_wallet.channels.get(&[1u8; 32]), Some(&new_commitment));
        // Verify commitment is recomputed after update
        let expected_commitment =
            compute_commitment(&new_wallet).expect("should compute commitment");
        assert_eq!(new_wallet.commitment, expected_commitment);
    }

    #[test]
    fn test_remove_channel() {
        let mut channels = std::collections::BTreeMap::new();
        channels.insert([1u8; 32], [2u8; 32]);
        let wallet = WalletState::from_channels([0u8; 32], channels);

        let new_wallet = remove_channel(wallet, &[1u8; 32]).expect("remove should succeed");

        assert_eq!(new_wallet.channels.len(), 0);
        // Verify commitment is recomputed (should be hash(wallet_id) for empty wallet, not zero)
        let expected_commitment =
            compute_commitment(&new_wallet).expect("should compute commitment");
        assert_eq!(new_wallet.commitment, expected_commitment);

        use crate::types::WALLET_INIT_DOMAIN;
        use crate::zkp::poseidon2_hash_fixed;
        let expected_empty = poseidon2_hash_fixed(&[WALLET_INIT_DOMAIN, &new_wallet.id[..]]);
        assert_eq!(new_wallet.commitment, expected_empty);
    }

    #[test]
    fn test_remove_channel_not_found() {
        let wallet = WalletState::default();
        let channel_id = [1u8; 32];

        let result = remove_channel(wallet, &channel_id);
        assert!(result.is_err());
        match result {
            Err(crate::errors::Error::Wallet(WalletError::ChannelNotFound(id))) => {
                assert_eq!(id, channel_id);
            }
            _ => panic!("Expected ChannelNotFound error"),
        }
    }

    #[test]
    fn test_get_channel() {
        let mut channels = std::collections::BTreeMap::new();
        channels.insert([1u8; 32], [2u8; 32]);
        let wallet = WalletState::from_channels([0u8; 32], channels);

        assert_eq!(get_channel(&wallet, &[1u8; 32]), Some([2u8; 32]));
        assert_eq!(get_channel(&wallet, &[3u8; 32]), None);
    }

    #[test]
    fn test_insert_channel_comprehensive() {
        let wallet_id = [0u8; 32];
        let channel_id = [1u8; 32];
        let empty_wallet = WalletState::new(wallet_id);

        // Test channel insertion
        let commitment1 = [100u8; 32];
        let wallet =
            insert_channel(empty_wallet, channel_id, commitment1).expect("insert should succeed");
        assert_eq!(wallet.channels.len(), 1);
        assert_ne!(wallet.commitment, [0u8; 32]);
        assert_eq!(wallet.channels.get(&channel_id), Some(&commitment1));

        // Test channel update changes commitment
        let previous_wallet_commitment = wallet.commitment;
        let commitment2 = [200u8; 32];
        let updated_wallet =
            insert_channel(wallet, channel_id, commitment2).expect("update should succeed");
        assert_eq!(updated_wallet.channels.len(), 1);
        assert_ne!(updated_wallet.commitment, previous_wallet_commitment);
        assert_eq!(updated_wallet.channels.get(&channel_id), Some(&commitment2));
    }
}
