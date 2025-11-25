//! Wallet state transition logic
//!
//! This module provides pure functions for applying state transitions to wallets.

use crate::errors::WalletError;
use crate::types::{ChannelCommitment, ChannelId};
use crate::wallet::commitment::compute_commitment_from_channels;
use crate::wallet::operation::WalletTransition;
use crate::wallet::state::WalletState;
use crate::Result;

/// Applies an insert channel operation to a wallet
///
/// Inserts or updates a channel commitment in a wallet, returning a new wallet with the
/// updated channel commitment and a newly computed commitment.
///
/// # Arguments
/// * `wallet` - The wallet to update
/// * `channel_id` - The channel identifier
/// * `channel_commitment` - The channel commitment to insert or update
///
/// # Returns
/// * `Ok(WalletState)` - Updated wallet with the new channel commitment and a newly computed commitment
///
/// # Errors
/// * `Err(Error::Wallet(WalletError::TooManyChannels))` - If the wallet would exceed MAX_CHANNELS after insertion
/// * `Err(Error)` - Other errors from commitment computation
///
/// # Examples
///
/// ```rust
/// use merkle_morph::wallet::state::WalletState;
/// use merkle_morph::wallet::transition::apply_insert_channel;
///
/// let wallet = WalletState::default();
/// let channel_id = [1u8; 32];
/// let commitment = [2u8; 32];
///
/// let updated_wallet = apply_insert_channel(wallet, channel_id, commitment)?;
/// assert_eq!(updated_wallet.channels.get(&channel_id), Some(&commitment));
/// # Ok::<(), merkle_morph::Error>(())
/// ```
pub fn apply_insert_channel(
    wallet: WalletState,
    channel_id: ChannelId,
    channel_commitment: ChannelCommitment,
) -> Result<WalletState> {
    let mut wallet = wallet;
    wallet.channels.insert(channel_id, channel_commitment);
    wallet.commitment = compute_commitment_from_channels(wallet.id, &wallet.channels)?;
    Ok(wallet)
}

/// Applies a remove channel operation to a wallet
///
/// Removes a channel from a wallet, returning the wallet without the specified channel
/// and with a newly computed commitment.
///
/// # Arguments
/// * `wallet` - The wallet to update
/// * `channel_id` - The channel identifier to remove
///
/// # Returns
/// * `Ok(WalletState)` - Updated wallet without the specified channel and with a newly computed commitment
///
/// # Errors
/// * `Err(Error::Wallet(WalletError::ChannelNotFound))` - If the channel does not exist in the wallet
/// * `Err(Error)` - Other errors from commitment computation
///
/// # Examples
///
/// ```rust
/// use merkle_morph::wallet::state::WalletState;
/// use merkle_morph::wallet::transition::{apply_insert_channel, apply_remove_channel};
/// use std::collections::BTreeMap;
///
/// let mut wallet = WalletState::default();
/// let channel_id = [1u8; 32];
/// let commitment = [2u8; 32];
///
/// wallet = apply_insert_channel(wallet, channel_id, commitment)?;
/// wallet = apply_remove_channel(wallet, &channel_id)?;
/// assert!(!wallet.channels.contains_key(&channel_id));
/// # Ok::<(), merkle_morph::Error>(())
/// ```
pub fn apply_remove_channel(wallet: WalletState, channel_id: &ChannelId) -> Result<WalletState> {
    if !wallet.channels.contains_key(channel_id) {
        return Err(WalletError::ChannelNotFound(*channel_id).into());
    }

    let mut wallet = wallet;
    wallet.channels.remove(channel_id);
    wallet.commitment = compute_commitment_from_channels(wallet.id, &wallet.channels)?;
    Ok(wallet)
}

/// Applies a wallet operation, returning the updated wallet.
///
/// This is a convenience function that transforms a wallet by applying the given operation.
/// It dispatches to the appropriate transition function based on the transition type.
///
/// # Arguments
/// * `wallet` - The wallet to update
/// * `transition` - The wallet operation to apply
///
/// # Returns
/// * `Ok(WalletState)` - Updated wallet with the operation applied and commitment recomputed
///
/// # Errors
/// * `Err(Error::Wallet(WalletError::ChannelNotFound))` - If the operation is `RemoveChannel` and the channel
///   does not exist in the wallet
/// * `Err(Error::Wallet(WalletError::TooManyChannels))` - If the operation is `InsertChannel` and would exceed MAX_CHANNELS
/// * `Err(Error)` - Other errors from commitment computation
///
/// # Examples
///
/// ```rust
/// use merkle_morph::wallet::state::WalletState;
/// use merkle_morph::wallet::WalletTransition;
/// use merkle_morph::wallet::transition::apply_operation;
///
/// let wallet = WalletState::default();
/// let channel_id = [1u8; 32];
/// let commitment = [2u8; 32];
///
/// // Insert a channel
/// let transition = WalletTransition::InsertChannel { channel_id, channel_commitment: commitment };
/// let wallet = apply_operation(wallet, &transition)?;
/// assert_eq!(wallet.channels.get(&channel_id), Some(&commitment));
///
/// // Remove the channel
/// let transition = WalletTransition::RemoveChannel { channel_id };
/// let wallet = apply_operation(wallet, &transition)?;
/// assert!(!wallet.channels.contains_key(&channel_id));
/// # Ok::<(), merkle_morph::Error>(())
/// ```
pub fn apply_operation(wallet: WalletState, transition: &WalletTransition) -> Result<WalletState> {
    match transition {
        WalletTransition::InsertChannel { channel_id, channel_commitment } =>
            apply_insert_channel(wallet, *channel_id, *channel_commitment),
        WalletTransition::RemoveChannel { channel_id } => apply_remove_channel(wallet, channel_id),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::types::MAX_CHANNELS;

    #[test]
    fn test_apply_insert_channel() {
        let wallet = WalletState::default();
        let channel_id = [1u8; 32];
        let commitment = [2u8; 32];

        let result = apply_insert_channel(wallet, channel_id, commitment);

        assert!(result.is_ok());
        let updated_wallet = result.expect("should insert channel successfully");
        assert_eq!(updated_wallet.channels.get(&channel_id), Some(&commitment));

        let mut max_channels_wallet = WalletState::default();
        for i in 0..MAX_CHANNELS {
            max_channels_wallet.channels.insert([i as u8; 32], [i as u8; 32]);
        }
        let overflow_channel_id = [255u8; 32];
        let overflow_commitment = [255u8; 32];

        let error_result =
            apply_insert_channel(max_channels_wallet, overflow_channel_id, overflow_commitment);

        assert!(error_result.is_err());
    }

    #[test]
    fn test_apply_remove_channel() {
        let wallet = WalletState::default();
        let channel_id = [1u8; 32];

        let error_result = apply_remove_channel(wallet, &channel_id);

        assert!(error_result.is_err());
        match error_result {
            Err(crate::Error::Wallet(WalletError::ChannelNotFound(id))) => {
                assert_eq!(id, channel_id);
            }
            _ => panic!("Expected ChannelNotFound error"),
        }

        let mut channels = BTreeMap::new();
        channels.insert(channel_id, [2u8; 32]);
        let wallet_with_channel = WalletState::from_channels([0u8; 32], channels);

        let success_result = apply_remove_channel(wallet_with_channel, &channel_id);

        assert!(success_result.is_ok());
        let updated_wallet = success_result.expect("should remove channel successfully");
        assert!(!updated_wallet.channels.contains_key(&channel_id));
    }

    #[test]
    fn test_apply_operation() {
        let wallet = WalletState::default();
        let channel_id = [1u8; 32];
        let commitment = [2u8; 32];
        let insert_transition =
            WalletTransition::InsertChannel { channel_id, channel_commitment: commitment };

        let insert_result = apply_operation(wallet, &insert_transition);

        assert!(insert_result.is_ok());
        let wallet_after_insert = insert_result.expect("should insert channel via apply_operation");
        assert_eq!(wallet_after_insert.channels.get(&channel_id), Some(&commitment));

        let remove_transition = WalletTransition::RemoveChannel { channel_id };

        let remove_result = apply_operation(wallet_after_insert, &remove_transition);

        assert!(remove_result.is_ok());
        let wallet_after_remove = remove_result.expect("should remove channel via apply_operation");
        assert!(!wallet_after_remove.channels.contains_key(&channel_id));
    }
}
