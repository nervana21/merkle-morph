//! Wallet state representation
//!
//! This module defines the wallet structure as a collection of channel commitments.
//! A wallet aggregates multiple channel commitments under a single identifier and
//! computes a Merkle root commitment over all its channels.
//!
//! Wallets serve as an intermediate aggregation layer between channels and the global
//! state. Each wallet maintains:
//! - A stable wallet identifier
//! - A collection of channel commitments indexed by channel ID
//! - A wallet commitment computed as a hash chain of channel commitments
//!
//! # Invariants
//!
//! - Wallet ID is immutable and stable across all state transitions
//! - Channel commitments are indexed by unique channel IDs (no duplicates)
//! - Wallet commitment is always up-to-date with current channel commitments
//! - Number of channels does not exceed MAX_CHANNELS
//! - Channel order in commitment computation is deterministic (sorted by channel ID)

use std::collections::BTreeMap;

use crate::types::{ChannelCommitment, ChannelId, WalletCommitment, WalletId};

/// Wallet state structure
///
/// A wallet aggregates channel commitments under a single identifier. The wallet's commitment
/// is computed as a hash chain of its constituent channel commitments.
#[derive(Clone, Debug, Default)]
pub struct WalletState {
    /// Stable wallet identifier
    pub id: WalletId,
    /// Collection of channel commitments indexed by channel ID
    pub channels: BTreeMap<ChannelId, ChannelCommitment>,
    /// Wallet commitment (hash chain) computed from channel commitments
    pub commitment: WalletCommitment,
}

impl WalletState {
    /// Creates a new wallet with a specific identifier
    ///
    /// # Arguments
    /// * `wallet_id` - The wallet identifier
    ///
    /// # Returns
    /// A new `WalletState` with the specified identifier, empty channel collection,
    /// and default commitment (zero bytes).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use merkle_morph::wallet::state::WalletState;
    ///
    /// let wallet_id = [1u8; 32];
    /// let wallet = WalletState::new(wallet_id);
    /// assert_eq!(wallet.id, wallet_id);
    /// assert!(wallet.channels.is_empty());
    /// ```
    pub fn new(wallet_id: WalletId) -> Self {
        Self { id: wallet_id, channels: BTreeMap::new(), commitment: WalletCommitment::default() }
    }

    /// Creates a new wallet with a specific identifier and initial set of channel commitments
    ///
    /// # Arguments
    /// * `wallet_id` - The wallet identifier
    /// * `channels` - A map of channel IDs to their commitments
    ///
    /// # Returns
    /// A new `WalletState` with the specified identifier and channel commitments.
    /// The commitment field is initialized to default (zero bytes) and should be
    /// recomputed using `compute_commitment` after construction.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use merkle_morph::wallet::state::WalletState;
    /// use std::collections::BTreeMap;
    ///
    /// let wallet_id = [1u8; 32];
    /// let mut channels = BTreeMap::new();
    /// channels.insert([10u8; 32], [20u8; 32]);
    /// channels.insert([30u8; 32], [40u8; 32]);
    ///
    /// let wallet = WalletState::from_channels(wallet_id, channels);
    /// assert_eq!(wallet.id, wallet_id);
    /// assert_eq!(wallet.channels.len(), 2);
    /// ```
    pub fn from_channels(
        wallet_id: WalletId,
        channels: BTreeMap<ChannelId, ChannelCommitment>,
    ) -> Self {
        Self { id: wallet_id, channels, commitment: WalletCommitment::default() }
    }

    /// Gets a channel commitment from the wallet
    ///
    /// # Arguments
    /// * `channel_id` - The channel identifier to look up
    ///
    /// # Returns
    /// * `Some(ChannelCommitment)` - The channel commitment if the channel exists
    /// * `None` - If the channel does not exist in the wallet
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
    /// assert_eq!(wallet.get_channel(&channel_id), None);
    /// let wallet = apply_insert_channel(wallet, channel_id, commitment)?;
    /// assert_eq!(wallet.get_channel(&channel_id), Some(commitment));
    /// # Ok::<(), merkle_morph::Error>(())
    /// ```
    pub fn get_channel(&self, channel_id: &ChannelId) -> Option<ChannelCommitment> {
        self.channels.get(channel_id).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let wallet_id = [1u8; 32];
        let wallet = WalletState::new(wallet_id);
        assert_eq!(wallet.id, wallet_id);
        assert!(wallet.channels.is_empty());
        assert_eq!(wallet.commitment, [0u8; 32]);
    }

    #[test]
    fn test_from_channels() {
        let wallet_id = [1u8; 32];
        let mut channels = BTreeMap::new();
        channels.insert([10u8; 32], [20u8; 32]);

        let wallet = WalletState::from_channels(wallet_id, channels);

        assert_eq!(wallet.id, wallet_id);
        assert_eq!(wallet.channels.len(), 1);
        assert_eq!(wallet.commitment, [0u8; 32]);
        assert_eq!(wallet.channels.get(&[10u8; 32]), Some(&[20u8; 32]));
    }

    #[test]
    fn test_get_channel() {
        let wallet_id = [1u8; 32];
        let mut channels = BTreeMap::new();
        let existing_channel_id = [10u8; 32];
        let existing_commitment = [20u8; 32];
        channels.insert(existing_channel_id, existing_commitment);
        let wallet = WalletState::from_channels(wallet_id, channels);

        let channel = wallet.get_channel(&existing_channel_id).expect("channel should exist");

        assert_eq!(channel, existing_commitment);

        let non_existing_channel_id = [30u8; 32];

        let channel = wallet.get_channel(&non_existing_channel_id);

        assert_eq!(channel, None);
    }
}
