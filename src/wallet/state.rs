#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
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
//! Unlike channels, wallets do not contain transition logic - they are simply containers
//! for channel commitments. State transitions are applied at the channel level, and
//! wallet commitments are recomputed when channels are added, updated, or removed.

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
    pub fn new(wallet_id: WalletId) -> Self {
        Self { id: wallet_id, channels: BTreeMap::new(), commitment: WalletCommitment::default() }
    }

    /// Creates a new wallet with a specific identifier and initial set of channel commitments
    pub fn from_channels(
        wallet_id: WalletId,
        channels: BTreeMap<ChannelId, ChannelCommitment>,
    ) -> Self {
        Self { id: wallet_id, channels, commitment: WalletCommitment::default() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_default() {
        let wallet = WalletState::default();
        assert_eq!(wallet.id, [0u8; 32]);
        assert!(wallet.channels.is_empty());
        assert_eq!(wallet.commitment, [0u8; 32]);
    }

    #[test]
    fn test_wallet_new() {
        let wallet_id = [1u8; 32];
        let wallet = WalletState::new(wallet_id);
        assert_eq!(wallet.id, wallet_id);
        assert!(wallet.channels.is_empty());
        assert_eq!(wallet.commitment, [0u8; 32]);
    }

    #[test]
    fn test_wallet_from_channels() {
        let wallet_id = [1u8; 32];
        let mut channels = BTreeMap::new();
        channels.insert([10u8; 32], [20u8; 32]);
        channels.insert([30u8; 32], [40u8; 32]);
        channels.insert([50u8; 32], [60u8; 32]);

        let wallet = WalletState::from_channels(wallet_id, channels);

        assert_eq!(wallet.id, wallet_id);
        assert_eq!(wallet.channels.len(), 3);
        assert_eq!(wallet.commitment, [0u8; 32]);
        assert_eq!(wallet.channels.get(&[10u8; 32]), Some(&[20u8; 32]));
        assert_eq!(wallet.channels.get(&[30u8; 32]), Some(&[40u8; 32]));
        assert_eq!(wallet.channels.get(&[50u8; 32]), Some(&[60u8; 32]));
    }

    #[test]
    fn test_wallet_from_channels_duplicate_overwrites() {
        let wallet_id = [1u8; 32];
        let mut channels = BTreeMap::new();
        let channel_id = [10u8; 32];
        channels.insert(channel_id, [20u8; 32]);
        channels.insert(channel_id, [30u8; 32]);

        let wallet = WalletState::from_channels(wallet_id, channels);
        assert_eq!(wallet.channels.len(), 1);
        assert_eq!(wallet.channels.get(&channel_id), Some(&[30u8; 32]));
    }

    #[test]
    fn test_wallet_new_equals_from_channels_empty() {
        let wallet_id = [1u8; 32];
        let wallet1 = WalletState::new(wallet_id);
        let wallet2 = WalletState::from_channels(wallet_id, BTreeMap::new());

        assert_eq!(wallet1.id, wallet2.id);
        assert_eq!(wallet1.channels, wallet2.channels);
        assert_eq!(wallet1.commitment, wallet2.commitment);
    }
}
