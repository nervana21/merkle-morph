//! Wallet state management and operations
//!
//! This module provides functionality for managing wallet states,
//! including channel aggregation and wallet-level hash accumulator computation.
//!
//! Empty wallets (created via `new()` or `from_channels()` with an empty input)
//! have a zero commitment value.

use crate::channel::{transfer, ChannelId, ChannelState};
use crate::utils::{compute_hash_chain, Bytes32};

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Type alias for wallet identifiers
pub type WalletId = [u8; 32];

/// Type alias for a collection of channels
pub type Channels = BTreeMap<ChannelId, ChannelState>;

/// A wallet aggregates channel states under a single hash accumulator and nonce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletState {
    /// Stable wallet identifier (e.g., long-lived public key hash)
    pub wallet_id: WalletId,
    /// Deterministic aggregation of channels by channel_id
    pub channels: Channels,
    /// The wallet commitment over all channels (hash chain)
    pub commitment: Bytes32,
    /// Monotonic counter for replay protection on wallet updates
    pub nonce: u64,
}

impl WalletState {
    /// Construct an empty wallet - the identity element for wallet operations.
    ///
    /// An empty wallet has no channels, a zero commitment hash, and a nonce of 0.
    /// It serves as the neutral starting state that can be combined with other wallets
    /// without changing their state.
    ///
    /// For theoretical background on category theory concepts, see the Overpass paper
    /// in docs/overpass_paper.pdf.
    pub fn new(wallet_id: WalletId) -> Self {
        Self {
            wallet_id,
            channels: BTreeMap::new(),
            commitment: [0u8; 32],
            nonce: 0,
        }
    }

    /// Construct a wallet from an initial set of channels.
    pub fn from_channels(wallet_id: WalletId, channels: Channels) -> Self {
        let commitment = compute_wallet_commitment(&channels);
        Self {
            wallet_id,
            channels,
            commitment,
            nonce: 0,
        }
    }

    /// Transfers an amount from party 0 to party 1 in a channel.
    pub fn transfer_in_channel(&self, channel_id: ChannelId, amount: u64) -> ChannelState {
        transfer(channel_id, &self.channels[&channel_id], amount)
    }
}

/// Deterministic wallet-level commitment:
/// - Leaf = H("MM_WLT_LEAF_v1" || channel_id || channel_commitment)
/// - Accumulate in ascending channel_id order via hash_chain starting from 0^32
fn compute_wallet_commitment(channels: &Channels) -> Bytes32 {
    // Start from zero for empty wallets.
    let mut accumulator: Bytes32 = [0u8; 32];
    for (channel_id, channel_state) in channels.iter() {
        let leaf = {
            let mut hasher = Sha256::new();
            hasher.update(b"MM_WLT_LEAF_v1");
            hasher.update(channel_id);
            hasher.update(channel_state.commitment);
            let x: Bytes32 = hasher.finalize().into();
            x
        };
        accumulator = compute_hash_chain(accumulator, &leaf);
    }
    accumulator
}

/// Inserts (or updates) a channel in the wallet and returns a new wallet state.
/// Nonce advances by +1 and the wallet commitment changes iff the channel commitment changed.
pub fn insert_channel(
    old: &WalletState,
    channel_id: ChannelId,
    channel: ChannelState,
) -> WalletState {
    let mut channels = old.channels.clone();
    channels.insert(channel_id, channel);
    let new_commitment = compute_wallet_commitment(&channels);
    WalletState {
        wallet_id: old.wallet_id,
        channels,
        commitment: new_commitment,
        nonce: old.nonce + 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::*;

    #[test]
    fn test_wallet_construction_and_basic_operations() {
        let wallet_id = [0u8; 32];
        let channel_id = [1u8; 32];

        // Test empty wallet construction
        let empty_wallet = WalletState::new(wallet_id);
        assert_eq!(empty_wallet.wallet_id, wallet_id);
        assert!(empty_wallet.channels.is_empty());
        assert_eq!(empty_wallet.nonce, 0);
        assert_eq!(empty_wallet.commitment, [0u8; 32]);

        // Test constructor equivalence for empty wallets
        let empty_wallet_from_channels = WalletState::from_channels(wallet_id, BTreeMap::new());
        assert_eq!(empty_wallet_from_channels.channels.len(), 0);
        assert_eq!(empty_wallet_from_channels.commitment, [0u8; 32]);
        assert_eq!(
            empty_wallet_from_channels.commitment,
            empty_wallet.commitment
        );

        // Test that empty wallets with different IDs have the same commitment
        let different_wallet_id = [21u8; 32];
        let empty_wallet_different_id = WalletState::new(different_wallet_id);
        assert_eq!(
            empty_wallet_different_id.commitment,
            empty_wallet.commitment
        );

        // Test zero balances (non-empty wallet with zero-value channels)
        let zero_channel = ChannelState::new([0, 0]);
        let zero_channel = transfer([4u8; 32], &zero_channel, 0);
        let mut channels = BTreeMap::new();
        channels.insert([4u8; 32], zero_channel);
        let wallet_with_zero_balances = WalletState::from_channels(wallet_id, channels);
        assert_ne!(wallet_with_zero_balances.commitment, [0u8; 32]);
        assert_eq!(wallet_with_zero_balances.channels.len(), 1);

        // Test creating a wallet from channels with actual balances
        let channel = ChannelState::new([100, 50]);
        let mut channels = BTreeMap::new();
        channels.insert(channel_id, channel);
        let wallet = WalletState::from_channels(wallet_id, channels);
        assert_eq!(wallet.channels.len(), 1);
        assert_ne!(wallet.commitment, empty_wallet.commitment);

        // Test channel insertion and updates
        let wallet = insert_channel(&empty_wallet, channel_id, ChannelState::new([100, 50]));
        assert_eq!(wallet.nonce, 1);
        assert_ne!(wallet.commitment, empty_wallet.commitment);

        let updated_channel = wallet.transfer_in_channel(channel_id, 10);
        let previous_wallet_commitment = wallet.commitment;
        let wallet = insert_channel(&wallet, channel_id, updated_channel);
        assert_eq!(wallet.nonce, 2);
        assert_ne!(wallet.commitment, previous_wallet_commitment);
    }

    #[test]
    fn test_wallet_determinism_and_ordering() {
        let wallet_id = [0u8; 32];
        let channel_id1 = [1u8; 32];
        let channel_id2 = [2u8; 32];

        // Test that insertion order does not affect final state
        let mut channels1 = BTreeMap::new();
        channels1.insert(channel_id1, ChannelState::new([100, 50]));
        channels1.insert(channel_id2, ChannelState::new([200, 100]));
        let wallet1 = WalletState::from_channels(wallet_id, channels1);

        let mut channels2 = BTreeMap::new();
        channels2.insert(channel_id2, ChannelState::new([200, 100]));
        channels2.insert(channel_id1, ChannelState::new([100, 50]));
        let wallet2 = WalletState::from_channels(wallet_id, channels2);

        assert_eq!(wallet1.commitment, wallet2.commitment);
        assert_eq!(wallet1.channels, wallet2.channels);

        // Test that channels are inserted in ascending order
        let mut iter = wallet1.channels.iter();
        let (first_id, _) = iter.next().unwrap();
        let (second_id, _) = iter.next().unwrap();
        assert_eq!(*first_id, channel_id1);
        assert_eq!(*second_id, channel_id2);
    }

    #[test]
    fn test_multi_party_channel_participation() {
        // Initialize wallets for different parties
        let mut p0_wallet = WalletState::new([0u8; 32]);
        let mut p1_wallet = WalletState::new([1u8; 32]);

        // Both parties participate in the same channel
        let shared_channel_id = [2u8; 32];
        let initial_channel = ChannelState::new([100, 0]);
        p0_wallet = insert_channel(&p0_wallet, shared_channel_id, initial_channel.clone());
        p1_wallet = insert_channel(&p1_wallet, shared_channel_id, initial_channel.clone());

        // Simulate a payment in the shared channel
        let updated_channel = transfer(shared_channel_id, &initial_channel, 30);
        p0_wallet = insert_channel(&p0_wallet, shared_channel_id, updated_channel.clone());
        p1_wallet = insert_channel(&p1_wallet, shared_channel_id, updated_channel.clone());

        // Verify both parties have consistent state for the shared channel
        assert_eq!(p0_wallet.channels[&shared_channel_id].balances, [70, 30]);
        assert_eq!(p1_wallet.channels[&shared_channel_id].balances, [70, 30]);
        assert_eq!(p0_wallet.nonce, 2);
        assert_eq!(p1_wallet.nonce, 2);

        // Test that parties can have additional channels not shared with others
        let p0_private_channel = ChannelState::new([21, 21]);
        p0_wallet = insert_channel(&p0_wallet, [3u8; 32], p0_private_channel);
        assert_eq!(p0_wallet.channels.len(), 2);
        assert_eq!(p0_wallet.nonce, 3);
        assert_eq!(p1_wallet.channels.len(), 1);
    }
}
