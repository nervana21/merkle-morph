//! Wallet state management and operations
//!
//! This module provides functionality for managing wallet states,
//! including channel aggregation and wallet-level hash accumulator computation.
//!
//! Empty wallets (created via `new()` or `from_channels()` with an empty input)
//! have a zero commitment value.
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::channel::compute_channel_commitment;
use crate::channel::hash;
use crate::channel::ChannelState;
use crate::errors::Result;
use crate::errors::WalletError;
use crate::types::Bytes32;
use crate::types::ChannelId;
use crate::types::WalletId;

/// Type alias for a collection of channels
pub type Channels = BTreeMap<ChannelId, ChannelState>;

/// A wallet aggregates channel states under a single hash accumulator and nonce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletState {
    /// Stable wallet identifier (e.g., long-lived public key hash)
    pub wallet_id: WalletId,
    /// Collection of channels indexed by channel ID
    pub channels: Channels,
    /// The wallet commitment over all channels
    pub commitment: Bytes32,
    /// Monotonic counter for replay protection on wallet updates
    pub nonce: u64,
}

/// Computes the next wallet state given an input.
/// Uses domain separation with tag "MM_CHAIN_v0" for future-proofing.
fn compute_update(prior_state: Bytes32, new_input: &[u8]) -> Bytes32 {
    let mut hasher = Sha256::new();
    hasher.update(b"MM_CHAIN_v0");
    hasher.update(prior_state);
    hasher.update(new_input);
    hasher.finalize().into()
}

/// Deterministic wallet-level commitment.
///
/// Hash = H("MM_WLT_HASH_v0"||channel_id||channel_commitment)
/// Accumulate in ascending channel_id order starting from 0
fn compute_commitment(channels: &Channels) -> Bytes32 {
    // Start from zero for empty wallets.
    let mut accumulator: Bytes32 = [0u8; 32];
    for (channel_id, channel_state) in channels.iter() {
        // Compute the actual channel commitment from the channel state
        let state_hash = hash(*channel_id, channel_state);
        let channel_commitment =
            compute_channel_commitment(*channel_id, state_hash, channel_state.nonce);

        let hash: Bytes32 = {
            let mut hasher = Sha256::new();
            hasher.update(b"MM_WLT_HASH_v0");
            hasher.update(channel_id);
            hasher.update(channel_commitment);
            hasher.finalize().into()
        };
        accumulator = compute_update(accumulator, &hash);
    }
    accumulator
}

impl WalletState {
    /// Construct an empty wallet - the identity element for wallet operations.
    ///
    /// An empty wallet has no channels, a zero commitment hash, and a nonce of 0.
    /// It serves as the neutral starting state that can be combined with other wallets
    /// without changing their state.
    ///
    /// For relevant background on category theory concepts, see the Overpass paper
    /// in docs/overpass.pdf.
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
        let commitment = compute_commitment(&channels);
        Self {
            wallet_id,
            channels,
            commitment,
            nonce: 0,
        }
    }

    /// Inserts (or updates) a channel in the wallet and returns the new wallet state.
    /// The nonce increases by 1.
    /// The wallet commitment changes iff the channel commitment changes.
    pub fn insert_channel(
        prior_state: &WalletState,
        channel_id: ChannelId,
        channel: ChannelState,
    ) -> Result<WalletState> {
        let mut channels = prior_state.channels.clone();
        channels.insert(channel_id, channel);
        let new_commitment = compute_commitment(&channels);
        Ok(WalletState {
            wallet_id: prior_state.wallet_id,
            channels,
            commitment: new_commitment,
            nonce: prior_state
                .nonce
                .checked_add(1)
                .ok_or(WalletError::WalletNonceOverflow)?,
        })
    }

    /// Transfers `amount` from sender to receiver in a channel.
    pub fn transfer_in_channel(&self, channel_id: ChannelId, amount: u64) -> Result<ChannelState> {
        let channel = self
            .channels
            .get(&channel_id)
            .ok_or(WalletError::ChannelNotFound(channel_id))?;
        Ok(channel
            .apply_transfer(channel_id, amount)
            .map_err(WalletError::from)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::*;
    use crate::errors::ChannelError;
    use crate::errors::Error;

    #[test]
    fn test_compute_update() {
        // Test basic functionality
        let prior_state = [0u8; 32];
        let new_input = b"new input";
        let updated_state = compute_update(prior_state, new_input);

        // New state should be different from old state
        assert_ne!(updated_state, prior_state);

        // Test same inputs produce same output
        let same_inputs = compute_update(prior_state, new_input);
        assert_eq!(updated_state, same_inputs);

        // Test a different input produces a different output
        let different_input = compute_update(prior_state, b"different input");
        assert_ne!(updated_state, different_input);

        // Test different prior state produces a different output
        let different_prior_state = compute_update([1u8; 32], new_input);
        assert_ne!(updated_state, different_prior_state);

        // Test with empty input
        let empty_input = compute_update(prior_state, b"");
        assert_ne!(updated_state, empty_input);
    }

    #[test]
    fn test_compute_commitment() {
        let wallet_id = [0u8; 32];

        // Test empty wallet
        let empty = WalletState::from_channels(wallet_id, BTreeMap::new());
        assert_eq!(empty.commitment, [0u8; 32]);

        // Test wallet with a single channel
        let mut channels = BTreeMap::new();
        channels.insert([1u8; 32], ChannelState::new(10));
        let single_channel = WalletState::from_channels(wallet_id, channels);
        assert_ne!(single_channel.commitment, [0u8; 32]);

        // Test wallet with multiple channels
        let mut channels = BTreeMap::new();
        channels.insert([1u8; 32], ChannelState::new(10));
        channels.insert([2u8; 32], ChannelState::new(20));
        let multi_channel = WalletState::from_channels(wallet_id, channels);
        assert_ne!(multi_channel.commitment, single_channel.commitment);
    }

    #[test]
    fn test_new() {
        let wallet_id = [0u8; 32];
        let wallet = WalletState::new(wallet_id);

        assert_eq!(wallet.wallet_id, wallet_id);
        assert_eq!(wallet.channels.len(), 0);
        assert_eq!(wallet.nonce, 0);
        assert_eq!(wallet.commitment, [0u8; 32]);
    }

    #[test]
    fn test_from_channels() {
        let wallet_id = [0u8; 32];
        let channel_id = [1u8; 32];

        // Test creating a wallet from channels
        let channel = ChannelState::new(100);
        let mut channels = BTreeMap::new();
        channels.insert(channel_id, channel);
        let wallet = WalletState::from_channels(wallet_id, channels);

        assert_eq!(wallet.channels.len(), 1);
        assert_ne!(wallet.commitment, [0u8; 32]);
    }

    #[test]
    fn test_insert_channel() {
        let wallet_id = [0u8; 32];
        let channel_id = [1u8; 32];
        let empty_wallet = WalletState::new(wallet_id);

        // Test channel insertion and updates
        let wallet =
            WalletState::insert_channel(&empty_wallet, channel_id, ChannelState::new(100)).unwrap();
        assert_eq!(wallet.nonce, 1);
        assert_ne!(wallet.commitment, empty_wallet.commitment);
        assert_eq!(wallet.channels.len(), 1);

        let updated_channel = wallet.transfer_in_channel(channel_id, 10).unwrap();
        let previous_wallet_commitment = wallet.commitment;
        let wallet = WalletState::insert_channel(&wallet, channel_id, updated_channel).unwrap();
        assert_eq!(wallet.nonce, 2);
        assert_ne!(wallet.commitment, previous_wallet_commitment);

        // Test nonce overflow
        let mut wallet = WalletState::new([0u8; 32]);
        wallet.nonce = u64::MAX;

        let result = WalletState::insert_channel(&wallet, [1u8; 32], ChannelState::new(100));
        assert!(matches!(
            result,
            Err(Error::Wallet(WalletError::WalletNonceOverflow))
        ));
    }

    #[test]
    fn test_transfer_in_channel() {
        let wallet_id = [0u8; 32];
        let channel_id = [1u8; 32];
        let channel = ChannelState::new(100);
        let mut channels = BTreeMap::new();
        channels.insert(channel_id, channel);
        let wallet = WalletState::from_channels(wallet_id, channels);

        // Test successful transfer
        let updated_channel = wallet.transfer_in_channel(channel_id, 10).unwrap();
        assert_eq!(updated_channel.sender_balance, 90);
        assert_eq!(updated_channel.receiver_balance, 10);

        // Test error handling for non-existent channel
        let non_existent_channel_id = [2u8; 32];
        let result = wallet.transfer_in_channel(non_existent_channel_id, 10);
        assert!(matches!(
            result,
            Err(Error::Wallet(WalletError::ChannelNotFound(id))) if id == non_existent_channel_id
        ));

        // Test error handling for insufficient balance
        let result = wallet.transfer_in_channel(channel_id, 200);
        assert!(matches!(
            result,
            Err(Error::Wallet(WalletError::Channel(
                ChannelError::InsufficientBalance
            )))
        ));
    }
}
