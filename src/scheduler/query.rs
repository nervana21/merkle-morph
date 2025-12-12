// SPDX-License-Identifier: CC0-1.0

//! Query interface for client read operations.
//!
//! This module provides traits for querying state without modifying it, enabling
//! clients to read wallet/channel state, batches, and global roots.

use crate::{Batch, Bytes32, ChannelId, Open, Result, WalletId, WalletState};

/// Trait for querying state without modification.
///
/// This trait provides read-only access to wallet state, channel state, batches,
/// and global roots. Implementations can use this for client SDKs, RPC servers,
/// or other read-only interfaces.
pub trait StateQuery: Send + Sync {
    /// Get a wallet state by ID.
    ///
    /// Returns `Ok(Some(state))` if the wallet exists, `Ok(None)` if it doesn't,
    /// or an error if retrieval fails.
    fn get_wallet(&self, wallet_id: WalletId) -> Result<Option<WalletState>>;

    /// Get a channel state by channel ID.
    ///
    /// This requires looking up the channel within a wallet. The implementation
    /// should search across all wallets to find the channel.
    ///
    /// Returns `Ok(Some(state))` if the channel exists, `Ok(None)` if it doesn't,
    /// or an error if retrieval fails.
    fn get_channel(&self, channel_id: ChannelId) -> Result<Option<Open>>;

    /// Get the current global root.
    ///
    /// Returns the root of the global Sparse Merkle Tree representing all wallet commitments.
    fn get_global_root(&self) -> Result<Bytes32>;

    /// Get a batch by its local batch number.
    ///
    /// Returns `Ok(Some(batch))` if the batch exists, `Ok(None)` if it doesn't,
    /// or an error if retrieval fails.
    fn get_batch(&self, batch_num: u32) -> Result<Option<Batch>>;

    /// Get the current batch number (sequence number).
    ///
    /// Returns the highest batch number that has been committed.
    fn get_batch_number(&self) -> Result<u32>;
}

/// Async version of the StateQuery trait for network-based implementations.
///
/// This trait provides async methods for querying state, suitable for RPC servers
/// or database-backed implementations.
#[async_trait::async_trait]
pub trait AsyncStateQuery: Send + Sync {
    /// Get a wallet state by ID (async).
    async fn get_wallet(&self, wallet_id: WalletId) -> Result<Option<WalletState>>;

    /// Get a channel state by channel ID (async).
    async fn get_channel(&self, channel_id: ChannelId) -> Result<Option<Open>>;

    /// Get the current global root (async).
    async fn get_global_root(&self) -> Result<Bytes32>;

    /// Get a batch by its local batch number (async).
    async fn get_batch(&self, batch_num: u32) -> Result<Option<Batch>>;

    /// Get the current batch number (sequence number) (async).
    async fn get_batch_number(&self) -> Result<u32>;
}
