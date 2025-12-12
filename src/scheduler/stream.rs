// SPDX-License-Identifier: CC0-1.0

//! Event streaming interface for incremental state updates.
//!
//! This module provides traits for subscribing to state changes, enabling
//! efficient incremental synchronization for clients.

use crate::{Batch, Bytes32, Result, WalletId};

/// Represents a state update event.
pub enum StateUpdate {
    /// A new batch has been committed.
    BatchCommitted {
        /// The batch number.
        batch_num: u32,
        /// The post-commitment root after this batch.
        post_root: Bytes32,
        /// The batch itself.
        batch: Box<Batch>,
    },
    /// A wallet has been updated.
    WalletUpdated {
        /// The wallet ID that was updated.
        wallet_id: WalletId,
        /// The batch number in which this update occurred.
        batch_num: u32,
    },
    /// The global root has changed.
    GlobalRootChanged {
        /// The new global root.
        root: Bytes32,
        /// The batch number that caused this change.
        batch_num: u32,
    },
}

/// Trait for streaming state updates.
///
/// This trait enables clients to subscribe to state changes and receive
/// incremental updates, avoiding the need for full state synchronization.
pub trait StateStream: Send + Sync {
    /// Subscribe to all state updates starting from a given batch number.
    ///
    /// Returns a stream of state updates. The stream will yield all updates
    /// from `from_batch_num` onwards, including future updates as they occur.
    ///
    /// # Arguments
    ///
    /// * `from_batch_num` - The batch number to start streaming from (inclusive).
    ///   Use 0 to stream from the beginning.
    fn subscribe_from(
        &self,
        from_batch_num: u32,
    ) -> Result<Box<dyn Iterator<Item = StateUpdate> + Send>>;

    /// Subscribe to updates for a specific wallet.
    ///
    /// Returns a stream of state updates that affect the specified wallet.
    /// The stream will yield updates as they occur.
    ///
    /// # Arguments
    ///
    /// * `wallet_id` - The wallet ID to subscribe to.
    fn subscribe_wallet(
        &self,
        wallet_id: WalletId,
    ) -> Result<Box<dyn Iterator<Item = StateUpdate> + Send>>;
}

/// Async version of the StateStream trait for async/await based implementations.
///
/// This trait provides async streams for state updates, suitable for async RPC
/// servers or async client SDKs.
#[async_trait::async_trait]
pub trait AsyncStateStream: Send + Sync {
    /// The type of async stream returned by subscription methods.
    type Stream: futures::Stream<Item = Result<StateUpdate>> + Send + 'static;

    /// Subscribe to all state updates starting from a given batch number (async).
    ///
    /// Returns an async stream of state updates. The stream will yield all updates
    /// from `from_batch_num` onwards, including future updates as they occur.
    ///
    /// # Arguments
    ///
    /// * `from_batch_num` - The batch number to start streaming from (inclusive).
    ///   Use 0 to stream from the beginning.
    async fn subscribe_from(&self, from_batch_num: u32) -> Result<Self::Stream>;

    /// Subscribe to updates for a specific wallet (async).
    ///
    /// Returns an async stream of state updates that affect the specified wallet.
    /// The stream will yield updates as they occur.
    ///
    /// # Arguments
    ///
    /// * `wallet_id` - The wallet ID to subscribe to.
    async fn subscribe_wallet(&self, wallet_id: WalletId) -> Result<Self::Stream>;
}
