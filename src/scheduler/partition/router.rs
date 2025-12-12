// SPDX-License-Identifier: CC0-1.0

//! Partition routing logic.
//!
//! This module defines the [`PartitionRouter`] trait and a simple hash-based
//! implementation for routing wallet and channel identifiers to partitions.

use std::hash::{Hash, Hasher};

use seahash::SeaHasher;

use super::types::PartitionId;
use crate::scheduler::UpdateEnvelope;
use crate::types::{ChannelId, WalletId};

/// Trait for routing wallet and channel identifiers to partition indices.
pub trait PartitionRouter: Send + Sync {
    /// Map a wallet id to its partition.
    fn route_wallet(&self, wallet_id: WalletId) -> PartitionId;

    /// Map a channel id to its partition.
    fn route_channel(&self, channel_id: ChannelId) -> PartitionId;

    /// Determine the partition that should handle an update envelope.
    ///
    /// The default implementation routes based on the first wallet in the
    /// access set, if present.
    fn get_partition_for_update(&self, envelope: &UpdateEnvelope) -> Option<PartitionId> {
        envelope.access_set.wallets.first().copied().map(|wallet_id| self.route_wallet(wallet_id))
    }
}

/// Simple hash-based router using SeaHash for stable deterministic hashing.
///
/// SeaHash provides deterministic output across processes and machines, making
/// it suitable for distributed deployments.
#[derive(Clone, Debug)]
pub struct SeaHashRouter {
    num_partitions: PartitionId,
}

impl SeaHashRouter {
    /// Construct a router over `num_partitions` partitions.
    ///
    /// # Panics
    ///
    /// Panics if `num_partitions` is 0, as routing requires at least one partition.
    #[track_caller]
    pub fn new(num_partitions: PartitionId) -> Self {
        assert!(num_partitions > 0, "num_partitions must be greater than 0");
        Self { num_partitions }
    }

    fn hash_to_partition<T: Hash>(&self, value: &T) -> PartitionId {
        let mut hasher = SeaHasher::new();
        value.hash(&mut hasher);
        (hasher.finish() as PartitionId) % self.num_partitions
    }
}

impl PartitionRouter for SeaHashRouter {
    fn route_wallet(&self, wallet_id: WalletId) -> PartitionId {
        self.hash_to_partition(&wallet_id)
    }

    fn route_channel(&self, channel_id: ChannelId) -> PartitionId {
        self.hash_to_partition(&channel_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduler::AccessSet;
    use crate::wallet::operation::WalletTransition;

    #[test]
    #[should_panic(expected = "num_partitions must be greater than 0")]
    fn test_new_panic() { SeaHashRouter::new(0); }

    #[test]
    fn test_new() {
        let router = SeaHashRouter::new(1);

        assert_eq!(router.num_partitions, 1);
    }

    #[test]
    fn test_route_wallet() {
        let router = SeaHashRouter::new(4);
        let wallet_id = [1u8; 32];

        let partition = router.route_wallet(wallet_id);

        assert!(partition < 4);
    }

    #[test]
    fn test_route_channel() {
        let router = SeaHashRouter::new(4);
        let channel_id = [2u8; 32];

        let partition = router.route_channel(channel_id);

        assert!(partition < 4);
    }

    #[test]
    fn test_get_partition_for_update() {
        let router = SeaHashRouter::new(4);
        let wallet_id = [3u8; 32];
        let envelope_empty = UpdateEnvelope {
            transition: WalletTransition::InsertChannel {
                channel_id: [0u8; 32],
                channel_commitment: [0u8; 32],
            },
            access_set: AccessSet { wallets: Vec::new(), prefixes: Vec::new() },
            fee_rate: None,
            submit_order: 0,
        };
        let envelope_with_wallet = UpdateEnvelope {
            transition: WalletTransition::InsertChannel {
                channel_id: [0u8; 32],
                channel_commitment: [0u8; 32],
            },
            access_set: AccessSet { wallets: vec![wallet_id], prefixes: Vec::new() },
            fee_rate: None,
            submit_order: 0,
        };

        assert_eq!(router.get_partition_for_update(&envelope_empty), None);

        assert!(router.get_partition_for_update(&envelope_with_wallet).is_some());
    }
}
