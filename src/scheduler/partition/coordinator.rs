// SPDX-License-Identifier: CC0-1.0

//! Partition coordination and metadata management.
//!
//! This module defines the [`PartitionCoordinator`] responsible for tracking
//! available partitions, their endpoints, and simple rebalancing plans. It uses
//! an in-memory data structure that is suitable for both tests and
//! single-process deployments, and can be wrapped or extended by higher
//! layers when a distributed registry is required.

use std::collections::BTreeMap;

use super::types::{PartitionEndpoint, PartitionId};

/// Plan for rebalancing wallet/channel assignments across partitions.
///
/// This structure records, for each partition, how many assignments should be
/// moved away from that partition to improve balance. Higher layers are
/// responsible for turning this plan into concrete wallet or channel
/// migrations and for executing them safely.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RebalancePlan {
    /// Mapping from partition id to number of assignments that should move away
    /// from that partition. This keeps the structure simple while still being
    /// useful for tests.
    pub moves_from_partition: BTreeMap<PartitionId, u64>,
}

/// Coordinator for partition metadata and endpoints.
#[derive(Clone, Debug, Default)]
pub struct PartitionCoordinator {
    partitions: BTreeMap<PartitionId, PartitionEndpoint>,
}

impl PartitionCoordinator {
    /// Create an empty coordinator.
    pub fn new() -> Self { Self { partitions: BTreeMap::new() } }

    /// Register or update a partition endpoint.
    pub fn register_partition(&mut self, partition_id: PartitionId, endpoint: PartitionEndpoint) {
        self.partitions.insert(partition_id, endpoint);
    }

    /// Lookup the endpoint for a partition.
    pub fn get_partition_endpoint(&self, partition_id: PartitionId) -> Option<PartitionEndpoint> {
        self.partitions.get(&partition_id).cloned()
    }

    /// Return the number of registered partitions.
    pub fn num_partitions(&self) -> usize { self.partitions.len() }

    /// Compute a rebalance plan that keeps the current distribution stable.
    ///
    /// Without explicit per-partition load information this coordinator cannot
    /// decide which concrete assignments should move. Instead it returns a
    /// conservative plan that maintains the existing placement while still
    /// exposing a structured summary that higher layers can refine using
    /// their own load metrics.
    pub fn rebalance_partitions(&self) -> crate::Result<RebalancePlan> {
        if self.partitions.is_empty() {
            return Ok(RebalancePlan::default());
        }

        let mut moves_from_partition = BTreeMap::new();
        for partition_id in self.partitions.keys().copied() {
            let moves = 0u64;
            moves_from_partition.insert(partition_id, moves);
        }

        Ok(RebalancePlan { moves_from_partition })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let coord = PartitionCoordinator::new();

        assert_eq!(coord.num_partitions(), 0);
    }

    #[test]
    fn test_register_partition() {
        let mut coord = PartitionCoordinator::new();
        let endpoint = PartitionEndpoint { address: "addr".to_string() };

        coord.register_partition(5, endpoint.clone());

        assert_eq!(coord.num_partitions(), 1);
        assert_eq!(coord.get_partition_endpoint(5), Some(endpoint));
    }

    #[test]
    fn test_get_partition_endpoint() {
        let mut coord = PartitionCoordinator::new();
        let endpoint = PartitionEndpoint { address: "addr".to_string() };
        coord.register_partition(3, endpoint.clone());
        assert_eq!(coord.get_partition_endpoint(3), Some(endpoint));
        assert_eq!(coord.get_partition_endpoint(7), None);
    }

    #[test]
    fn test_num_partitions() {
        let coord = PartitionCoordinator::new();
        assert_eq!(coord.num_partitions(), 0);
    }

    #[test]
    fn test_rebalance_partitions() {
        let coord_empty = PartitionCoordinator::new();
        let plan_empty = coord_empty.rebalance_partitions().expect("ok");
        assert!(plan_empty.moves_from_partition.is_empty());

        let mut coord_nonempty = PartitionCoordinator::new();
        coord_nonempty.register_partition(2, PartitionEndpoint { address: "b".to_string() });
        let plan_nonempty = coord_nonempty.rebalance_partitions().expect("ok");
        assert_eq!(plan_nonempty.moves_from_partition.len(), 1);
        assert_eq!(plan_nonempty.moves_from_partition.get(&2), Some(&0));
    }
}
