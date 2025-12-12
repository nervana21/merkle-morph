// SPDX-License-Identifier: CC0-1.0

//! Cross-partition transaction coordination.
//!
//! This module provides a two-phase commit (2PC) coordination mechanism for transactions
//! that affect multiple partitions. The implementation enforces resource reservation,
//! conflict detection, and proper locking to ensure consistency across partitions.

use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::types::PartitionId;
use crate::types::{ChannelId, WalletId};

/// Identifier for a prepared cross-partition transaction.
pub type PrepareId = u64;

/// State of a prepared transaction in the 2PC protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
enum PrepareState {
    /// Transaction is prepared and resources are reserved.
    Prepared,
    /// Transaction has been committed.
    Committed,
    /// Transaction has been aborted.
    Aborted,
}

/// Resource reservation for a partition.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ResourceReservation {
    /// Wallets reserved by this transaction.
    wallets: HashSet<WalletId>,
    /// Channels reserved by this transaction.
    channels: HashSet<ChannelId>,
    /// Optional expiration time for the reservation (for timeout handling).
    expires_at: Option<Instant>,
}

/// A prepared cross-partition transaction with its state and reservations.
struct PreparedTransaction {
    /// Resource reservations per partition.
    partition_reservations: BTreeMap<PartitionId, ResourceReservation>,
    /// Current state of the transaction.
    state: PrepareState,
}

/// Transaction that affects multiple partitions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrossPartitionTransaction {
    /// Wallets touched by this transaction, grouped by partition.
    pub wallets_by_partition: BTreeMap<PartitionId, Vec<WalletId>>,
    /// Channels touched by this transaction, grouped by partition.
    pub channels_by_partition: BTreeMap<PartitionId, Vec<ChannelId>>,
}

/// Response from a partition during the prepare phase.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartitionPrepareResponse {
    /// Partition that produced this response.
    pub partition_id: PartitionId,
    /// Whether the partition successfully reserved resources for this transaction.
    pub success: bool,
    /// Optional error message if preparation failed.
    pub error: Option<String>,
}

/// Internal state of the coordinator (protected by Mutex).
struct CoordinatorState {
    /// Next prepare ID to assign.
    next_prepare_id: PrepareId,
    /// Map of prepared transactions by prepare ID.
    prepared_transactions: BTreeMap<PrepareId, PreparedTransaction>,
    /// Map of active reservations by partition, then by resource (wallet/channel).
    active_reservations: BTreeMap<PartitionId, BTreeMap<PrepareId, ResourceReservation>>,
}

/// Coordinator for cross-partition transactions with thread-safe 2PC implementation.
pub struct CrossPartitionCoordinator {
    /// Internal state of the coordinator (protected by Mutex).
    state: Arc<Mutex<CoordinatorState>>,
    /// Timeout duration for resource reservations.
    timeout_duration: Duration,
}

impl Default for CrossPartitionCoordinator {
    fn default() -> Self { Self::new() }
}

impl CrossPartitionCoordinator {
    /// Create a new coordinator with default timeout (30 seconds).
    pub fn new() -> Self { Self::new_with_timeout(Duration::from_secs(30)) }

    /// Create a new coordinator with a custom timeout duration.
    ///
    /// # Arguments
    ///
    /// * `duration` - The timeout duration for resource reservations. Reservations
    ///   that are not committed or aborted within this duration will be automatically
    ///   cleaned up to prevent deadlocks.
    pub fn new_with_timeout(duration: Duration) -> Self {
        Self {
            state: Arc::new(Mutex::new(CoordinatorState {
                next_prepare_id: 0,
                prepared_transactions: BTreeMap::new(),
                active_reservations: BTreeMap::new(),
            })),
            timeout_duration: duration,
        }
    }

    /// Clean up expired reservations.
    ///
    /// This method removes reservations that have expired and marks the corresponding
    /// prepared transactions as aborted if they're still in Prepared state.
    fn cleanup_expired_reservations(&self, state: &mut CoordinatorState) {
        let now = Instant::now();
        let mut expired_prepare_ids = HashSet::new();

        // Find all expired reservations
        for (_, reservations) in state.active_reservations.iter_mut() {
            let mut to_remove = Vec::new();
            for (prepare_id, reservation) in reservations.iter() {
                if let Some(expires_at) = reservation.expires_at {
                    if expires_at < now {
                        to_remove.push(*prepare_id);
                        expired_prepare_ids.insert(*prepare_id);
                    }
                }
            }
            // Remove expired reservations
            for prepare_id in to_remove {
                reservations.remove(&prepare_id);
            }
        }

        // Mark expired prepared transactions as aborted
        for prepare_id in expired_prepare_ids {
            if let Some(prepared) = state.prepared_transactions.get_mut(&prepare_id) {
                if matches!(prepared.state, PrepareState::Prepared) {
                    prepared.state = PrepareState::Aborted;
                }
            }
        }
    }

    /// Phase 1: prepare a cross-partition transaction.
    ///
    /// This method:
    /// 1. Checks for conflicts with existing reservations
    /// 2. Reserves resources (wallets/channels) for each partition
    /// 3. Returns success/failure per partition
    /// 4. If any partition fails, all reservations are aborted
    pub fn prepare_cross_partition(
        &self,
        tx: CrossPartitionTransaction,
    ) -> crate::Result<(PrepareId, Vec<PartitionPrepareResponse>)> {
        let mut state = self.state.lock().map_err(|_| {
            crate::errors::GlobalError::Internal("coordinator mutex poisoned".into())
        })?;

        // Clean up expired reservations before processing
        self.cleanup_expired_reservations(&mut state);

        // Assign prepare ID
        let prepare_id = state.next_prepare_id;
        state.next_prepare_id = state
            .next_prepare_id
            .checked_add(1)
            .ok_or_else(|| crate::errors::GlobalError::Internal("prepare id overflow".into()))?;

        // Collect all partition IDs involved
        let mut partition_ids: Vec<PartitionId> = tx
            .wallets_by_partition
            .keys()
            .chain(tx.channels_by_partition.keys())
            .copied()
            .collect();
        partition_ids.sort();
        partition_ids.dedup();

        // Try to reserve resources for each partition
        let mut responses = Vec::new();
        let mut reservations = BTreeMap::new();
        let mut all_succeeded = true;

        for partition_id in partition_ids.iter() {
            let wallets = tx.wallets_by_partition.get(partition_id).cloned().unwrap_or_default();
            let channels = tx.channels_by_partition.get(partition_id).cloned().unwrap_or_default();

            let conflict =
                Self::find_reservation_conflict(&state, *partition_id, &wallets, &channels);

            if let Some(conflict_msg) = conflict {
                responses.push(PartitionPrepareResponse {
                    partition_id: *partition_id,
                    success: false,
                    error: Some(conflict_msg),
                });
                all_succeeded = false;
            } else {
                let reservation = ResourceReservation {
                    wallets: wallets.iter().copied().collect(),
                    channels: channels.iter().copied().collect(),
                    expires_at: Some(Instant::now() + self.timeout_duration),
                };
                reservations.insert(*partition_id, reservation.clone());
                state
                    .active_reservations
                    .entry(*partition_id)
                    .or_default()
                    .insert(prepare_id, reservation);

                responses.push(PartitionPrepareResponse {
                    partition_id: *partition_id,
                    success: true,
                    error: None,
                });
            }
        }

        // If any partition failed, abort all reservations
        if !all_succeeded {
            for partition_id in reservations.keys() {
                state.active_reservations.get_mut(partition_id).and_then(|r| r.remove(&prepare_id));
            }
            return Ok((prepare_id, responses));
        }

        // Store the prepared transaction
        state.prepared_transactions.insert(
            prepare_id,
            PreparedTransaction {
                partition_reservations: reservations,
                state: PrepareState::Prepared,
            },
        );

        responses.sort_by_key(|r| r.partition_id);
        Ok((prepare_id, responses))
    }

    /// Find a conflict with existing reservations.
    ///
    /// Returns the first conflict found (if any) as an error message.
    fn find_reservation_conflict(
        state: &CoordinatorState,
        partition_id: PartitionId,
        wallets: &[WalletId],
        channels: &[ChannelId],
    ) -> Option<String> {
        let active = state.active_reservations.get(&partition_id)?;
        let now = Instant::now();

        for (other_prepare_id, reservation) in active.iter() {
            // Skip expired reservations
            if let Some(expires_at) = reservation.expires_at {
                if expires_at < now {
                    continue;
                }
            }

            // Check wallet conflicts
            for wallet in wallets {
                if reservation.wallets.contains(wallet) {
                    return Some(format!(
                        "wallet {:?} already reserved by prepare_id {}",
                        wallet, other_prepare_id
                    ));
                }
            }

            // Check channel conflicts
            for channel in channels {
                if reservation.channels.contains(channel) {
                    return Some(format!(
                        "channel {:?} already reserved by prepare_id {}",
                        channel, other_prepare_id
                    ));
                }
            }
        }

        None
    }

    /// Phase 2: commit a previously prepared cross-partition transaction.
    ///
    /// This method:
    /// 1. Validates that the prepare_id exists and is in Prepared state
    /// 2. Marks the transaction as Committed
    /// 3. Releases reservations (resources are now "locked" by the committed batch)
    pub fn commit_cross_partition(&self, prepare_id: PrepareId) -> crate::Result<()> {
        let mut state = self.state.lock().map_err(|_| {
            crate::errors::GlobalError::Internal("coordinator mutex poisoned".into())
        })?;

        // Clean up expired reservations before processing
        self.cleanup_expired_reservations(&mut state);

        let prepared = state.prepared_transactions.get_mut(&prepare_id).ok_or_else(|| {
            crate::errors::GlobalError::InvalidParameters(format!(
                "prepare_id {} not found",
                prepare_id
            ))
        })?;

        match prepared.state {
            PrepareState::Prepared => {
                // Mark as committed
                prepared.state = PrepareState::Committed;

                // Release reservations (they're now committed to the batch)
                let partition_ids: Vec<_> =
                    prepared.partition_reservations.keys().copied().collect();
                for partition_id in partition_ids {
                    state
                        .active_reservations
                        .get_mut(&partition_id)
                        .and_then(|r| r.remove(&prepare_id));
                }

                Ok(())
            }
            PrepareState::Committed => Ok(()),
            PrepareState::Aborted =>
                Err(crate::Error::Global(crate::errors::GlobalError::InvalidParameters(format!(
                    "prepare_id {} was aborted, cannot commit",
                    prepare_id
                )))),
        }
    }

    /// Abort a previously prepared cross-partition transaction.
    ///
    /// This method:
    /// 1. Validates that the prepare_id exists
    /// 2. Releases all reservations
    /// 3. Marks the transaction as Aborted
    pub fn abort_cross_partition(&self, prepare_id: PrepareId) -> crate::Result<()> {
        let mut state = self.state.lock().map_err(|_| {
            crate::errors::GlobalError::Internal("coordinator mutex poisoned".into())
        })?;

        // Clean up expired reservations before processing
        self.cleanup_expired_reservations(&mut state);

        // Collect partition IDs first while we have the prepared reference
        let partition_ids: Vec<_> = {
            let prepared = state.prepared_transactions.get_mut(&prepare_id).ok_or_else(|| {
                crate::errors::GlobalError::InvalidParameters(format!(
                    "prepare_id {} not found",
                    prepare_id
                ))
            })?;
            prepared.partition_reservations.keys().copied().collect()
        };

        // Release all reservations (prepared reference is dropped, so we can borrow state mutably)
        for partition_id in partition_ids {
            state.active_reservations.get_mut(&partition_id).and_then(|r| r.remove(&prepare_id));
        }

        // Mark as aborted
        let prepared = state.prepared_transactions.get_mut(&prepare_id).ok_or_else(|| {
            crate::errors::GlobalError::InvalidParameters(format!(
                "prepare_id {} not found",
                prepare_id
            ))
        })?;
        prepared.state = PrepareState::Aborted;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let coord = CrossPartitionCoordinator::new();

        assert_eq!(coord.timeout_duration, Duration::from_secs(30));
    }

    #[test]
    fn test_new_with_timeout() {
        let duration = Duration::from_secs(5);

        let coord = CrossPartitionCoordinator::new_with_timeout(duration);

        assert_eq!(coord.timeout_duration, duration);
    }

    #[test]
    fn test_prepare_cross_partition() {
        let coord = CrossPartitionCoordinator::new();
        let empty_tx = CrossPartitionTransaction {
            wallets_by_partition: BTreeMap::new(),
            channels_by_partition: BTreeMap::new(),
        };

        let (id0, responses0) = coord
            .prepare_cross_partition(empty_tx)
            .expect("prepare should succeed for empty transaction");

        assert_eq!(id0, 0);
        assert!(responses0.is_empty());

        let mut wallets_only = BTreeMap::new();
        wallets_only.insert(1u32, vec![[1u8; 32]]);
        let tx1 = CrossPartitionTransaction {
            wallets_by_partition: wallets_only,
            channels_by_partition: BTreeMap::new(),
        };

        let (id1, responses1) = coord
            .prepare_cross_partition(tx1)
            .expect("prepare should succeed for wallets-only transaction");

        assert_eq!(id1, 1);
        assert_eq!(responses1.len(), 1);
        assert!(responses1[0].success);

        let mut channels_only = BTreeMap::new();
        channels_only.insert(2u32, vec![[10u8; 32]]);
        let tx2 = CrossPartitionTransaction {
            wallets_by_partition: BTreeMap::new(),
            channels_by_partition: channels_only,
        };

        let (id2, responses2) = coord
            .prepare_cross_partition(tx2)
            .expect("prepare should succeed for channels-only transaction");

        assert_eq!(id2, 2);
        assert_eq!(responses2.len(), 1);
        assert!(responses2[0].success);

        let mut both_wallets = BTreeMap::new();
        both_wallets.insert(3u32, vec![[2u8; 32]]);
        let mut both_channels = BTreeMap::new();
        both_channels.insert(3u32, vec![[11u8; 32]]);
        let tx3 = CrossPartitionTransaction {
            wallets_by_partition: both_wallets,
            channels_by_partition: both_channels,
        };

        let (id3, responses3) = coord
            .prepare_cross_partition(tx3)
            .expect("prepare should succeed for transaction with both wallets and channels");

        assert_eq!(id3, 3);
        assert_eq!(responses3.len(), 1);
        assert!(responses3[0].success);

        let mut dedup_wallets = BTreeMap::new();
        dedup_wallets.insert(4u32, vec![[3u8; 32]]);
        let mut dedup_channels = BTreeMap::new();
        dedup_channels.insert(4u32, vec![[12u8; 32]]);
        let tx4 = CrossPartitionTransaction {
            wallets_by_partition: dedup_wallets,
            channels_by_partition: dedup_channels,
        };

        let (id4, responses4) = coord
            .prepare_cross_partition(tx4)
            .expect("prepare should succeed for deduplicated transaction");

        assert_eq!(id4, 4);
        assert_eq!(responses4.len(), 1);

        let mut conflict_wallets = BTreeMap::new();
        conflict_wallets.insert(1u32, vec![[1u8; 32]]);
        let tx5 = CrossPartitionTransaction {
            wallets_by_partition: conflict_wallets,
            channels_by_partition: BTreeMap::new(),
        };

        let (id5, responses5) = coord
            .prepare_cross_partition(tx5)
            .expect("prepare should return error response for conflicting wallet");

        assert_eq!(id5, 5);
        assert_eq!(responses5.len(), 1);
        assert!(!responses5[0].success);
        assert!(responses5[0]
            .error
            .as_ref()
            .expect("error should be present for failed prepare")
            .contains("wallet"));

        let mut conflict_channels = BTreeMap::new();
        conflict_channels.insert(2u32, vec![[10u8; 32]]);
        let tx6 = CrossPartitionTransaction {
            wallets_by_partition: BTreeMap::new(),
            channels_by_partition: conflict_channels,
        };

        let (id6, responses6) = coord
            .prepare_cross_partition(tx6)
            .expect("prepare should return error response for conflicting channel");

        assert_eq!(id6, 6);
        assert_eq!(responses6.len(), 1);
        assert!(!responses6[0].success);
        assert!(responses6[0]
            .error
            .as_ref()
            .expect("error should be present for failed prepare")
            .contains("channel"));

        let mut multi_wallets = BTreeMap::new();
        multi_wallets.insert(5u32, vec![[4u8; 32]]);
        multi_wallets.insert(6u32, vec![[5u8; 32]]);
        let tx7 = CrossPartitionTransaction {
            wallets_by_partition: multi_wallets,
            channels_by_partition: BTreeMap::new(),
        };

        let (id7, responses7) = coord
            .prepare_cross_partition(tx7)
            .expect("prepare should succeed for multi-partition transaction");

        assert_eq!(id7, 7);
        assert_eq!(responses7.len(), 2);
        assert!(responses7.iter().all(|r| r.success));

        let mut partial_wallets = BTreeMap::new();
        partial_wallets.insert(7u32, vec![[6u8; 32]]);
        partial_wallets.insert(1u32, vec![[1u8; 32]]);
        let tx8 = CrossPartitionTransaction {
            wallets_by_partition: partial_wallets,
            channels_by_partition: BTreeMap::new(),
        };

        let (id8, responses8) = coord
            .prepare_cross_partition(tx8)
            .expect("prepare should return mixed success/failure for partial conflict");

        assert_eq!(id8, 8);
        assert_eq!(responses8.len(), 2);
        let success_count = responses8.iter().filter(|r| r.success).count();
        let fail_count = responses8.iter().filter(|r| !r.success).count();
        assert_eq!(success_count, 1);
        assert_eq!(fail_count, 1);
    }

    #[test]
    fn test_commit_cross_partition() {
        let coord = CrossPartitionCoordinator::new();

        let result = coord.commit_cross_partition(999);

        assert!(result.is_err());

        let mut wallets = BTreeMap::new();
        wallets.insert(1u32, vec![[1u8; 32]]);
        let tx = CrossPartitionTransaction {
            wallets_by_partition: wallets,
            channels_by_partition: BTreeMap::new(),
        };
        let (prepare_id, _) = coord.prepare_cross_partition(tx).expect("prepare should succeed");

        let result = coord.commit_cross_partition(prepare_id);

        assert!(result.is_ok());

        let result = coord.commit_cross_partition(prepare_id);

        assert!(result.is_ok());

        let mut wallets2 = BTreeMap::new();
        wallets2.insert(2u32, vec![[2u8; 32]]);
        let tx2 = CrossPartitionTransaction {
            wallets_by_partition: wallets2,
            channels_by_partition: BTreeMap::new(),
        };
        let (prepare_id2, _) = coord.prepare_cross_partition(tx2).expect("prepare should succeed");
        coord.abort_cross_partition(prepare_id2).expect("abort should succeed");

        let result = coord.commit_cross_partition(prepare_id2);

        assert!(result.is_err());
    }

    #[test]
    fn test_abort_cross_partition() {
        let coord = CrossPartitionCoordinator::new();

        let result = coord.abort_cross_partition(999);

        assert!(result.is_err());

        let mut wallets = BTreeMap::new();
        wallets.insert(1u32, vec![[1u8; 32]]);
        let tx = CrossPartitionTransaction {
            wallets_by_partition: wallets,
            channels_by_partition: BTreeMap::new(),
        };
        let (prepare_id, _) = coord.prepare_cross_partition(tx).expect("prepare should succeed");

        let result = coord.abort_cross_partition(prepare_id);

        assert!(result.is_ok());
    }
}
