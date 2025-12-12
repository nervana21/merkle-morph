// SPDX-License-Identifier: CC0-1.0

//! Executor abstraction for state transition execution.
//!
//! This module provides the `Executor` trait for executing wallet transitions and
//! computing global roots. Implementations can use different storage backends
//! (in-memory, database, distributed) while maintaining the same interface.
//!
//! The executor owns and manages wallet state, allowing different execution
//! strategies (optimistic, pessimistic, parallel) to be plugged in without
//! changing scheduler logic.

use std::collections::BTreeMap;

use crate::global::commitment::types::GlobalRoot;
use crate::types::CHAIN_DOMAIN;
use crate::{
    apply_operation, compute_commitment_from_channels, poseidon2_hash_fixed, Batch, Result,
    WalletCommitment, WalletId, WalletState, WalletTransition,
};

/// Trait for executing wallet transitions and computing global state.
///
/// Executors own and manage wallet state, providing methods to:
/// - Retrieve wallet state
/// - Apply wallet transitions
/// - Compute global roots
/// - Replay batches (for verification)
///
/// Implementations can use different storage backends (in-memory, database,
/// distributed) while maintaining the same interface.
pub trait Executor: Send + Sync {
    /// Get a wallet state by ID.
    ///
    /// Returns `Ok(Some(state))` if the wallet exists, `Ok(None)` if it doesn't,
    /// or an error if retrieval fails.
    fn get_wallet(&self, wallet_id: WalletId) -> Result<Option<WalletState>>;

    /// Get all wallets managed by this executor.
    ///
    /// Returns a map of all wallet IDs to their current states. Implementations
    /// should override this method if they can provide a more efficient
    /// implementation for their storage backend.
    fn get_all_wallets(&self) -> Result<BTreeMap<WalletId, WalletState>> { Ok(BTreeMap::new()) }

    /// Apply a wallet transition and update the executor's state.
    ///
    /// This method:
    /// 1. Retrieves the current wallet state (or creates a new one if missing)
    /// 2. Applies the transition
    /// 3. Updates the wallet commitment
    /// 4. Stores the updated state
    ///
    /// Returns the updated wallet commitment.
    fn apply_wallet_transition(
        &mut self,
        wallet_id: WalletId,
        transition: &WalletTransition,
    ) -> Result<WalletCommitment>;

    /// Compute the global root from all wallets in the executor.
    ///
    /// Uses hash chain aggregation over sorted wallet IDs to deterministically
    /// compute the global state root.
    fn compute_global_root(&self) -> Result<GlobalRoot>;

    /// Replay a batch of transitions without modifying state (for verification).
    ///
    /// This method applies all transitions in the batch to a copy of the current
    /// state and returns the resulting global root. The executor's state is not
    /// modified.
    ///
    /// Returns the post-batch global root.
    fn replay_batch(&self, batch: &Batch) -> Result<GlobalRoot> {
        let mut wallets = self.get_all_wallets()?;
        for (wallet_id, transition) in batch.affected_wallets.iter().zip(batch.transitions.iter()) {
            let wallet =
                wallets.get(wallet_id).cloned().unwrap_or_else(|| WalletState::new(*wallet_id));
            let updated = apply_operation(wallet, transition)?;
            let commitment = compute_commitment_from_channels(*wallet_id, &updated.channels)?;
            wallets.insert(*wallet_id, WalletState { commitment, ..updated });
        }
        Ok(compute_global_root_from_wallets(&wallets))
    }
}

/// Async version of the Executor trait for database-backed and network-based implementations.
///
/// This trait provides async methods for executors that need to perform I/O operations.
/// Implementations can use this for database queries, network requests, or other async operations.
#[async_trait::async_trait]
pub trait AsyncExecutor: Send + Sync {
    /// Get a wallet state by ID (async).
    async fn get_wallet(&self, wallet_id: WalletId) -> Result<Option<WalletState>>;

    /// Get all wallets managed by this executor (async).
    async fn get_all_wallets(&self) -> Result<BTreeMap<WalletId, WalletState>>;

    /// Apply a wallet transition and update the executor's state (async).
    async fn apply_wallet_transition(
        &mut self,
        wallet_id: WalletId,
        transition: &WalletTransition,
    ) -> Result<WalletCommitment>;

    /// Compute the global root from all wallets in the executor (async).
    async fn compute_global_root(&self) -> Result<GlobalRoot>;

    /// Replay a batch of transitions without modifying state (async).
    async fn replay_batch(&self, batch: &Batch) -> Result<GlobalRoot>;
}

/// In-memory executor implementation using a BTreeMap for wallet storage.
///
/// Stores all wallet state in memory and uses hash chain aggregation for global
/// root computation. Provides O(log n) lookups and deterministic ordering.
#[derive(Clone, Debug)]
pub struct InMemoryExecutor {
    wallets: BTreeMap<WalletId, WalletState>,
}

impl InMemoryExecutor {
    /// Create a new in-memory executor with an initial wallet map.
    pub fn new(wallets: BTreeMap<WalletId, WalletState>) -> Self { Self { wallets } }

    /// Create a new empty in-memory executor.
    pub fn empty() -> Self { Self { wallets: BTreeMap::new() } }

    /// Get a reference to the internal wallet map.
    pub fn wallets(&self) -> &BTreeMap<WalletId, WalletState> { &self.wallets }

    /// Get a mutable reference to the internal wallet map.
    pub fn wallets_mut(&mut self) -> &mut BTreeMap<WalletId, WalletState> { &mut self.wallets }
}

impl Executor for InMemoryExecutor {
    fn get_wallet(&self, wallet_id: WalletId) -> Result<Option<WalletState>> {
        Ok(self.wallets.get(&wallet_id).cloned())
    }

    fn get_all_wallets(&self) -> Result<BTreeMap<WalletId, WalletState>> {
        Ok(self.wallets.clone())
    }

    fn apply_wallet_transition(
        &mut self,
        wallet_id: WalletId,
        transition: &WalletTransition,
    ) -> Result<WalletCommitment> {
        let wallet =
            self.wallets.get(&wallet_id).cloned().unwrap_or_else(|| WalletState::new(wallet_id));
        let updated = apply_operation(wallet, transition)?;
        let commitment = compute_commitment_from_channels(wallet_id, &updated.channels)?;
        self.wallets.insert(wallet_id, WalletState { commitment, ..updated });
        Ok(commitment)
    }

    fn compute_global_root(&self) -> Result<GlobalRoot> {
        Ok(compute_global_root_from_wallets(&self.wallets))
    }
}

/// Deterministically hash all wallet commitments into a single global root.
///
/// Uses a hash chain aggregation over sorted wallet IDs to produce a
/// deterministic global state root. The aggregation order is guaranteed by
/// BTreeMap's sorted iteration.
pub fn compute_global_root_from_wallets(wallets: &BTreeMap<WalletId, WalletState>) -> GlobalRoot {
    let mut acc = [0u8; 32];
    for (wallet_id, state) in wallets.iter() {
        acc =
            poseidon2_hash_fixed(&[CHAIN_DOMAIN, &acc[..], &wallet_id[..], &state.commitment[..]]);
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduler::batch::{Batch, BatchProofBundle, FeeMetadata};

    #[test]
    fn test_new() {
        let wallet_id = [1u8; 32];

        let mut wallets = BTreeMap::new();

        wallets.insert(wallet_id, WalletState::new(wallet_id));
        let executor = InMemoryExecutor::new(wallets);
        assert_eq!(executor.wallets.len(), 1);
    }

    #[test]
    fn test_empty() {
        let executor = InMemoryExecutor::empty();

        assert!(executor.wallets.is_empty());
    }

    #[test]
    fn test_wallets() {
        let wallet_id = [2u8; 32];
        let mut wallets = BTreeMap::new();
        wallets.insert(wallet_id, WalletState::new(wallet_id));
        let executor = InMemoryExecutor::new(wallets);

        let wallets_ref = executor.wallets();

        assert_eq!(wallets_ref.len(), 1);
    }

    #[test]
    fn test_wallets_mut() {
        let wallet_id = [3u8; 32];
        let mut executor = InMemoryExecutor::empty();

        let wallets_mut = executor.wallets_mut();

        wallets_mut.insert(wallet_id, WalletState::new(wallet_id));
        assert_eq!(executor.wallets.len(), 1);
    }

    #[test]
    fn test_compute_global_root_from_wallets() {
        let empty_wallets = BTreeMap::new();

        let empty_root = compute_global_root_from_wallets(&empty_wallets);

        assert_eq!(empty_root, [0u8; 32]);

        let wallet_id = [4u8; 32];
        let mut wallets = BTreeMap::new();
        wallets.insert(wallet_id, WalletState::new(wallet_id));

        let non_empty_root = compute_global_root_from_wallets(&wallets);

        assert_ne!(non_empty_root, [0u8; 32]);
    }

    #[test]
    fn test_get_wallet() {
        let wallet_id1 = [5u8; 32];
        let wallet_id2 = [6u8; 32];
        let mut wallets = BTreeMap::new();
        wallets.insert(wallet_id1, WalletState::new(wallet_id1));
        let executor = InMemoryExecutor::new(wallets);

        let existing = executor.get_wallet(wallet_id1).expect("get_wallet should succeed");

        assert!(existing.is_some());

        let missing = executor.get_wallet(wallet_id2).expect("get_wallet should succeed");

        assert!(missing.is_none());
    }

    #[test]
    fn test_get_all_wallets() {
        let wallet_id = [7u8; 32];
        let mut wallets = BTreeMap::new();
        wallets.insert(wallet_id, WalletState::new(wallet_id));
        let executor = InMemoryExecutor::new(wallets.clone());

        let all_wallets = executor.get_all_wallets().expect("get_all_wallets should succeed");

        assert_eq!(all_wallets.len(), 1);
        assert_eq!(all_wallets.get(&wallet_id).expect("wallet should exist").id, wallet_id);
    }

    #[test]
    fn test_apply_wallet_transition() {
        let wallet_id1 = [8u8; 32];
        let wallet_id2 = [9u8; 32];
        let channel_id = [10u8; 32];
        let channel_commitment = [11u8; 32];
        let mut wallets = BTreeMap::new();
        wallets.insert(wallet_id1, WalletState::new(wallet_id1));
        let mut executor = InMemoryExecutor::new(wallets);
        let transition = WalletTransition::InsertChannel { channel_id, channel_commitment };

        let commitment_existing = executor
            .apply_wallet_transition(wallet_id1, &transition)
            .expect("apply_wallet_transition should succeed");

        assert_ne!(commitment_existing, [0u8; 32]);

        let commitment_new = executor
            .apply_wallet_transition(wallet_id2, &transition)
            .expect("apply_wallet_transition should succeed");

        assert_ne!(commitment_new, [0u8; 32]);
    }

    #[test]
    fn test_compute_global_root() {
        let wallet_id = [12u8; 32];
        let mut wallets = BTreeMap::new();
        wallets.insert(wallet_id, WalletState::new(wallet_id));
        let executor = InMemoryExecutor::new(wallets);
        let root = executor.compute_global_root().expect("compute_global_root should succeed");
        assert_ne!(root, [0u8; 32]);
    }

    #[test]
    fn test_replay_batch() {
        let wallet_id1 = [13u8; 32];
        let wallet_id2 = [14u8; 32];
        let channel_id = [15u8; 32];
        let channel_commitment = [16u8; 32];
        let empty_executor = InMemoryExecutor::empty();
        let empty_batch = Batch::new(
            vec![],
            vec![],
            [0u8; 32],
            [0u8; 32],
            0,
            [0u8; 32],
            FeeMetadata { fee_rate: None, payer: None },
            BatchProofBundle { batch_proof: None, wallet_transition_proofs: vec![] },
        );

        let empty_root =
            empty_executor.replay_batch(&empty_batch).expect("replay_batch should succeed");

        assert_eq!(empty_root, [0u8; 32]);

        let mut wallets = BTreeMap::new();
        wallets.insert(wallet_id1, WalletState::new(wallet_id1));
        let executor_with_wallet = InMemoryExecutor::new(wallets);
        let transition = WalletTransition::InsertChannel { channel_id, channel_commitment };
        let batch_existing = Batch::new(
            vec![transition.clone()],
            vec![wallet_id1],
            [0u8; 32],
            [0u8; 32],
            1,
            [0u8; 32],
            FeeMetadata { fee_rate: None, payer: None },
            BatchProofBundle { batch_proof: None, wallet_transition_proofs: vec![] },
        );

        let existing_root = executor_with_wallet
            .replay_batch(&batch_existing)
            .expect("replay_batch should succeed");

        assert_ne!(existing_root, [0u8; 32]);

        let batch_new = Batch::new(
            vec![transition],
            vec![wallet_id2],
            [0u8; 32],
            [0u8; 32],
            2,
            [0u8; 32],
            FeeMetadata { fee_rate: None, payer: None },
            BatchProofBundle { batch_proof: None, wallet_transition_proofs: vec![] },
        );

        let new_root =
            executor_with_wallet.replay_batch(&batch_new).expect("replay_batch should succeed");

        assert_ne!(new_root, [0u8; 32]);
    }
}
