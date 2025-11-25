//! Global state representation
//!
//! This module provides the global state structure that maintains the
//! Merkle root of the global Sparse Merkle Tree. The global root is computed
//! by composing subtree roots, enabling verification without access to individual
//! wallet commitments. Global state roots are anchored to Bitcoin for ordering,
//! double-spending prevention, and dispute resolution.

use crate::types::{Bytes32, WalletCommitments};

/// Global state structure
///
/// Maintains the Merkle root of the global Sparse Merkle Tree, computed by composing
/// subtree roots. Global state roots are anchored to Bitcoin for ordering,
/// double-spending prevention, and dispute resolution.
///
/// The `changes` field is a changeset representing wallet commitments that changed
/// in this transition. It only contains wallets for which the local system has keys and
/// can create transitions.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct GlobalState {
    /// Merkle root of the global SMT (computed by composing subtree roots)
    pub wallets_root: Bytes32,
    /// Local wallet commitments that changed in this transition
    pub changes: WalletCommitments,
    /// Current nonce
    pub nonce: u32,
}

impl GlobalState {
    /// Creates a new empty global state
    pub fn new() -> Self {
        Self { wallets_root: [0u8; 32], changes: WalletCommitments::new(), nonce: 0 }
    }

    /// Creates a global state with a specific root and nonce
    pub fn with_root_and_nonce(root: Bytes32, nonce: u32) -> Self {
        Self { wallets_root: root, changes: WalletCommitments::new(), nonce }
    }

    /// Creates a global state with root, nonce, and wallet commitments
    ///
    /// # Arguments
    /// * `root` - Merkle root of the global SMT (computed by composing subtree roots)
    /// * `changes` - Local wallet commitments that changed in this transition
    /// * `nonce` - Current nonce
    pub fn with_commitments(root: Bytes32, changes: WalletCommitments, nonce: u32) -> Self {
        Self { wallets_root: root, changes, nonce }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let state = GlobalState::new();

        assert_eq!(state.wallets_root, [0u8; 32]);
        assert_eq!(state.changes, WalletCommitments::new());
        assert_eq!(state.nonce, 0);
    }

    #[test]
    fn test_with_root_and_nonce() {
        let root = [1u8; 32];
        let nonce = 42u32;

        let state = GlobalState::with_root_and_nonce(root, nonce);

        assert_eq!(state.wallets_root, root);
        assert_eq!(state.changes, WalletCommitments::new());
        assert_eq!(state.nonce, nonce);
    }

    #[test]
    fn test_with_commitments() {
        let root = [2u8; 32];
        let mut changes = WalletCommitments::new();
        let wallet_id = [3u8; 32];
        let commitment = [4u8; 32];
        changes.insert(wallet_id, commitment);
        let nonce = 100u32;

        let state = GlobalState::with_commitments(root, changes.clone(), nonce);

        assert_eq!(state.wallets_root, root);
        assert_eq!(state.changes, changes);
        assert_eq!(state.nonce, nonce);
    }
}
