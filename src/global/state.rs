#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
//! Global state representation
//!
//! This module provides the global state structure that maintains only the
//! Merkle root of wallet commitments. Global state roots are anchored
//! to Bitcoin to provide:
//! - Global ordering and timestamping
//! - Double-spending prevention
//! - Canonical state for dispute resolution
//!
//! While individual wallet/channel transitions can occur offline, global state
//! transitions must be anchored to Bitcoin to ensure global consistency.

use crate::types::{Bytes32, WalletCommitments};

/// Global state structure
///
/// Maintains the Merkle root of all wallet commitments. Global state roots are
/// anchored to Bitcoin for ordering, double-spending prevention, and dispute resolution.
///
/// The `changes` field is a changeset representing wallet commitments that changed
/// in this transition. It only contains wallets for which the local system has keys and
/// can create transitions.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct GlobalState {
    /// Merkle root of all wallet commitments
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
    /// * `root` - Merkle root of all wallet commitments
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
        let default = GlobalState::default();
        assert_eq!(default, GlobalState::default());
    }

    #[test]
    fn test_with_root_and_nonce() {
        let root = [1u8; 32];
        let nonce = 42;
        let state = GlobalState::with_root_and_nonce(root, nonce);
        assert_eq!(state.wallets_root, root);
        assert_eq!(state.nonce, nonce);
        assert!(state.changes.is_empty());
    }

    #[test]
    fn test_with_commitments() {
        let root = [2u8; 32];
        let nonce = 100;
        let mut changes = WalletCommitments::new();
        changes.insert([1u8; 32], [10u8; 32]);
        changes.insert([2u8; 32], [20u8; 32]);
        changes.insert([3u8; 32], [30u8; 32]);
        let changes_clone = changes.clone();
        let state = GlobalState::with_commitments(root, changes, nonce);
        assert_eq!(state.wallets_root, root);
        assert_eq!(state.nonce, nonce);
        assert_eq!(state.changes, changes_clone);
    }
}
