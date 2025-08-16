//! Global state management for wallet aggregation.
//!
//! This module provides the top-level state container that manages
//! a collection of wallets, each containing multiple payment channels.
//! The global state maintains a monotonic nonce for replay protection
//! across all wallet operations.

use crate::wallet::{WalletId, WalletState};
use std::collections::BTreeMap;

/// Type alias for a collection of wallets
pub type Wallets = BTreeMap<WalletId, WalletState>;

/// Global state structure with wallet management.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GlobalState {
    /// Collection of wallets indexed by wallet ID
    pub wallets: Wallets,
    /// Monotonic counter for replay protection
    pub nonce: u64,
}

impl GlobalState {
    /// Creates a new empty global state.
    pub fn new() -> Self {
        Self {
            wallets: Wallets::new(),
            nonce: 0,
        }
    }
}

impl Default for GlobalState {
    fn default() -> Self {
        Self::new()
    }
}

/// Inserts or updates a wallet in the global state.
///
/// # Arguments
/// * `global_state` - The global state to update
/// * `wallet_id` - The unique identifier for the wallet
/// * `wallet_state` - The wallet state to insert or update
///
/// # Note
/// This function inserts a new wallet if the wallet_id doesn't exist,
/// or updates an existing wallet if the wallet_id already exists.
/// The global nonce is incremented to ensure state uniqueness.
pub fn insert_wallet(
    global_state: &mut GlobalState,
    wallet_id: WalletId,
    wallet_state: WalletState,
) {
    global_state.wallets.insert(wallet_id, wallet_state);
    global_state.nonce += 1;
}

/// Retrieves a wallet from the global state.
///
/// # Arguments
/// * `global_state` - The global state to query
/// * `wallet_id` - The unique identifier for the wallet
///
/// # Returns
/// The wallet state if it exists, `None` otherwise
pub fn get_wallet<'a>(
    global_state: &'a GlobalState,
    wallet_id: &WalletId,
) -> Option<&'a WalletState> {
    global_state.wallets.get(wallet_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let state = GlobalState::new();
        assert!(state.wallets.is_empty());
        assert_eq!(state.nonce, 0);
    }

    #[test]
    fn test_insert_wallet() {
        let mut global_state = GlobalState::new();
        let wallet_id = [0u8; 32];
        let wallet_state = WalletState::new(wallet_id);

        // Test inserting new wallet
        insert_wallet(&mut global_state, wallet_id, wallet_state);
        assert!(global_state.wallets.contains_key(&wallet_id));
        assert_eq!(global_state.nonce, 1);

        // Test that inserting wallet with same ID increments nonce
        let second_wallet_state = WalletState::new(wallet_id);
        insert_wallet(&mut global_state, wallet_id, second_wallet_state);
        assert_eq!(global_state.nonce, 2);
    }

    #[test]
    fn test_get_wallet() {
        let mut global_state = GlobalState::new();
        let wallet_id = [0u8; 32];
        let wallet_state = WalletState::new(wallet_id);
        insert_wallet(&mut global_state, wallet_id, wallet_state);

        // Test retrieving existing wallet
        let retrieved_wallet = get_wallet(&global_state, &wallet_id);
        assert_eq!(retrieved_wallet.unwrap().wallet_id, wallet_id);

        // Test retrieving non-existent wallet
        let non_existent_id = [1u8; 32];
        let non_existent_wallet = get_wallet(&global_state, &non_existent_id);
        assert!(non_existent_wallet.is_none());
    }

    #[test]
    fn test_multiple_wallets() {
        let mut global_state = GlobalState::new();
        let wallet_id0 = [0u8; 32];
        let wallet_id1 = [1u8; 32];

        let wallet_state0 = WalletState::new(wallet_id0);
        let wallet_state1 = WalletState::new(wallet_id1);

        insert_wallet(&mut global_state, wallet_id0, wallet_state0);
        insert_wallet(&mut global_state, wallet_id1, wallet_state1);

        assert_eq!(global_state.nonce, 2);
        assert!(get_wallet(&global_state, &wallet_id0).is_some());
        assert!(get_wallet(&global_state, &wallet_id1).is_some());
    }
}
