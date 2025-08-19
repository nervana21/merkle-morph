//! Global state management for wallet aggregation.
//!
//! This module provides the top-level state container that manages
//! a collection of wallets, each containing multiple payment channels.
//! The global state maintains a monotonic nonce for replay protection
//! across all wallet operations.
use std::collections::BTreeMap;

use crate::errors::GlobalError;
use crate::types::WalletId;
use crate::wallet::WalletState;

/// Type alias for a collection of wallets
pub type Wallets = BTreeMap<WalletId, WalletState>;

/// Global state structure with wallet management.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GlobalState {
    /// Collection of wallets indexed by wallet ID
    pub wallets: Wallets,
    /// Monotonic counter for replay protection on global state updates
    pub nonce: u64,
}

impl GlobalState {
    /// Creates a new empty global state.
    pub fn new() -> Self { Self { wallets: Wallets::new(), nonce: 0 } }
}

impl Default for GlobalState {
    fn default() -> Self { Self::new() }
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
) -> Result<(), GlobalError> {
    global_state.wallets.insert(wallet_id, wallet_state);
    global_state.nonce =
        global_state.nonce.checked_add(1).ok_or(GlobalError::GlobalNonceOverflow)?;
    Ok(())
}

/// Retrieves a wallet from the global state.
///
/// # Arguments
/// * `global_state` - The global state to query
/// * `wallet_id` - The unique identifier for the wallet
///
/// # Returns
/// The wallet state if it exists, or a `GlobalError::WalletNotFound` error
pub fn get_wallet<'a>(
    global_state: &'a GlobalState,
    wallet_id: &WalletId,
) -> Result<&'a WalletState, GlobalError> {
    global_state.wallets.get(wallet_id).ok_or(GlobalError::WalletNotFound(*wallet_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let new = GlobalState::new();
        assert!(new.wallets.is_empty());
        assert_eq!(new.nonce, 0);
    }

    #[test]
    fn test_default() {
        let new = GlobalState::new();
        let default = GlobalState::default();
        assert_eq!(new, default);
    }

    #[test]
    fn test_insert_wallet() {
        let mut global = GlobalState::new();
        let wallet_id = [0u8; 32];
        let wallet_state = WalletState::new(wallet_id);

        // Test inserting new wallet
        insert_wallet(&mut global, wallet_id, wallet_state.clone()).unwrap();
        assert!(global.wallets.contains_key(&wallet_id));
        assert_eq!(global.nonce, 1);

        // Test that inserting wallet with same ID increments nonce
        let same_id = WalletState::new(wallet_id);
        insert_wallet(&mut global, wallet_id, same_id).unwrap();
        assert_eq!(global.nonce, 2);

        // Test GlobalNonceOverflow error
        global.nonce = u64::MAX;
        let nonce_overflow = insert_wallet(&mut global, wallet_id, wallet_state);
        assert!(matches!(nonce_overflow, Err(GlobalError::GlobalNonceOverflow)));
    }

    #[test]
    fn test_get_wallet() {
        let mut global = GlobalState::new();
        let wallet_id = [0u8; 32];
        let wallet_state = WalletState::new(wallet_id);
        insert_wallet(&mut global, wallet_id, wallet_state).unwrap();

        // Test retrieving existing wallet
        let existing = get_wallet(&global, &wallet_id);
        assert_eq!(existing.unwrap().wallet_id, wallet_id);

        // Test retrieving non-existent wallet
        let non_existent_id = [1u8; 32];
        let non_existent = get_wallet(&global, &non_existent_id);
        assert_eq!(non_existent.unwrap_err(), GlobalError::WalletNotFound(non_existent_id));
    }
}
