//! Cryptographic hash functions and state management
use sha2::{Digest, Sha256};

/// Type alias for 32-byte arrays used throughout cryptographic operations
pub type Bytes32 = [u8; 32];

/// A state representing the current state hash and nonce
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    /// The state hash representing the current state
    pub root: Bytes32,
    /// The current nonce value
    pub nonce: u64,
}

/// Computes a new hash by chaining the old hash with new input data.
/// Uses domain separation with tag "MM_CHAIN_v1" for future-proofing.
pub fn compute_hash_chain(old: Bytes32, input: &[u8]) -> Bytes32 {
    let mut hasher = Sha256::new();
    hasher.update(b"MM_CHAIN_v1");
    hasher.update(old);
    hasher.update(input);
    hasher.finalize().into()
}

/// Applies a wallet update to the global state and increases nonce by 1
pub fn global_apply_wallet_update(global: &State, wallet_commitment: Bytes32) -> State {
    let mut next = global.clone();

    // Create input that includes the wallet commitment
    let mut input = Vec::new();
    input.extend_from_slice(b"wallet-update:");
    input.extend_from_slice(&wallet_commitment);

    // Update global state hash using the existing hash mechanism
    next.root = compute_hash_chain(global.root, &input);

    // Nonce +1 invariant
    next.nonce = global.nonce + 1;

    next
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_hash_chain() {
        let empty = [0u8; 32];
        let input1 = b"test1";
        let input2 = b"test2";

        // Test determinism and uniqueness
        let hash1 = compute_hash_chain(empty, input1);
        let hash2 = compute_hash_chain(empty, input2);
        assert_eq!(compute_hash_chain(empty, input1), hash1); // determinism
        assert_ne!(hash1, hash2); // uniqueness
        assert_ne!(hash1, empty); // not identity

        // Test chaining
        let chain1 = compute_hash_chain(compute_hash_chain(empty, b"a"), b"b");
        let chain2 = compute_hash_chain(empty, b"ab");
        assert_ne!(chain1, chain2); // chaining != concatenation
    }

    #[test]
    fn test_global_apply_wallet_update() {
        let global = State {
            root: [0u8; 32],
            nonce: 0,
        };
        let wallet_commitment = [21u8; 32];

        let updated_global = global_apply_wallet_update(&global, wallet_commitment);

        // Test nonce increment
        assert_eq!(updated_global.nonce, global.nonce + 1);

        // Test state hash changes
        assert_ne!(updated_global.root, global.root);

        // Test determinism
        let updated_global2 = global_apply_wallet_update(&global, wallet_commitment);
        assert_eq!(updated_global.root, updated_global2.root);
        assert_eq!(updated_global.nonce, updated_global2.nonce);

        // Test different inputs produce different results
        let different_wallet_commitment = [99u8; 32];
        let updated_global3 = global_apply_wallet_update(&global, different_wallet_commitment);
        assert_ne!(updated_global.root, updated_global3.root);
        assert_eq!(updated_global3.nonce, global.nonce + 1);
    }
}
