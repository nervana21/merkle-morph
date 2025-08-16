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
}
