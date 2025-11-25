//! Hasher implementations for SMT operations

use super::config::DEFAULT_CONFIG;
use crate::global::smt::{SmtConfig, SmtHasher};
use crate::types::Bytes32;
use crate::zkp::poseidon2_hash_fixed;

/// Poseidon2 hasher implementation for SMT operations
///
/// This struct implements the [`SmtHasher`] trait using Poseidon2.
#[derive(Clone, Copy, Debug, Default)]
pub struct Poseidon2Hasher;

impl SmtHasher for Poseidon2Hasher {
    fn hash_leaf(&self, domain_tag: &[u8], wallet_id: Bytes32, commitment: Bytes32) -> Bytes32 {
        poseidon2_hash_fixed(&[domain_tag, &wallet_id[..], &commitment[..]])
    }

    fn hash_internal(&self, domain_tag: &[u8], left: Bytes32, right: Bytes32) -> Bytes32 {
        poseidon2_hash_fixed(&[domain_tag, &left[..], &right[..]])
    }

    fn zero_hash(&self) -> Bytes32 { [0u8; 32] }
}

/// Default hasher instance (Poseidon2)
pub(crate) const DEFAULT_HASHER: Poseidon2Hasher = Poseidon2Hasher;

/// Computes an internal node hash using the default hasher and config
///
/// This is a convenience function for the common case where we use the default
/// Poseidon2 hasher and Merkle Morph v0 configuration.
#[inline]
pub(crate) fn hash_internal_node(left: Bytes32, right: Bytes32) -> Bytes32 {
    DEFAULT_HASHER.hash_internal(DEFAULT_CONFIG.internal_domain_tag(), left, right)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_leaf() {
        let hasher = Poseidon2Hasher;
        let domain_tag = b"test_domain";
        let wallet_id = [1u8; 32];
        let commitment = [2u8; 32];

        let result = hasher.hash_leaf(domain_tag, wallet_id, commitment);

        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_hash_internal() {
        let hasher = Poseidon2Hasher;
        let domain_tag = b"test_domain";
        let left = [1u8; 32];
        let right = [2u8; 32];

        let result = hasher.hash_internal(domain_tag, left, right);

        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_zero_hash() {
        let hasher = Poseidon2Hasher;

        let result = hasher.zero_hash();

        assert_eq!(result, [0u8; 32]);
    }
}
