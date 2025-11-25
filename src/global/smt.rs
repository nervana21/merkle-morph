//! Sparse Merkle Tree traits and abstractions
//!
//! This module defines traits for extensible SMT implementations, allowing
//! different hash functions, configurations, and tree structures to be used
//! while maintaining a consistent interface.

use std::collections::BTreeMap;

use crate::types::{Bytes32, WalletCommitment, WalletId};

/// Gets the bit value at the given depth (0-255) from a wallet ID
///
/// This utility function extracts a single bit from a 32-byte wallet ID at a specific depth.
/// The depth corresponds to the level in the Sparse Merkle Tree, where depth 0 is the root
/// and each subsequent depth uses the next bit of the wallet ID to determine the path.
///
/// # Arguments
/// * `wallet_id` - The 32-byte wallet identifier
/// * `depth` - The depth in the tree (0-255), corresponding to which bit to extract
///
/// # Returns
/// The bit value (0 or 1) at the specified depth, or 0 if depth is out of range
///
/// # Example
///
/// ```rust
/// use merkle_morph::global::smt::get_bit_at_depth;
///
/// let mut wallet_id = [0u8; 32];
/// wallet_id[0] = 0b10100000; // Set first byte
///
/// assert_eq!(get_bit_at_depth(&wallet_id, 0), 1); // First bit (MSB of first byte)
/// assert_eq!(get_bit_at_depth(&wallet_id, 1), 0); // Second bit
/// assert_eq!(get_bit_at_depth(&wallet_id, 2), 1); // Third bit
/// ```
pub fn get_bit_at_depth(wallet_id: &WalletId, depth: u8) -> u8 {
    let byte_index = (depth / 8) as usize;
    let bit_index = depth % 8;
    if byte_index < 32 {
        (wallet_id[byte_index] >> (7 - bit_index)) & 1
    } else {
        0
    }
}

/// Trait for hash functions used in Sparse Merkle Tree operations
///
/// This trait abstracts over different hash function implementations,
/// allowing the SMT to work with different hash algorithms while
/// maintaining the same interface.
///
/// # Example
///
/// ```rust,no_run
/// use merkle_morph::global::smt::SmtHasher;
/// use merkle_morph::types::Bytes32;
///
/// struct Poseidon2Hasher;
///
/// impl SmtHasher for Poseidon2Hasher {
///     fn hash_leaf(&self, domain_tag: &[u8], wallet_id: Bytes32, commitment: Bytes32) -> Bytes32 {
///         // Implementation using Poseidon2
///         # [0u8; 32]
///     }
///
///     fn hash_internal(&self, domain_tag: &[u8], left: Bytes32, right: Bytes32) -> Bytes32 {
///         // Implementation using Poseidon2
///         # [0u8; 32]
///     }
///
///     fn zero_hash(&self) -> Bytes32 {
///         [0u8; 32]
///     }
/// }
/// ```
pub trait SmtHasher {
    /// Computes the hash for a leaf node
    ///
    /// The leaf hash combines the domain tag, wallet ID, and wallet commitment.
    /// This ensures domain separation and prevents hash collisions.
    ///
    /// # Arguments
    /// * `domain_tag` - Domain separation tag (e.g., `"MM_WLT_v0"`)
    /// * `wallet_id` - The wallet identifier (32 bytes)
    /// * `commitment` - The wallet commitment (32 bytes)
    ///
    /// # Returns
    /// The computed leaf hash (32 bytes)
    fn hash_leaf(&self, domain_tag: &[u8], wallet_id: Bytes32, commitment: Bytes32) -> Bytes32;

    /// Computes the hash for an internal node
    ///
    /// The internal node hash combines the domain tag with the left and right
    /// child hashes to form the parent node hash.
    ///
    /// # Arguments
    /// * `domain_tag` - Domain separation tag (e.g., `"MM_GLOBAL_v0"`)
    /// * `left` - Left child hash (32 bytes)
    /// * `right` - Right child hash (32 bytes)
    ///
    /// # Returns
    /// The computed internal node hash (32 bytes)
    fn hash_internal(&self, domain_tag: &[u8], left: Bytes32, right: Bytes32) -> Bytes32;

    /// Returns the zero hash used for empty nodes
    ///
    /// Empty nodes in the SMT use a special zero hash value. This must be
    /// consistent across all operations to ensure tree structure correctness.
    ///
    /// # Returns
    /// The zero hash value (32 bytes)
    fn zero_hash(&self) -> Bytes32;
}

/// Trait for SMT configuration parameters
///
/// This trait abstracts over different configuration options for the SMT,
/// allowing protocol versioning and customization of domain tags and tree
/// parameters.
///
/// # Example
///
/// ```rust,no_run
/// use merkle_morph::global::smt::SmtConfig;
///
/// struct MerkleMorphV0Config;
///
/// impl SmtConfig for MerkleMorphV0Config {
///     fn leaf_domain_tag(&self) -> &[u8] {
///         b"MM_WLT_v0"
///     }
///
///     fn internal_domain_tag(&self) -> &[u8] {
///         b"MM_GLOBAL_v0"
///     }
///
///     fn max_depth(&self) -> u8 {
///         255
///     }
/// }
/// ```
pub trait SmtConfig {
    /// Returns the domain tag for leaf nodes
    ///
    /// This tag is used to prefix leaf node hashes, ensuring domain
    /// separation and preventing hash collisions.
    ///
    /// # Returns
    /// The leaf domain tag as a byte slice
    fn leaf_domain_tag(&self) -> &[u8];

    /// Returns the domain tag for internal nodes
    ///
    /// This tag is used to prefix internal node hashes, ensuring domain
    /// separation from leaf nodes and other hash contexts.
    ///
    /// # Returns
    /// The internal domain tag as a byte slice
    fn internal_domain_tag(&self) -> &[u8];

    /// Returns the maximum depth of the tree
    ///
    /// The tree depth determines how many bits of the wallet ID are used
    /// for the path. For 256-bit wallet IDs, this should be 255 (0-indexed).
    ///
    /// # Returns
    /// The maximum depth (0-indexed, so 255 for 256-bit IDs)
    fn max_depth(&self) -> u8;
}

/// Provides sibling hashes for Merkle proof generation
///
/// Provides functionality for obtaining sibling hashes
/// from different sources (memory, database, network)
/// without needing individual wallet commitments in memory.
/// Sibling hashes are obtained from available subtree roots or SMT nodes.
///
/// # Example
///
/// ```rust,no_run
/// use merkle_morph::global::smt::{SmtSiblingProvider, SmtHasher, SmtConfig};
/// use merkle_morph::types::{Bytes32, WalletId};
/// use merkle_morph::errors::Result;
///
/// struct DatabaseProvider;
///
/// impl<H: SmtHasher, C: SmtConfig> SmtSiblingProvider<H, C> for DatabaseProvider {
///     fn get_sibling_hash(
///         &mut self,
///         wallet_id: WalletId,
///         depth: u8,
///         hasher: &H,
///         config: &C,
///     ) -> Result<Bytes32> {
///         // Query database for sibling hash at this depth
///         // This can be an untrusted database - verification happens later
///         # Ok([0u8; 32])
///     }
/// }
/// ```
pub trait SmtSiblingProvider<H: SmtHasher, C: SmtConfig> {
    /// Gets the sibling hash at a specific depth for a wallet ID
    ///
    /// The sibling is the hash of the subtree with the opposite bit at this
    /// depth, but same prefix up to depth-1.
    ///
    /// # Arguments
    /// * `wallet_id` - The wallet ID to find the sibling for
    /// * `depth` - The depth to find the sibling at (0 = root level)
    /// * `hasher` - The hash function implementation
    /// * `config` - The SMT configuration
    ///
    /// # Returns
    /// The sibling hash at this depth, or zero hash if the sibling subtree is empty
    fn get_sibling_hash(
        &mut self,
        wallet_id: WalletId,
        depth: u8,
        hasher: &H,
        config: &C,
    ) -> crate::errors::Result<Bytes32>;
}

/// Trait for core Sparse Merkle Tree operations
///
/// This trait defines the essential operations for building and working with
/// Sparse Merkle Trees.
///
/// The trait is generic over `H` (hasher) and `C` (config) to allow different
/// combinations of hash functions and configurations.
pub trait SparseMerkleTree<H: SmtHasher, C: SmtConfig> {
    /// Computes the root hash of the SMT for the given wallet commitments
    ///
    /// This is the core operation that builds the tree structure from a set
    /// of wallet commitments and returns the root hash.
    ///
    /// # Arguments
    /// * `wallet_commitments` - Map of wallet IDs to their commitments
    /// * `hasher` - The hash function implementation
    /// * `config` - The SMT configuration
    ///
    /// # Returns
    /// The root hash of the SMT, or the zero hash if empty
    fn compute_root(
        &self,
        wallet_commitments: &BTreeMap<WalletId, WalletCommitment>,
        hasher: &H,
        config: &C,
    ) -> Bytes32;
}
