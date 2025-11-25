//! Sparse Merkle Tree traits and abstractions
//!
//! This module defines traits for extensible SMT implementations, allowing
//! different hash functions, configurations, and tree structures to be used
//! while maintaining a consistent interface.
//!
//! # Usage Example
//!
//! ```rust
//! use merkle_morph::global::commitment::{build_smt_root_with, MerkleMorphV0Config, Poseidon2Hasher};
//! use merkle_morph::global::smt::{SmtConfig, SmtHasher};
//! use std::collections::BTreeMap;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Use the default implementation
//! let mut commitments = BTreeMap::new();
//! commitments.insert([1u8; 32], [2u8; 32]);
//! let subtree = merkle_morph::global::compute_subtree_root(&commitments, [1u8; 32], [1u8; 32])?;
//! let root = merkle_morph::global::compose_to_global_root(&[subtree])?;
//!
//! // Or use the trait-based API explicitly
//! let hasher = Poseidon2Hasher;
//! let config = MerkleMorphV0Config;
//! let root2 = build_smt_root_with(&hasher, &config, &commitments);
//! assert_eq!(root, root2);
//! # Ok(())
//! # }
//! ```
//!
//! # Protocol Versioning Example
//!
//! To support a new protocol version with different domain tags:
//!
//! ```rust,no_run
//! use merkle_morph::global::smt::{SmtConfig, SmtHasher};
//! use merkle_morph::global::commitment::{build_smt_root_with, Poseidon2Hasher};
//!
//! struct MerkleMorphV1Config;
//!
//! impl SmtConfig for MerkleMorphV1Config {
//!     fn leaf_domain_tag(&self) -> &[u8] {
//!         b"MM_WLT_v1"  // New version tag
//!     }
//!
//!     fn internal_domain_tag(&self) -> &[u8] {
//!         b"MM_GLOBAL_v1"  // New version tag
//!     }
//!
//!     fn max_depth(&self) -> u8 {
//!         255
//!     }
//! }
//!
//! // Use the new config
//! let hasher = Poseidon2Hasher;
//! let config = MerkleMorphV1Config;
//! // ... use with build_smt_root_with
//! ```
//!
//! # Why Custom Implementation?
//!
//! The Merkle Morph protocol requires very specific SMT properties that make
//! generic libraries unsuitable:
//!
//! - **Custom domain separation tags**: Protocol-specific tags (`"MM_WLT_v0"`,
//!   `"MM_GLOBAL_v0"`) must be used exactly as specified for compatibility
//!   with the ZKP system and other protocol components.
//!
//! - **Subtree composition**: The protocol requires subtree roots with range
//!   tracking (`SubtreeRoot`) for partial verification, allowing users to
//!   verify global state without downloading all wallet data.
//!
//! - **256-bit depth**: The tree uses all 256 bits of wallet IDs for the path,
//!   providing a complete mapping from wallet ID space to tree structure.
//!
//! - **Zero hash for empty nodes**: Empty nodes use `[0u8; 32]` as the zero
//!   hash, which must match exactly for consistency with the ZKP system.
//!
//! These requirements are fixed by the protocol specification and cannot be
//! changed without breaking compatibility. However, by using traits, we can
//! make the implementation extensible for protocol versioning and testing.

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
    /// This tag is used to prefix leaf node hashes, ensuring domain separation
    /// and preventing collisions with other hash contexts.
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
/// without needing all wallet commitments in memory.
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
///         hasher: &H,
///         config: &C,
///         wallet_id: WalletId,
///         depth: u8,
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
    /// * `hasher` - The hash function implementation
    /// * `config` - The SMT configuration
    /// * `wallet_id` - The wallet ID to find the sibling for
    /// * `depth` - The depth to find the sibling at (0 = root level)
    ///
    /// # Returns
    /// The sibling hash at this depth, or zero hash if the sibling subtree is empty
    fn get_sibling_hash(
        &mut self,
        hasher: &H,
        config: &C,
        wallet_id: WalletId,
        depth: u8,
    ) -> crate::errors::Result<Bytes32>;
}

/// Trait for core Sparse Merkle Tree operations
///
/// This trait defines the essential operations for building and working with
/// Sparse Merkle Trees. Implementations can vary in their internal structure
/// and optimizations while maintaining the same interface.
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
    /// * `hasher` - The hash function implementation
    /// * `config` - The SMT configuration
    /// * `wallet_commitments` - Map of wallet IDs to their commitments
    ///
    /// # Returns
    /// The root hash of the SMT, or the zero hash if empty
    fn compute_root(
        &self,
        hasher: &H,
        config: &C,
        wallet_commitments: &std::collections::BTreeMap<WalletId, WalletCommitment>,
    ) -> Bytes32;
}
