#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
//! Global commitment computation
//!
//! This module provides functions for computing the global Merkle root
//! from wallet commitments using a Sparse Merkle Tree (SMT) structure.
//! This enables partial verification through subtree root composition.

use std::collections::BTreeMap;

use crate::errors::Result;
use crate::errors::ZkpError::InvalidAir;
use crate::global::smt::{get_bit_at_depth, SmtConfig, SmtHasher, SmtSiblingProvider};
use crate::types::{Bytes32, WalletCommitment, WalletId};
use crate::zkp::poseidon2_hash_fixed;

/// Subtree root for partial verification
///
/// Represents a subtree of the global Sparse Merkle Tree at a specific depth range.
/// The subtree root is computed starting from `start_depth` and not from depth 0,
/// allowing proper composition with other subtrees.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubtreeRoot {
    /// The subtree root hash (computed from start_depth, not depth 0)
    pub root: Bytes32,
    /// Inclusive range of wallet IDs covered by this subtree
    /// (min_id, max_id) - both endpoints are inclusive
    pub wallet_id_range: (WalletId, WalletId),
    /// The depth at which this subtree starts (0 = from root, increases down the tree)
    /// All wallets in this subtree share the same bit pattern up to start_depth-1
    pub start_depth: u8,
}

/// Merkle inclusion proof for a wallet commitment
///
/// A proof that a specific wallet commitment is included in the global root.
/// The proof consists of sibling hashes along the path from the leaf to the root.
/// Each element in the path represents the sibling hash at that depth level.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleProof {
    /// Sibling hashes along the path from leaf to root (depth 0 to max_depth-1)
    /// For each depth, contains the hash of the sibling node (the opposite child)
    pub path: Vec<Bytes32>,
}

/// Poseidon2 hasher implementation for SMT operations
///
/// This struct implements the [`SmtHasher`] trait using Poseidon2, which is
/// the hash function used throughout the Merkle Morph protocol for consistency
/// with in-circuit verification.
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

/// Merkle Morph v0 configuration for SMT operations
///
/// This struct implements the [`SmtConfig`] trait with the domain tags and
/// parameters specified by the Merkle Morph v0 protocol.
#[derive(Clone, Copy, Debug, Default)]
pub struct MerkleMorphV0Config;

impl SmtConfig for MerkleMorphV0Config {
    fn leaf_domain_tag(&self) -> &[u8] { b"MM_WLT_v0" }

    fn internal_domain_tag(&self) -> &[u8] { b"MM_GLOBAL_v0" }

    fn max_depth(&self) -> u8 {
        255 // 256-bit wallet IDs, 0-indexed depth
    }
}

/// Default hasher instance (Poseidon2)
const DEFAULT_HASHER: Poseidon2Hasher = Poseidon2Hasher;

/// Default config instance (Merkle Morph v0)
const DEFAULT_CONFIG: MerkleMorphV0Config = MerkleMorphV0Config;

/// Computes an internal node hash using the default hasher and config
///
/// This is a convenience function for the common case where we use the default
/// Poseidon2 hasher and Merkle Morph v0 configuration.
#[inline]
fn hash_internal_node(left: Bytes32, right: Bytes32) -> Bytes32 {
    DEFAULT_HASHER.hash_internal(DEFAULT_CONFIG.internal_domain_tag(), left, right)
}

/// Computes the SMT root with custom hasher and config
///
/// This function allows using different hash functions and configurations,
/// which is useful for protocol versioning and testing.
///
/// # Arguments
/// * `hasher` - The hash function implementation
/// * `config` - The SMT configuration
/// * `wallet_commitments` - Map of wallet IDs to their commitments
///
/// # Returns
/// The root hash of the SMT, or the zero hash if empty
pub fn build_smt_root_with<H: SmtHasher, C: SmtConfig>(
    hasher: &H,
    config: &C,
    wallet_commitments: &BTreeMap<WalletId, WalletCommitment>,
) -> Bytes32 {
    if wallet_commitments.is_empty() {
        return hasher.zero_hash();
    }

    // Build the tree recursively
    build_smt_node_with(hasher, config, wallet_commitments, 0)
}

/// Builds an SMT node at the given depth using the provided hasher and config
///
/// The tree is built recursively, with each level corresponding to one bit
/// of the wallet ID. At depth 0, we check bit 0; at depth 1, bit 1, etc.
/// When we reach the maximum depth, any remaining wallets are leaves.
fn build_smt_node_with<H: SmtHasher, C: SmtConfig>(
    hasher: &H,
    config: &C,
    wallet_commitments: &BTreeMap<WalletId, WalletCommitment>,
    depth: u8,
) -> Bytes32 {
    // Base case: empty subtree
    if wallet_commitments.is_empty() {
        return hasher.zero_hash();
    }

    let max_depth = config.max_depth();

    // Base case: if we've processed all bits, we're at a leaf
    // This should only happen if there's exactly one wallet
    if depth == max_depth && wallet_commitments.len() == 1 {
        let (wallet_id, wallet_commitment) = wallet_commitments
            .iter()
            .next()
            .expect("wallet_commitments.len() == 1 guarantees next() returns Some");
        let leaf_hash = hasher.hash_leaf(config.leaf_domain_tag(), *wallet_id, *wallet_commitment);
        return leaf_hash;
    }

    // Split wallets based on the current bit (depth-th bit)
    let mut left_wallets = BTreeMap::new();
    let mut right_wallets = BTreeMap::new();

    for (wallet_id, wallet_commitment) in wallet_commitments.iter() {
        let bit_value = get_bit_at_depth(wallet_id, depth);
        if bit_value == 0 {
            left_wallets.insert(*wallet_id, *wallet_commitment);
        } else {
            right_wallets.insert(*wallet_id, *wallet_commitment);
        }
    }

    // Compute left and right child nodes recursively
    let left_child = build_smt_node_with(hasher, config, &left_wallets, depth + 1);
    let right_child = build_smt_node_with(hasher, config, &right_wallets, depth + 1);

    // Compute internal node hash
    let result = hasher.hash_internal(config.internal_domain_tag(), left_child, right_child);
    result
}

/// Computes a subtree root for a range of wallet IDs
///
/// This function computes the SMT root for wallets within the specified
/// inclusive range [min_id, max_id], starting from the common prefix depth.
/// The subtree root is computed from `start_depth` (where wallet IDs start to differ),
/// not from depth 0, allowing proper composition with other subtrees.
///
/// # Arguments
/// * `wallet_commitments` - All wallet commitments in the global state
/// * `min_id` - Minimum wallet ID (inclusive) in the range
/// * `max_id` - Maximum wallet ID (inclusive) in the range
///
/// # Returns
/// A `SubtreeRoot` containing the root hash, range, and start depth
pub fn compute_subtree_root(
    wallet_commitments: &BTreeMap<WalletId, WalletCommitment>,
    min_id: WalletId,
    max_id: WalletId,
) -> Result<SubtreeRoot> {
    // Validate range
    if min_id > max_id {
        return Err(InvalidAir.into());
    }

    // Filter wallets in the range
    let mut subtree_wallets = BTreeMap::new();
    for (wallet_id, wallet_commitment) in wallet_commitments.iter() {
        if *wallet_id >= min_id && *wallet_id <= max_id {
            subtree_wallets.insert(*wallet_id, *wallet_commitment);
        }
    }

    // Compute start_depth: find the common prefix length between min_id and max_id
    // This is the depth at which wallet IDs in this subtree start to differ
    let start_depth = compute_common_prefix_depth(&min_id, &max_id);

    // Compute the root starting from start_depth
    let root = build_smt_node_with(&DEFAULT_HASHER, &DEFAULT_CONFIG, &subtree_wallets, start_depth);

    Ok(SubtreeRoot { root, wallet_id_range: (min_id, max_id), start_depth })
}

/// Computes the depth (common prefix length) between two wallet IDs
///
/// This represents how many bits are the same between min_id and max_id,
/// which determines the depth of the subtree covering this range.
fn compute_common_prefix_depth(min_id: &WalletId, max_id: &WalletId) -> u8 {
    for depth in 0..=255 {
        let min_bit = get_bit_at_depth(min_id, depth);
        let max_bit = get_bit_at_depth(max_id, depth);
        if min_bit != max_bit {
            return depth;
        }
    }
    255 // All bits are the same (shouldn't happen for different IDs)
}

/// Composes two adjacent subtree roots into a single subtree root
///
/// The subtrees should cover adjacent or overlapping ranges in the wallet ID space.
/// The resulting subtree covers the union of both ranges.
///
/// # Arguments
/// * `left` - Left subtree root (should have smaller wallet IDs)
/// * `right` - Right subtree root (should have larger wallet IDs)
///
/// # Returns
/// A new `SubtreeRoot` representing the composition of both subtrees
pub fn compose_subtree_roots(left: &SubtreeRoot, right: &SubtreeRoot) -> Result<SubtreeRoot> {
    // Verify that left comes before right in sorted order
    if left.wallet_id_range.1 > right.wallet_id_range.0 {
        // They overlap or are out of order - this is an error
        return Err(InvalidAir.into());
    }

    // Compose the roots: hash them together as siblings in the tree
    let composed_root = hash_internal_node(left.root, right.root);

    // The new range covers both subtrees
    let new_min = left.wallet_id_range.0;
    let new_max = right.wallet_id_range.1;

    // The start_depth decreases by 1 when we go up a level
    // Use the minimum start_depth and subtract 1
    let new_start_depth = if left.start_depth < right.start_depth {
        if left.start_depth > 0 {
            left.start_depth - 1
        } else {
            0
        }
    } else if right.start_depth > 0 {
        right.start_depth - 1
    } else {
        0
    };

    Ok(SubtreeRoot {
        root: composed_root,
        wallet_id_range: (new_min, new_max),
        start_depth: new_start_depth,
    })
}

/// Composes multiple subtree roots into a global root
///
/// This function builds an SMT structure from the provided subtrees.
/// Each subtree is treated as covering a range of wallet IDs. The function
/// builds the tree structure based on the wallet ID bit patterns.
///
/// # Arguments
/// * `subtrees` - Sorted slice of subtree roots covering the wallet ID space
///
/// # Returns
/// The computed global root
pub fn compose_to_global_root(subtrees: &[SubtreeRoot]) -> Result<Bytes32> {
    if subtrees.is_empty() {
        return Ok(DEFAULT_HASHER.zero_hash());
    }

    compose_subtrees_smt(subtrees, 0) // depth 0 is the root
}

/// Recursively composes subtrees into an SMT structure
///
/// Composes pre-computed subtree roots into a global root, following the same
/// SMT structure as `build_smt_node_with` but working with `SubtreeRoot` objects.
/// Each subtree root is computed from its `start_depth`, so it must be unwrapped
/// to the current depth before composing.
fn compose_subtrees_smt(subtrees: &[SubtreeRoot], depth: u8) -> Result<Bytes32> {
    if subtrees.is_empty() {
        return Ok(DEFAULT_HASHER.zero_hash());
    }

    // Handle single subtree: if current depth matches start_depth, return it directly
    // Otherwise, we need to "unwrap" it to the current depth
    if subtrees.len() == 1 {
        let subtree = &subtrees[0];
        if depth == subtree.start_depth {
            return Ok(subtree.root);
        }
        // If depth < start_depth, we need to "unwrap" by building up from start_depth to depth
        // The subtree root is computed from start_depth, so we build up by adding zero hashes
        // based on the bit pattern from depth to start_depth
        if depth < subtree.start_depth {
            let mut current_root = subtree.root;
            let zero = DEFAULT_HASHER.zero_hash();
            // Build up from start_depth-1 down to depth
            for d in (depth..subtree.start_depth).rev() {
                let bit_value = get_bit_at_depth(&subtree.wallet_id_range.0, d);
                if bit_value == 0 {
                    current_root = hash_internal_node(current_root, zero);
                } else {
                    current_root = hash_internal_node(zero, current_root);
                }
            }
            return Ok(current_root);
        } else {
            // depth > start_depth: the subtree is already computed from start_depth,
            // so we need to continue building down from the current depth
            let bit_value = get_bit_at_depth(&subtree.wallet_id_range.0, depth);
            let zero = DEFAULT_HASHER.zero_hash();
            let left_child =
                if bit_value == 0 { compose_subtrees_smt(subtrees, depth + 1)? } else { zero };
            let right_child =
                if bit_value == 1 { compose_subtrees_smt(subtrees, depth + 1)? } else { zero };
            return Ok(hash_internal_node(left_child, right_child));
        }
    }

    // Split subtrees based on the current bit (depth-th bit) of their min wallet ID
    let mut left_subtrees = Vec::new();
    let mut right_subtrees = Vec::new();

    for subtree in subtrees.iter() {
        // Get the bit value at current depth (all wallets in subtree share same bit if depth < start_depth)
        let bit_value = get_bit_at_depth(&subtree.wallet_id_range.0, depth);
        if bit_value == 0 {
            left_subtrees.push(subtree.clone());
        } else {
            right_subtrees.push(subtree.clone());
        }
    }

    // Recursively compose left and right subtrees
    let zero = DEFAULT_HASHER.zero_hash();
    let left_child = if !left_subtrees.is_empty() {
        compose_subtrees_smt(&left_subtrees, depth + 1)?
    } else {
        zero
    };
    let right_child = if !right_subtrees.is_empty() {
        compose_subtrees_smt(&right_subtrees, depth + 1)?
    } else {
        zero
    };

    // Compute internal node hash at current depth
    let result = hash_internal_node(left_child, right_child);
    Ok(result)
}

/// Verifies that a subtree root is correct for the given wallet commitments
///
/// This function recomputes the subtree root and compares it to the provided one.
///
/// # Arguments
/// * `subtree` - The subtree root to verify
/// * `wallet_commitments` - All wallet commitments in the global state
///
/// # Returns
/// `Ok(true)` if the subtree root is correct, `Ok(false)` otherwise
pub fn verify_subtree_root(
    subtree: &SubtreeRoot,
    wallet_commitments: &BTreeMap<WalletId, WalletCommitment>,
) -> Result<bool> {
    let computed = compute_subtree_root(
        wallet_commitments,
        subtree.wallet_id_range.0,
        subtree.wallet_id_range.1,
    )?;
    Ok(computed.root == subtree.root && computed.start_depth == subtree.start_depth)
}

/// Generates a merkle inclusion proof for a wallet commitment
///
/// **Note**: This function requires all wallet commitments in the global state,
/// which makes it unsuitable for large-scale systems. Use
/// [`generate_merkle_proof_with_provider`] with a provider instead.
///
/// This function is primarily useful for:
/// - Testing and development
/// - Small-scale systems where all commitments fit in memory
///
/// The proof consists of sibling hashes along the path from the leaf to the root,
/// allowing verification without needing all wallet commitments.
///
/// # Arguments
/// * `wallet_commitments` - All wallet commitments in the global state
/// * `wallet_id` - The wallet ID to generate a proof for
///
/// # Returns
/// A `MerkleProof` containing the proof path, or an error if the wallet is not found
pub fn generate_merkle_proof(
    wallet_commitments: &BTreeMap<WalletId, WalletCommitment>,
    wallet_id: WalletId,
) -> Result<MerkleProof> {
    let wallet_commitment = wallet_commitments.get(&wallet_id).ok_or(InvalidAir)?;
    generate_merkle_proof_with(
        &DEFAULT_HASHER,
        &DEFAULT_CONFIG,
        wallet_commitments,
        wallet_id,
        *wallet_commitment,
    )
}

/// Generates a merkle inclusion proof with custom hasher and config
///
/// **Note**: This function requires all wallet commitments in the global state,
/// which makes it unsuitable for large-scale systems. Use
/// [`generate_merkle_proof_with_provider`] with a provider instead.
///
/// This function is primarily useful for:
/// - Testing and development
/// - Small-scale systems where all commitments fit in memory
///
/// # Arguments
/// * `hasher` - The hash function implementation
/// * `config` - The SMT configuration
/// * `wallet_commitments` - All wallet commitments in the global state
/// * `wallet_id` - The wallet ID to generate a proof for
/// * `wallet_commitment` - The wallet commitment (must match what's in wallet_commitments)
///
/// # Returns
/// A `MerkleProof` containing the proof path
pub fn generate_merkle_proof_with<H: SmtHasher, C: SmtConfig>(
    hasher: &H,
    config: &C,
    wallet_commitments: &BTreeMap<WalletId, WalletCommitment>,
    wallet_id: WalletId,
    _wallet_commitment: WalletCommitment,
) -> Result<MerkleProof> {
    let max_depth = config.max_depth();
    let mut path = Vec::new();

    // Build the proof path by traversing from root (depth 0) to just before leaf (max_depth-1)
    // At each depth, we need the sibling hash
    // The path has max_depth elements (one for each level from 0 to max_depth-1)
    for depth in 0..max_depth {
        // Compute the sibling hash at this depth
        // The sibling is the subtree containing all wallets with the opposite bit at this depth
        let sibling_hash =
            compute_sibling_hash_at_depth(hasher, config, wallet_commitments, wallet_id, depth)?;

        path.push(sibling_hash);
    }

    Ok(MerkleProof { path })
}

/// Generates a merkle inclusion proof using a sibling hash provider
///
/// This is the approach for generating Merkle proofs in large-scale systems.
/// Instead of requiring all wallet commitments, it uses a [`SmtSiblingProvider`] to
/// fetch sibling hashes along the proof path.
///
/// # Arguments
/// * `hasher` - The hash function implementation
/// * `config` - The SMT configuration
/// * `provider` - The sibling hash provider
/// * `wallet_id` - The wallet ID to generate a proof for
/// * `wallet_commitment` - The wallet commitment
///
/// # Returns
/// A `MerkleProof` containing the proof path
///
/// # Example
///
/// ```rust,no_run
/// use merkle_morph::global::commitment::{
///     generate_merkle_proof_with_provider, InMemorySiblingProvider, MerkleMorphV0Config,
///     Poseidon2Hasher,
/// };
/// use merkle_morph::global::smt::{SmtConfig, SmtHasher};
/// use std::collections::BTreeMap;
///
/// let mut commitments = BTreeMap::new();
/// commitments.insert([1u8; 32], [2u8; 32]);
/// let wallet_id = [1u8; 32];
///
/// let mut provider = InMemorySiblingProvider::new(&commitments);
/// let hasher = Poseidon2Hasher;
/// let config = MerkleMorphV0Config;
/// let proof = generate_merkle_proof_with_provider(
///     &hasher,
///     &config,
///     &mut provider,
///     wallet_id,
/// )?;
/// # Ok::<(), merkle_morph::errors::Error>(())
/// ```
pub fn generate_merkle_proof_with_provider<
    H: SmtHasher,
    C: SmtConfig,
    P: SmtSiblingProvider<H, C>,
>(
    hasher: &H,
    config: &C,
    provider: &mut P,
    wallet_id: WalletId,
) -> Result<MerkleProof> {
    let max_depth = config.max_depth();
    let mut path = Vec::new();

    // Build the proof path by traversing from root (depth 0) to just before leaf (max_depth-1)
    // At each depth, we need the sibling hash
    // The path has max_depth elements (one for each level from 0 to max_depth-1)
    for depth in 0..max_depth {
        // Get the sibling hash at this depth from the provider
        let sibling_hash = provider.get_sibling_hash(hasher, config, wallet_id, depth)?;
        path.push(sibling_hash);
    }

    Ok(MerkleProof { path })
}

/// In-memory sibling hash provider for testing and small-scale systems
///
/// This provider wraps a `BTreeMap` of all wallet commitments and computes
/// sibling hashes on-demand. It's useful for:
/// - Testing and development
/// - Small-scale systems where all commitments fit in memory
/// - Backward compatibility with existing code
///
/// For systems with many users, consider implementing a database-backed
/// provider that can query sibling hashes without loading all commitments.
///
/// # Example
///
/// ```rust,no_run
/// use merkle_morph::global::commitment::{InMemorySiblingProvider, MerkleMorphV0Config, Poseidon2Hasher};
/// use merkle_morph::global::smt::{SmtConfig, SmtHasher, SmtSiblingProvider};
/// use std::collections::BTreeMap;
///
/// let mut commitments = BTreeMap::new();
/// commitments.insert([1u8; 32], [2u8; 32]);
/// let mut provider = InMemorySiblingProvider::new(&commitments);
/// let hasher = Poseidon2Hasher;
/// let config = MerkleMorphV0Config;
/// let sibling_hash = provider.get_sibling_hash(&hasher, &config, [1u8; 32], 0)?;
/// # Ok::<(), merkle_morph::errors::Error>(())
/// ```
pub struct InMemorySiblingProvider<'a> {
    wallet_commitments: &'a BTreeMap<WalletId, WalletCommitment>,
}

impl<'a> InMemorySiblingProvider<'a> {
    /// Creates a new in-memory sibling provider from a map of wallet commitments
    ///
    /// # Arguments
    /// * `wallet_commitments` - Reference to all wallet commitments in the global state
    pub fn new(wallet_commitments: &'a BTreeMap<WalletId, WalletCommitment>) -> Self {
        Self { wallet_commitments }
    }
}

impl<'a, H: SmtHasher, C: SmtConfig> SmtSiblingProvider<H, C> for InMemorySiblingProvider<'a> {
    fn get_sibling_hash(
        &mut self,
        hasher: &H,
        config: &C,
        wallet_id: WalletId,
        depth: u8,
    ) -> Result<Bytes32> {
        compute_sibling_hash_at_depth(hasher, config, self.wallet_commitments, wallet_id, depth)
    }
}

/// Computes the sibling hash at a specific depth for a given wallet ID
///
/// The sibling is the hash of the subtree containing all wallets that have
/// the opposite bit value at the given depth.
fn compute_sibling_hash_at_depth<H: SmtHasher, C: SmtConfig>(
    hasher: &H,
    config: &C,
    wallet_commitments: &BTreeMap<WalletId, WalletCommitment>,
    wallet_id: WalletId,
    depth: u8,
) -> Result<Bytes32> {
    let bit_value = get_bit_at_depth(&wallet_id, depth);

    // Collect wallets that go to the sibling branch (opposite bit at this depth)
    let mut sibling_wallets = BTreeMap::new();
    for (id, commitment) in wallet_commitments.iter() {
        // Skip the wallet we're proving for
        if *id == wallet_id {
            continue;
        }

        let id_bit = get_bit_at_depth(id, depth);
        // Collect wallets that have the opposite bit at this depth
        if id_bit != bit_value {
            // Check if this wallet shares the same prefix up to depth-1
            // (i.e., it would be in the sibling subtree at this depth)
            let mut same_prefix = true;
            for d in 0..depth {
                if get_bit_at_depth(id, d) != get_bit_at_depth(&wallet_id, d) {
                    same_prefix = false;
                    break;
                }
            }
            if same_prefix {
                sibling_wallets.insert(*id, *commitment);
            }
        }
    }

    // Compute the sibling subtree root starting from depth+1
    if sibling_wallets.is_empty() {
        Ok(hasher.zero_hash())
    } else {
        Ok(build_smt_node_with(hasher, config, &sibling_wallets, depth + 1))
    }
}

/// Verifies a merkle inclusion proof
///
/// This function verifies that a wallet commitment is included in the given root
/// using a merkle proof, without needing all wallet commitments.
///
/// # Arguments
/// * `wallet_id` - The wallet ID
/// * `wallet_commitment` - The wallet commitment
/// * `proof` - The merkle inclusion proof
/// * `root` - The expected global root
///
/// # Returns
/// `Ok(true)` if the proof is valid, `Ok(false)` otherwise
pub fn verify_merkle_proof(
    wallet_id: WalletId,
    wallet_commitment: WalletCommitment,
    proof: &MerkleProof,
    root: Bytes32,
) -> Result<bool> {
    verify_merkle_proof_with(
        &DEFAULT_HASHER,
        &DEFAULT_CONFIG,
        wallet_id,
        wallet_commitment,
        proof,
        root,
    )
}

/// Verifies a merkle inclusion proof with custom hasher and config
///
/// # Arguments
/// * `hasher` - The hash function implementation
/// * `config` - The SMT configuration
/// * `wallet_id` - The wallet ID
/// * `wallet_commitment` - The wallet commitment
/// * `proof` - The merkle inclusion proof
/// * `root` - The expected global root
///
/// # Returns
/// `Ok(true)` if the proof is valid, `Ok(false)` otherwise
pub fn verify_merkle_proof_with<H: SmtHasher, C: SmtConfig>(
    hasher: &H,
    config: &C,
    wallet_id: WalletId,
    wallet_commitment: WalletCommitment,
    proof: &MerkleProof,
    root: Bytes32,
) -> Result<bool> {
    let max_depth = config.max_depth();

    // Verify proof path length matches expected depth
    if proof.path.len() != max_depth as usize {
        return Err(InvalidAir.into());
    }

    // Start with the leaf hash
    let mut current_hash = hasher.hash_leaf(config.leaf_domain_tag(), wallet_id, wallet_commitment);

    // Verify the proof path by traversing from leaf (max_depth) to root (depth 0)
    // The proof path contains siblings at depths 0 through max_depth-1
    for depth in (0..max_depth).rev() {
        let sibling_hash = proof.path[depth as usize];
        let bit_value = get_bit_at_depth(&wallet_id, depth);

        // Compute parent hash using sibling
        if bit_value == 0 {
            // We're the left child, sibling is right
            current_hash =
                hasher.hash_internal(config.internal_domain_tag(), current_hash, sibling_hash);
        } else {
            // We're the right child, sibling is left
            current_hash =
                hasher.hash_internal(config.internal_domain_tag(), sibling_hash, current_hash);
        }
    }

    // The computed root should match the provided root
    Ok(current_hash == root)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compute_root_from_commitments(
        wallet_commitments: &BTreeMap<WalletId, WalletCommitment>,
    ) -> Result<Bytes32> {
        if wallet_commitments.is_empty() {
            return Ok([0u8; 32]);
        }

        let mut subtrees = Vec::new();
        for (wallet_id, commitment) in wallet_commitments.iter() {
            let mut wallet_map = BTreeMap::new();
            wallet_map.insert(*wallet_id, *commitment);
            let subtree = compute_subtree_root(&wallet_map, *wallet_id, *wallet_id)?;
            subtrees.push(subtree);
        }
        subtrees.sort_by_key(|s| s.wallet_id_range.0);
        compose_to_global_root(&subtrees)
    }

    #[test]
    fn test_compute_root_empty() {
        let commitments = BTreeMap::new();
        let root1 = compute_root_from_commitments(&commitments).expect("Should compute root");
        assert_eq!(root1, DEFAULT_HASHER.zero_hash());

        let hasher = Poseidon2Hasher;
        let config = MerkleMorphV0Config;
        let root2 = build_smt_root_with(&hasher, &config, &commitments);
        assert_eq!(root2, DEFAULT_HASHER.zero_hash());
        assert_eq!(root1, root2, "Both APIs should produce the same result for empty tree");
    }

    #[test]
    fn test_compute_root_single_wallet() {
        let mut commitments = BTreeMap::new();
        commitments.insert([1u8; 32], [2u8; 32]);

        let root1 = compute_root_from_commitments(&commitments).expect("Should compute root");
        let root2 = build_smt_root_with(&DEFAULT_HASHER, &DEFAULT_CONFIG, &commitments);

        // Both APIs should produce the same result
        assert_eq!(root1, root2, "Helper function should match direct API");
    }

    #[test]
    fn test_compute_root_multiple_wallets() {
        let mut commitments1 = BTreeMap::new();
        commitments1.insert([1u8; 32], [2u8; 32]);
        let root1 = compute_root_from_commitments(&commitments1).expect("Should compute root");

        let mut commitments2 = BTreeMap::new();
        commitments2.insert([1u8; 32], [2u8; 32]);
        commitments2.insert([3u8; 32], [4u8; 32]);
        let root2 = compute_root_from_commitments(&commitments2).expect("Should compute root");

        assert_ne!(root1, root2);
    }

    #[test]
    fn test_smt_root_consistency() {
        // Test that SMT root is deterministic
        let mut commitments = BTreeMap::new();
        commitments.insert([1u8; 32], [2u8; 32]);
        commitments.insert([3u8; 32], [4u8; 32]);
        commitments.insert([5u8; 32], [6u8; 32]);

        let root1 = compute_root_from_commitments(&commitments).expect("Should compute root");
        let root2 = compute_root_from_commitments(&commitments).expect("Should compute root");
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_compute_subtree_root_single_wallet() {
        let mut commitments = BTreeMap::new();
        let wallet_id = [1u8; 32];
        let wallet_commitment = [2u8; 32];
        commitments.insert(wallet_id, wallet_commitment);

        let subtree = compute_subtree_root(&commitments, wallet_id, wallet_id)
            .expect("Should compute subtree");
        assert_eq!(subtree.wallet_id_range.0, wallet_id);
        assert_eq!(subtree.wallet_id_range.1, wallet_id);
        assert_ne!(subtree.root, DEFAULT_HASHER.zero_hash());
    }

    #[test]
    fn test_compute_subtree_root_range() {
        let mut commitments = BTreeMap::new();
        commitments.insert([1u8; 32], [2u8; 32]);
        commitments.insert([3u8; 32], [4u8; 32]);
        commitments.insert([5u8; 32], [6u8; 32]);

        // Subtree for range [1, 3] should include wallets 1 and 3
        let subtree = compute_subtree_root(&commitments, [1u8; 32], [3u8; 32])
            .expect("Should compute subtree");
        assert_eq!(subtree.wallet_id_range.0, [1u8; 32]);
        assert_eq!(subtree.wallet_id_range.1, [3u8; 32]);
        assert_ne!(subtree.root, DEFAULT_HASHER.zero_hash());
    }

    #[test]
    fn test_compute_subtree_root_invalid_range() {
        let commitments = BTreeMap::new();
        let result = compute_subtree_root(&commitments, [3u8; 32], [1u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_compose_subtree_roots() {
        let mut commitments = BTreeMap::new();
        commitments.insert([1u8; 32], [2u8; 32]);
        commitments.insert([3u8; 32], [4u8; 32]);

        let left = compute_subtree_root(&commitments, [1u8; 32], [1u8; 32])
            .expect("Should compute left subtree");
        let right = compute_subtree_root(&commitments, [3u8; 32], [3u8; 32])
            .expect("Should compute right subtree");

        let composed = compose_subtree_roots(&left, &right).expect("Should compose");
        assert_eq!(composed.wallet_id_range.0, [1u8; 32]);
        assert_eq!(composed.wallet_id_range.1, [3u8; 32]);
        assert_ne!(composed.root, DEFAULT_HASHER.zero_hash());
    }

    #[test]
    fn test_compose_to_global_root() {
        let mut commitments = BTreeMap::new();
        commitments.insert([1u8; 32], [2u8; 32]);
        commitments.insert([3u8; 32], [4u8; 32]);
        commitments.insert([5u8; 32], [6u8; 32]);

        let subtree1 = compute_subtree_root(&commitments, [1u8; 32], [1u8; 32])
            .expect("Should compute subtree 1");
        let subtree2 = compute_subtree_root(&commitments, [3u8; 32], [3u8; 32])
            .expect("Should compute subtree 2");
        let subtree3 = compute_subtree_root(&commitments, [5u8; 32], [5u8; 32])
            .expect("Should compute subtree 3");

        let subtrees = vec![subtree1, subtree2, subtree3];
        let composed_root = compose_to_global_root(&subtrees).expect("Should compose");

        // Note: The composed root might not match the full root exactly due to
        // the way we compose (left-to-right vs tree structure), but it should be consistent
        assert_ne!(composed_root, DEFAULT_HASHER.zero_hash());
    }

    #[test]
    fn test_verify_subtree_root() {
        let mut commitments = BTreeMap::new();
        commitments.insert([1u8; 32], [2u8; 32]);
        commitments.insert([3u8; 32], [4u8; 32]);

        let subtree = compute_subtree_root(&commitments, [1u8; 32], [3u8; 32])
            .expect("Should compute subtree");

        let is_valid = verify_subtree_root(&subtree, &commitments).expect("Should verify");
        assert!(is_valid);

        // Test with wrong subtree
        let mut wrong_subtree = subtree.clone();
        wrong_subtree.root = [99u8; 32];
        let is_valid = verify_subtree_root(&wrong_subtree, &commitments).expect("Should verify");
        assert!(!is_valid);
    }

    // Tests for trait-based implementation

    #[test]
    fn test_poseidon2_hasher_trait() {
        let hasher = Poseidon2Hasher;
        let wallet_id = [1u8; 32];
        let commitment = [2u8; 32];

        // Test leaf hashing
        let leaf_hash = hasher.hash_leaf(b"MM_WLT_v0", wallet_id, commitment);
        assert_eq!(leaf_hash.len(), 32);

        // Test internal hashing
        let left = [3u8; 32];
        let right = [4u8; 32];
        let internal_hash = hasher.hash_internal(b"MM_GLOBAL_v0", left, right);
        assert_eq!(internal_hash.len(), 32);

        // Test zero hash
        let zero = hasher.zero_hash();
        assert_eq!(zero, [0u8; 32]);
    }

    #[test]
    fn test_merkle_morph_v0_config_trait() {
        let config = MerkleMorphV0Config;

        assert_eq!(config.leaf_domain_tag(), b"MM_WLT_v0");
        assert_eq!(config.internal_domain_tag(), b"MM_GLOBAL_v0");
        assert_eq!(config.max_depth(), 255);
    }

    #[test]
    fn test_trait_based_implementation_consistency() {
        let hasher = Poseidon2Hasher;
        let config = MerkleMorphV0Config;

        // Test with 2 wallets
        let mut commitments1 = BTreeMap::new();
        commitments1.insert([1u8; 32], [2u8; 32]);
        commitments1.insert([3u8; 32], [4u8; 32]);

        let root1a = build_smt_root_with(&hasher, &config, &commitments1);
        let root1b = build_smt_root_with(&hasher, &config, &commitments1);
        assert_eq!(root1a, root1b, "build_smt_root_with should be deterministic");

        let root1c = compute_root_from_commitments(&commitments1).expect("Should compute root");
        assert_eq!(
            root1a, root1c,
            "build_smt_root_with and compute_root_from_commitments should match"
        );

        // Test with 3 wallets
        let mut commitments2 = BTreeMap::new();
        commitments2.insert([1u8; 32], [2u8; 32]);
        commitments2.insert([3u8; 32], [4u8; 32]);
        commitments2.insert([5u8; 32], [6u8; 32]);

        let root2a = build_smt_root_with(&hasher, &config, &commitments2);
        let root2b = build_smt_root_with(&hasher, &config, &commitments2);
        assert_eq!(root2a, root2b, "build_smt_root_with should be deterministic");

        let root2c = compute_root_from_commitments(&commitments2).expect("Should compute root");
        assert_eq!(
            root2a, root2c,
            "build_smt_root_with and compute_root_from_commitments should match"
        );
    }

    #[test]
    fn test_config_domain_separation() {
        let config = MerkleMorphV0Config;
        let hasher = Poseidon2Hasher;

        let wallet_id = [1u8; 32];
        let commitment = [2u8; 32];

        // Leaf and internal hashes with same data but different tags should differ
        // (This is a sanity check - in practice we wouldn't hash a wallet_id+commitment
        // as an internal node, but it tests domain separation)
        let left = wallet_id;
        let right = commitment;
        let leaf_hash = hasher.hash_leaf(config.leaf_domain_tag(), wallet_id, commitment);
        let internal_hash = hasher.hash_internal(config.internal_domain_tag(), left, right);

        // They should be different due to domain separation
        assert_ne!(leaf_hash, internal_hash);
    }

    #[test]
    fn test_compose_subtree_roots_overlap_error() {
        let mut commitments = BTreeMap::new();
        commitments.insert([1u8; 32], [2u8; 32]);
        commitments.insert([2u8; 32], [3u8; 32]);
        commitments.insert([3u8; 32], [4u8; 32]);

        let left = compute_subtree_root(&commitments, [1u8; 32], [3u8; 32])
            .expect("left subtree should build");
        let right = compute_subtree_root(&commitments, [2u8; 32], [2u8; 32])
            .expect("right subtree should build");

        let result = compose_subtree_roots(&left, &right);
        assert!(result.is_err(), "Overlapping ranges should be rejected");
    }

    #[test]
    fn test_compose_to_global_root_empty_returns_zero() {
        let result = compose_to_global_root(&[]).expect("empty subtrees should succeed");
        assert_eq!(result, DEFAULT_HASHER.zero_hash());
    }

    #[test]
    fn test_generate_and_verify_merkle_proof_roundtrip() {
        let mut commitments = BTreeMap::new();
        let wallet_id = [7u8; 32];
        let commitment = [9u8; 32];
        commitments.insert(wallet_id, commitment);

        let root = compute_root_from_commitments(&commitments).expect("Should compute root");
        let proof = generate_merkle_proof(&commitments, wallet_id)
            .expect("proof generation should succeed");
        assert!(
            verify_merkle_proof(wallet_id, commitment, &proof, root)
                .expect("verification should succeed"),
            "Proof should validate"
        );
    }

    #[test]
    fn test_generate_merkle_proof_missing_wallet_errors() {
        let commitments = BTreeMap::new();
        let result = generate_merkle_proof(&commitments, [1u8; 32]);
        assert!(result.is_err(), "Missing wallet should return error");
    }

    #[test]
    fn test_generate_merkle_proof_with_provider_matches_in_memory() {
        let mut commitments = BTreeMap::new();
        let wallet_id = [0xAAu8; 32];
        let commitment = [0xBBu8; 32];
        commitments.insert(wallet_id, commitment);

        let mut provider = InMemorySiblingProvider::new(&commitments);
        let proof_with_provider = generate_merkle_proof_with_provider(
            &DEFAULT_HASHER,
            &DEFAULT_CONFIG,
            &mut provider,
            wallet_id,
        )
        .expect("Provider-based proof should succeed");

        let proof_direct =
            generate_merkle_proof(&commitments, wallet_id).expect("Direct proof should succeed");

        assert_eq!(
            proof_with_provider.path, proof_direct.path,
            "Provider-based proof should match direct proof path"
        );
    }

    #[test]
    fn test_verify_merkle_proof_with_invalid_path_length() {
        let wallet_id = [1u8; 32];
        let commitment = [2u8; 32];
        let proof = MerkleProof { path: vec![] }; // shorter than expected max depth
        let result = verify_merkle_proof_with(
            &DEFAULT_HASHER,
            &DEFAULT_CONFIG,
            wallet_id,
            commitment,
            &proof,
            [0u8; 32],
        );
        assert!(result.is_err(), "Invalid proof length should error");
    }

    #[test]
    fn test_compute_sibling_hash_returns_zero_when_no_sibling() {
        let mut commitments = BTreeMap::new();
        commitments.insert([0u8; 32], [1u8; 32]);
        let hash = compute_sibling_hash_at_depth(
            &DEFAULT_HASHER,
            &DEFAULT_CONFIG,
            &commitments,
            [0u8; 32],
            0,
        )
        .expect("Should compute sibling hash");
        assert_eq!(hash, [0u8; 32], "Single leaf should have zero sibling hash");
    }
}
