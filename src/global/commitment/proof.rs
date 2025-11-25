//! Merkle proof generation and verification

use std::collections::BTreeMap;

use super::builder::build_smt_node_with;
use super::config::DEFAULT_CONFIG;
use super::hasher::DEFAULT_HASHER;
use super::types::MerkleProof;
use crate::errors::ZkpError::InvalidAir;
use crate::global::smt::{get_bit_at_depth, SmtConfig, SmtHasher, SmtSiblingProvider};
use crate::types::{WalletCommitment, WalletId};
use crate::{Bytes32, Result};

/// Generates a merkle inclusion proof using a sibling hash provider
///
/// This function uses a [`SmtSiblingProvider`] to fetch sibling hashes along the proof path
/// from the root (depth 0) to the leaf level (depth max_depth-1).
///
/// The proof consists of sibling hashes along the path from the leaf to the root,
/// allowing verification without needing access to individual wallet commitments.
/// Each element in the proof path represents the sibling hash at that depth level.
///
/// # Arguments
/// * `wallet_id` - The wallet ID to generate a proof for
/// * `hasher` - The hash function implementation
/// * `config` - The SMT configuration
/// * `provider` - The sibling hash provider
///
/// # Returns
/// A `MerkleProof` containing the proof path with `max_depth` sibling hashes
///
/// # Example
///
/// ```rust,no_run
/// use merkle_morph::global::commitment::{
///     generate_merkle_proof, InMemorySiblingProvider, MerkleMorphV0Config,
///     Poseidon2Hasher,
/// };
/// use merkle_morph::global::smt::{SmtConfig, SmtHasher};
/// use merkle_morph::types::{WalletCommitment, WalletId};
/// use std::collections::BTreeMap;
///
/// let mut commitments = BTreeMap::new();
/// let wallet_id: WalletId = [1u8; 32];
/// let wallet_commitment: WalletCommitment = [2u8; 32];
/// commitments.insert(wallet_id, wallet_commitment);
///
/// let mut provider = InMemorySiblingProvider::new(&commitments);
/// let hasher = Poseidon2Hasher;
/// let config = MerkleMorphV0Config;
/// let proof = generate_merkle_proof(
///     wallet_id,
///     &hasher,
///     &config,
///     &mut provider,
/// )?;
/// # Ok::<(), merkle_morph::errors::Error>(())
/// ```
pub fn generate_merkle_proof<H: SmtHasher, C: SmtConfig, P: SmtSiblingProvider<H, C>>(
    wallet_id: WalletId,
    hasher: &H,
    config: &C,
    provider: &mut P,
) -> Result<MerkleProof> {
    let max_depth = config.max_depth();
    let mut path = Vec::new();

    for depth in 0..max_depth {
        let sibling_hash = provider.get_sibling_hash(wallet_id, depth, hasher, config)?;
        path.push(sibling_hash);
    }

    Ok(MerkleProof { path })
}

/// Computes the sibling hash at a specific depth for a given wallet ID
///
/// The sibling is the hash of the subtree containing wallets that have
/// the opposite bit value at the given depth. Requires access to wallet commitment
/// hashes for the sibling subtree.
pub(crate) fn compute_sibling_hash_at_depth<H: SmtHasher, C: SmtConfig>(
    wallet_id: WalletId,
    depth: u8,
    hasher: &H,
    config: &C,
    wallet_commitments: &BTreeMap<WalletId, WalletCommitment>,
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
        Ok(build_smt_node_with(&sibling_wallets, depth + 1, hasher, config))
    }
}

/// Verifies a merkle inclusion proof
///
/// This function verifies that a wallet commitment is included in the given root
/// using a merkle proof.
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
        wallet_id,
        wallet_commitment,
        proof,
        root,
        &DEFAULT_HASHER,
        &DEFAULT_CONFIG,
    )
}

/// Verifies a merkle inclusion proof with custom hasher and config
///
/// # Arguments
/// * `wallet_id` - The wallet ID
/// * `wallet_commitment` - The wallet commitment
/// * `proof` - The merkle inclusion proof
/// * `root` - The expected global root
/// * `hasher` - The hash function implementation
/// * `config` - The SMT configuration
///
/// # Returns
/// `Ok(true)` if the proof is valid, `Ok(false)` otherwise
pub fn verify_merkle_proof_with<H: SmtHasher, C: SmtConfig>(
    wallet_id: WalletId,
    wallet_commitment: WalletCommitment,
    proof: &MerkleProof,
    root: Bytes32,
    hasher: &H,
    config: &C,
) -> Result<bool> {
    let max_depth = config.max_depth();

    // Verify proof path length matches expected depth
    if proof.path.len() != max_depth as usize {
        return Err(InvalidAir.into());
    }

    // Start with the leaf hash
    let mut current_hash = hasher.hash_leaf(config.leaf_domain_tag(), wallet_id, wallet_commitment);

    // Verify the proof path by traversing from leaf (depth max_depth-1) to root (depth 0)
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
    use std::collections::BTreeMap;

    use super::*;
    use crate::global::commitment::{
        build_smt_root_with, InMemorySiblingProvider, MerkleMorphV0Config, Poseidon2Hasher,
    };
    use crate::global::smt::{SmtConfig, SmtHasher};

    struct ErrorProvider;

    impl<H: SmtHasher, C: SmtConfig> SmtSiblingProvider<H, C> for ErrorProvider {
        fn get_sibling_hash(
            &mut self,
            _wallet_id: WalletId,
            _depth: u8,
            _hasher: &H,
            _config: &C,
        ) -> Result<Bytes32> {
            Err(crate::errors::ZkpError::InvalidAir.into())
        }
    }

    #[test]
    fn test_generate_merkle_proof() {
        let mut commitments = BTreeMap::new();
        let wallet_id = [1u8; 32];
        let wallet_commitment = [2u8; 32];
        commitments.insert(wallet_id, wallet_commitment);
        let mut provider = InMemorySiblingProvider::new(&commitments);
        let hasher = Poseidon2Hasher;
        let config = MerkleMorphV0Config;

        let result = generate_merkle_proof(wallet_id, &hasher, &config, &mut provider);

        assert!(result.is_ok());
        let proof = result.expect("proof generation should succeed");
        assert_eq!(proof.path.len(), config.max_depth() as usize);

        let mut error_provider = ErrorProvider;

        let error_result = generate_merkle_proof(wallet_id, &hasher, &config, &mut error_provider);

        assert!(error_result.is_err());
    }

    #[test]
    fn test_verify_merkle_proof() {
        let mut commitments = BTreeMap::new();
        let wallet_id = [1u8; 32];
        let wallet_commitment = [2u8; 32];
        commitments.insert(wallet_id, wallet_commitment);
        let mut provider = InMemorySiblingProvider::new(&commitments);
        let hasher = Poseidon2Hasher;
        let config = MerkleMorphV0Config;
        let proof = generate_merkle_proof(wallet_id, &hasher, &config, &mut provider)
            .expect("proof generation should succeed");
        let root = crate::global::commitment::build_smt_root_with(&commitments, &hasher, &config);

        let result = verify_merkle_proof(wallet_id, wallet_commitment, &proof, root);

        assert!(result.expect("verification should succeed"));
    }

    #[test]
    fn test_verify_merkle_proof_with() {
        let hasher = Poseidon2Hasher;
        let config = MerkleMorphV0Config;
        let wallet_id_zero_bit = [0u8; 32];
        let wallet_id_mixed_bits = {
            let mut id = [0u8; 32];
            id[0] = 0b10101010;
            id
        };
        let wallet_commitment = [2u8; 32];
        let mut commitments = BTreeMap::new();
        commitments.insert(wallet_id_zero_bit, wallet_commitment);
        let mut provider = InMemorySiblingProvider::new(&commitments);
        let proof = generate_merkle_proof(wallet_id_zero_bit, &hasher, &config, &mut provider)
            .expect("proof generation should succeed");
        let root = build_smt_root_with(&commitments, &hasher, &config);
        let wrong_length_proof = MerkleProof { path: vec![] };

        let error_result = verify_merkle_proof_with(
            wallet_id_zero_bit,
            wallet_commitment,
            &wrong_length_proof,
            root,
            &hasher,
            &config,
        );

        assert!(error_result.is_err());

        let valid_result = verify_merkle_proof_with(
            wallet_id_zero_bit,
            wallet_commitment,
            &proof,
            root,
            &hasher,
            &config,
        );

        assert!(valid_result.expect("verification should succeed"));

        let invalid_root = [255u8; 32];

        let invalid_result = verify_merkle_proof_with(
            wallet_id_zero_bit,
            wallet_commitment,
            &proof,
            invalid_root,
            &hasher,
            &config,
        );

        assert!(!invalid_result.expect("verification should succeed"));

        commitments.insert(wallet_id_mixed_bits, [3u8; 32]);
        let mut provider_mixed = InMemorySiblingProvider::new(&commitments);
        let proof_mixed =
            generate_merkle_proof(wallet_id_mixed_bits, &hasher, &config, &mut provider_mixed)
                .expect("proof generation should succeed");
        let root_mixed = build_smt_root_with(&commitments, &hasher, &config);

        let mixed_result = verify_merkle_proof_with(
            wallet_id_mixed_bits,
            [3u8; 32],
            &proof_mixed,
            root_mixed,
            &hasher,
            &config,
        );

        assert!(mixed_result.expect("verification should succeed"));
    }
}
