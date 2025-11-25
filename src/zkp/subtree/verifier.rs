//! Subtree root validity proof verification
//!
//! This module provides functions for verifying zero-knowledge proofs
//! for subtree root validity.

use p3_uni_stark::verify;

use crate::errors::ZkpError;
use crate::zkp::subtree::air::SubtreeRootValidityAir;
use crate::zkp::subtree::public_inputs::{build_public_values, SubtreeRootPublicInput};
use crate::zkp::types::{Proof, StarkConfig};
use crate::Result;

/// Verify a zero-knowledge proof for subtree root validity
///
/// This function verifies that a subtree root is correctly computed from
/// wallet commitments in a range without requiring access to the wallet
/// commitments themselves.
///
/// # Arguments
/// * `config` - Proof system configuration (`StarkConfig`)
/// * `proof` - The zero-knowledge proof to verify
/// * `public_inputs` - Public inputs containing subtree root
///
/// # Returns
/// `Ok(())` if the proof is valid, `Err` otherwise
pub fn verify_subtree_root_validity(
    config: &StarkConfig,
    proof: &Proof,
    public_inputs: &SubtreeRootPublicInput,
) -> Result<()> {
    let air = SubtreeRootValidityAir::new();
    let public_values = build_public_values(public_inputs);

    verify(config, &air, proof, &public_values)
        .map_err(|_| crate::Error::Zkp(ZkpError::ProofVerificationFailed))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::global::commitment::{build_smt_node_with, MerkleMorphV0Config, Poseidon2Hasher};
    use crate::zkp::subtree::prover::prove_subtree_root_validity;
    use crate::zkp::types::create_config;

    #[test]
    fn test_verify_subtree_root_validity() {
        let config = create_config().expect("Should create config");
        let mut commitments = BTreeMap::new();
        let wallet_id = [1u8; 32];
        let wallet_commitment = [2u8; 32];
        commitments.insert(wallet_id, wallet_commitment);

        let proof = prove_subtree_root_validity(&commitments, wallet_id, wallet_id, &config)
            .expect("Should generate proof");

        let start_depth = 0u8;
        let root =
            build_smt_node_with(&commitments, start_depth, &Poseidon2Hasher, &MerkleMorphV0Config);
        let public_inputs: SubtreeRootPublicInput = root;

        verify_subtree_root_validity(&config, &proof, &public_inputs)
            .expect("Should verify valid proof");

        let wrong_public_inputs: SubtreeRootPublicInput = [0xFFu8; 32];
        assert!(verify_subtree_root_validity(&config, &proof, &wrong_public_inputs).is_err());
    }
}
