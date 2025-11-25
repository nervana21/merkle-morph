//! Subtree root validity proof generation
//!
//! This module provides functions for generating zero-knowledge proofs
//! for subtree root validity.

use std::collections::BTreeMap;

use p3_uni_stark::prove;

use crate::global::commitment::{build_smt_node_with, MerkleMorphV0Config, Poseidon2Hasher};
use crate::global::smt::get_bit_at_depth;
use crate::types::{WalletCommitment, WalletId};
use crate::zkp::subtree::air::SubtreeRootValidityAir;
use crate::zkp::subtree::public_inputs::{build_public_values, SubtreeRootPublicInput};
use crate::zkp::subtree::trace::build_subtree_trace;
use crate::zkp::types::{Proof, StarkConfig};
use crate::Result;

/// Generate a zero-knowledge proof for subtree root validity
///
/// This function proves that a subtree root is correctly computed from
/// wallet commitments in a range. The proof demonstrates that the subtree
/// root is the result of building an SMT from the wallet commitments starting
/// at the computed start_depth.
///
/// # Arguments
/// * `wallet_commitments` - Map of wallet IDs to their commitments (only those in range will be used)
/// * `min_id` - Minimum wallet ID in range (inclusive)
/// * `max_id` - Maximum wallet ID in range (inclusive)
/// * `config` - Proof system configuration (`StarkConfig`)
///
/// # Returns
/// A zero-knowledge proof for the subtree root validity
pub fn prove_subtree_root_validity(
    wallet_commitments: &BTreeMap<WalletId, WalletCommitment>,
    min_id: WalletId,
    max_id: WalletId,
    config: &StarkConfig,
) -> Result<Proof> {
    // Compute subtree root data
    // We need to compute the root and start_depth first

    // Validate range
    if min_id > max_id {
        return Err(crate::Error::Global(crate::errors::GlobalError::InvalidParameters(format!(
            "Invalid range: min_id ({:?}) > max_id ({:?})",
            min_id, max_id
        ))));
    }

    // Filter wallets in the range
    let mut subtree_wallets = BTreeMap::new();
    for (wallet_id, wallet_commitment) in wallet_commitments.iter() {
        if *wallet_id >= min_id && *wallet_id <= max_id {
            subtree_wallets.insert(*wallet_id, *wallet_commitment);
        }
    }

    // Compute start_depth
    // Special case: if min_id == max_id, return 0 (single wallet subtree from root)
    let start_depth = if min_id == max_id {
        0
    } else {
        let mut depth = 0u8;
        for d in 0..=255 {
            let min_bit = get_bit_at_depth(&min_id, d);
            let max_bit = get_bit_at_depth(&max_id, d);
            if min_bit != max_bit {
                depth = d;
                break;
            }
        }
        depth
    };

    // Compute the root
    let root =
        build_smt_node_with(&subtree_wallets, start_depth, &Poseidon2Hasher, &MerkleMorphV0Config);

    // Build trace
    let trace = build_subtree_trace(wallet_commitments, min_id, max_id, start_depth)?;

    // Build AIR
    let air = SubtreeRootValidityAir::new();

    // Build public inputs (only subtree_root is verified in-circuit)
    let public_inputs: SubtreeRootPublicInput = root;

    // Build public values
    let public_values = build_public_values(&public_inputs);

    // Generate proof
    let proof = prove(config, &air, trace, &public_values);
    Ok(proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zkp::types::create_config;

    #[test]
    fn test_prove_subtree_root_validity() {
        let config = create_config().expect("Should create config");

        let invalid_min_id = [2u8; 32];
        let invalid_max_id = [1u8; 32];
        let empty_commitments = BTreeMap::new();

        let invalid_result = prove_subtree_root_validity(
            &empty_commitments,
            invalid_min_id,
            invalid_max_id,
            &config,
        );

        assert!(invalid_result.is_err());

        let single_wallet_id = [1u8; 32];
        let single_wallet_commitment = [2u8; 32];
        let mut single_commitments = BTreeMap::new();
        single_commitments.insert(single_wallet_id, single_wallet_commitment);

        let single_result = prove_subtree_root_validity(
            &single_commitments,
            single_wallet_id,
            single_wallet_id,
            &config,
        );

        assert!(single_result.is_ok());

        let mut min_id = [0u8; 32];
        min_id[31] = 0;
        let mut max_id = [0u8; 32];
        max_id[31] = 1;
        let min_commitment = [10u8; 32];
        let max_commitment = [20u8; 32];
        let mut multi_commitments = BTreeMap::new();
        multi_commitments.insert(min_id, min_commitment);
        multi_commitments.insert(max_id, max_commitment);

        let multi_result = prove_subtree_root_validity(&multi_commitments, min_id, max_id, &config);

        assert!(multi_result.is_ok());
    }
}
