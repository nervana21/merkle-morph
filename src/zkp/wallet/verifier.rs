//! Wallet proof verification
//!
//! This module provides functions for verifying zero-knowledge proofs
//! for wallet commitment aggregation.

use p3_uni_stark::verify;

use crate::errors::ZkpError;
use crate::zkp::verifier_common::{
    build_public_values_from_id_and_commitment, build_public_values_from_id_and_two_commitments,
};
use crate::zkp::wallet::air::WalletCommitmentAir;
use crate::zkp::wallet::public_inputs::{WalletPublicInputs, WalletTransitionPublicInputs};
use crate::zkp::wallet::transition_air::WalletTransitionAir;
use crate::{Proof, Result, StarkConfig};

/// Verify a zero-knowledge proof for a wallet commitment
///
/// This function verifies that a wallet commitment was correctly computed
/// from channel commitments. The proof demonstrates that the wallet commitment
/// is the result of aggregating all channel commitments in sorted order.
///
/// # Arguments
/// * `config` - Proof system configuration (`StarkConfig`)
/// * `public_inputs` - Public inputs containing wallet_id and wallet_commitment
/// * `proof` - Zero-knowledge proof to verify
///
/// # Returns
/// * `Ok(())` - If the proof is valid
/// * `Err(ZkpError::ProofVerificationFailed)` - If the proof verification fails
pub fn verify_wallet_commitment(
    config: &StarkConfig,
    public_inputs: &WalletPublicInputs,
    proof: &Proof,
) -> Result<()> {
    let air = WalletCommitmentAir::new();

    let public_values = build_public_values_from_id_and_commitment(
        public_inputs.wallet_id,
        public_inputs.wallet_commitment,
    );

    verify(config, &air, proof, &public_values).map_err(|_| ZkpError::ProofVerificationFailed)?;

    Ok(())
}

/// Verify a zero-knowledge proof for wallet transitions
///
/// This function verifies that wallet transitions were correctly computed.
/// The proof demonstrates that each transition in the sequence is valid and that
/// transitions are properly chained together.
///
/// # Arguments
/// * `config` - Proof system configuration (`StarkConfig`)
/// * `public_inputs` - Public inputs containing wallet_id, initial_wallet_commitment, and final_wallet_commitment
/// * `proof` - Zero-knowledge proof to verify
///
/// # Returns
/// * `Ok(())` - If the proof is valid
/// * `Err(ZkpError::ProofVerificationFailed)` - If the proof verification fails
pub fn verify_wallet_transition(
    config: &StarkConfig,
    public_inputs: &WalletTransitionPublicInputs,
    proof: &Proof,
) -> Result<()> {
    let air = WalletTransitionAir::new();

    let public_values = build_public_values_from_id_and_two_commitments(
        public_inputs.wallet_id,
        public_inputs.initial_wallet_commitment,
        public_inputs.final_wallet_commitment,
    );

    verify(config, &air, proof, &public_values).map_err(|_| ZkpError::ProofVerificationFailed)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::wallet::commitment::compute_commitment_from_channels;
    use crate::wallet::operation::WalletTransition;
    use crate::wallet::state::WalletState;
    use crate::wallet::transition::apply_operation;
    use crate::zkp::types::create_config;
    use crate::zkp::wallet::prover::{prove_wallet_commitment, prove_wallet_transition};

    fn create_test_config() -> StarkConfig { create_config().expect("Should create config") }

    fn create_test_wallet(wallet_id: u8, channels: &[(u8, u8)]) -> WalletState {
        let mut map = BTreeMap::new();
        for (cid, comm) in channels.iter() {
            let mut channel_id = [0u8; 32];
            channel_id[31] = *cid;

            let mut channel_commitment = [0u8; 32];
            channel_commitment[31] = *comm;

            map.insert(channel_id, channel_commitment);
        }
        WalletState::from_channels([wallet_id; 32], map)
    }

    fn assert_verification_fails(result: Result<()>) {
        assert!(matches!(result, Err(crate::Error::Zkp(ZkpError::ProofVerificationFailed))));
    }

    #[test]
    fn test_verify_wallet_commitment() {
        let config = create_test_config();
        let wallet = create_test_wallet(1, &[(10, 20)]);
        let proof =
            prove_wallet_commitment(&config, &wallet).expect("Valid wallet should generate proof");

        let wallet_commitment = compute_commitment_from_channels(wallet.id, &wallet.channels)
            .expect("should compute commitment");
        let public_inputs = WalletPublicInputs { wallet_id: wallet.id, wallet_commitment };
        verify_wallet_commitment(&config, &public_inputs, &proof)
            .expect("Verifier should correctly convert and pass valid public inputs");

        let wrong_wallet_id = [2u8; 32];
        let public_inputs = WalletPublicInputs { wallet_id: wrong_wallet_id, wallet_commitment };
        assert_verification_fails(verify_wallet_commitment(&config, &public_inputs, &proof));

        let wrong_wallet = create_test_wallet(99, &[]);
        let wrong_commitment =
            compute_commitment_from_channels(wrong_wallet.id, &wrong_wallet.channels)
                .expect("should compute commitment");
        let public_inputs =
            WalletPublicInputs { wallet_id: wallet.id, wallet_commitment: wrong_commitment };
        assert_verification_fails(verify_wallet_commitment(&config, &public_inputs, &proof));
    }

    #[test]
    fn test_verify_wallet_transition() {
        let config = create_test_config();
        let old_wallet = create_test_wallet(1, &[(10, 20)]);
        let channel_id = [5u8; 32];
        let channel_commitment = [30u8; 32];
        let insert_channel = WalletTransition::InsertChannel { channel_id, channel_commitment };
        let old_wallet_copy = WalletState {
            id: old_wallet.id,
            channels: old_wallet.channels.clone(),
            commitment: old_wallet.commitment,
        };
        let new_wallet = apply_operation(old_wallet_copy, &insert_channel)
            .expect("Valid transition should succeed");
        let proof =
            prove_wallet_transition(&config, &[&old_wallet, &new_wallet], &[&insert_channel])
                .expect("Valid transition should generate proof");

        let old_wallet_commitment =
            compute_commitment_from_channels(old_wallet.id, &old_wallet.channels)
                .expect("should compute commitment");
        let new_wallet_commitment =
            compute_commitment_from_channels(new_wallet.id, &new_wallet.channels)
                .expect("should compute commitment");
        let public_inputs = WalletTransitionPublicInputs {
            wallet_id: old_wallet.id,
            initial_wallet_commitment: old_wallet_commitment,
            final_wallet_commitment: new_wallet_commitment,
        };
        verify_wallet_transition(&config, &public_inputs, &proof)
            .expect("Verifier should correctly convert and pass valid public inputs");

        let wrong_wallet_id = [2u8; 32];
        let public_inputs = WalletTransitionPublicInputs {
            wallet_id: wrong_wallet_id,
            initial_wallet_commitment: old_wallet_commitment,
            final_wallet_commitment: new_wallet_commitment,
        };
        assert_verification_fails(verify_wallet_transition(&config, &public_inputs, &proof));

        let wrong_wallet = create_test_wallet(99, &[]);
        let wrong_old_commitment =
            compute_commitment_from_channels(wrong_wallet.id, &wrong_wallet.channels)
                .expect("should compute commitment");
        let public_inputs = WalletTransitionPublicInputs {
            wallet_id: old_wallet.id,
            initial_wallet_commitment: wrong_old_commitment,
            final_wallet_commitment: new_wallet_commitment,
        };
        assert_verification_fails(verify_wallet_transition(&config, &public_inputs, &proof));

        let wrong_new_commitment =
            compute_commitment_from_channels(wrong_wallet.id, &wrong_wallet.channels)
                .expect("should compute commitment");
        let public_inputs = WalletTransitionPublicInputs {
            wallet_id: old_wallet.id,
            initial_wallet_commitment: old_wallet_commitment,
            final_wallet_commitment: wrong_new_commitment,
        };
        assert_verification_fails(verify_wallet_transition(&config, &public_inputs, &proof));
    }
}
