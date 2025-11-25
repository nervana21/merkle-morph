//! Channel proof verification
//!
//! This module provides functions for verifying zero-knowledge proofs
//! for channel state transitions. The verification ensures that
//! a channel state transition is valid and that the commitment
//! correctly represents the channel state.

use p3_uni_stark::verify;

use crate::errors::ZkpError;
use crate::zkp::channel::air::ChannelTransitionAir;
use crate::zkp::channel::public_inputs::ChannelPublicInputs;
use crate::zkp::verifier_common::build_public_values_from_id_commitment_and_pubkey;
use crate::{Proof, Result, StarkConfig};

/// Verify a zero-knowledge proof for a channel state transition
///
/// This function verifies that a channel state transition was correctly computed.
/// The proof demonstrates that the channel commitment is correctly computed from
/// the channel state using Poseidon2 hashing. The verification ensures balance
/// conservation, nonce increments, commitment integrity, and sender authentication.
///
/// # Arguments
/// * `config` - Proof system configuration (`StarkConfig`)
/// * `public_inputs` - Public inputs containing channel_id, channel_commitment, and sender_pubkey
/// * `proof` - Zero-knowledge proof to verify
///
/// # Returns
/// * `Ok(())` - If the proof is valid
/// * `Err(ZkpError::ProofVerificationFailed)` - If the proof verification fails
pub fn verify_channel_transition(
    config: &StarkConfig,
    public_inputs: &ChannelPublicInputs,
    proof: &Proof,
) -> Result<()> {
    let air = ChannelTransitionAir::new();

    let public_values = build_public_values_from_id_commitment_and_pubkey(
        public_inputs.channel_id,
        public_inputs.channel_commitment,
        public_inputs.sender_pubkey,
    );

    verify(config, &air, proof, &public_values).map_err(|_| ZkpError::ProofVerificationFailed)?;

    Ok(())
}
#[cfg(test)]
mod tests {
    use bitcoin::secp256k1::SecretKey;

    use super::*;
    use crate::channel::commitment::state_commitment::compute_open_commitment;
    use crate::channel::state::Open;
    use crate::channel::test_utils::{revocation_secrets, test_keys};
    use crate::channel::transition::transfer::apply_transfer_state_only;
    use crate::channel::TransferAmount;
    use crate::zkp::channel::prover::prove_channel_transition;
    use crate::zkp::types::create_config;

    #[test]
    fn test_verify_channel_transition() {
        let config = create_config().expect("Failed to create STARK config");
        let (sender_pubkey, receiver_pubkey) = test_keys();
        let sender_sk =
            SecretKey::from_slice(&[1u8; 32]).expect("32-byte array should always be valid");
        let channel_id = [0u8; 32];
        let (sender_revocation_secret, receiver_revocation_secret) = revocation_secrets();
        let old_state = Open::new(
            sender_pubkey,
            receiver_pubkey,
            100,
            sender_revocation_secret,
            receiver_revocation_secret,
        );
        let amount = TransferAmount::new(30).expect("Failed to create transfer amount");
        let new_state =
            apply_transfer_state_only(&old_state, &amount).expect("Failed to apply transfer state");
        let proof = prove_channel_transition(
            channel_id, &old_state, &amount, &new_state, &sender_sk, &config,
        )
        .expect("Failed to generate channel transition proof");
        let commitment = compute_open_commitment(channel_id, &new_state);
        let public_inputs_ok =
            ChannelPublicInputs { channel_id, channel_commitment: commitment, sender_pubkey };

        let ok_result = verify_channel_transition(&config, &public_inputs_ok, &proof);

        assert!(ok_result.is_ok());

        let wrong_channel_id = [1u8; 32];
        let public_inputs_err = ChannelPublicInputs {
            channel_id: wrong_channel_id,
            channel_commitment: commitment,
            sender_pubkey,
        };

        let err_result = verify_channel_transition(&config, &public_inputs_err, &proof);

        assert!(matches!(err_result, Err(crate::Error::Zkp(ZkpError::ProofVerificationFailed))));
    }
}
