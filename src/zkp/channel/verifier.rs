#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
//! Channel proof verification
//!
//! This module provides functions for verifying zero-knowledge proofs
//! for channel state transitions. The verification ensures that
//! a channel state transition is valid and that the commitment
//! correctly represents the channel state.

use p3_uni_stark::verify;

use crate::errors::{Result, ZkpError};
use crate::zkp::channel::air::ChannelTransitionAir;
use crate::zkp::channel::public_inputs::ChannelPublicInputs;
use crate::zkp::verifier_common::build_public_values_from_id_and_commitment;
use crate::zkp::{Proof, StarkConfig};

/// Verify a zero-knowledge proof for a channel state transition
///
/// This function verifies that a channel state transition was correctly computed.
/// The proof demonstrates that the channel commitment is correctly computed from
/// the channel state using Poseidon2 hashing. The verification ensures balance
/// conservation, nonce increments, and commitment integrity.
///
/// # Arguments
/// * `config` - Proof system configuration (`StarkConfig`)
/// * `public_inputs` - Public inputs containing channel_id and channel_commitment
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

    let public_values = build_public_values_from_id_and_commitment(
        public_inputs.channel_id,
        public_inputs.channel_commitment,
    );

    verify(config, &air, proof, &public_values).map_err(|_| ZkpError::ProofVerificationFailed)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::commitment::compute_commitment;
    use crate::channel::state::ChannelState;
    use crate::channel::transition::apply_transfer_state_only;
    use crate::channel::TransferAmount;
    use crate::zkp::channel::prover::prove_channel_transition;
    use crate::zkp::types::create_config;

    fn create_test_config() -> StarkConfig { create_config().expect("Should create config") }

    fn create_transition(
        old_balance: u64,
        amount: u64,
    ) -> (ChannelState, TransferAmount, ChannelState) {
        let old_state = ChannelState::new(old_balance);
        let amount = TransferAmount::new(amount).expect("valid transfer");
        let new_state =
            apply_transfer_state_only(&old_state, &amount).expect("Valid transfer should succeed");
        (old_state, amount, new_state)
    }

    fn assert_verification_fails(result: Result<()>) {
        assert!(matches!(
            result,
            Err(crate::errors::Error::Zkp(ZkpError::ProofVerificationFailed))
        ));
    }

    #[test]
    fn test_verify_channel_transition() {
        let config = create_test_config();
        let channel_id = [0u8; 32];
        let (old_state, amount, new_state) = create_transition(100, 30);
        let proof = prove_channel_transition(&config, channel_id, &old_state, &amount, &new_state)
            .expect("Valid transition should generate proof");

        let channel_commitment = compute_commitment(channel_id, &new_state);
        let public_inputs = ChannelPublicInputs { channel_id, channel_commitment };
        verify_channel_transition(&config, &public_inputs, &proof)
            .expect("Verifier should correctly convert and pass valid public inputs");

        let wrong_channel_id = [1u8; 32];
        let public_inputs =
            ChannelPublicInputs { channel_id: wrong_channel_id, channel_commitment };
        assert_verification_fails(verify_channel_transition(&config, &public_inputs, &proof));

        let wrong_commitment = compute_commitment(channel_id, &ChannelState::new(200));
        let public_inputs =
            ChannelPublicInputs { channel_id, channel_commitment: wrong_commitment };
        assert_verification_fails(verify_channel_transition(&config, &public_inputs, &proof));
    }
}
