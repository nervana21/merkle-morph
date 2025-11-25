//! Common proof generation utilities
//!
//! This module provides shared functionality for generating zero-knowledge proofs
//! across different proof types (channel, wallet, etc.).

use p3_air::Air;
use p3_uni_stark::{prove, DebugConstraintBuilder, ProverConstraintFolder, SymbolicAirBuilder};

use crate::zkp::types::{bytes32_to_fields, Proof, StarkConfig, Trace, Val};
use crate::{Bytes32, Result};

/// Generate a zero-knowledge proof with common verification logic
///
/// This function handles the common pattern of:
/// 1. Extracting commitment fields from the trace
/// 2. Verifying the commitment matches the expected value
/// 3. Building public values from ID and commitment
/// 4. Generating the proof
///
/// # Arguments
/// * `config` - Proof system configuration (`StarkConfig`)
/// * `trace` - Execution trace
/// * `extract_commitment` - Closure to extract commitment fields from the trace
/// * `expected_commitment` - Expected commitment value to verify against
/// * `id` - Identifier (channel_id or wallet_id)
/// * `air` - AIR instance for the proof
///
/// # Returns
/// A zero-knowledge proof
pub(super) fn prove_with_commitment<A>(
    config: &StarkConfig,
    trace: Trace,
    extract_commitment: impl FnOnce(&Trace) -> Result<Vec<Val>>,
    expected_commitment: Bytes32,
    id: Bytes32,
    air: &A,
) -> Result<Proof>
where
    A: Air<SymbolicAirBuilder<Val>>
        + for<'a> Air<ProverConstraintFolder<'a, StarkConfig>>
        + for<'a> Air<DebugConstraintBuilder<'a, Val>>,
{
    // Extract commitment fields from trace
    let commitment_fields = extract_commitment(&trace)?;

    // Verify commitment matches expected
    let expected_fields = bytes32_to_fields(expected_commitment);
    if commitment_fields != expected_fields {
        return Err(crate::Error::Zkp(crate::errors::ZkpError::ProofGenerationFailed));
    }

    // Build public values: ID fields followed by commitment fields
    let mut public_values = Vec::new();
    let id_fields = bytes32_to_fields(id);
    public_values.extend(id_fields.iter().map(|f| Val::from(*f)));
    public_values.extend(commitment_fields.iter().map(|f| Val::from(*f)));

    // Generate proof
    let proof = prove(config, air, trace, &public_values);
    Ok(proof)
}

#[cfg(test)]
mod tests {
    use p3_air::{Air, BaseAir};
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_uni_stark::{DebugConstraintBuilder, ProverConstraintFolder, SymbolicAirBuilder};

    use super::*;
    use crate::zkp::types::{create_config, Val};

    #[derive(Clone, Copy)]
    struct NoopAir;

    impl BaseAir<Val> for NoopAir {
        fn width(&self) -> usize { 0 }
    }

    impl Air<SymbolicAirBuilder<Val>> for NoopAir {
        fn eval(&self, _builder: &mut SymbolicAirBuilder<Val>) {}
    }

    impl<'a> Air<ProverConstraintFolder<'a, StarkConfig>> for NoopAir {
        fn eval(&self, _builder: &mut ProverConstraintFolder<'a, StarkConfig>) {}
    }

    impl<'a> Air<DebugConstraintBuilder<'a, Val>> for NoopAir {
        fn eval(&self, _builder: &mut DebugConstraintBuilder<'a, Val>) {}
    }

    #[test]
    fn test_prove_with_commitment_rejects_mismatched_commitment() {
        let config = create_config().expect("config should build");
        let trace = RowMajorMatrix::new(vec![Val::ZERO; 8], 1);
        let expected_commitment = [0x11u8; 32];
        let id = [0x22u8; 32];

        let result = prove_with_commitment(
            &config,
            trace,
            |_| Ok(vec![Val::ZERO; 8]), // Extracted value differs from expected commitment
            expected_commitment,
            id,
            &NoopAir,
        );
        assert!(matches!(result, Err(crate::Error::Zkp(_))), "Mismatched commitment should error");
    }
}
