#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
//! Common verification utilities
//!
//! This module provides shared helper functions for building public values
//! from IDs and commitments for zero-knowledge proof verification.

use crate::types::Bytes32;
use crate::zkp::types::{bytes32_to_fields, Val};

/// Build public values vector from an ID and a commitment
///
/// This function converts a Bytes32 ID and a Bytes32 commitment to field elements
/// and builds a public values vector suitable for proof verification.
///
/// # Arguments
/// * `id`: The identifier (channel_id or wallet_id)
/// * `commitment`: The commitment value
///
/// # Returns
/// A vector of field elements: [id_fields (8), commitment_fields (8)]
pub(crate) fn build_public_values_from_id_and_commitment(
    id: Bytes32,
    commitment: Bytes32,
) -> Vec<Val> {
    let mut public_values = Vec::new();
    let id_fields = bytes32_to_fields(id);
    public_values.extend(id_fields.iter().map(|f| Val::from(*f)));

    let commitment_fields = bytes32_to_fields(commitment);
    public_values.extend(commitment_fields.iter().map(|f| Val::from(*f)));

    public_values
}

/// Build public values vector from an ID and two commitments
///
/// This function converts a Bytes32 ID and two Bytes32 commitments to field elements
/// and builds a public values vector suitable for proof verification.
///
/// # Arguments
/// * `id`: The identifier (wallet_id)
/// * `initial_commitment`: The initial commitment value
/// * `final_commitment`: The final commitment value
///
/// # Returns
/// A vector of field elements: [id_fields (8), initial_commitment_fields (8), final_commitment_fields (8)]
pub(crate) fn build_public_values_from_id_and_two_commitments(
    id: Bytes32,
    initial_commitment: Bytes32,
    final_commitment: Bytes32,
) -> Vec<Val> {
    let mut public_values = Vec::new();
    let id_fields = bytes32_to_fields(id);
    public_values.extend(id_fields.iter().map(|f| Val::from(*f)));

    let initial_commitment_fields = bytes32_to_fields(initial_commitment);
    public_values.extend(initial_commitment_fields.iter().map(|f| Val::from(*f)));

    let final_commitment_fields = bytes32_to_fields(final_commitment);
    public_values.extend(final_commitment_fields.iter().map(|f| Val::from(*f)));

    public_values
}

#[allow(dead_code)]
pub(crate) fn build_public_values_from_commitment(commitment: Bytes32) -> Vec<Val> {
    let commitment_fields = bytes32_to_fields(commitment);
    commitment_fields.iter().map(|f| Val::from(*f)).collect()
}
