//! Common verification utilities
//!
//! This module provides shared helper functions for building public values
//! from IDs and commitments for zero-knowledge proof verification.

use crate::zkp::types::{bytes32_to_fields, Val};
use crate::Bytes32;

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

/// Build public values vector from an ID, commitment, and sender public key
///
/// This function converts a Bytes32 ID, a Bytes32 commitment, and an XOnlyPublicKey
/// to field elements and builds a public values vector suitable for proof verification
/// with sender authentication.
///
/// # Arguments
/// * `id`: The identifier (channel_id)
/// * `commitment`: The commitment value
/// * `sender_pubkey`: The sender's public key (32 bytes, X-only)
///
/// # Returns
/// A vector of field elements: [id_fields (8), commitment_fields (8), pubkey_fields (8)]
pub(crate) fn build_public_values_from_id_commitment_and_pubkey(
    id: Bytes32,
    commitment: Bytes32,
    sender_pubkey: bitcoin::secp256k1::XOnlyPublicKey,
) -> Vec<Val> {
    let mut public_values = Vec::new();
    let id_fields = bytes32_to_fields(id);
    public_values.extend(id_fields.iter().map(|f| Val::from(*f)));

    let commitment_fields = bytes32_to_fields(commitment);
    public_values.extend(commitment_fields.iter().map(|f| Val::from(*f)));

    // Convert XOnlyPublicKey (32 bytes) to Bytes32, then to fields
    let pubkey_bytes: Bytes32 = sender_pubkey.serialize();
    let pubkey_fields = bytes32_to_fields(pubkey_bytes);
    public_values.extend(pubkey_fields.iter().map(|f| Val::from(*f)));

    public_values
}
