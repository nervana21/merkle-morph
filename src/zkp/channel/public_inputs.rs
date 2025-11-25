#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
//! Channel public inputs for zero-knowledge proof verification
//!
//! This module defines the public inputs structure for channel transition proofs.

use crate::types::{ChannelCommitment, ChannelId};

/// Channel public inputs structure
///
/// Public inputs for channel transition proof verification. This struct contains only
/// public values that are committed in the proof. These values are revealed to the
/// verifier and must match what is attested in the zero-knowledge proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelPublicInputs {
    /// Channel identifier
    pub channel_id: ChannelId,
    /// Channel commitment (commitment to the new state)
    pub channel_commitment: ChannelCommitment,
}
