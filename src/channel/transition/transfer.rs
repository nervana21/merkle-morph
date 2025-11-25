//! Transfer transition
//!
//! This transition processes a transfer within an Open channel.
//!
//! This transition specifies:
//! - Valid source and target states: Open → Open
//! - Preconditions that must hold before the transition can be applied
//! - Postconditions that are guaranteed after a successful transition
//! - Input requirements and validation rules
//! - Nonce progression rules (strict +1 increment)
//! - Fee semantics and allocation policies

use std::fmt;
use std::ops::Deref;

use bitcoin::secp256k1::SecretKey;

use crate::channel::commitment::state_commitment::compute_open_commitment;
use crate::channel::state::Open;
use crate::errors::ChannelError::{
    BalanceOverflow, ChannelNonceOverflow, InsufficientBalance, MetadataTooLarge,
};
use crate::types::{ChannelCommitment, ChannelId, MAX_METADATA_SIZE};
use crate::zkp::prove_channel_transition;
use crate::{Proof, Result, StarkConfig};

/// Transfer amount structure
///
/// A validated transfer amount for channel state transitions. Represents a non-zero amount
/// to transfer from the sender to the receiver in a unilateral channel. The receiver is
/// fixed by the channel state.
///
/// # Usage
///
/// `TransferAmount` implements `Deref<Target = u64>`, so it can be used directly
/// as a `u64` in most contexts:
///
/// ```rust
/// use merkle_morph::channel::TransferAmount;
///
/// fn main() -> Result<(), merkle_morph::errors::ChannelError> {
///     let amount = TransferAmount::new(100)?;
///     let doubled = *amount * 2;
///     Ok(())
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferAmount(u64);

impl TransferAmount {
    /// Create a new transfer amount
    ///
    /// # Arguments
    /// * `amount` - The amount to transfer (must be > 0)
    ///
    /// # Returns
    /// * `Ok(TransferAmount)` - If the amount is valid
    /// * `Err(ChannelError::InvalidZeroTransfer)` - If amount is 0
    pub fn new(amount: u64) -> std::result::Result<Self, crate::errors::ChannelError> {
        if amount == 0 {
            return Err(crate::errors::ChannelError::InvalidZeroTransfer);
        }
        Ok(Self(amount))
    }
}

impl Deref for TransferAmount {
    type Target = u64;

    #[inline]
    fn deref(&self) -> &Self::Target { &self.0 }
}

fn validate_metadata_size(metadata: &[u8]) -> Result<()> {
    if metadata.len() > MAX_METADATA_SIZE {
        return Err(MetadataTooLarge { size: metadata.len(), max_size: MAX_METADATA_SIZE }.into());
    }
    Ok(())
}

/// Result of a channel transfer operation
///
/// Contains the new state, commitment, and proof for the transition.
pub struct TransferResult {
    /// New channel state after transition
    pub new_state: Open,
    /// Commitment to the new state
    pub commitment: ChannelCommitment,
    /// Proof for the transition
    pub proof: Proof,
}

impl fmt::Debug for TransferResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransferResult")
            .field("new_state", &"<hidden>")
            .field("commitment", &"<hidden>")
            .field("proof", &"<hidden>")
            .finish()
    }
}

/// Internal function for pure state transitions
///
/// This function performs a pure state transition without generating proofs or commitments.
/// It is used internally by ZKP proof generation code and cross-channel claim operations.
///
/// # Arguments
/// * `state` - Current Open state
/// * `amount` - Transfer amount to apply
///
/// # Returns
/// * `Ok(Open)` - New Open state after transfer
/// * `Err(Error::Channel(ChannelError::InsufficientBalance))` - Error if sender has insufficient balance
/// * `Err(Error::Channel(ChannelError::BalanceOverflow))` - Error if balance operations would overflow
/// * `Err(Error::Channel(ChannelError::ChannelNonceOverflow))` - Error if nonce would overflow
pub fn apply_transfer_state_only(state: &Open, amount: &TransferAmount) -> Result<Open> {
    validate_metadata_size(&state.metadata)?;

    let new_sender_balance =
        state.sender_balance.checked_sub(**amount).ok_or(InsufficientBalance)?;
    let new_receiver_balance =
        state.receiver_balance.checked_add(**amount).ok_or(BalanceOverflow)?;

    let new_nonce = state.nonce.checked_add(1).ok_or(ChannelNonceOverflow)?;

    let new_state = Open {
        sender_pubkey: state.sender_pubkey,
        receiver_pubkey: state.receiver_pubkey,
        sender_revocation_pubkey: state.sender_revocation_pubkey,
        receiver_revocation_pubkey: state.receiver_revocation_pubkey,
        sender_revocation_secret: state.sender_revocation_secret,
        receiver_revocation_secret: state.receiver_revocation_secret,
        sender_balance: new_sender_balance,
        receiver_balance: new_receiver_balance,
        nonce: new_nonce,
        commitment: state.commitment,
        metadata: state.metadata.clone(),
        timeout_blocks: state.timeout_blocks,
    };

    Ok(new_state)
}

/// Apply a transfer operation to a channel
///
/// This function generates a proof and commitment for the state transition.
///
/// # Arguments
/// * `channel_id` - Channel identifier
/// * `state` - Current Open state
/// * `amount` - Transfer amount to apply
/// * `sender_sk` - Sender's private key for computing authentication hash
/// * `config` - Proof system configuration
///
/// # Returns
/// * `Ok(TransferResult)` - Contains new state, commitment, and proof
/// * `Err(Error::Channel(ChannelError::InsufficientBalance))` - Error if sender has insufficient balance
/// * `Err(Error::Channel(ChannelError::BalanceOverflow))` - Error if balance operations would overflow
/// * `Err(Error::Channel(ChannelError::ChannelNonceOverflow))` - Error if nonce would overflow
/// * `Err(Error::Channel(ChannelError))` - Other channel errors from proof generation
///
/// # Examples
///
/// ```rust
/// use merkle_morph::channel::state::Open;
/// use merkle_morph::channel::TransferAmount;
/// use merkle_morph::channel::transition::transfer::apply_transfer;
/// use merkle_morph::zkp::create_config;
/// use bitcoin::secp256k1::{Secp256k1, SecretKey, XOnlyPublicKey};
///
/// let secp = Secp256k1::new();
/// let sender_sk =
///     SecretKey::from_slice(&[1u8; 32]).expect("32-byte array should always be a valid SecretKey");
/// let receiver_sk =
///     SecretKey::from_slice(&[2u8; 32]).expect("32-byte array should always be a valid SecretKey");
/// let sender_pubkey = XOnlyPublicKey::from_keypair(&sender_sk.keypair(&secp)).0;
/// let receiver_pubkey = XOnlyPublicKey::from_keypair(&receiver_sk.keypair(&secp)).0;
///
/// let state = Open::new(sender_pubkey, receiver_pubkey, 100);
/// let amount = TransferAmount::new(30).expect("valid transfer");
/// let config = create_config()?;
/// let channel_id = [0u8; 32];
///
/// // Generate proof
/// let result = apply_transfer(channel_id, &state, &amount, &sender_sk, &config)?;
/// assert_eq!(result.new_state.sender_balance(), 70);
/// # Ok::<(), merkle_morph::errors::Error>(())
/// ```
pub fn apply_transfer(
    channel_id: ChannelId,
    state: &Open,
    amount: &TransferAmount,
    sender_sk: &SecretKey,
    config: &StarkConfig,
) -> Result<TransferResult> {
    let new_state = apply_transfer_state_only(state, amount)?;
    let commitment = compute_open_commitment(channel_id, &new_state);
    let proof = prove_channel_transition(channel_id, state, amount, &new_state, sender_sk, config)?;

    Ok(TransferResult { new_state, commitment, proof })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::test_utils::*;
    use crate::types::ChannelCommitment;
    use crate::zkp::create_config;

    #[test]
    fn test_new() {
        assert!(matches!(
            TransferAmount::new(0),
            Err(crate::errors::ChannelError::InvalidZeroTransfer)
        ));

        assert!(matches!(TransferAmount::new(1), Ok(TransferAmount(1))));
    }

    #[test]
    fn test_apply_transfer_state_only() {
        let (sender_pubkey, receiver_pubkey) = test_keys();
        let (sender_revocation_secret, receiver_revocation_secret) = revocation_secrets();
        let amount = TransferAmount::new(30).expect("valid transfer");
        let metadata_too_large_state = Open {
            sender_pubkey,
            receiver_pubkey,
            sender_revocation_pubkey: sender_pubkey,
            receiver_revocation_pubkey: receiver_pubkey,
            sender_revocation_secret: [0u8; 32],
            receiver_revocation_secret: [0u8; 32],
            sender_balance: 100,
            receiver_balance: 0,
            nonce: 0,
            commitment: ChannelCommitment::default(),
            metadata: vec![0u8; crate::types::MAX_METADATA_SIZE + 1],
            timeout_blocks: 144,
        };

        assert!(matches!(
            apply_transfer_state_only(&metadata_too_large_state, &amount),
            Err(crate::Error::Channel(crate::errors::ChannelError::MetadataTooLarge { .. }))
        ));

        let insufficient_state = Open {
            sender_pubkey,
            receiver_pubkey,
            sender_revocation_pubkey: sender_pubkey,
            receiver_revocation_pubkey: receiver_pubkey,
            sender_revocation_secret: [0u8; 32],
            receiver_revocation_secret: [0u8; 32],
            sender_balance: 20,
            receiver_balance: 0,
            nonce: 0,
            commitment: ChannelCommitment::default(),
            metadata: vec![],
            timeout_blocks: 144,
        };

        assert!(matches!(
            apply_transfer_state_only(&insufficient_state, &amount),
            Err(crate::Error::Channel(crate::errors::ChannelError::InsufficientBalance))
        ));

        let balance_overflow_state = Open {
            sender_pubkey,
            receiver_pubkey,
            sender_revocation_pubkey: sender_pubkey,
            receiver_revocation_pubkey: receiver_pubkey,
            sender_revocation_secret: [0u8; 32],
            receiver_revocation_secret: [0u8; 32],
            sender_balance: 100,
            receiver_balance: u64::MAX,
            nonce: 0,
            commitment: ChannelCommitment::default(),
            metadata: vec![],
            timeout_blocks: 144,
        };

        assert!(matches!(
            apply_transfer_state_only(&balance_overflow_state, &amount),
            Err(crate::Error::Channel(crate::errors::ChannelError::BalanceOverflow))
        ));

        let nonce_overflow_state = Open {
            sender_pubkey,
            receiver_pubkey,
            sender_revocation_pubkey: sender_pubkey,
            receiver_revocation_pubkey: receiver_pubkey,
            sender_revocation_secret: [0u8; 32],
            receiver_revocation_secret: [0u8; 32],
            sender_balance: 100,
            receiver_balance: 0,
            nonce: u32::MAX,
            commitment: ChannelCommitment::default(),
            metadata: vec![],
            timeout_blocks: 144,
        };

        assert!(matches!(
            apply_transfer_state_only(&nonce_overflow_state, &amount),
            Err(crate::Error::Channel(crate::errors::ChannelError::ChannelNonceOverflow))
        ));

        let valid_state = Open::new(
            sender_pubkey,
            receiver_pubkey,
            100,
            sender_revocation_secret,
            receiver_revocation_secret,
        );

        let new_state = apply_transfer_state_only(&valid_state, &amount).expect("valid");

        assert_eq!(new_state.sender_balance(), 70);
        assert_eq!(new_state.receiver_balance(), 30);
        assert_eq!(new_state.nonce, 1);
    }

    #[test]
    fn test_apply_transfer() {
        let (sender_pubkey, receiver_pubkey) = test_keys();
        let sender_sk = SecretKey::from_slice(&[1u8; 32])
            .expect("32-byte array should always be a valid SecretKey");
        let config = create_config().expect("Should create config");
        let channel_id = [0u8; 32];
        let (sender_revocation_secret, receiver_revocation_secret) = revocation_secrets();
        let amount = TransferAmount::new(30).expect("valid transfer");

        let metadata_too_large_state = Open {
            sender_pubkey,
            receiver_pubkey,
            sender_revocation_pubkey: sender_pubkey,
            receiver_revocation_pubkey: receiver_pubkey,
            sender_revocation_secret: [0u8; 32],
            receiver_revocation_secret: [0u8; 32],
            sender_balance: 100,
            receiver_balance: 0,
            nonce: 0,
            commitment: ChannelCommitment::default(),
            metadata: vec![0u8; crate::types::MAX_METADATA_SIZE + 1],
            timeout_blocks: 144,
        };

        assert!(matches!(
            apply_transfer(channel_id, &metadata_too_large_state, &amount, &sender_sk, &config),
            Err(crate::Error::Channel(crate::errors::ChannelError::MetadataTooLarge { .. }))
        ));

        let insufficient_state = Open {
            sender_pubkey,
            receiver_pubkey,
            sender_revocation_pubkey: sender_pubkey,
            receiver_revocation_pubkey: receiver_pubkey,
            sender_revocation_secret: [0u8; 32],
            receiver_revocation_secret: [0u8; 32],
            sender_balance: 20,
            receiver_balance: 0,
            nonce: 0,
            commitment: ChannelCommitment::default(),
            metadata: vec![],
            timeout_blocks: 144,
        };

        assert!(matches!(
            apply_transfer(channel_id, &insufficient_state, &amount, &sender_sk, &config),
            Err(crate::Error::Channel(crate::errors::ChannelError::InsufficientBalance))
        ));

        let balance_overflow_state = Open {
            sender_pubkey,
            receiver_pubkey,
            sender_revocation_pubkey: sender_pubkey,
            receiver_revocation_pubkey: receiver_pubkey,
            sender_revocation_secret: [0u8; 32],
            receiver_revocation_secret: [0u8; 32],
            sender_balance: 100,
            receiver_balance: u64::MAX,
            nonce: 0,
            commitment: ChannelCommitment::default(),
            metadata: vec![],
            timeout_blocks: 144,
        };

        assert!(matches!(
            apply_transfer(channel_id, &balance_overflow_state, &amount, &sender_sk, &config),
            Err(crate::Error::Channel(crate::errors::ChannelError::BalanceOverflow))
        ));

        let nonce_overflow_state = Open {
            sender_pubkey,
            receiver_pubkey,
            sender_revocation_pubkey: sender_pubkey,
            receiver_revocation_pubkey: receiver_pubkey,
            sender_revocation_secret: [0u8; 32],
            receiver_revocation_secret: [0u8; 32],
            sender_balance: 100,
            receiver_balance: 0,
            nonce: u32::MAX,
            commitment: ChannelCommitment::default(),
            metadata: vec![],
            timeout_blocks: 144,
        };

        assert!(matches!(
            apply_transfer(channel_id, &nonce_overflow_state, &amount, &sender_sk, &config),
            Err(crate::Error::Channel(crate::errors::ChannelError::ChannelNonceOverflow))
        ));

        let valid_state = Open::new(
            sender_pubkey,
            receiver_pubkey,
            100,
            sender_revocation_secret,
            receiver_revocation_secret,
        );

        let result =
            apply_transfer(channel_id, &valid_state, &amount, &sender_sk, &config).expect("valid");

        assert_eq!(result.new_state.sender_balance(), 70);
        assert_eq!(result.new_state.receiver_balance(), 30);
        assert_eq!(result.new_state.nonce, 1);
    }
}
