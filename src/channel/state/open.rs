//! Open state
//!
//! This state represents an active channel that can process transfers
//! between a fixed sender and receiver. The channel tracks static
//! identity (pubkeys) and dynamic state (balances, nonce, commitment,
//! metadata).
//!
//! # Invariants
//!
//! - Sender and receiver balances sum to the channel's total capacity
//! - Nonce increments on each transition
//! - Commitment is always up-to-date with current state
//! - Channel is not closed

use bitcoin::secp256k1::{Secp256k1, SecretKey, XOnlyPublicKey};

use crate::btx::timelock::FORCE_CLOSE_TIMEOUT_BLOCKS;
use crate::types::ChannelCommitment;
/// Active channel state with fixed participants, balances, and commitment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Open {
    /// Sender's public key
    pub sender_pubkey: XOnlyPublicKey,
    /// Receiver's public key
    pub receiver_pubkey: XOnlyPublicKey,
    /// Revocation pubkey controlled by the sender (used to penalize receiver)
    pub sender_revocation_pubkey: XOnlyPublicKey,
    /// Revocation pubkey controlled by the receiver (used to penalize sender)
    pub receiver_revocation_pubkey: XOnlyPublicKey,
    /// Revocation secret the sender will reveal when this state is revoked
    pub sender_revocation_secret: [u8; 32],
    /// Revocation secret the receiver will reveal when this state is revoked
    pub receiver_revocation_secret: [u8; 32],
    /// Balance of the sender
    pub sender_balance: u64,
    /// Balance of the receiver
    pub receiver_balance: u64,
    /// Current nonce value
    pub nonce: u32,
    /// Commitment over the channel state
    pub commitment: ChannelCommitment,
    /// Additional metadata associated with the channel
    pub metadata: Vec<u8>,
    /// CSV timelock duration in blocks (configurable per channel)
    pub timeout_blocks: u16,
}

impl Open {
    /// Creates a new Open state with default timeout
    ///
    /// # Arguments
    /// * `sender_pubkey` - Sender's public key
    /// * `receiver_pubkey` - Receiver's public key
    /// * `total_capacity` - Total channel capacity
    ///
    /// # Examples
    ///
    /// ```rust
    /// use merkle_morph::channel::state::Open;
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
    /// let sender_revocation_secret =
    ///     SecretKey::from_slice(&[3u8; 32]).expect("32-byte array should always be a valid SecretKey");
    /// let receiver_revocation_secret =
    ///     SecretKey::from_slice(&[4u8; 32]).expect("32-byte array should always be a valid SecretKey");
    ///
    /// let state = Open::new(
    ///     sender_pubkey,
    ///     receiver_pubkey,
    ///     100,
    ///     sender_revocation_secret,
    ///     receiver_revocation_secret,
    /// );
    /// assert_eq!(state.sender_balance(), 100);
    /// assert_eq!(state.receiver_balance(), 0);
    /// ```
    pub fn new(
        sender_pubkey: XOnlyPublicKey,
        receiver_pubkey: XOnlyPublicKey,
        total_capacity: u64,
        sender_revocation_secret: SecretKey,
        receiver_revocation_secret: SecretKey,
    ) -> Self {
        Self::with_timeout(
            sender_pubkey,
            receiver_pubkey,
            total_capacity,
            FORCE_CLOSE_TIMEOUT_BLOCKS,
            sender_revocation_secret,
            receiver_revocation_secret,
        )
    }

    /// Creates a new Open state with a custom timeout
    ///
    /// This allows per-channel configuration of the CSV timelock delay.
    /// The timeout determines how many blocks must pass before a unilateral
    /// close transaction can be spent.
    ///
    /// # Arguments
    /// * `sender_pubkey` - Sender's public key
    /// * `receiver_pubkey` - Receiver's public key
    /// * `total_capacity` - Total channel capacity
    /// * `timeout_blocks` - CSV timelock duration in blocks
    ///
    /// # Examples
    ///
    /// ```rust
    /// use merkle_morph::channel::state::Open;
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
    /// // Create a channel with a custom 100-block timeout
    /// let sender_revocation_secret =
    ///     SecretKey::from_slice(&[3u8; 32]).expect("32-byte array should always be a valid SecretKey");
    /// let receiver_revocation_secret =
    ///     SecretKey::from_slice(&[4u8; 32]).expect("32-byte array should always be a valid SecretKey");
    ///
    /// // Create a channel with a custom 100-block timeout
    /// let state = Open::with_timeout(
    ///     sender_pubkey,
    ///     receiver_pubkey,
    ///     100,
    ///     100,
    ///     sender_revocation_secret,
    ///     receiver_revocation_secret,
    /// );
    /// assert_eq!(state.timeout_blocks, 100);
    /// ```
    pub fn with_timeout(
        sender_pubkey: XOnlyPublicKey,
        receiver_pubkey: XOnlyPublicKey,
        total_capacity: u64,
        timeout_blocks: u16,
        sender_revocation_secret: SecretKey,
        receiver_revocation_secret: SecretKey,
    ) -> Self {
        let secp = Secp256k1::new();
        let sender_revocation_pubkey =
            XOnlyPublicKey::from_keypair(&sender_revocation_secret.keypair(&secp)).0;
        let receiver_revocation_pubkey =
            XOnlyPublicKey::from_keypair(&receiver_revocation_secret.keypair(&secp)).0;

        Self {
            sender_pubkey,
            receiver_pubkey,
            sender_revocation_pubkey,
            receiver_revocation_pubkey,
            sender_revocation_secret: sender_revocation_secret.secret_bytes(),
            receiver_revocation_secret: receiver_revocation_secret.secret_bytes(),
            sender_balance: total_capacity,
            receiver_balance: 0,
            nonce: 0,
            commitment: ChannelCommitment::default(),
            metadata: vec![],
            timeout_blocks,
        }
    }

    /// Gets the sender's balance
    pub fn sender_balance(&self) -> u64 { self.sender_balance }

    /// Gets the receiver's balance
    pub fn receiver_balance(&self) -> u64 { self.receiver_balance }

    /// Computes the total channel capacity as the sum of both balances
    pub fn total_capacity(&self) -> u64 { self.sender_balance + self.receiver_balance }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::test_utils::*;

    #[test]
    fn test_new() {
        let (sender_pubkey, receiver_pubkey) = test_keys();
        let (sender_revocation_secret, receiver_revocation_secret) = revocation_secrets();
        let state = Open::new(
            sender_pubkey,
            receiver_pubkey,
            150,
            sender_revocation_secret,
            receiver_revocation_secret,
        );

        assert_eq!(state.sender_pubkey, sender_pubkey);
        assert_eq!(state.receiver_pubkey, receiver_pubkey);
        assert_eq!(state.sender_balance, 150);
        assert_eq!(state.receiver_balance, 0);
        assert_eq!(state.nonce, 0);
        assert_eq!(state.commitment, ChannelCommitment::default());
        assert_eq!(state.metadata, Vec::<u8>::new());
        assert_eq!(state.timeout_blocks, FORCE_CLOSE_TIMEOUT_BLOCKS);
    }

    #[test]
    fn test_with_timeout() {
        let (sender_pubkey, receiver_pubkey) = test_keys();
        let (sender_revocation_secret, receiver_revocation_secret) = revocation_secrets();
        let state = Open::with_timeout(
            sender_pubkey,
            receiver_pubkey,
            120,
            200,
            sender_revocation_secret,
            receiver_revocation_secret,
        );

        assert_eq!(state.sender_pubkey, sender_pubkey);
        assert_eq!(state.receiver_pubkey, receiver_pubkey);
        assert_eq!(state.sender_balance, 120);
        assert_eq!(state.receiver_balance, 0);
        assert_eq!(state.nonce, 0);
        assert_eq!(state.timeout_blocks, 200);
    }

    #[test]
    fn test_sender_balance() {
        let (sender_pubkey, receiver_pubkey) = test_keys();
        let (sender_revocation_secret, receiver_revocation_secret) = revocation_secrets();
        let state = Open::new(
            sender_pubkey,
            receiver_pubkey,
            100,
            sender_revocation_secret,
            receiver_revocation_secret,
        );

        assert_eq!(state.sender_balance(), 100);
    }

    #[test]
    fn test_receiver_balance() {
        let (sender_pubkey, receiver_pubkey) = test_keys();
        let (sender_revocation_secret, receiver_revocation_secret) = revocation_secrets();
        let state = Open::new(
            sender_pubkey,
            receiver_pubkey,
            100,
            sender_revocation_secret,
            receiver_revocation_secret,
        );

        assert_eq!(state.receiver_balance(), 0);
    }

    #[test]
    fn test_total_capacity() {
        let (sender_pubkey, receiver_pubkey) = test_keys();
        let (sender_revocation_secret, receiver_revocation_secret) = revocation_secrets();
        let state = Open::new(
            sender_pubkey,
            receiver_pubkey,
            90,
            sender_revocation_secret,
            receiver_revocation_secret,
        );

        assert_eq!(state.total_capacity(), 90);
    }
}
