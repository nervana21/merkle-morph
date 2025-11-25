#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
//! Wallet input type for state transitions
//!
//! This module defines the input types for wallet state transitions.
//! Wallet operations include inserting/removing channels.

use crate::types::{ChannelCommitment, ChannelId};

/// Wallet input structure
///
/// Input for a wallet state transition. Represents various operations that can be applied
/// to a wallet: inserting or updating channel commitments, and removing channels.
///
/// # Usage
///
/// ```rust
/// use merkle_morph::wallet::WalletInput;
/// use merkle_morph::types::{ChannelId, ChannelCommitment};
///
/// // Insert or update a channel
/// let channel_id = [1u8; 32];
/// let commitment = [2u8; 32];
/// let input = WalletInput::InsertChannel { channel_id, channel_commitment: commitment };
/// assert_eq!(input.channel_id(), channel_id);
///
/// // Remove a channel
/// let remove_input = WalletInput::RemoveChannel { channel_id };
/// assert_eq!(remove_input.channel_id(), channel_id);
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum WalletInput {
    /// Insert or update a channel commitment in the wallet
    InsertChannel {
        /// Channel identifier
        channel_id: ChannelId,
        /// Channel commitment hash
        channel_commitment: ChannelCommitment,
    },

    /// Remove a channel from the wallet
    RemoveChannel {
        /// Channel identifier to remove
        channel_id: ChannelId,
    },
}

impl WalletInput {
    /// Get the channel ID for this input
    ///
    /// All wallet inputs operate on a channel, so this always returns a channel ID.
    ///
    /// # Returns
    ///
    /// The channel ID that this input operates on.
    #[inline]
    pub fn channel_id(&self) -> ChannelId {
        match self {
            Self::InsertChannel { channel_id, .. } | Self::RemoveChannel { channel_id } =>
                *channel_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_channel_input() {
        let channel_id = [1u8; 32];
        let commitment = [2u8; 32];
        let input = WalletInput::InsertChannel { channel_id, channel_commitment: commitment };
        assert_eq!(input.channel_id(), channel_id);
    }

    #[test]
    fn test_remove_channel_input() {
        let channel_id = [1u8; 32];
        let input = WalletInput::RemoveChannel { channel_id };
        assert_eq!(input.channel_id(), channel_id);
    }

    #[test]
    fn test_channel_id_consistency() {
        let channel_id = [42u8; 32];
        let commitment = [99u8; 32];

        let insert = WalletInput::InsertChannel { channel_id, channel_commitment: commitment };
        let remove = WalletInput::RemoveChannel { channel_id };

        assert_eq!(insert.channel_id(), channel_id);
        assert_eq!(remove.channel_id(), channel_id);
        assert_eq!(insert.channel_id(), remove.channel_id());
    }

    #[test]
    fn test_equality() {
        let channel_id1 = [1u8; 32];
        let channel_id2 = [2u8; 32];
        let commitment1 = [10u8; 32];
        let commitment2 = [20u8; 32];

        let input1 =
            WalletInput::InsertChannel { channel_id: channel_id1, channel_commitment: commitment1 };
        let input2 =
            WalletInput::InsertChannel { channel_id: channel_id1, channel_commitment: commitment1 };
        let input3 =
            WalletInput::InsertChannel { channel_id: channel_id1, channel_commitment: commitment2 };
        let input4 =
            WalletInput::InsertChannel { channel_id: channel_id2, channel_commitment: commitment1 };
        let input5 = WalletInput::RemoveChannel { channel_id: channel_id1 };

        assert_eq!(input1, input2);
        assert_ne!(input1, input3);
        assert_ne!(input1, input4);
        assert_ne!(input1, input5);
    }

    #[test]
    fn test_clone() {
        let channel_id = [5u8; 32];
        let commitment = [15u8; 32];
        let input = WalletInput::InsertChannel { channel_id, channel_commitment: commitment };
        let cloned = input.clone();

        assert_eq!(input, cloned);
        assert_eq!(input.channel_id(), cloned.channel_id());
    }

    #[test]
    fn test_debug_format() {
        let channel_id = [7u8; 32];
        let commitment = [17u8; 32];
        let input = WalletInput::InsertChannel { channel_id, channel_commitment: commitment };

        let debug_str = format!("{:?}", input);
        assert!(debug_str.contains("InsertChannel"));
    }
}
