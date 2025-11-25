//! Wallet operation types for state transitions
//!
//! This module defines the operation types for wallet state transitions.
//! Wallet operations include inserting/updating channel commitments and removing channels.
//!
//! Operations are pure data structures that represent operations to be applied to wallet state.
//! They are used with the `apply_operation` function to perform state transitions.

use crate::types::{ChannelCommitment, ChannelId};

/// Wallet transition structure
///
/// Transition for a wallet state change. Represents various operations that can be applied
/// to a wallet: inserting or updating channel commitments, and removing channels.
///
/// # Usage
///
/// ```rust
/// use merkle_morph::wallet::WalletTransition;
/// use merkle_morph::types::{ChannelId, ChannelCommitment};
///
/// // Insert or update a channel
/// let channel_id = [1u8; 32];
/// let commitment = [2u8; 32];
/// let transition = WalletTransition::InsertChannel { channel_id, channel_commitment: commitment };
/// assert_eq!(transition.channel_id(), channel_id);
///
/// // Remove a channel
/// let remove_transition = WalletTransition::RemoveChannel { channel_id };
/// assert_eq!(remove_transition.channel_id(), channel_id);
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum WalletTransition {
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

impl WalletTransition {
    /// Get the channel ID for this transition
    ///
    /// All wallet transitions operate on a channel, so this always returns a channel ID.
    ///
    /// # Returns
    ///
    /// The channel ID that this transition operates on.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use merkle_morph::wallet::operation::WalletTransition;
    ///
    /// let channel_id = [1u8; 32];
    /// let commitment = [2u8; 32];
    ///
    /// let insert = WalletTransition::InsertChannel { channel_id, channel_commitment: commitment };
    /// assert_eq!(insert.channel_id(), channel_id);
    ///
    /// let remove = WalletTransition::RemoveChannel { channel_id };
    /// assert_eq!(remove.channel_id(), channel_id);
    /// ```
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
    fn test_channel_id() {
        let channel_id_1 = [1u8; 32];
        let channel_commitment = [2u8; 32];

        let insert_transition =
            WalletTransition::InsertChannel { channel_id: channel_id_1, channel_commitment };

        assert_eq!(insert_transition.channel_id(), channel_id_1);

        let channel_id_2 = [3u8; 32];

        let remove_transition = WalletTransition::RemoveChannel { channel_id: channel_id_2 };

        assert_eq!(remove_transition.channel_id(), channel_id_2);
    }
}
