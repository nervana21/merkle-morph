//! Wallet commitment computation
//!
//! This module provides a function for computing wallet commitments as hash chains
//! from channel commitments. Wallet commitments aggregate multiple channel commitments
//! under a single wallet identifier, enabling efficient verification of wallet state.
//!
//! The commitment computation uses a deterministic hash chain:
//! 1. Initialize with wallet ID: `poseidon2("MM_WLT_INIT_v0" || wallet_id)`
//! 2. For each channel (in sorted order): hash channel ID and commitment
//! 3. Accumulate using chain domain: `poseidon2("MM_CHAIN_v0" || accumulator || hash)`
//!
//! This ensures that:
//! - Empty wallets have a deterministic commitment based on wallet ID
//! - Channel order is deterministic (sorted by channel ID)
//! - The commitment can be verified in zero-knowledge proofs

use std::collections::BTreeMap;

use crate::types::{
    ChannelCommitment, ChannelId, WalletCommitment, WalletId, CHAIN_DOMAIN, MAX_CHANNELS,
    WALLET_HASH_DOMAIN, WALLET_INIT_DOMAIN,
};
use crate::zkp::poseidon2_hash_fixed;
use crate::{Bytes32, Result};

/// Computes commitment from wallet_id and a map of channel commitments
///
/// Channels are processed in sorted order by channel_id to match trace generation.
/// The commitment is computed using a deterministic hash chain that aggregates
/// all channel commitments under a single wallet identifier.
///
/// The commitment is computed by:
/// 1. Initialize accumulator with:
///    poseidon2("MM_WLT_INIT_v0" || wallet_id)
///
/// 2. For each channel compute:
///    poseidon2("MM_WLT_HASH_v0" || channel_id || channel_commitment)
///
/// 3. Accumulate all hashes using:
///    poseidon2("MM_CHAIN_v0" || accumulator || hash)
///
/// Empty wallets have commitment = poseidon2("MM_WLT_INIT_v0" || wallet_id).
///
/// # Arguments
/// * `wallet_id` - The wallet identifier
/// * `channels` - A map of channel IDs to their commitments
///
/// # Returns
/// * `Ok(WalletCommitment)` - The computed wallet commitment
///
/// # Errors
/// * `Err(Error::Wallet(WalletError::TooManyChannels))` - If the wallet has more than MAX_CHANNELS channels
///
/// # Examples
///
/// ```rust
/// use merkle_morph::wallet::commitment::compute_commitment_from_channels;
/// use std::collections::BTreeMap;
///
/// let wallet_id = [0u8; 32];
/// let mut channels = BTreeMap::new();
/// channels.insert([1u8; 32], [2u8; 32]);
/// channels.insert([3u8; 32], [4u8; 32]);
///
/// let commitment = compute_commitment_from_channels(wallet_id, &channels)?;
/// assert_ne!(commitment, [0u8; 32]);
/// # Ok::<(), merkle_morph::Error>(())
/// ```
pub fn compute_commitment_from_channels(
    wallet_id: WalletId,
    channels: &BTreeMap<ChannelId, ChannelCommitment>,
) -> Result<WalletCommitment> {
    if channels.len() > MAX_CHANNELS {
        return Err(crate::Error::Wallet(crate::errors::WalletError::TooManyChannels {
            channel_count: channels.len(),
            max_channels: MAX_CHANNELS,
        }));
    }

    let mut accumulator: Bytes32 = poseidon2_hash_fixed(&[WALLET_INIT_DOMAIN, &wallet_id[..]]);

    let mut sorted_channels: Vec<_> = channels.iter().collect();
    sorted_channels.sort_by_key(|(id, _)| *id);

    for (channel_id, channel_commitment) in sorted_channels.iter() {
        let hash: Bytes32 =
            poseidon2_hash_fixed(&[WALLET_HASH_DOMAIN, &channel_id[..], &channel_commitment[..]]);
        accumulator = poseidon2_hash_fixed(&[CHAIN_DOMAIN, &accumulator[..], &hash[..]]);
    }

    Ok(accumulator)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_commitment_from_channels() {
        let wallet_id = [1u8; 32];
        let mut too_many_channels = BTreeMap::new();
        for i in 0..=MAX_CHANNELS {
            too_many_channels.insert([i as u8; 32], [i as u8; 32]);
        }

        assert!(compute_commitment_from_channels(wallet_id, &too_many_channels).is_err());

        let empty_channels = BTreeMap::new();

        let empty_result = compute_commitment_from_channels(wallet_id, &empty_channels)
            .expect("empty channels should always compute a valid commitment");

        #[rustfmt::skip]
        assert_eq!(
            empty_result,
            [
                0xa6, 0xfe, 0xde, 0x5c, 0x69, 0x8f, 0xa3, 0x07,
                0x7e, 0xd2, 0x19, 0x6a, 0x3e, 0xdc, 0x95, 0x42,
                0x37, 0x8e, 0x4f, 0x49, 0x8a, 0xd2, 0x41, 0x11,
                0x4a, 0xa6, 0x32, 0x24, 0xe1, 0xea, 0xdf, 0x66
            ]
        );

        let mut one_channel = BTreeMap::new();
        one_channel.insert([2u8; 32], [3u8; 32]);

        let one_result = compute_commitment_from_channels(wallet_id, &one_channel)
            .expect("one channel should always compute a valid commitment");

        #[rustfmt::skip]
        assert_eq!(
            one_result,
            [
                0x8c, 0xdc, 0x7d, 0x4d, 0x1c, 0xbc, 0xc7, 0x00,
                0x17, 0xbf, 0xd5, 0x02, 0x42, 0xde, 0xfb, 0x04,
                0x2b, 0x3c, 0x11, 0x4b, 0x74, 0x88, 0xec, 0x4e,
                0x3f, 0x59, 0x21, 0x2e, 0x81, 0x8c, 0x4c, 0x36
            ]
        );
        assert_ne!(one_result, empty_result);
    }
}
