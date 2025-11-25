//! SMT node key encoding and prefix utilities
//!
//! This module provides functions for encoding/decoding SMT node keys
//! and working with bit-prefix patterns. Node keys encode the bit-prefix path to
//! a node in the tree, enabling efficient lookups and tree navigation.

use crate::types::WalletId;

/// Encodes an SMT node key from depth and wallet ID prefix
///
/// The node key format is: `[depth: u8][prefix_bytes...]`
/// where prefix_bytes contains the first `ceil(depth/8)` bytes of the
/// wallet ID prefix.
///
/// # Arguments
/// * `wallet_id` - The wallet ID (used to extract prefix bits)
/// * `depth` - The depth of the node (0-255)
///
/// # Returns
/// Encoded node key as a byte vector
pub fn encode_node_key(wallet_id: &WalletId, depth: u8) -> Vec<u8> {
    let mut key = Vec::with_capacity(33); // depth (1 byte) + up to 32 bytes prefix
    key.push(depth);

    // Add prefix bytes: we need ceil(depth/8) bytes
    // Use .clamp(1, 32) to ensure at least 1 byte is included when depth is 0
    // (needed for sibling encoding where bit 0 may be flipped)
    let prefix_bytes = ((depth as usize + 7) / 8).clamp(1, 32);
    key.extend_from_slice(&wallet_id[..prefix_bytes]);

    key
}

/// Encodes a sibling node key
///
/// For a given wallet ID and depth, computes the key for its sibling node
/// (the node with the opposite bit at this depth, but same prefix up to depth-1).
///
/// # Arguments
/// * `wallet_id` - The wallet ID
/// * `depth` - The depth at which to find the sibling
///
/// # Returns
/// Encoded sibling node key
pub fn encode_sibling_node_key(wallet_id: &WalletId, depth: u8) -> Vec<u8> {
    let mut sibling_id = *wallet_id;

    // Flip the bit at the current depth
    let byte_index = (depth / 8) as usize;
    let bit_index = depth % 8;
    if byte_index < 32 {
        sibling_id[byte_index] ^= 1 << (7 - bit_index);
    }

    encode_node_key(&sibling_id, depth)
}

/// Decodes a node key to extract depth and prefix
///
/// # Arguments
/// * `key` - The encoded node key
///
/// # Returns
/// `(depth, prefix_bytes)` where prefix_bytes is a 32-byte array
/// (padded with zeros if the prefix is shorter)
pub fn decode_node_key(key: &[u8]) -> Option<(u8, [u8; 32])> {
    if key.is_empty() {
        return None;
    }

    let depth = key[0];
    let mut prefix = [0u8; 32];

    // Copy prefix bytes (at most 32 bytes)
    // Use .clamp(1, 32) to match encode behavior (at least 1 byte for depth 0)
    let prefix_len = ((depth as usize + 7) / 8).clamp(1, 32).min(key.len() - 1);
    if prefix_len > 0 && key.len() > 1 {
        prefix[..prefix_len].copy_from_slice(&key[1..=prefix_len]);
    }

    Some((depth, prefix))
}

/// Computes the bit-prefix bytes for a wallet ID up to a given depth
///
/// This is used for querying wallets that match a specific prefix pattern.
///
/// # Arguments
/// * `wallet_id` - The wallet ID
/// * `depth` - The depth (number of bits in prefix)
///
/// # Returns
/// Byte array containing the prefix (first ceil(depth/8) bytes)
pub fn compute_prefix_bytes(wallet_id: &WalletId, depth: u8) -> Vec<u8> {
    let prefix_bytes = ((depth as usize + 7) / 8).min(32);
    wallet_id[..prefix_bytes].to_vec()
}

/// Computes the sibling prefix bytes
///
/// For a given wallet ID and depth, computes the prefix bytes for the sibling
/// subtree (opposite bit at depth, same prefix up to depth-1).
///
/// # Arguments
/// * `wallet_id` - The wallet ID
/// * `depth` - The depth
///
/// # Returns
/// Prefix bytes for the sibling subtree
pub fn compute_sibling_prefix_bytes(wallet_id: &WalletId, depth: u8) -> Vec<u8> {
    let mut sibling_id = *wallet_id;

    // Flip the bit at the current depth
    let byte_index = (depth / 8) as usize;
    let bit_index = depth % 8;
    if byte_index < 32 {
        sibling_id[byte_index] ^= 1 << (7 - bit_index);
    }

    compute_prefix_bytes(&sibling_id, depth)
}

/// Checks if a wallet ID matches a prefix pattern
///
/// # Arguments
/// * `wallet_id` - The wallet ID to check
/// * `prefix` - The prefix bytes to match
/// * `depth` - The depth (number of bits to match)
///
/// # Returns
/// `true` if the wallet ID matches the prefix up to the given depth
pub fn matches_prefix(wallet_id: &WalletId, prefix: &[u8], depth: u8) -> bool {
    // Check byte-level matches first
    let prefix_bytes = ((depth as usize + 7) / 8).min(32);
    if prefix.len() < prefix_bytes || wallet_id.len() < prefix_bytes {
        return false;
    }

    // Check full bytes
    for i in 0..(depth as usize / 8) {
        if wallet_id[i] != prefix[i] {
            return false;
        }
    }

    // Check partial byte if depth is not a multiple of 8
    let remainder_bits = depth % 8;
    if remainder_bits > 0 {
        let last_byte_idx = depth as usize / 8;
        if last_byte_idx >= wallet_id.len() || last_byte_idx >= prefix.len() {
            return false;
        }

        // Mask to check only the relevant bits
        let mask = !((1u8 << (8 - remainder_bits)) - 1);
        if (wallet_id[last_byte_idx] & mask) != (prefix[last_byte_idx] & mask) {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_node_key() {
        let wallet_id = [1u8; 32];
        let depth = 8u8;

        let key = encode_node_key(&wallet_id, depth);

        assert_eq!(key[0], 8);
        assert_eq!(key.len(), 2);
        assert_eq!(key[1], 1);
    }

    #[test]
    fn test_encode_sibling_node_key() {
        let mut wallet_id = [0u8; 32];
        wallet_id[0] = 0b10000000;
        let depth = 0u8;

        let key = encode_sibling_node_key(&wallet_id, depth);

        let decoded = decode_node_key(&key).expect("encoded key should be decodable");
        assert_eq!(decoded.0, 0);
        assert_eq!(decoded.1[0] & 0b10000000, 0);
    }

    #[test]
    fn test_decode_node_key() {
        let empty_key: &[u8] = &[];

        assert_eq!(decode_node_key(empty_key), None);

        let depth_only = &[5u8];

        let decoded = decode_node_key(depth_only).expect("depth-only key should be decodable");

        assert_eq!(decoded.0, 5);
        assert_eq!(decoded.1, [0u8; 32]);

        let key_with_prefix = &[8u8, 42u8];

        let decoded2 =
            decode_node_key(key_with_prefix).expect("key with prefix should be decodable");

        assert_eq!(decoded2.0, 8);
        assert_eq!(decoded2.1[0], 42);
        assert_eq!(decoded2.1[1..], [0u8; 31]);
    }

    #[test]
    fn test_compute_prefix_bytes() {
        let wallet_id = [1u8; 32];
        let depth = 16u8;

        let prefix = compute_prefix_bytes(&wallet_id, depth);

        assert_eq!(prefix.len(), 2);
        assert_eq!(prefix[0], 1);
        assert_eq!(prefix[1], 1);
    }

    #[test]
    fn test_compute_sibling_prefix_bytes() {
        let mut wallet_id = [0u8; 32];
        wallet_id[0] = 0b10000000;
        let depth = 1u8;

        let prefix = compute_sibling_prefix_bytes(&wallet_id, depth);

        assert_eq!(prefix[0], 0b11000000);
    }

    #[test]
    fn test_matches_prefix() {
        let mut wallet_id = [0u8; 32];
        wallet_id[0] = 0b11110000u8;
        wallet_id[1] = 0b10101010u8;
        let prefix_too_short = &[];

        assert!(!matches_prefix(&wallet_id, prefix_too_short, 8));

        let prefix_full_byte_match = &[0b11110000u8];

        assert!(matches_prefix(&wallet_id, prefix_full_byte_match, 8));

        let prefix_full_byte_mismatch = &[0b11110001u8];

        assert!(!matches_prefix(&wallet_id, prefix_full_byte_mismatch, 8));

        let prefix_partial_match = &[0b11110000u8];

        assert!(matches_prefix(&wallet_id, prefix_partial_match, 4));

        let prefix_partial_mismatch = &[0b11100000u8];

        assert!(!matches_prefix(&wallet_id, prefix_partial_mismatch, 4));
    }
}
