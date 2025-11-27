//! Bitcoin time lock utilities
//!
//! This module provides utilities for working with Bitcoin time locks,
//! specifically CheckSequenceVerify (CSV) for relative time locks.

use bitcoin::Sequence;

/// Default force close timeout in blocks (~24 hours at 10 minutes per block)
pub const FORCE_CLOSE_TIMEOUT_BLOCKS: u16 = 144;

/// Compute sequence number for a relative time lock in blocks
///
/// Bitcoin uses the sequence field with OP_CHECKSEQUENCEVERIFY (CSV) to implement
/// relative time locks. The sequence number encodes the number of blocks that must
/// pass before the transaction can be included in a block.
///
/// # Arguments
/// * `blocks` - Number of blocks for the time lock (must be <= 65535)
///
/// # Returns
/// A Sequence value with the CSV flag set and the block count encoded
///
/// # Examples
///
/// ```rust
/// use merkle_morph::btx::timelock::compute_sequence_for_blocks;
///
/// let sequence = compute_sequence_for_blocks(144);
/// // This sequence requires 144 blocks to pass before the transaction can be confirmed
/// ```
pub fn compute_sequence_for_blocks(blocks: u16) -> Sequence {
    // CSV requires the most significant bit to be set (0x80000000)
    // The lower 16 bits encode the relative lock time in blocks
    // Format: 0x80000000 | blocks
    let sequence_value = 0x8000_0000u32 | (blocks as u32);
    Sequence::from_consensus(sequence_value)
}

/// Validate that a CSV time lock is satisfied
///
/// Checks if the current block height is sufficient to satisfy the time lock
/// encoded in the sequence number.
///
/// # Arguments
/// * `sequence` - The sequence number from the transaction input
/// * `current_height` - Current block height
/// * `lock_height` - Block height when the transaction was first seen/broadcast
///
/// # Returns
/// * `true` - Time lock is satisfied, transaction can be confirmed
/// * `false` - Time lock is not yet satisfied
///
/// # Examples
///
/// ```rust
/// use merkle_morph::btx::timelock::{compute_sequence_for_blocks, validate_csv_timelock};
///
/// let sequence = compute_sequence_for_blocks(144);
/// let lock_height = 1000;
/// let current_height = 1144; // 144 blocks later
///
/// assert!(validate_csv_timelock(sequence, current_height, lock_height));
///
/// let current_height = 1100; // Only 100 blocks later
/// assert!(!validate_csv_timelock(sequence, current_height, lock_height));
/// ```
pub fn validate_csv_timelock(sequence: Sequence, current_height: u32, lock_height: u32) -> bool {
    // Check if CSV flag is set (most significant bit)
    let sequence_value = sequence.to_consensus_u32();
    if (sequence_value & 0x8000_0000) == 0 {
        // CSV not enabled, no time lock
        return true;
    }

    // Extract the block count from lower 16 bits
    let required_blocks = (sequence_value & 0x0000_FFFF) as u16;

    // Check if enough blocks have passed
    let blocks_passed = current_height.saturating_sub(lock_height);
    blocks_passed >= required_blocks as u32
}

/// Extract the block count from a sequence number
///
/// Returns the number of blocks encoded in a CSV sequence number.
///
/// # Arguments
/// * `sequence` - The sequence number
///
/// # Returns
/// * `Some(blocks)` - If CSV is enabled, returns the block count
/// * `None` - If CSV is not enabled
pub fn extract_csv_blocks(sequence: Sequence) -> Option<u16> {
    let sequence_value = sequence.to_consensus_u32();
    if (sequence_value & 0x8000_0000) == 0 {
        return None;
    }
    Some((sequence_value & 0x0000_FFFF) as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_sequence_for_blocks() {
        let sequence = compute_sequence_for_blocks(144);
        let sequence_value = sequence.to_consensus_u32();
        assert_eq!(sequence_value & 0x8000_0000, 0x8000_0000);
        assert_eq!(sequence_value & 0x0000_FFFF, 144);
    }

    #[test]
    fn test_validate_csv_timelock() {
        let no_csv_sequence = Sequence::from_consensus(0x0000_0000);
        assert!(validate_csv_timelock(no_csv_sequence, 1000, 1000));
        let csv_sequence = compute_sequence_for_blocks(100);
        assert!(validate_csv_timelock(csv_sequence, 1100, 1000));
        assert!(!validate_csv_timelock(csv_sequence, 1050, 1000));
    }

    #[test]
    fn test_extract_csv_blocks() {
        let no_csv_sequence = Sequence::from_consensus(0x0000_0000);
        assert_eq!(extract_csv_blocks(no_csv_sequence), None);
        let csv_sequence = compute_sequence_for_blocks(200);
        assert_eq!(extract_csv_blocks(csv_sequence), Some(200));
    }
}
