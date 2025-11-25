//! Core type definitions for the Merkle Morph library
//!
//! This module defines fundamental types used across multiple modules,
//! providing a common location for shared type definitions.

// ============================================================================
// Fundamental Types
// ============================================================================

/// Type alias for 32-byte arrays used across cryptographic operations
pub type Bytes32 = [u8; 32];

// ============================================================================
// Channel Domain
// ============================================================================

/// Type alias for channel identifiers
pub type ChannelId = Bytes32;

/// Type alias for channel commitments
pub type ChannelCommitment = Bytes32;

/// Domain separation tag for channel commitments
///
/// This tag is used to prefix channel commitment hashes to ensure domain separation
/// and prevent collisions with other hash contexts.
pub const CHANNEL_DOMAIN_TAG: &[u8] = b"MM_CH_v0"; // merkle morph channel v0

// ============================================================================
// Wallet Domain
// ============================================================================

/// Type alias for wallet identifiers
pub type WalletId = Bytes32;

/// Type alias for wallet commitments
pub type WalletCommitment = Bytes32;

/// Type alias for wallet commitment maps
pub type WalletCommitments = std::collections::BTreeMap<WalletId, WalletCommitment>;

/// Domain separation tag for wallet initialization
///
/// This tag is used to prefix wallet initialization hashes to ensure domain separation
/// and prevent collisions with other hash contexts.
pub const WALLET_INIT_DOMAIN: &[u8] = b"MM_WLT_INIT_v0";

/// Domain separation tag for wallet hash computation
///
/// This tag is used to prefix wallet hash computations to ensure domain separation
/// and prevent collisions with other hash contexts.
pub const WALLET_HASH_DOMAIN: &[u8] = b"MM_WLT_HASH_v0";

/// Maximum number of channels supported in a single wallet
///
/// This limit is enforced both in wallet commitment computation and in zero-knowledge
/// proof trace generation to ensure consistent behavior across the system.
pub const MAX_CHANNELS: usize = 16;

/// Maximum size of channel metadata in bytes
pub const MAX_METADATA_SIZE: usize = 256;

// ============================================================================
// Chain Domain
// ============================================================================

/// Domain separation tag for accumulator chain computation
///
/// This tag is used to prefix accumulator chain hashes to ensure domain separation
/// and prevent collisions with other hash contexts.
pub const CHAIN_DOMAIN: &[u8] = b"MM_CHAIN_v0";

// ============================================================================
// Bitcoin Transaction Domain
// ============================================================================

/// Domain separation tag for Bitcoin transaction commitments
///
/// This tag is used to prefix Bitcoin transaction commitment hashes to ensure domain separation
/// and prevent collisions with other hash contexts.
pub const BTX_DOMAIN_TAG: &[u8] = b"MM_BTX_v0"; // merkle morph bitcoin transaction v0

// ============================================================================
// Script Domain
// ============================================================================

/// Domain separation tag for script commitments
///
/// This tag is used to prefix script commitment hashes to ensure domain separation
/// and prevent collisions with other hash contexts.
pub const SCRIPT_DOMAIN_TAG: &[u8] = b"MM_SCRIPT_v0"; // merkle morph script v0

// ============================================================================
// Bitcoin OP_RETURN Format
// ============================================================================

/// Magic bytes for OP_RETURN data format: "MMGL" (Merkle Morph Global)
pub const OP_RETURN_MAGIC_BYTES: &[u8; 4] = b"MMGL";

// Length constants
/// Length of magic bytes in OP_RETURN format
pub const OP_RETURN_MAGIC_LEN: usize = 4;
/// Current version of OP_RETURN data format
pub const OP_RETURN_VERSION: u8 = 0;
/// Length of version field in OP_RETURN format
pub const OP_RETURN_VERSION_LEN: usize = 1;
/// Length of global root field in OP_RETURN format
pub const OP_RETURN_GLOBAL_ROOT_LEN: usize = 32;
/// Length of nonce field in OP_RETURN format
pub const OP_RETURN_NONCE_LEN: usize = 4;

/// Total length of OP_RETURN data format (41 bytes)
pub const OP_RETURN_TOTAL_LEN: usize =
    OP_RETURN_MAGIC_LEN + OP_RETURN_VERSION_LEN + OP_RETURN_GLOBAL_ROOT_LEN + OP_RETURN_NONCE_LEN;

// Offset constants
/// Offset of magic bytes in OP_RETURN data
pub const OP_RETURN_OFFSET_MAGIC: usize = 0;
/// Offset of version field in OP_RETURN data
pub const OP_RETURN_OFFSET_VERSION: usize = OP_RETURN_OFFSET_MAGIC + OP_RETURN_MAGIC_LEN;
/// Offset of global root field in OP_RETURN data
pub const OP_RETURN_OFFSET_GLOBAL_ROOT: usize = OP_RETURN_OFFSET_VERSION + OP_RETURN_VERSION_LEN;
/// Offset of nonce field in OP_RETURN data
pub const OP_RETURN_OFFSET_NONCE: usize = OP_RETURN_OFFSET_GLOBAL_ROOT + OP_RETURN_GLOBAL_ROOT_LEN;
