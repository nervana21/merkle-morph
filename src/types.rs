// SPDX-License-Identifier: CC0-1.0

//! Core type definitions for the Merkle Morph library
//!
//! This module defines fundamental types used across multiple modules,
//! providing a common location for shared type definitions.

// ============================================================================
// Type Definitions
// ============================================================================

/// Type alias for 32-byte arrays used across cryptographic operations
pub type Bytes32 = [u8; 32];

/// Type alias for Bitcoin block hashes
pub type BitcoinBlockHash = Bytes32;

/// Type alias for Bitcoin transaction IDs
pub type BitcoinTxId = Bytes32;

/// Type alias for channel commitments
pub type ChannelCommitment = Bytes32;

/// Type alias for channel identifiers
pub type ChannelId = Bytes32;

/// Type alias for data availability hashes
pub type DaHash = Bytes32;

/// Type alias for hash chain/accumulator values
pub type HashChainValue = Bytes32;

/// Type alias for intermediate state hashes
pub type StateHash = Bytes32;

/// Type alias for wallet commitments
pub type WalletCommitment = Bytes32;

/// Type alias for wallet identifiers
pub type WalletId = Bytes32;

/// Type alias for wallet commitment maps
pub type WalletCommitments = std::collections::BTreeMap<WalletId, WalletCommitment>;

// ============================================================================
// Constants
// ============================================================================

// ----------------------------------------------------------------------------
// Domain Separation Tags
// ----------------------------------------------------------------------------

/// Domain separation tag for accumulator chain computation
///
/// This tag is used to prefix accumulator chain hashes to ensure domain separation
/// and prevent collisions with other hash contexts.
pub const CHAIN_DOMAIN: &[u8] = b"MM_CHAIN_v0";

/// Domain separation tag for channel commitments
///
/// This tag is used to prefix channel commitment hashes to ensure domain separation
/// and prevent collisions with other hash contexts.
pub const CHANNEL_DOMAIN_TAG: &[u8] = b"MM_CH_v0";

/// Domain separation tag for Bitcoin transaction commitments
///
/// This tag is used to prefix Bitcoin transaction commitment hashes to ensure domain separation
/// and prevent collisions with other hash contexts.
pub const BTX_DOMAIN_TAG: &[u8] = b"MM_BTX_v0";

/// Domain separation tag for P2A taproot tweaks (global anchoring)
pub const P2A_DOMAIN_TAG: &[u8] = b"MM_P2A_v0";

/// Domain separation tag for script commitments
///
/// This tag is used to prefix script commitment hashes to ensure domain separation
/// and prevent collisions with other hash contexts.
pub const SCRIPT_DOMAIN_TAG: &[u8] = b"MM_SCRIPT_v0";

/// Domain separation tag for transition witness hashes
///
/// This tag is used to prefix transition witness hashes to ensure domain separation
/// and prevent collisions with other hash contexts.
pub const TRANSITION_WITNESS_DOMAIN_TAG: &[u8] = b"MM_TRANSITION_WITNESS_v0";

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

// ----------------------------------------------------------------------------
// Bitcoin Script & Transaction Constants
// ----------------------------------------------------------------------------

/// Script detection constants
///
/// These constants define the opcodes and byte patterns used to identify
/// different Bitcoin script types, particularly Pay-to-Taproot (P2TR) and
/// Pay-to-Anchor (P2A) scripts.
/// OP_1 opcode (0x51) - used in P2TR and P2A scripts
pub const OP_1: u8 = 0x51;
/// Push 32 bytes opcode (0x20) - used in P2TR scripts
pub const PUSH_32_BYTES: u8 = 0x20;
/// Push 2 bytes opcode (0x02) - used in P2A scripts
pub const PUSH_2_BYTES: u8 = 0x02;
/// First byte of P2A anchor marker (0x4e)
pub const P2A_MARKER_BYTE_1: u8 = 0x4e;
/// Second byte of P2A anchor marker (0x73)
pub const P2A_MARKER_BYTE_2: u8 = 0x73;
/// P2TR script length (34 bytes: OP_1 + push_32 + 32 bytes)
pub const P2TR_SCRIPT_LEN: usize = 34;
/// P2A script length (4 bytes: OP_1 + push_2 + 2 marker bytes)
pub const P2A_SCRIPT_LEN: usize = 4;

/// Size of the transaction version field in bytes
pub const TX_VERSION_SIZE: usize = 4;

/// Size of the transaction locktime field in bytes
pub const TX_LOCKTIME_SIZE: usize = 4;

/// Size of a transaction outpoint in bytes (32 bytes txid + 4 bytes vout)
pub const TX_OUTPOINT_SIZE: usize = 36;

/// Size of the transaction sequence field in bytes
pub const TX_SEQUENCE_SIZE: usize = 4;

/// Size of the transaction output value field in bytes
pub const TX_VALUE_SIZE: usize = 8;

/// Size of the script length byte in bytes
pub const TX_SCRIPT_LENGTH_BYTE_SIZE: usize = 1;

/// Size of the witness marker and flag in bytes (0x00 + 0x01)
pub const TX_WITNESS_MARKER_SIZE: usize = 2;

/// Multiplier for base size in weight calculation (weight = base_size * 3 + total_size)
pub const TX_WEIGHT_BASE_MULTIPLIER: usize = 3;

/// Estimated base transaction overhead in bytes
///
/// This is a conservative estimate for version (4) + locktime (4) + minimum VarInt sizes
/// for input count (1) + output count (1) = 10 bytes total.
pub const TX_BASE_OVERHEAD_ESTIMATE: usize = 10;

// ----------------------------------------------------------------------------
// Channel Constants
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// Wallet Constants
// ----------------------------------------------------------------------------

/// Maximum number of channels supported in a single wallet
pub const MAX_CHANNELS: usize = 16;

/// Maximum size of channel metadata in bytes
pub const MAX_METADATA_SIZE: usize = 256;

// ----------------------------------------------------------------------------
// TRUC (Topologically Restricted Until Confirmation) Constants
// ----------------------------------------------------------------------------

/// Witness scale factor (4x) for converting vbytes to weight
///
/// Bitcoin uses weight = vbytes * WITNESS_SCALE_FACTOR for SegWit transactions.
pub const WITNESS_SCALE_FACTOR: usize = 4;

/// Maximum virtual size for a TRUC parent transaction (v3)
///
/// This limit ensures TRUC transactions stay within package relay size constraints.
/// Based on Bitcoin Core's TRUC_MAX_VSIZE constant (10000 vbytes).
pub const TRUC_MAX_VSIZE: usize = 10000;

/// Maximum virtual size for a TRUC child transaction (v3 spending unconfirmed v3)
///
/// This limit applies to transactions that spend from unconfirmed TRUC transactions.
/// Based on Bitcoin Core's TRUC_CHILD_MAX_VSIZE constant (1000 vbytes).
pub const TRUC_CHILD_MAX_VSIZE: usize = 1000;

// ----------------------------------------------------------------------------
// P2A (Pay-to-Address) Anchor Constants
// ----------------------------------------------------------------------------

/// Default network for P2A anchoring (tests/regtest)
pub const P2A_DEFAULT_NETWORK: bitcoin::Network = bitcoin::Network::Regtest;

/// Default internal taproot key (x-only G) for anchoring
#[rustfmt::skip]
pub const P2A_DEFAULT_INTERNAL_KEY_BYTES: [u8; 32] = [
    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
    0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
    0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9,
    0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
];

/// Default value (sats) for anchor outputs
pub const P2A_DEFAULT_VALUE_SATS: u64 = 0;
