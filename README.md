[![License: CC0-1.0](https://img.shields.io/badge/license-CC0--1.0-blue)](LICENSE)

# Merkle-Morph

Privacy-preserving payment channels with zero-knowledge proofs, anchored to Bitcoin.

## Overview

Merkle-Morph provides a three-layer architecture for off-chain payment channels:

1. **Channels**: Unidirectional payment channels between sender and receiver
2. **Wallets**: Aggregation layer that groups multiple channel commitments using hash chains
3. **Global State**: Merkle root of all wallet commitments, anchored to Bitcoin

For detailed theoretical documentation on the framework and category-theoretic foundations, see [docs/overpass.md](docs/overpass.md).

## Features

- **Unidirectional State Channels**: Sender/receiver balance tracking with deterministic state transitions
- **Wallet Aggregation**: Multi-channel wallet management with hash chain commitments
- **Global State Management**: Sparse Merkle Tree (SMT) of wallet commitments with Bitcoin anchoring
- **Zero-Knowledge Proofs**: STARK proofs for channel, wallet, and global state transitions using Plonky3
- **Bitcoin Anchoring**: OP_RETURN-based anchoring for global ordering and double-spending prevention

## Quick Start

```bash
cargo build
cargo test
```

## Usage Examples

### Basic Channel Operations

```rust
use merkle_morph::channel::{ChannelState, TransferAmount};
use merkle_morph::channel::transition::apply_transfer;
use merkle_morph::zkp::create_config;
use merkle_morph::types::ChannelId;

// Start with a channel that has 100 sats in the sender's balance
let channel = ChannelState::new(100);
let channel_id: ChannelId = [0u8; 32];

// Create a transfer of 21 sats
let amount = TransferAmount::new(21)?;
let config = create_config()?;

// Apply the transfer and generate a zero-knowledge proof
// The proof verifies the transfer is valid without revealing balances
let result = apply_transfer(&channel, &amount, &config, channel_id)?;

// After the transfer:
// - Sender now has 79 sats (100 - 21)
// - Receiver now has 21 sats
assert_eq!(result.new_state.sender_balance, 79);
assert_eq!(result.new_state.receiver_balance, 21);
```

### Wallet Management

```rust
use merkle_morph::wallet::{WalletState, insert_channel};
use merkle_morph::channel::commitment::compute_commitment;
use merkle_morph::types::{WalletId, ChannelId};

// Create a new wallet
let wallet_id: WalletId = [0u8; 32];
let empty_wallet = WalletState::new(wallet_id);

// Add a channel to this wallet
// First, create a channel and compute its commitment
let channel_id: ChannelId = [1u8; 32];
let channel_state = ChannelState::new(100);
let channel_commitment = compute_commitment(channel_id, &channel_state);

// Insert the channel into the wallet
let wallet = insert_channel(empty_wallet, channel_id, channel_commitment)?;
```

### Global State Management

```rust
use merkle_morph::global::{GlobalState, compose_to_global_root, compute_subtree_root, generate_merkle_proof, verify_merkle_proof};
use std::collections::BTreeMap;

// Build your view of the global state using subtree composition
// Locally track your wallet commitments (used later for membership proofs)
let mut local_wallet_commitments = BTreeMap::new();
local_wallet_commitments.insert(wallet_id, wallet.commitment);

// Create a subtree for your wallet
let mut wallet_map = BTreeMap::new();
wallet_map.insert(wallet_id, wallet.commitment);
let subtree = compute_subtree_root(&wallet_map, wallet_id, wallet_id)?;

// Compose subtrees to get the global root
// In production, you'd also include subtree roots from other parties
let wallets_root = compose_to_global_root(&[subtree])?;
let global_state = GlobalState::with_root_and_nonce(wallets_root, 1);

// Generate a proof that your wallet is in the tree
let merkle_proof = generate_merkle_proof(&local_wallet_commitments, wallet_id)?;

// Anyone can verify this proof revealing any additional information
let is_valid = verify_merkle_proof(
    wallet_id, 
    wallet.commitment, 
    &merkle_proof, 
    global_state.wallets_root
)?;
assert!(is_valid);
```

## License

CC0-1.0

## Security

This is experimental software in active development. Please use appropriate caution.