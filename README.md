[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Docs.rs](https://img.shields.io/docsrs/merkle-morph)](https://docs.rs/merkle-morph)
[![crates.io](https://img.shields.io/crates/v/merkle-morph)](https://crates.io/crates/merkle-morph)

# Merkle-Morph

A Rust library for state channel systems with merkle tree verification.

## Current Status

- State transitions with cryptographic hashing
- Merkle tree operations for state commitments
- Channel state management with balance tracking
- Wallet state management with channel aggregation
- Complete state propagation: Channel → Wallet → Global
- Nonce-based replay protection

## Quick Start

```bash
cargo build
cargo test
```

## Usage

### Basic State Transitions

```rust
use merkle_morph::{State, Transition, HashRootUpdater, HashTransitionVerifier};

let genesis = State { root: [0u8; 32], nonce: 0 };
let transition = Transition::new(&genesis, b"update", &HashRootUpdater);
assert!(transition.verify(&genesis, &HashTransitionVerifier));
```

### Complete State Channel System

```rust
use merkle_morph::{State, wallet::{WalletState, wallet_apply_channel}, channel::ChannelState, global_apply_channel_delta};

// Setup initial states
let global = State { root: [0u8; 32], nonce: 0 };
let wallet = WalletState::new([1u8; 32]);
let channel = ChannelState::new([5u8; 32], [100, 0]);

// Add the channel to the wallet first
let wallet = wallet_apply_channel(&wallet, channel.clone());

// Apply a channel delta and propagate through the entire system
let (updated_global, updated_wallet, updated_channel) =
    global_apply_channel_delta(&global, &wallet, &channel, -5, 5).unwrap();
```

## License

MIT
