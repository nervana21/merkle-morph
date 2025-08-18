[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

# Merkle-Morph

A Rust library for unilateral state channels and zero-knowledge authentication.

## Current Status

- **Unilateral State Channels**: Complete implementation with sender/receiver balance tracking
- **Wallet Aggregation**: Multi-channel wallet management with hash accumulators
- **Global State Management**: Top-level wallet collection with state propagation
- **Comprehensive Error Handling**: Detailed error types for all operations

## Quick Start

```bash
cargo build
cargo test
```

## Usage

### Basic Channel Operations

```rust
use merkle_morph::{ChannelState, WalletState, GlobalState};
use merkle_morph::global::insert_wallet;
use merkle_morph::types::{ChannelId, WalletId};

// Create a payment channel with initial sender balance
let channel = ChannelState::new(100);
let channel_id: ChannelId = [0u8; 32];

let updated_channel = channel.apply_transfer(channel_id, 21)?;
assert_eq!(updated_channel.sender_balance, 79);
assert_eq!(updated_channel.receiver_balance, 21);
```

### Wallet Management

```rust
// Create an empty wallet
let wallet_id: WalletId = [0u8; 32];
let empty_wallet = WalletState::new(wallet_id);

// Add channel to wallet
let wallet = WalletState::insert_channel(
    &wallet,
    channel_id,
    updated_channel
)?;
assert_eq!(wallet.nonce, 1);

// Transfer within a channel in the wallet
let new_channel_state = wallet.transfer_in_channel(channel_id, 10)?;
```

### Global State Management

```rust
// Create global state and add wallet
let mut global = GlobalState::new();
insert_wallet(&mut global, wallet_id, wallet)?;
assert_eq!(global.nonce, 1);

// Retrieve wallet from global state
let retrieved_wallet = merkle_morph::global::get_wallet(&global, &wallet_id)?;
```

## License

MIT
