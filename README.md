[![License: CC0-1.0](https://img.shields.io/badge/license-CC0--1.0-blue)](LICENSE)

# Merkle-Morph

Zero-knowledge state channels secured by Bitcoin.

Deep Dive: [docs/overpass.md](docs/overpass.md).

## Architecture

- **Channels**: Unidirectional channels with explicit lifecycle states plus Bitcoin transaction builders for cooperative and force-close paths.
- **Wallets**: Hash-chain aggregation of channel commitments.
- **Global state**: Sparse Merkle Tree over wallet commitments with subtree composition and inclusion proofs; supports OP_RETURN anchoring.
- **ZKP**: Plonky3 STARK proofs for channel transitions, wallet aggregation, subtree validity, and global root composition.
- **Bitcoin utilities**: Script builders, miniscript helpers, Taproot support, and timelock utilities.

## Crate layout

- `channel`: State machine, commitment hashing, Bitcoin TX builders, and transitions.
- `wallet`: Wallet state, hash-chain commitments, and transitions.
- `global`: Sparse Merkle Tree utilities, subtree composition, proofs, and Bitcoin anchoring helpers.
- `zkp`: Plonky3 wiring plus proof/verify helpers for channel, wallet, subtree, and global circuits.
- `btx`: Bitcoin transaction category helpers.

## Quick start

```bash
cargo build
cargo test
```

## Core flows (high level)

### Channel transition with proof

```rust
use merkle_morph::channel::{apply_transfer, compute_open_commitment, Open, TransferAmount};
use merkle_morph::types::ChannelId;
use merkle_morph::zkp::create_config;
use bitcoin::secp256k1::{Secp256k1, SecretKey, XOnlyPublicKey};

let secp = Secp256k1::new();
let sender_sk = SecretKey::from_slice(&[1u8; 32])?;
let receiver_sk = SecretKey::from_slice(&[2u8; 32])?;
let sender_pub = XOnlyPublicKey::from_keypair(&sender_sk.keypair(&secp)).0;
let receiver_pub = XOnlyPublicKey::from_keypair(&receiver_sk.keypair(&secp)).0;
let sender_revocation = SecretKey::from_slice(&[3u8; 32])?;
let receiver_revocation = SecretKey::from_slice(&[4u8; 32])?;

let channel_id: ChannelId = [0u8; 32];
let state = Open::new(sender_pub, receiver_pub, 100, sender_revocation, receiver_revocation);
let amount = TransferAmount::new(21)?;

let proof_cfg = create_config()?;
let result = apply_transfer(channel_id, &state, &amount, &sender_sk, &proof_cfg)?;
let _commitment = compute_open_commitment(channel_id, &result.new_state);
# Ok::<(), merkle_morph::errors::Error>(())
```

### Wallet aggregation

```rust
use merkle_morph::channel::compute_open_commitment;
use merkle_morph::wallet::{apply_insert_channel, WalletState};
use merkle_morph::types::{ChannelId, WalletId};

let wallet_id: WalletId = [9u8; 32];
let channel_id: ChannelId = [0u8; 32];
let channel_commitment = compute_open_commitment(channel_id, &state);

let wallet = WalletState::new(wallet_id);
let wallet = apply_insert_channel(wallet, channel_id, channel_commitment)?;
# Ok::<(), merkle_morph::errors::Error>(())
```

### Global root + inclusion proof

```rust
use merkle_morph::global::{
    compose_to_global_root, compute_subtree_root, generate_merkle_proof, verify_merkle_proof,
    InMemorySiblingProvider, MerkleMorphV0Config, Poseidon2Hasher,
};
use merkle_morph::zkp::create_config;
use std::collections::BTreeMap;

let mut commitments = BTreeMap::new();
commitments.insert(wallet.id, wallet.commitment);

let zk_cfg = create_config()?;
let subtree = compute_subtree_root(&zk_cfg, &commitments, wallet.id, wallet.id)?;
let global_root = compose_to_global_root(&[subtree])?;

let mut provider = InMemorySiblingProvider::new(&commitments);
let proof = generate_merkle_proof(wallet.id, &Poseidon2Hasher, &MerkleMorphV0Config, &mut provider)?;
assert!(verify_merkle_proof(wallet.id, wallet.commitment, &proof, global_root)?);
# Ok::<(), merkle_morph::errors::Error>(())
```

### Anchoring to Bitcoin

`global::anchor` exposes helpers to encode/decode OP_RETURN payloads (`encode_op_return_data`, `decode_op_return_data`) so a composed global root can be published on-chain for ordering and dispute resolution.

## License

CC0-1.0

## Security

This is experimental software in active development. Please use appropriate caution.