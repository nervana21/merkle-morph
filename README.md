[![License: CC0-1.0](https://img.shields.io/badge/license-CC0--1.0-blue)](LICENSE)

# Merkle-Morph

**Fast, secure Bitcoin payments.**

Merkle-Morph is a Rust library that implements trustless state channels anchored to Bitcoin.

## Why Merkle-Morph?

- **Instant Payments**: Settle transactions immediately without waiting for blockchain confirmations
- **Bitcoin Security**: All funds are secured by Bitcoin's blockchain with force-close capabilities
- **Zero-Knowledge Privacy**: State transitions are proven without revealing sensitive information
- **Trustless Operation**: No trusted intermediaries required
- **Cost-Effective**: Minimize on-chain fees by batching operations and using multi-party anchoring for fee sharing

## Quick Start

```bash
cargo build
cargo test --release
```

## Documentation

For technical details, architecture, and implementation specifics, see [docs/overpass.md](docs/overpass.md).

## Minimum Supported Rust Version (MSRV)

The merkle-morph library should always compile with any combination of features on Rust **1.74.0**.

## Testing

Example testnet4 transaction:

- https://mempool.space/testnet4/tx/d752f8034c53ec15df5c2f300ef6d211b41ca12788e5edbc1dc0eab29666cd48

## License

CC0-1.0

## Security

This is experimental software in active development. Please use appropriate caution.