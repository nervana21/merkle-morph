// SPDX-License-Identifier: CC0-1.0

//! Bitcoin transaction commitment computation
//!
//! This module provides functions for computing cryptographic commitments
//! over Bitcoin transaction state using Poseidon2 hashing.

use crate::btx::state::{BitcoinTransaction, Utxo};
use crate::types::{Bytes32, StateHash, BTX_DOMAIN_TAG};
use crate::zkp::{poseidon2_hash_bytes, poseidon2_hash_fixed};

/// Type alias for Bitcoin transaction commitments
pub type BtxCommitment = Bytes32;

/// Computes a commitment over a Bitcoin transaction
///
/// The commitment is computed using Poseidon2 hashing with domain separation.
/// The commitment includes all inputs and outputs of the transaction.
///
/// # Arguments
/// * `tx` - The Bitcoin transaction to commit to
///
/// # Returns
/// A 32-byte commitment hash
pub fn compute_commitment(tx: &BitcoinTransaction) -> BtxCommitment {
    let state_hash = compute_state_hash(tx);
    compute_btx_commitment(state_hash)
}

/// Computes the Bitcoin transaction commitment from state hash using Poseidon2.
///
/// Uses domain separation tag `BTX_DOMAIN_TAG` to prevent collisions with other hash contexts.
///
/// # Arguments
/// * `state_hash` - Hash of the transaction state (inputs and outputs)
///
/// # Returns
/// A 32-byte commitment hash
pub fn compute_btx_commitment(state_hash: StateHash) -> BtxCommitment {
    let mut input = Vec::new();
    input.extend_from_slice(BTX_DOMAIN_TAG);
    input.extend_from_slice(&state_hash);
    poseidon2_hash_bytes(&input)
}

/// Computes the hash of a transaction state (inputs and outputs)
///
/// This includes all input UTXOs and output UTXOs, but excludes the commitment itself.
fn compute_state_hash(tx: &BitcoinTransaction) -> StateHash {
    let inputs: Vec<Utxo> = tx.inputs_data.iter().map(|id| id.utxo.clone()).collect();
    let inputs_hash = hash_utxos(&inputs);
    let outputs_hash = hash_utxos(&tx.outputs);
    poseidon2_hash_fixed(&[&inputs_hash, &outputs_hash])
}

/// Hashes a vector of UTXOs
///
/// Each UTXO is hashed as: txid || index || value || address
/// Then all UTXO hashes are combined.
fn hash_utxos(utxos: &[Utxo]) -> StateHash {
    if utxos.is_empty() {
        return [0u8; 32];
    }

    let mut utxo_hashes = Vec::new();
    for utxo in utxos {
        let utxo_hash = hash_single_utxo(utxo);
        utxo_hashes.push(utxo_hash);
    }

    if utxo_hashes.len() == 1 {
        utxo_hashes[0]
    } else {
        let mut combined = Vec::new();
        for hash in &utxo_hashes {
            combined.extend_from_slice(hash);
        }
        poseidon2_hash_bytes(&combined)
    }
}

/// Hashes a single UTXO
///
/// The UTXO is hashed as: txid || index || value || script_pubkey
fn hash_single_utxo(utxo: &Utxo) -> StateHash {
    let mut input = Vec::new();
    input.extend_from_slice(utxo.txid.as_ref());
    input.extend_from_slice(&utxo.index.to_le_bytes());
    input.extend_from_slice(&utxo.value.to_le_bytes());
    input.extend_from_slice(utxo.script_pubkey().as_bytes());
    poseidon2_hash_bytes(&input)
}

#[cfg(test)]
mod tests {
    use bitcoin::address::NetworkUnchecked;
    use bitcoin::{Address, Txid};

    use super::*;
    use crate::btx::state::{BitcoinTransaction, Utxo};

    fn addr(s: &str) -> Address<NetworkUnchecked> { s.parse().expect("valid Bitcoin address") }

    #[test]
    fn test_compute_btx_commitment() {
        let state_hash = [1u8; 32];

        let commitment = compute_btx_commitment(state_hash);

        assert_eq!(commitment.len(), 32);
    }

    #[test]
    fn test_compute_commitment() {
        let txid1 = Txid::from_byte_array([1u8; 32]);
        let txid2 = Txid::from_byte_array([2u8; 32]);
        let txid3 = Txid::from_byte_array([3u8; 32]);
        let txid4 = Txid::from_byte_array([4u8; 32]);
        let address1 = addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        let address2 = addr("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");

        let empty_tx = BitcoinTransaction::new(vec![], vec![]);

        let commitment_empty = compute_commitment(&empty_tx);

        assert_eq!(commitment_empty.len(), 32);

        let input1 = Utxo::new(txid1, 0, 1000, address1);
        let output1 = Utxo::new(txid2, 0, 500, address2);
        let single_tx = BitcoinTransaction::new(vec![input1], vec![output1]);

        let commitment_single = compute_commitment(&single_tx);

        assert_eq!(commitment_single.len(), 32);

        let input_multiple1 = Utxo::new(txid1, 0, 1000, address1);
        let input_multiple2 = Utxo::new(txid3, 1, 2000, address1);
        let input_multiple3 = Utxo::new(txid4, 2, 3000, address1);
        let output_multiple1 = Utxo::new(txid2, 0, 500, address2);
        let output_multiple2 = Utxo::new(txid1, 1, 1500, address2);
        let output_multiple3 = Utxo::new(txid2, 2, 2500, address2);
        let multiple_tx = BitcoinTransaction::new(
            vec![input_multiple1, input_multiple2, input_multiple3],
            vec![output_multiple1, output_multiple2, output_multiple3],
        );

        let commitment_multiple = compute_commitment(&multiple_tx);

        assert_eq!(commitment_multiple.len(), 32);
    }
}
