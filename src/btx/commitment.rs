//! Bitcoin transaction commitment computation
//!
//! This module provides functions for computing cryptographic commitments
//! over Bitcoin transaction state using Poseidon2 hashing.

use crate::btx::state::{BitcoinTransaction, Utxo};
use crate::types::BTX_DOMAIN_TAG;
use crate::zkp::{poseidon2_hash_bytes, poseidon2_hash_fixed};
use crate::Bytes32;

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

/// Computes the hash of a transaction state (inputs and outputs)
///
/// This includes all input UTXOs and output UTXOs, but excludes the commitment itself.
fn compute_state_hash(tx: &BitcoinTransaction) -> Bytes32 {
    let inputs: Vec<Utxo> = tx.inputs_data.iter().map(|id| id.utxo.clone()).collect();
    let inputs_hash = hash_utxos(&inputs);
    let outputs_hash = hash_utxos(&tx.outputs);
    poseidon2_hash_fixed(&[&inputs_hash, &outputs_hash])
}

/// Hashes a vector of UTXOs
///
/// Each UTXO is hashed as: txid || index || value || address
/// Then all UTXO hashes are combined.
fn hash_utxos(utxos: &[Utxo]) -> Bytes32 {
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
fn hash_single_utxo(utxo: &Utxo) -> Bytes32 {
    let mut input = Vec::new();
    input.extend_from_slice(utxo.txid.as_ref());
    input.extend_from_slice(&utxo.index.to_le_bytes());
    input.extend_from_slice(&utxo.value.to_le_bytes());
    // Use the script_pubkey method which handles both explicit and derived scripts
    input.extend_from_slice(utxo.script_pubkey().as_bytes());
    poseidon2_hash_bytes(&input)
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
pub fn compute_btx_commitment(state_hash: Bytes32) -> BtxCommitment {
    let mut input = Vec::new();
    input.extend_from_slice(BTX_DOMAIN_TAG);
    input.extend_from_slice(&state_hash);
    poseidon2_hash_bytes(&input)
}

#[cfg(test)]
mod tests {
    use bitcoin::address::NetworkUnchecked;
    use bitcoin::hashes::Hash;
    use bitcoin::{Address, Txid};

    use super::*;
    use crate::btx::state::Utxo;

    #[test]
    fn test_compute_commitment_empty() {
        let tx = BitcoinTransaction::new(vec![], vec![]);
        let commitment1 = compute_commitment(&tx);
        let commitment2 = compute_commitment(&tx);

        assert_eq!(commitment1, commitment2);
    }

    #[test]
    fn test_compute_commitment_deterministic() {
        let txid1 = Txid::from_byte_array([0x01; 32]);
        let txid2 = Txid::from_byte_array([0x02; 32]);
        let addr1: Address<NetworkUnchecked> =
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".parse().expect("valid Bitcoin address");
        let addr2: Address<NetworkUnchecked> =
            "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".parse().expect("valid Bitcoin address");
        let inputs = vec![Utxo::new(txid1, 0, 1000, addr1)];
        let outputs = vec![Utxo::new(txid2, 0, 1000, addr2)];
        let tx = BitcoinTransaction::new(inputs, outputs);

        let commitment1 = compute_commitment(&tx);
        let commitment2 = compute_commitment(&tx);

        assert_eq!(commitment1, commitment2);
    }

    #[test]
    fn test_compute_commitment_different_inputs() {
        let txid1 = Txid::from_byte_array([0x01; 32]);
        let txid2 = Txid::from_byte_array([0x02; 32]);
        let txid3 = Txid::from_byte_array([0x03; 32]);
        let addr1: Address<NetworkUnchecked> =
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".parse().expect("valid Bitcoin address");
        let addr2: Address<NetworkUnchecked> =
            "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".parse().expect("valid Bitcoin address");
        let inputs1 = vec![Utxo::new(txid1, 0, 1000, addr1.clone())];
        let inputs2 = vec![Utxo::new(txid2, 0, 1000, addr1)];
        let outputs = vec![Utxo::new(txid3, 0, 1000, addr2)];

        let tx1 = BitcoinTransaction::new(inputs1, outputs.clone());
        let tx2 = BitcoinTransaction::new(inputs2, outputs);

        let commitment1 = compute_commitment(&tx1);
        let commitment2 = compute_commitment(&tx2);

        assert_ne!(commitment1, commitment2);
    }

    #[test]
    fn test_compute_commitment_different_outputs() {
        let txid1 = Txid::from_byte_array([0x01; 32]);
        let txid2 = Txid::from_byte_array([0x02; 32]);
        let txid3 = Txid::from_byte_array([0x03; 32]);
        let addr1: Address<NetworkUnchecked> =
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".parse().expect("valid Bitcoin address");
        let addr2: Address<NetworkUnchecked> =
            "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".parse().expect("valid Bitcoin address");
        let addr3: Address<NetworkUnchecked> =
            "1CounterpartyXXXXXXXXXXXXXXXUWLpVr".parse().expect("valid Bitcoin address");
        let inputs = vec![Utxo::new(txid1, 0, 1000, addr1)];
        let outputs1 = vec![Utxo::new(txid2, 0, 1000, addr2)];
        let outputs2 = vec![Utxo::new(txid3, 0, 1000, addr3)];

        let tx1 = BitcoinTransaction::new(inputs.clone(), outputs1);
        let tx2 = BitcoinTransaction::new(inputs, outputs2);

        let commitment1 = compute_commitment(&tx1);
        let commitment2 = compute_commitment(&tx2);

        assert_ne!(commitment1, commitment2);
    }

    #[test]
    fn test_compute_commitment_multiple_utxos() {
        let txid1 = Txid::from_byte_array([0x01; 32]);
        let txid2 = Txid::from_byte_array([0x02; 32]);
        let txid3 = Txid::from_byte_array([0x03; 32]);
        let addr1: Address<NetworkUnchecked> =
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".parse().expect("valid Bitcoin address");
        let addr2: Address<NetworkUnchecked> =
            "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".parse().expect("valid Bitcoin address");
        let addr3: Address<NetworkUnchecked> =
            "1CounterpartyXXXXXXXXXXXXXXXUWLpVr".parse().expect("valid Bitcoin address");
        let inputs = vec![Utxo::new(txid1, 0, 1000, addr1), Utxo::new(txid2, 1, 2000, addr2)];
        let outputs = vec![Utxo::new(txid3, 0, 3000, addr3)];
        let tx = BitcoinTransaction::new(inputs, outputs);

        let commitment = compute_commitment(&tx);

        assert_ne!(commitment, [0u8; 32]);
    }

    #[test]
    fn test_hash_single_utxo() {
        let txid1 = Txid::from_byte_array([0x01; 32]);
        let txid2 = Txid::from_byte_array([0x02; 32]);
        let addr: Address<NetworkUnchecked> =
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".parse().expect("valid Bitcoin address");
        let utxo1 = Utxo::new(txid1, 0, 1000, addr.clone());
        let utxo2 = Utxo::new(txid1, 0, 1000, addr.clone());
        let utxo3 = Utxo::new(txid2, 0, 1000, addr);

        let hash1 = hash_single_utxo(&utxo1);
        let hash2 = hash_single_utxo(&utxo2);
        let hash3 = hash_single_utxo(&utxo3);

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_compute_btx_commitment() {
        let state_hash1 = [0u8; 32];
        let state_hash2 = [1u8; 32];

        let commitment1 = compute_btx_commitment(state_hash1);
        let commitment2 = compute_btx_commitment(state_hash1);
        let commitment3 = compute_btx_commitment(state_hash2);

        assert_eq!(commitment1, commitment2);
        assert_ne!(commitment1, commitment3);
    }
}
