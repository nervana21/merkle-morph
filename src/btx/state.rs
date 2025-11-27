// SPDX-License-Identifier: CC0-1.0

//! Bitcoin transaction state representation
//!
//! This module defines the state structures for Bitcoin transactions,
//! including UTXO (Unspent Transaction Output) and BitcoinTransaction types.

use bitcoin::absolute::LockTime;
use bitcoin::address::NetworkUnchecked;
use bitcoin::script::{ScriptPubKeyBuf, ScriptSigBuf};
use bitcoin::transaction::Version;
use bitcoin::{Address, OutPoint, Sequence, Txid, Witness};

/// Represents a Bitcoin UTXO (Unspent Transaction Output)
///
/// A UTXO is an output from a previous transaction that can be spent as an input
/// in a new transaction. It is uniquely identified by the transaction ID and output index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Utxo {
    /// Transaction ID of the transaction that created this UTXO
    pub txid: Txid,
    /// Output index within the transaction
    pub index: u32,
    /// Value in satoshis
    pub value: u64,
    /// Bitcoin address that can spend this UTXO
    pub address: Address<NetworkUnchecked>,
    /// Script public key (locking script) for this UTXO
    ///
    /// If `None`, the script_pubkey will be derived from the address.
    /// If `Some`, this explicit script_pubkey will be used.
    pub script_pubkey: Option<ScriptPubKeyBuf>,
}

impl Utxo {
    /// Creates a new UTXO with the given parameters
    ///
    /// # Arguments
    /// * `txid` - Transaction ID
    /// * `index` - Output index
    /// * `value` - Value in satoshis
    /// * `address` - Bitcoin address
    pub fn new(txid: Txid, index: u32, value: u64, address: Address<NetworkUnchecked>) -> Self {
        Self { txid, index, value, address, script_pubkey: None }
    }

    /// Creates a new UTXO with explicit script_pubkey
    ///
    /// # Arguments
    /// * `txid` - Transaction ID
    /// * `index` - Output index
    /// * `value` - Value in satoshis
    /// * `address` - Bitcoin address
    /// * `script_pubkey` - Explicit script public key
    pub fn with_script_pubkey(
        txid: Txid,
        index: u32,
        value: u64,
        address: Address<NetworkUnchecked>,
        script_pubkey: ScriptPubKeyBuf,
    ) -> Self {
        Self { txid, index, value, address, script_pubkey: Some(script_pubkey) }
    }

    /// Gets the transaction ID
    pub fn txid(&self) -> &Txid { &self.txid }

    /// Gets the output index
    pub fn index(&self) -> u32 { self.index }

    /// Gets the value in satoshis
    pub fn value(&self) -> u64 { self.value }

    /// Gets the Bitcoin address
    pub fn address(&self) -> &Address<NetworkUnchecked> { &self.address }

    /// Gets the script public key
    ///
    /// If an explicit script_pubkey was set, returns it.
    /// Otherwise, derives it from the address.
    pub fn script_pubkey(&self) -> ScriptPubKeyBuf {
        self.script_pubkey
            .clone()
            .unwrap_or_else(|| self.address.assume_checked_ref().script_pubkey().to_owned())
    }

    /// Gets the OutPoint for this UTXO
    pub fn outpoint(&self) -> OutPoint { OutPoint { txid: self.txid, vout: self.index } }
}

/// Represents full input data for a Bitcoin transaction
///
/// Contains the UTXO being spent along with the unlocking script data
/// (scriptSig for legacy, witness for SegWit).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxInputData {
    /// The UTXO being spent
    pub utxo: Utxo,
    /// Script signature (unlocking script for legacy transactions)
    pub script_sig: ScriptSigBuf,
    /// Witness data (for SegWit transactions)
    pub witness: Witness,
    /// Sequence number
    pub sequence: Sequence,
}

impl TxInputData {
    /// Creates a new TxInputData
    ///
    /// # Arguments
    /// * `utxo` - The UTXO being spent
    /// * `script_sig` - Script signature
    /// * `witness` - Witness data
    /// * `sequence` - Sequence number
    pub fn new(utxo: Utxo, script_sig: ScriptSigBuf, witness: Witness, sequence: Sequence) -> Self {
        Self { utxo, script_sig, witness, sequence }
    }

    /// Creates an input with witness (empty script_sig)
    pub fn with_witness(utxo: Utxo, witness: Witness, sequence: Sequence) -> Self {
        Self { utxo, script_sig: ScriptSigBuf::new(), witness, sequence }
    }

    /// Creates an input with script_sig (no witness)
    ///
    /// Inputs with script_sig can be spent to create P2TR/P2A outputs. The validation
    /// in `validate_p2tr_witnesses()` allows non-witness inputs as long as all outputs
    /// are P2TR/P2A.
    pub fn with_script_sig(utxo: Utxo, script_sig: ScriptSigBuf, sequence: Sequence) -> Self {
        Self { utxo, script_sig, witness: Witness::new(), sequence }
    }
}

/// Represents a Bitcoin transaction
///
/// A Bitcoin transaction consumes UTXOs as inputs and produces new UTXOs as outputs.
/// The transaction includes full input data with scripts and witnesses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitcoinTransaction {
    /// Transaction version
    pub version: Version,
    /// Full input data with scripts and witnesses
    pub inputs_data: Vec<TxInputData>,
    /// Output UTXOs being created
    pub outputs: Vec<Utxo>,
    /// Lock time
    pub lock_time: LockTime,
}

impl BitcoinTransaction {
    /// Creates a new Bitcoin transaction with the given inputs and outputs
    ///
    /// Defaults to version 3 (TRUC) to enable zero-fee transactions with CPFP support.
    /// If version 2 transactions are required (e.g., for large transactions >10KB or
    /// complex topologies), use `with_scripts()` to specify the version explicitly.
    ///
    /// # Arguments
    /// * `inputs` - Vector of input UTXOs
    /// * `outputs` - Vector of output UTXOs
    ///
    /// Note: This creates TxInputData with empty scripts. For full script data,
    /// use `with_scripts()` instead.
    pub fn new(inputs: Vec<Utxo>, outputs: Vec<Utxo>) -> Self {
        let inputs_data: Vec<TxInputData> = inputs
            .into_iter()
            .map(|utxo| TxInputData::new(utxo, ScriptSigBuf::new(), Witness::new(), Sequence::MAX))
            .collect();
        Self { version: Version::THREE, inputs_data, outputs, lock_time: LockTime::ZERO }
    }

    /// Creates a new Bitcoin transaction with full script data
    ///
    /// # Arguments
    /// * `version` - Transaction version
    /// * `inputs_data` - Full input data with scripts/witnesses
    /// * `outputs` - Vector of output UTXOs
    /// * `lock_time` - Lock time
    pub fn with_scripts(
        version: Version,
        inputs_data: Vec<TxInputData>,
        outputs: Vec<Utxo>,
        lock_time: LockTime,
    ) -> Self {
        Self { version, inputs_data, outputs, lock_time }
    }

    /// Gets a reference to the input UTXOs
    ///
    /// This derives the UTXOs from the inputs_data field.
    pub fn inputs(&self) -> Vec<Utxo> {
        self.inputs_data.iter().map(|id| id.utxo.clone()).collect()
    }

    /// Gets a reference to the full input data
    pub fn inputs_data(&self) -> &[TxInputData] { &self.inputs_data }

    /// Gets a reference to the output UTXOs
    pub fn outputs(&self) -> &[Utxo] { &self.outputs }

    /// Checks if this transaction has full script data
    ///
    /// Returns true if at least one input has a non-empty script_sig or witness.
    pub fn has_scripts(&self) -> bool {
        self.inputs_data
            .iter()
            .any(|input| !input.script_sig.is_empty() || !input.witness.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use hex;

    use super::*;

    fn addr(s: &str) -> Address<NetworkUnchecked> { s.parse().expect("valid Bitcoin address") }

    #[test]
    fn test_new() {
        let txid = Txid::from_byte_array([1u8; 32]);
        let address = addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");

        let utxo = Utxo::new(txid, 0, 1000, address);

        assert_eq!(utxo.txid, txid);
        assert_eq!(utxo.index, 0);
        assert_eq!(utxo.value, 1000);
        assert_eq!(utxo.address, address);
        assert_eq!(utxo.script_pubkey, None);
    }

    #[test]
    fn test_with_script_pubkey() {
        let txid = Txid::from_byte_array([2u8; 32]);
        let address = addr("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
        #[rustfmt::skip]
        let script = ScriptPubKeyBuf::from_bytes(vec![
            0x76, 0xa9, 0x14, 0x89, 0xab, 0xcd, 0xef, 0xab,
            0xba, 0xab, 0xba, 0xab, 0xba, 0xab, 0xba, 0xab,
            0xba, 0xab, 0xba, 0x88, 0xac,
        ]);

        let utxo = Utxo::with_script_pubkey(txid, 1, 2000, address, script.clone());

        assert_eq!(utxo.txid, txid);
        assert_eq!(utxo.index, 1);
        assert_eq!(utxo.value, 2000);
        assert_eq!(utxo.address, address);
        assert_eq!(utxo.script_pubkey, Some(script));
    }

    #[test]
    fn test_txid() {
        let txid = Txid::from_byte_array([3u8; 32]);
        let address = addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        let utxo = Utxo::new(txid, 0, 1000, address);

        let result = utxo.txid();

        assert_eq!(result, &txid);
    }

    #[test]
    fn test_index() {
        let txid = Txid::from_byte_array([4u8; 32]);
        let address = addr("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
        let utxo = Utxo::new(txid, 5, 1000, address);

        let result = utxo.index();

        assert_eq!(result, 5);
    }

    #[test]
    fn test_value() {
        let txid = Txid::from_byte_array([5u8; 32]);
        let address = addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        let utxo = Utxo::new(txid, 0, 5000, address);

        let result = utxo.value();

        assert_eq!(result, 5000);
    }

    #[test]
    fn test_address() {
        let txid = Txid::from_byte_array([6u8; 32]);
        let address = addr("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
        let utxo = Utxo::new(txid, 0, 1000, address);

        let result = utxo.address();

        assert_eq!(result, &address);
    }

    #[test]
    fn test_script_pubkey() {
        let txid1 = Txid::from_byte_array([7u8; 32]);
        let address1 = addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        #[rustfmt::skip]
        let script = ScriptPubKeyBuf::from_bytes(vec![
            0x76, 0xa9, 0x14, 0x89, 0xab, 0xcd, 0xef, 0xab,
            0xba, 0xab, 0xba, 0xab, 0xba, 0xab, 0xba, 0xab,
            0xba, 0xab, 0xba, 0x88, 0xac,
        ]);
        let utxo_with_script = Utxo::with_script_pubkey(txid1, 0, 1000, address1, script.clone());

        let result_with_script = utxo_with_script.script_pubkey();

        assert_eq!(result_with_script, script);

        let txid2 = Txid::from_byte_array([8u8; 32]);
        let address2 = addr("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
        let utxo_without_script = Utxo::new(txid2, 0, 1000, address2);

        let result_without_script = utxo_without_script.script_pubkey();

        assert_eq!(result_without_script, address2.assume_checked_ref().script_pubkey());
    }

    #[test]
    fn test_outpoint() {
        let txid = Txid::from_byte_array([9u8; 32]);
        let address = addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        let utxo = Utxo::new(txid, 3, 1000, address);

        let result = utxo.outpoint();

        assert_eq!(result.txid, txid);
        assert_eq!(result.vout, 3);
    }

    #[test]
    fn test_tx_input_data_new() {
        let txid = Txid::from_byte_array([10u8; 32]);
        let address = addr("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
        let utxo = Utxo::new(txid, 0, 1000, address);
        let script_bytes =
            hex::decode("76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac").expect("valid hex");
        let script_sig = ScriptSigBuf::from_bytes(script_bytes);
        let mut witness = Witness::new();
        witness.push(vec![1u8; 32]);
        let sequence = Sequence::from_consensus(0xFFFFFFFF);

        let input_data =
            TxInputData::new(utxo.clone(), script_sig.clone(), witness.clone(), sequence);

        assert_eq!(input_data.utxo, utxo);
        assert_eq!(input_data.script_sig, script_sig);
        assert_eq!(input_data.witness, witness);
        assert_eq!(input_data.sequence, sequence);
    }

    #[test]
    fn test_with_witness() {
        let txid = Txid::from_byte_array([11u8; 32]);
        let address = addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        let utxo = Utxo::new(txid, 0, 1000, address);
        let mut witness = Witness::new();
        witness.push(vec![2u8; 32]);
        let sequence = Sequence::from_consensus(0xFFFFFFFE);

        let input_data = TxInputData::with_witness(utxo.clone(), witness.clone(), sequence);

        assert_eq!(input_data.utxo, utxo);
        assert_eq!(input_data.script_sig, ScriptSigBuf::new());
        assert_eq!(input_data.witness, witness);
        assert_eq!(input_data.sequence, sequence);
    }

    #[test]
    fn test_with_script_sig() {
        let txid = Txid::from_byte_array([12u8; 32]);
        let address = addr("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
        let utxo = Utxo::new(txid, 0, 1000, address);
        let script_bytes =
            hex::decode("76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac").expect("valid hex");
        let script_sig = ScriptSigBuf::from_bytes(script_bytes);
        let sequence = Sequence::from_consensus(0xFFFFFFFD);

        let input_data = TxInputData::with_script_sig(utxo.clone(), script_sig.clone(), sequence);

        assert_eq!(input_data.utxo, utxo);
        assert_eq!(input_data.script_sig, script_sig);
        assert_eq!(input_data.witness, Witness::new());
        assert_eq!(input_data.sequence, sequence);
    }

    #[test]
    fn test_bitcoin_transaction_new() {
        let txid1 = Txid::from_byte_array([13u8; 32]);
        let txid2 = Txid::from_byte_array([14u8; 32]);
        let address1 = addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        let address2 = addr("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
        let input1 = Utxo::new(txid1, 0, 1000, address1);
        let input2 = Utxo::new(txid2, 1, 2000, address2);
        let output1 = Utxo::new(txid1, 0, 2500, address1);

        let tx =
            BitcoinTransaction::new(vec![input1.clone(), input2.clone()], vec![output1.clone()]);

        assert_eq!(tx.version, Version::THREE);
        assert_eq!(tx.inputs_data.len(), 2);
        assert_eq!(tx.inputs_data[0].utxo, input1);
        assert_eq!(tx.inputs_data[1].utxo, input2);
        assert_eq!(tx.inputs_data[0].script_sig, ScriptSigBuf::new());
        assert_eq!(tx.inputs_data[0].witness, Witness::new());
        assert_eq!(tx.inputs_data[0].sequence, Sequence::MAX);
        assert_eq!(tx.outputs, vec![output1]);
        assert_eq!(tx.lock_time, LockTime::ZERO);
    }

    #[test]
    fn test_with_scripts() {
        let txid = Txid::from_byte_array([15u8; 32]);
        let address = addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        let utxo = Utxo::new(txid, 0, 1000, address);
        let script_bytes =
            hex::decode("76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac").expect("valid hex");
        let script_sig = ScriptSigBuf::from_bytes(script_bytes);
        let mut witness = Witness::new();
        witness.push(vec![3u8; 32]);
        let input_data = TxInputData::new(utxo, script_sig, witness, Sequence::MAX);
        let output = Utxo::new(txid, 0, 500, address);
        let version = Version::ONE;
        let lock_time = LockTime::from_consensus(1000);

        let tx = BitcoinTransaction::with_scripts(
            version,
            vec![input_data.clone()],
            vec![output.clone()],
            lock_time,
        );

        assert_eq!(tx.version, version);
        assert_eq!(tx.inputs_data, vec![input_data]);
        assert_eq!(tx.outputs, vec![output]);
        assert_eq!(tx.lock_time, lock_time);
    }

    #[test]
    fn test_inputs() {
        let txid1 = Txid::from_byte_array([16u8; 32]);
        let txid2 = Txid::from_byte_array([17u8; 32]);
        let address1 = addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        let address2 = addr("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
        let input1 = Utxo::new(txid1, 0, 1000, address1);
        let input2 = Utxo::new(txid2, 1, 2000, address2);
        let output = Utxo::new(txid1, 0, 2500, addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"));
        let tx = BitcoinTransaction::new(vec![input1.clone(), input2.clone()], vec![output]);

        let result = tx.inputs();

        assert_eq!(result, vec![input1, input2]);
    }

    #[test]
    fn test_inputs_data() {
        let txid = Txid::from_byte_array([18u8; 32]);
        let address = addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        let utxo = Utxo::new(txid, 0, 1000, address);
        let script_bytes =
            hex::decode("76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac").expect("valid hex");
        let script_sig = ScriptSigBuf::from_bytes(script_bytes);
        let mut witness = Witness::new();
        witness.push(vec![4u8; 32]);
        let input_data = TxInputData::new(utxo, script_sig, witness, Sequence::MAX);
        let output = Utxo::new(txid, 0, 500, addr("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"));
        let tx = BitcoinTransaction::with_scripts(
            Version::TWO,
            vec![input_data.clone()],
            vec![output],
            LockTime::ZERO,
        );

        let result = tx.inputs_data();

        assert_eq!(result, &[input_data]);
    }

    #[test]
    fn test_outputs() {
        let txid = Txid::from_byte_array([19u8; 32]);
        let address1 = addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        let address2 = addr("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
        let input = Utxo::new(txid, 0, 1000, address1);
        let output1 = Utxo::new(txid, 0, 500, address2);
        let output2 = Utxo::new(txid, 1, 400, address2);
        let tx = BitcoinTransaction::new(vec![input], vec![output1.clone(), output2.clone()]);

        let result = tx.outputs();

        assert_eq!(result, &[output1, output2]);
    }

    #[test]
    fn test_has_scripts() {
        let txid1 = Txid::from_byte_array([20u8; 32]);
        let address1 = addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        let input1 = Utxo::new(txid1, 0, 1000, address1);
        let output1 = Utxo::new(txid1, 0, 500, addr("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"));
        let tx_without_scripts = BitcoinTransaction::new(vec![input1], vec![output1]);

        let result_false = tx_without_scripts.has_scripts();

        assert!(!result_false);

        let txid2 = Txid::from_byte_array([21u8; 32]);
        let address2 = addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        let utxo2 = Utxo::new(txid2, 0, 1000, address2);
        let script_bytes =
            hex::decode("76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac").expect("valid hex");
        let script_sig = ScriptSigBuf::from_bytes(script_bytes);
        let input_data = TxInputData::new(utxo2, script_sig, Witness::new(), Sequence::MAX);
        let output2 = Utxo::new(txid2, 0, 500, addr("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"));
        let tx_with_scripts = BitcoinTransaction::with_scripts(
            Version::TWO,
            vec![input_data],
            vec![output2],
            LockTime::ZERO,
        );

        let result_true = tx_with_scripts.has_scripts();

        assert!(result_true);
    }
}
