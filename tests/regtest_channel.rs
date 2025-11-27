//! End-to-end test: Bitcoin regtest wallet funding, channel operations, and on-chain settlement

use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::Result;
use bitcoin::address::NetworkUnchecked;
use bitcoin::bip32::{DerivationPath, Fingerprint};
use bitcoin::consensus::Encodable;
use bitcoin::psbt::{GetKey, KeyRequest, Psbt, PsbtSighashType};
use bitcoin::script::ScriptSigBuf;
use bitcoin::secp256k1::{SecretKey, XOnlyPublicKey};
use bitcoin::sighash::ScriptPath;
use bitcoin::taproot::{LeafVersion, TapLeafHash};
use bitcoin::{Network, PrivateKey, Sequence, Transaction, TxIn, TxOut};
use bitcoin_core_client_rpc_30_0_0::node::NodeManager;
use bitcoin_core_client_rpc_30_0_0::{
    BitcoinClientV30_0_0, BitcoinNodeManager, DefaultTransport, TestConfig,
};
use merkle_morph::btx::state::Utxo;
use merkle_morph::channel::commitment::{
    compute_cooperative_closing_commitment, compute_open_commitment,
};
use merkle_morph::channel::funding::ChannelFunding;
use merkle_morph::channel::state::{CooperativeClosing, Open};
use merkle_morph::channel::{apply_cooperative_close, apply_transfer, TransferAmount};
use merkle_morph::global::commitment::{compose_to_global_root, compute_subtree_root};
use merkle_morph::global::GlobalState;
use merkle_morph::types::{ChannelCommitment, ChannelId, WalletId};
use merkle_morph::wallet::commitment::compute_commitment_from_channels as compute_wallet_commitment;
use merkle_morph::wallet::state::WalletState;
use merkle_morph::zkp::create_config;
use merkle_morph::zkp::global::{prove_global_root_composition, verify_global_root_composition};

fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    let chars: Vec<char> = s.chars().collect();
    let len = chars.len();

    for (i, ch) in chars.iter().enumerate() {
        if i > 0 && (len - i) % 3 == 0 {
            result.push(',');
        }
        result.push(*ch);
    }
    result
}

fn format_hash(bytes: &[u8; 32]) -> String { hex::encode(bytes) }

/// Wallet funding information
struct WalletFundingInfo {
    sender_address_str: String,
    sender_address: bitcoin::Address<NetworkUnchecked>,
    receiver_address_str: String,
    receiver_address: bitcoin::Address<NetworkUnchecked>,
    block_reward_address: bitcoin::Address,
}

/// Channel funding UTXO information
struct ChannelFundingUtxo {
    txid: bitcoin::Txid,
    vout: u32,
    value: u64,
    address: bitcoin::Address<NetworkUnchecked>,
    funding: ChannelFunding,
}

async fn setup_bitcoin_wallet_and_fund(
    client: &Arc<DefaultTransport>,
) -> Result<WalletFundingInfo> {
    println!("\n=== Creating and Funding Wallets ===");

    let wallet_name = "test_wallet";
    match client.load_wallet(wallet_name.to_string(), None).await {
        Ok(_) => {}
        Err(_) => {
            let _create_result = client
                .create_wallet(
                    wallet_name.to_string(),
                    Some(false),
                    Some(false),
                    Some("".to_string()),
                    Some(false),
                    Some(true),
                    Some(false),
                    Some(false),
                )
                .await?;
        }
    }

    let sender_address_resp =
        client.get_new_address(Some("".to_string()), Some("bech32m".to_string())).await?;
    let sender_address_str = sender_address_resp.value.clone();
    let sender_address: bitcoin::Address<NetworkUnchecked> =
        sender_address_str.parse().expect("valid address");

    let receiver_address_resp =
        client.get_new_address(Some("".to_string()), Some("bech32m".to_string())).await?;
    let receiver_address_str = receiver_address_resp.value.clone();
    let receiver_address: bitcoin::Address<NetworkUnchecked> =
        receiver_address_str.parse().expect("valid address");

    println!("Sender address: {}", sender_address_str);
    println!("Receiver address: {}", receiver_address_str);

    let block_reward_address_resp =
        client.get_new_address(Some("".to_string()), Some("bech32m".to_string())).await?;
    let block_reward_address_str = block_reward_address_resp.value.clone();

    let block_reward_addr_unchecked: bitcoin::Address<NetworkUnchecked> =
        block_reward_address_str.parse().expect("valid address");
    let block_reward_addr: bitcoin::Address = block_reward_addr_unchecked.assume_checked();
    let block_reward_addr_for_return = block_reward_addr;
    // Convert bitcoin::Address to RPC client's Address type
    let block_reward_addr_rpc_unchecked =
        bitcoin_core_client_rpc_30_0_0::Address::from_str(&block_reward_address_str)?;
    let block_reward_addr_rpc = block_reward_addr_rpc_unchecked.assume_checked();

    let _generate_result =
        client.generate_to_address(101, block_reward_addr_rpc.clone(), Some(2000)).await?;

    // Fund the sender with enough to open a channel and pay transaction fees
    // Channel will be funded with ~5K sats (enough for ~2.1K sats in transfers + buffer)
    let channel_funding_amount = 5_000u64;
    let estimated_fee = 2_000u64;
    // Add a small buffer (10 sats) to account for Bitcoin Core's fee adjustments
    // which may slightly reduce the output amount
    let fee_buffer = 10u64;
    let sender_amount_sats = channel_funding_amount + estimated_fee + fee_buffer;
    let sender_amount_btc = sender_amount_sats as f64 / 100_000_000.0;

    // Send funds from block_reward_addr to sender_address
    let send_outputs = vec![serde_json::json!({ sender_address_str.clone(): sender_amount_btc })];
    let empty_inputs: Vec<serde_json::Value> = vec![];
    let raw_tx_response = client
        .create_raw_transaction(empty_inputs, send_outputs, Some(0), Some(false), Some(3))
        .await?;
    let raw_tx_hex_str = raw_tx_response.value.clone();
    let fund_options = serde_json::json!({
        "feeRate": 0.0001,
        "includeWatching": true,
        "lockUnspents": false,
        "replaceable": false,
    });
    let funded_tx =
        client.fund_raw_transaction(raw_tx_hex_str, Some(fund_options), None::<bool>).await?;
    let funded_tx_hex = funded_tx.hex.clone();

    let signed_tx = client
        .sign_raw_transaction_with_wallet(
            funded_tx_hex,
            None::<Vec<serde_json::Value>>,
            None::<String>,
        )
        .await?;
    let send_hex = signed_tx.hex.clone();

    let _send_txid_resp = client.send_raw_transaction(send_hex.clone(), None, None).await?;

    // Mine a block to confirm the transaction
    let _generate_result =
        client.generate_to_address(1, block_reward_addr_rpc.clone(), Some(2000)).await?;

    // Get balance of just the sender address, not the entire wallet
    let utxos_resp = client
        .list_unspent(
            Some(0),
            Some(9999999),
            Some(vec![serde_json::json!(sender_address_str.clone())]),
            Some(true),
            None,
        )
        .await?;
    let utxos: Vec<serde_json::Value> = utxos_resp.value;
    let mut sender_balance_sats = 0u64;
    for utxo in &utxos {
        if let Some(amount) = utxo["amount"].as_f64() {
            sender_balance_sats += (amount * 100_000_000.0) as u64;
        }
    }
    println!("Sender initial balance: {} sats", format_number(sender_balance_sats));

    Ok(WalletFundingInfo {
        sender_address_str,
        sender_address,
        receiver_address_str,
        receiver_address,
        block_reward_address: block_reward_addr_for_return,
    })
}

async fn create_channel_funding_transaction(
    client: &Arc<DefaultTransport>,
    wallet_info: &WalletFundingInfo,
    block_reward_address: &bitcoin::Address,
) -> Result<ChannelFundingUtxo> {
    println!("\n=== Creating Channel Funding Transaction ===");

    // Generate test keys for channel participants
    let sender_sk = SecretKey::from_secret_bytes([1u8; 32])
        .expect("32-byte array should always be a valid SecretKey");
    let receiver_sk = SecretKey::from_secret_bytes([2u8; 32])
        .expect("32-byte array should always be a valid SecretKey");
    let sender_pubkey =
        bitcoin::key::XOnlyPublicKey::from(XOnlyPublicKey::from_keypair(&sender_sk.keypair()).0);
    let receiver_pubkey =
        bitcoin::key::XOnlyPublicKey::from(XOnlyPublicKey::from_keypair(&receiver_sk.keypair()).0);

    // Generate revocation secrets for challenge pubkeys
    let sender_revocation_secret =
        SecretKey::from_secret_bytes([3u8; 32]).expect("valid sender revocation secret");
    let receiver_revocation_secret =
        SecretKey::from_secret_bytes([4u8; 32]).expect("valid receiver revocation secret");

    // Create 2-of-2 taproot multisig funding address
    let mut funding = ChannelFunding::new(
        sender_pubkey,
        receiver_pubkey,
        sender_revocation_secret,
        receiver_revocation_secret,
        Network::Regtest,
    )?;
    let channel_funding_address = funding.funding_address;
    let channel_funding_address_str = channel_funding_address.assume_checked().to_string();
    println!("Channel funding address: {}", channel_funding_address_str);

    // Fund the channel with ~5K sats
    // This is sufficient for the test transfers (1K + 1.1K = 2.1K sats total) plus a small buffer
    let initial_channel_balance = 5_000u64;
    let estimated_fee = 2_000u64; // Reserve for transaction fees

    println!("Channel funding amount: {} sats", format_number(initial_channel_balance),);

    let wallet_balance_check =
        client.get_balance(Some("*".to_string()), Some(0), Some(false), None).await?;
    let wallet_balance_check_sats = (wallet_balance_check.value * 100_000_000.0) as u64;
    let required_amount = initial_channel_balance + estimated_fee;
    if wallet_balance_check_sats < required_amount {
        anyhow::bail!(
            "Insufficient wallet balance: {} sats (need {} sats for channel funding + fees)",
            format_number(wallet_balance_check_sats),
            format_number(required_amount)
        );
    }

    let utxos_resp = client
        .list_unspent(
            Some(0),
            Some(9999999),
            Some(vec![serde_json::json!(wallet_info.sender_address_str.clone())]),
            Some(true),
            None,
        )
        .await?;
    let utxos: Vec<serde_json::Value> = utxos_resp.value;
    if utxos.is_empty() {
        anyhow::bail!("No UTXOs available for channel funding");
    }

    let channel_funding_amount = initial_channel_balance as f64 / 100_000_000.0;
    let funding_outputs =
        vec![serde_json::json!({ channel_funding_address_str.clone(): channel_funding_amount })];

    let empty_inputs: Vec<serde_json::Value> = vec![];
    let raw_tx_response = client
        .create_raw_transaction(empty_inputs, funding_outputs, Some(0), Some(false), Some(3))
        .await?;
    let raw_tx_hex_str = raw_tx_response.value.clone();
    let fund_options = serde_json::json!({
        "feeRate": 0.0001,
        "includeWatching": true,
        "lockUnspents": false,
        "replaceable": false,
    });
    let funded_tx =
        client.fund_raw_transaction(raw_tx_hex_str, Some(fund_options), None::<bool>).await?;
    let funded_tx_hex = funded_tx.hex.clone();

    let signed_tx = client
        .sign_raw_transaction_with_wallet(
            funded_tx_hex,
            None::<Vec<serde_json::Value>>,
            None::<String>,
        )
        .await?;
    let funding_hex = signed_tx.hex.clone();

    let funding_txid_resp = client.send_raw_transaction(funding_hex, None, None).await?;
    let funding_txid_str = funding_txid_resp.value.clone();

    // Convert bitcoin::Address to RPC client's Address type
    let block_reward_address_str = block_reward_address.to_string();
    let block_reward_address_rpc_unchecked =
        bitcoin_core_client_rpc_30_0_0::Address::from_str(&block_reward_address_str)?;
    let block_reward_address_rpc = block_reward_address_rpc_unchecked.assume_checked();
    let _ = client.generate_to_address(1, block_reward_address_rpc.clone(), Some(2000)).await?;

    // Parse directly into RPC client's Txid type for get_raw_transaction
    let funding_txid_rpc: bitcoin_core_client_rpc_30_0_0::Txid = funding_txid_str.parse()?;
    let funding_tx_hex_resp = client.get_raw_transaction(funding_txid_rpc, Some(0), None).await?;
    // Also parse into bitcoin::Txid for later use
    let funding_txid_parsed: bitcoin::Txid = funding_txid_str.parse()?;
    let funding_tx_hex = funding_tx_hex_resp.value;
    let decoded_funding_tx = client.decode_raw_transaction(funding_tx_hex, None).await?;

    let channel_funding_utxo_txid = funding_txid_parsed;
    let mut channel_funding_utxo_vout = 0u32;
    let mut channel_funding_utxo_value = 0u64;

    if let Some(vouts) = decoded_funding_tx.vout.as_array() {
        for (vout_idx, vout) in vouts.iter().enumerate() {
            // Bitcoin Core returns addresses in different formats (array for legacy/P2SH, string for bech32/bech32m)
            let mut found_address = false;

            if let Some(addresses) = vout["scriptPubKey"]["addresses"].as_array() {
                if let Some(addr) = addresses.first() {
                    if addr.as_str() == Some(&channel_funding_address_str) {
                        found_address = true;
                    }
                }
            }

            if !found_address {
                if let Some(addr) = vout["scriptPubKey"]["address"].as_str() {
                    if addr == channel_funding_address_str {
                        found_address = true;
                    }
                }
            }

            if found_address {
                if let Some(value) = vout["value"].as_f64() {
                    channel_funding_utxo_vout = vout_idx as u32;
                    channel_funding_utxo_value = (value * 100_000_000.0) as u64;
                    println!("Channel-funding UTXO: txid={}", channel_funding_utxo_txid);
                    break;
                }
            }
        }
    }

    if channel_funding_utxo_value == 0 {
        println!("Failed to find channel-funding UTXO");
        println!("Looking for address: {}", channel_funding_address_str);
        if let Some(vouts) = decoded_funding_tx.vout.as_array() {
            println!("Transaction has {} outputs", vouts.len());
            for (idx, vout) in vouts.iter().enumerate() {
                println!("  Output {}: value={:?}", idx, vout["value"]);
                if let Some(addr) = vout["scriptPubKey"]["address"].as_str() {
                    println!("    address: {}", addr);
                }
                if let Some(addresses) = vout["scriptPubKey"]["addresses"].as_array() {
                    println!("    addresses: {:?}", addresses);
                }
            }
        }
        anyhow::bail!("Failed to find channel-funding UTXO");
    }

    // Update the ChannelFunding with the actual UTXO information
    funding.update_funding_utxo(
        channel_funding_utxo_txid,
        channel_funding_utxo_vout,
        channel_funding_utxo_value,
    );

    Ok(ChannelFundingUtxo {
        txid: channel_funding_utxo_txid,
        vout: channel_funding_utxo_vout,
        value: channel_funding_utxo_value,
        address: channel_funding_address,
        funding,
    })
}

fn create_channel(
    channel_id: ChannelId,
    funding_utxo: &ChannelFundingUtxo,
) -> (Open, ChannelCommitment, SecretKey) {
    println!("\n=== Creating Channel from Channel-Funding Transaction ===");

    // Generate test keys for channel participants
    let sender_sk = bitcoin::secp256k1::SecretKey::from_secret_bytes([1u8; 32])
        .expect("32-byte array should always be a valid SecretKey");
    let receiver_sk = bitcoin::secp256k1::SecretKey::from_secret_bytes([2u8; 32])
        .expect("32-byte array should always be a valid SecretKey");
    let sender_pubkey = XOnlyPublicKey::from_keypair(&sender_sk.keypair()).0;
    let receiver_pubkey = XOnlyPublicKey::from_keypair(&receiver_sk.keypair()).0;

    let sender_revocation_secret = bitcoin::secp256k1::SecretKey::from_secret_bytes([3u8; 32])
        .expect("valid sender revocation secret");
    let receiver_revocation_secret = bitcoin::secp256k1::SecretKey::from_secret_bytes([4u8; 32])
        .expect("valid receiver revocation secret");
    let initial_channel_state = Open::new(
        sender_pubkey,
        receiver_pubkey,
        funding_utxo.value,
        sender_revocation_secret,
        receiver_revocation_secret,
    );
    let channel_commitment = compute_open_commitment(channel_id, &initial_channel_state);
    println!("Channel ID: {}", format_hash(&channel_id));
    println!(
        "Initial channel state: sender={}, receiver={}",
        format_number(initial_channel_state.sender_balance),
        format_number(initial_channel_state.receiver_balance)
    );
    println!("Channel commitment: {}", format_hash(&channel_commitment));

    (initial_channel_state, channel_commitment, sender_sk)
}

fn perform_channel_transfers(
    initial_state: &Open,
    zkp_config: &merkle_morph::zkp::types::StarkConfig,
    channel_id: ChannelId,
    sender_sk: &SecretKey,
) -> Result<Open> {
    println!("\n=== Merkle Morph Channel Transfers ===");

    let transfer1_amount = TransferAmount::new(1_000)?;
    let transfer1_result =
        apply_transfer(initial_state, &transfer1_amount, channel_id, zkp_config, sender_sk)?;

    println!("Transfer 1: {} sats", format_number(*transfer1_amount));
    println!(
        "  New state: sender={}, receiver={}, nonce={}",
        format_number(transfer1_result.new_state.sender_balance),
        format_number(transfer1_result.new_state.receiver_balance),
        transfer1_result.new_state.nonce
    );

    let transfer2_amount = TransferAmount::new(1_100)?;
    let transfer2_result = apply_transfer(
        &transfer1_result.new_state,
        &transfer2_amount,
        channel_id,
        zkp_config,
        sender_sk,
    )?;

    println!("\nTransfer 2: {} sats", format_number(*transfer2_amount));
    println!(
        "  New state: sender={}, receiver={}, nonce={}",
        format_number(transfer2_result.new_state.sender_balance),
        format_number(transfer2_result.new_state.receiver_balance),
        transfer2_result.new_state.nonce
    );

    let final_channel_state = transfer2_result.new_state;
    println!(
        "\nFinal channel state: sender={}, receiver={}",
        format_number(final_channel_state.sender_balance),
        format_number(final_channel_state.receiver_balance)
    );

    Ok(final_channel_state)
}

fn close_channel(
    channel_state: &Open,
    channel_id: ChannelId,
    config: &merkle_morph::zkp::types::StarkConfig,
) -> Result<CooperativeClosing> {
    println!("\n=== Closing Channel and Creating Settlement Transactions ===");

    // Use cooperative close to transition from Open to CooperativeClosing
    // Estimate a reasonable fee for a 2-output settlement transaction (~200-300 sats on regtest)
    let estimated_fee = 300u64;
    let closing_result = apply_cooperative_close(channel_state, estimated_fee, channel_id, config)?;

    println!(
        "Channel closed.\nFinal balances: sender={}, receiver={}, total_fee={}",
        format_number(closing_result.new_state.sender_balance),
        format_number(closing_result.new_state.receiver_balance),
        format_number(closing_result.new_state.total_fee)
    );

    Ok(closing_result.new_state)
}

fn prove_and_verify_global_state(
    config: &merkle_morph::zkp::types::StarkConfig,
    wallet_id: WalletId,
    channel_id: ChannelId,
    channel_commitment: ChannelCommitment,
    description: &str,
) -> Result<()> {
    println!("\n=== {} ===", description);

    let mut channels = BTreeMap::new();
    channels.insert(channel_id, channel_commitment);
    let wallet = WalletState::from_channels(wallet_id, channels);

    let wallet_commitment = compute_wallet_commitment(wallet.id, &wallet.channels)?;
    println!("Wallet ID: {}", format_hash(&wallet_id));
    println!("Wallet commitment: {}", format_hash(&wallet_commitment));

    let mut wallet_commitments = BTreeMap::new();
    wallet_commitments.insert(wallet_id, wallet_commitment);

    let subtree = compute_subtree_root(config, &wallet_commitments, wallet_id, wallet_id)?;

    let global_root = compose_to_global_root(std::slice::from_ref(&subtree))?;
    println!("Global root: {}", format_hash(&global_root));

    let global_state = GlobalState::with_root_and_nonce(global_root, 0);

    let proof = prove_global_root_composition(config, &[subtree])?;
    println!("ZKP generated ✓");

    verify_global_root_composition(config, global_state.wallets_root, &proof)?;
    println!("ZKP verified ✓");

    Ok(())
}

async fn create_and_broadcast_settlement_transaction(
    client: &Arc<DefaultTransport>,
    closed_state: &CooperativeClosing,
    funding_utxo: &ChannelFundingUtxo,
    wallet_info: &WalletFundingInfo,
    block_reward_address: &bitcoin::Address,
) -> Result<()> {
    println!(
        "Using channel-funding UTXO: txid={}, vout={}, amount={} sats",
        funding_utxo.txid,
        funding_utxo.vout,
        format_number(funding_utxo.value)
    );

    let channel_funding_utxo_obj =
        Utxo::new(funding_utxo.txid, funding_utxo.vout, funding_utxo.value, funding_utxo.address);

    let sender_output = Utxo::new(
        bitcoin::Txid::from_byte_array([0u8; 32]),
        0,
        closed_state.sender_balance,
        wallet_info.sender_address,
    );

    let receiver_output = Utxo::new(
        bitcoin::Txid::from_byte_array([0u8; 32]),
        0,
        closed_state.receiver_balance,
        wallet_info.receiver_address,
    );

    // The fee was already deducted from balances in closed_state
    // The actual transaction fee will be: funding_utxo.value - total_outputs
    let estimated_fee = closed_state.total_fee;
    let total_outputs = closed_state.sender_balance + closed_state.receiver_balance;
    let expected_change =
        funding_utxo.value.saturating_sub(total_outputs).saturating_sub(estimated_fee);

    let dust_threshold = 546u64;
    let mut settlement_outputs = vec![sender_output.clone(), receiver_output.clone()];

    if expected_change > dust_threshold {
        let change_output = Utxo::new(
            bitcoin::Txid::from_byte_array([0u8; 32]),
            2,
            expected_change,
            wallet_info.sender_address,
        );
        settlement_outputs.push(change_output.clone());
        println!(
            "  Expected change output: {} sats back to sender",
            format_number(expected_change)
        );
    }

    println!("Settlement transaction structure:");
    println!("  Inputs: 1 ({} sats)", format_number(channel_funding_utxo_obj.value));
    println!(
        "  Outputs: sender={} sats, receiver={} sats",
        format_number(closed_state.sender_balance),
        format_number(closed_state.receiver_balance)
    );
    if expected_change > dust_threshold {
        println!("  Change: {} sats back to sender", format_number(expected_change));
    }
    println!("  Estimated fee: {} sats", format_number(estimated_fee));

    println!("\n=== Creating and Broadcasting Settlement Transaction ===");

    // The closing fee was already deducted from balances in closed_state
    // Use the balances directly - the actual transaction fee will be the difference
    // between the input value and the sum of outputs
    let sender_output_sats = closed_state.sender_balance;
    let receiver_output_sats = closed_state.receiver_balance;

    println!(
        "Settlement outputs: sender={}, receiver={}",
        format_number(sender_output_sats),
        format_number(receiver_output_sats)
    );

    // Build the transaction manually
    let sender_script = wallet_info.sender_address.assume_checked_ref().script_pubkey().to_owned();
    let receiver_script =
        wallet_info.receiver_address.assume_checked_ref().script_pubkey().to_owned();

    let unsigned_tx = Transaction {
        version: bitcoin::transaction::Version::THREE,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: funding_utxo.funding.funding_utxo.outpoint(),
            script_sig: ScriptSigBuf::new(),
            sequence: Sequence::MAX,
            witness: bitcoin::Witness::new(),
        }],
        outputs: vec![
            TxOut {
                amount: bitcoin::Amount::from_sat(sender_output_sats)?,
                script_pubkey: sender_script,
            },
            TxOut {
                amount: bitcoin::Amount::from_sat(receiver_output_sats)?,
                script_pubkey: receiver_script,
            },
        ],
    };

    // Create PSBT and set up taproot script path signing
    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx)?;
    let input = &mut psbt.inputs[0];

    // Set witness UTXO
    input.witness_utxo = Some(TxOut {
        amount: bitcoin::Amount::from_sat(funding_utxo.value)?,
        script_pubkey: funding_utxo.funding.funding_script_pubkey(),
    });

    // Find the cooperative script leaf (2-of-2 multisig)
    let (cooperative_script_miniscript, control_block_miniscript) = funding_utxo
        .funding
        .spend_info
        .leaves()
        .find(|leaf| {
            let script = leaf.script();
            script.as_bytes() == funding_utxo.funding.cooperative_script.as_bytes()
        })
        .map(|leaf| (leaf.script().to_owned(), leaf.control_block().clone()))
        .ok_or_else(|| anyhow::anyhow!("Cooperative script leaf not found in taproot tree"))?;

    // Convert miniscript types to bitcoin types
    let script_bytes = cooperative_script_miniscript.as_bytes();
    let cooperative_script = bitcoin::script::TapScriptBuf::from_bytes(script_bytes.to_vec());
    let control_block_bytes = control_block_miniscript.serialize();
    let control_block = bitcoin::taproot::ControlBlock::decode(&control_block_bytes)
        .map_err(|_| anyhow::anyhow!("Failed to convert control block"))?;

    input.tap_scripts = {
        let mut map = BTreeMap::new();
        map.insert(control_block.clone(), (cooperative_script.clone(), LeafVersion::TapScript));
        map
    };

    let leaf_hash: TapLeafHash =
        ScriptPath::new(&cooperative_script, LeafVersion::TapScript).into();

    input.tap_key_origins = {
        let mut map = BTreeMap::new();
        map.insert(
            funding_utxo.funding.sender_pubkey,
            (vec![leaf_hash], (Fingerprint::from([0u8; 4]), DerivationPath::master())),
        );
        map.insert(
            funding_utxo.funding.receiver_pubkey,
            (vec![leaf_hash], (Fingerprint::from([0u8; 4]), DerivationPath::master())),
        );
        map
    };

    input.tap_internal_key = Some(funding_utxo.funding.spend_info.internal_key());

    if let Some(merkle_root_miniscript) = funding_utxo.funding.spend_info.merkle_root() {
        use miniscript::bitcoin::hashes::Hash as MiniscriptHash;
        let merkle_root_bytes = *MiniscriptHash::as_byte_array(&merkle_root_miniscript);
        let merkle_root = bitcoin::TapNodeHash::from_byte_array(merkle_root_bytes);
        input.tap_merkle_root = Some(merkle_root);
    }
    input.sighash_type = Some(PsbtSighashType::from(bitcoin::sighash::TapSighashType::Default));

    // Sign with both sender and receiver keys
    let sender_sk = bitcoin::secp256k1::SecretKey::from_secret_bytes([1u8; 32])
        .expect("32-byte array should always be a valid SecretKey");
    let receiver_sk = bitcoin::secp256k1::SecretKey::from_secret_bytes([2u8; 32])
        .expect("32-byte array should always be a valid SecretKey");

    struct KeyStore {
        sender: PrivateKey,
        receiver: PrivateKey,
        sender_pubkey: bitcoin::key::XOnlyPublicKey,
        receiver_pubkey: bitcoin::key::XOnlyPublicKey,
    }
    impl GetKey for KeyStore {
        type Error = bitcoin::psbt::SignError;
        fn get_key(
            &self,
            key_request: &KeyRequest,
        ) -> std::result::Result<Option<PrivateKey>, Self::Error> {
            match key_request {
                KeyRequest::XOnlyPubkey(xonly) if *xonly == self.sender_pubkey =>
                    Ok(Some(self.sender)),
                KeyRequest::XOnlyPubkey(xonly) if *xonly == self.receiver_pubkey =>
                    Ok(Some(self.receiver)),
                _ => Ok(None),
            }
        }
    }

    let keystore = KeyStore {
        sender: PrivateKey::new(sender_sk, Network::Regtest),
        receiver: PrivateKey::new(receiver_sk, Network::Regtest),
        sender_pubkey: funding_utxo.funding.sender_pubkey,
        receiver_pubkey: funding_utxo.funding.receiver_pubkey,
    };
    psbt.sign(&keystore)
        .map_err(|(_, errors)| anyhow::anyhow!("PSBT signing failed: {:?}", errors))?;

    // Finalize the input
    psbt.inputs[0].finalize_taproot_script_path_input();
    let signed_tx = psbt.extract_tx()?;

    let mut tx_bytes = Vec::new();
    signed_tx.consensus_encode(&mut tx_bytes)?;
    let hex = hex::encode(&tx_bytes);

    println!("Settlement transaction signed and finalized");

    let txid_resp = client.send_raw_transaction(hex, None, None).await?;
    let txid_str = txid_resp.value.clone();
    println!("Settlement transaction broadcasted! TXID: {}", txid_str);

    // Convert bitcoin::Address to RPC client's Address type
    let block_reward_address_str = block_reward_address.to_string();
    let block_reward_address_rpc_unchecked =
        bitcoin_core_client_rpc_30_0_0::Address::from_str(&block_reward_address_str)?;
    let block_reward_address_rpc = block_reward_address_rpc_unchecked.assume_checked();
    let _generate_result =
        client.generate_to_address(1, block_reward_address_rpc.clone(), Some(2000)).await?;

    // Convert bitcoin::Txid to RPC client's Txid type
    let txid_rpc: bitcoin_core_client_rpc_30_0_0::Txid = txid_str.parse()?;
    let tx_hex_resp = client.get_raw_transaction(txid_rpc, Some(0), None).await?;
    // Also parse into bitcoin::Txid for later use
    let _txid_parsed: bitcoin::Txid = txid_str.parse()?;
    let tx_hex = tx_hex_resp.value;

    let decoded_tx = client.decode_raw_transaction(tx_hex, None).await?;

    let mut total_input: u64 = 0;
    let mut found_funding_utxo = false;
    if let Some(vins) = decoded_tx.vin.as_array() {
        for vin in vins {
            if let Some(txid_in_str) = vin["txid"].as_str() {
                if let Some(vout_in) = vin["vout"].as_u64() {
                    let prev_txid_parsed: bitcoin::Txid = txid_in_str.parse()?;

                    if prev_txid_parsed == funding_utxo.txid && vout_in == funding_utxo.vout as u64
                    {
                        found_funding_utxo = true;
                        println!(
                            "✓ Settlement transaction uses channel funding UTXO (txid={}, vout={})",
                            funding_utxo.txid, funding_utxo.vout
                        );
                    }

                    // Convert bitcoin::Txid to RPC client's Txid type
                    let prev_txid_rpc: bitcoin_core_client_rpc_30_0_0::Txid =
                        txid_in_str.parse()?;
                    let prev_tx_hex_resp =
                        client.get_raw_transaction(prev_txid_rpc, Some(0), None).await?;
                    let prev_tx_hex = prev_tx_hex_resp.value;
                    let prev_decoded = client.decode_raw_transaction(prev_tx_hex, None).await?;
                    if let Some(outputs) = prev_decoded.vout.as_array() {
                        if let Some(output) = outputs.get(vout_in as usize) {
                            if let Some(value) = output["value"].as_f64() {
                                total_input += (value * 100_000_000.0) as u64;
                            }
                        }
                    }
                }
            }
        }
    }

    if !found_funding_utxo {
        println!("⚠ Warning: Settlement transaction did not use the channel funding UTXO");
        println!("  Expected: txid={}, vout={}", funding_utxo.txid, funding_utxo.vout);
    }

    let mut total_output: u64 = 0;
    if let Some(vouts) = decoded_tx.vout.as_array() {
        for vout in vouts {
            if let Some(value) = vout["value"].as_f64() {
                total_output += (value * 100_000_000.0) as u64;
            }
        }
    }

    let fee = total_input - total_output;
    println!("Settlement transaction fee: {} sats", format_number(fee));

    // Get current balances using list_unspent (same method as initial balance calculation)
    let sender_utxos_resp = client
        .list_unspent(
            Some(0),
            Some(9999999),
            Some(vec![serde_json::json!(wallet_info.sender_address_str.clone())]),
            Some(true),
            None,
        )
        .await?;
    let sender_utxos: Vec<serde_json::Value> = sender_utxos_resp.value;
    let mut final_sender_balance_sats = 0u64;
    for utxo in &sender_utxos {
        if let Some(amount) = utxo["amount"].as_f64() {
            final_sender_balance_sats += (amount * 100_000_000.0) as u64;
        }
    }

    let receiver_utxos_resp = client
        .list_unspent(
            Some(0),
            Some(9999999),
            Some(vec![serde_json::json!(wallet_info.receiver_address_str.clone())]),
            Some(true),
            None,
        )
        .await?;
    let receiver_utxos: Vec<serde_json::Value> = receiver_utxos_resp.value;
    let mut final_receiver_balance_sats = 0u64;
    for utxo in &receiver_utxos {
        if let Some(amount) = utxo["amount"].as_f64() {
            final_receiver_balance_sats += (amount * 100_000_000.0) as u64;
        }
    }

    println!("\n=== Final Balances ===");
    println!("Sender final balance: {} sats", format_number(final_sender_balance_sats));
    println!("Receiver final balance: {} sats", format_number(final_receiver_balance_sats));
    println!(
        "\nSettlement transaction fees ({} sats) were deducted from inputs",
        format_number(fee)
    );

    Ok(())
}

#[tokio::test]
async fn e2e() -> Result<()> {
    println!("\n=== Starting E2E Channel-BTX Test ===");

    let config = TestConfig::default();
    let node_manager = BitcoinNodeManager::new_with_config(&config)?;
    node_manager.start().await?;
    let client: Arc<DefaultTransport> = node_manager.create_transport().await?;

    let _node_manager_guard = node_manager;

    let wallet_info = setup_bitcoin_wallet_and_fund(&client).await?;

    let funding_utxo = create_channel_funding_transaction(
        &client,
        &wallet_info,
        &wallet_info.block_reward_address,
    )
    .await?;

    let channel_id: ChannelId = [1u8; 32];
    let (initial_channel_state, channel_commitment, sender_sk) =
        create_channel(channel_id, &funding_utxo);

    let zkp_config = create_config().expect("Should create ZKP config");
    let test_wallet_id: WalletId = [0u8; 32];

    prove_and_verify_global_state(
        &zkp_config,
        test_wallet_id,
        channel_id,
        channel_commitment,
        "Global ZKP: Proving Initial Channel State",
    )?;

    let final_channel_state =
        perform_channel_transfers(&initial_channel_state, &zkp_config, channel_id, &sender_sk)?;

    let closed_channel_state = close_channel(&final_channel_state, channel_id, &zkp_config)?;

    let final_channel_commitment =
        compute_cooperative_closing_commitment(channel_id, &closed_channel_state);

    prove_and_verify_global_state(
        &zkp_config,
        test_wallet_id,
        channel_id,
        final_channel_commitment,
        "Global ZKP: Proving Final Channel State",
    )?;

    create_and_broadcast_settlement_transaction(
        &client,
        &closed_channel_state,
        &funding_utxo,
        &wallet_info,
        &wallet_info.block_reward_address,
    )
    .await?;

    println!("\n=== E2E Test Completed Successfully ===");

    Ok(())
}
