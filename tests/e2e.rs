//! End-to-end test: Bitcoin regtest wallet funding, channel operations, and on-chain settlement

use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::Result;
use bitcoin::address::NetworkUnchecked;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::SecretKey;
use bitcoin_core_client_rpc_30_0_0::node::NodeManager;
use bitcoin_core_client_rpc_30_0_0::{
    BitcoinClientV30_0_0, BitcoinNodeManager, DefaultTransport, TestConfig,
};
use merkle_morph::btx::state::{BitcoinTransaction, Utxo};
use merkle_morph::channel::commitment::{
    compute_cooperative_closing_commitment, compute_open_commitment,
};
use merkle_morph::channel::state::{CooperativeClosing, Open};
use merkle_morph::channel::{
    apply_cooperative_close, apply_transfer, calculate_close_outputs, TransferAmount,
};
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

/// Wallet funding information
struct WalletFundingInfo {
    sender_address_str: String,
    sender_address: bitcoin::Address<NetworkUnchecked>,
    receiver_address_str: String,
    receiver_address: bitcoin::Address<NetworkUnchecked>,
    block_reward_address: bitcoin::Address,
    wallet_balance_sats: u64,
}

/// Channel funding UTXO information
struct ChannelFundingUtxo {
    txid: bitcoin::Txid,
    vout: u32,
    value: u64,
    address: bitcoin::Address<NetworkUnchecked>,
}

async fn setup_bitcoin_wallet_and_fund(
    client: &Arc<DefaultTransport>,
) -> Result<WalletFundingInfo> {
    println!("\n=== Creating and Funding Wallets ===");

    let wallet_name = "test_wallet";
    match client.load_wallet(wallet_name.to_string(), None).await {
        Ok(_) => println!("Loaded existing wallet: {}", wallet_name),
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
            println!("Created new wallet: {}", wallet_name);
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
    println!("Block reward address: {}", block_reward_address_str);

    let sender_addr: bitcoin::Address = sender_address.clone().assume_checked();
    let _generate_result = client.generate_to_address(101, sender_addr, Some(2000)).await?;

    let block_reward_addr_unchecked: bitcoin::Address<NetworkUnchecked> =
        block_reward_address_str.parse().expect("valid address");
    let block_reward_addr: bitcoin::Address = block_reward_addr_unchecked.assume_checked();
    let block_reward_addr_for_return = block_reward_addr.clone();
    let _generate_result = client.generate_to_address(1, block_reward_addr, Some(2000)).await?;

    let sender_balance_resp = client
        .get_received_by_address(sender_address.clone().assume_checked(), Some(0), Some(false))
        .await?;
    let sender_balance = sender_balance_resp.value;
    let sender_balance_sats = (sender_balance * 100_000_000.0) as u64;
    println!("Sender initial balance (received): {} sats", format_number(sender_balance_sats));

    let wallet_balance_resp =
        client.get_balance(Some("*".to_string()), Some(0), Some(false), None).await?;
    let wallet_balance = wallet_balance_resp.value;
    let wallet_balance_sats = (wallet_balance * 100_000_000.0) as u64;
    println!("Sender wallet spendable balance: {} sats", format_number(wallet_balance_sats));

    Ok(WalletFundingInfo {
        sender_address_str,
        sender_address,
        receiver_address_str,
        receiver_address,
        block_reward_address: block_reward_addr_for_return,
        wallet_balance_sats,
    })
}

async fn create_channel_funding_transaction(
    client: &Arc<DefaultTransport>,
    wallet_info: &WalletFundingInfo,
    block_reward_address: &bitcoin::Address,
) -> Result<ChannelFundingUtxo> {
    println!("\n=== Creating Channel Funding Transaction ===");

    // Limit to 2 BTC to stay within BabyBear's 31-bit field range
    let max_channel_balance = wallet_info.wallet_balance_sats.saturating_sub(10_000_000);
    let initial_channel_balance = if max_channel_balance > 200_000_000 {
        200_000_000u64
    } else if max_channel_balance > 10_000_000 {
        max_channel_balance
    } else {
        anyhow::bail!(
            "Insufficient wallet balance: {} sats (need at least 0.11 BTC for channel funding)",
            format_number(wallet_info.wallet_balance_sats)
        );
    };
    println!(
        "Planned channel funding amount: {} sats ({} BTC)",
        format_number(initial_channel_balance),
        initial_channel_balance as f64 / 100_000_000.0
    );

    let wallet_balance_check =
        client.get_balance(Some("*".to_string()), Some(0), Some(false), None).await?;
    let wallet_balance_check_sats = (wallet_balance_check.value * 100_000_000.0) as u64;
    let required_amount = initial_channel_balance + 10_000_000;
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

    let mut total_utxo_value = 0u64;
    for utxo in &utxos {
        if let Some(amount) = utxo["amount"].as_f64() {
            total_utxo_value += (amount * 100_000_000.0) as u64;
        }
    }
    println!(
        "Available UTXOs: {} UTXOs, total value: {} sats",
        utxos.len(),
        format_number(total_utxo_value)
    );

    let channel_funding_address_resp =
        client.get_new_address(Some("".to_string()), Some("bech32m".to_string())).await?;
    let channel_funding_address_str = channel_funding_address_resp.value.clone();
    let channel_funding_address: bitcoin::Address<NetworkUnchecked> =
        channel_funding_address_str.parse().expect("valid address");
    println!("Channel funding address: {}", channel_funding_address_str);

    let channel_funding_amount = initial_channel_balance as f64 / 100_000_000.0;
    let funding_outputs =
        vec![serde_json::json!({ channel_funding_address_str.clone(): channel_funding_amount })];

    let funding_psbt_options = serde_json::json!({
        "feeRate": 0.0001,
        "includeWatching": true,
        "lockUnspents": false,
        "replaceable": false,
    });

    let funding_response = client
        .wallet_create_funded_psbt(
            Some(vec![]),
            funding_outputs,
            Some(0),
            Some(funding_psbt_options),
            Some(false),
            None,
        )
        .await?;
    let funding_psbt = funding_response.psbt;

    let signed_funding_resp = client
        .wallet_process_psbt(
            funding_psbt,
            Some(true),
            Some("ALL".to_string()),
            Some(true),
            Some(true),
        )
        .await?;
    let signed_funding_psbt = signed_funding_resp.psbt;

    let finalized_funding_resp = client.finalize_psbt(signed_funding_psbt, Some(true)).await?;
    let funding_hex = finalized_funding_resp
        .hex
        .ok_or_else(|| anyhow::anyhow!("Failed to get hex from finalized funding PSBT"))?;

    let funding_txid_resp = client.send_raw_transaction(funding_hex, None, None).await?;
    let funding_txid_str = funding_txid_resp.value.clone();
    println!("Channel funding transaction broadcasted! TXID: {}", funding_txid_str);

    let _generate_result =
        client.generate_to_address(1, block_reward_address.clone(), Some(2000)).await?;
    println!("Block mined to confirm funding transaction");

    let funding_txid_parsed = funding_txid_str.parse::<bitcoin::Txid>()?;
    let funding_tx_hex_resp =
        client.get_raw_transaction(funding_txid_parsed, Some(0), None).await?;
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
                    println!(
                        "Channel-funding UTXO: txid={}, vout={}, amount={} sats",
                        channel_funding_utxo_txid,
                        channel_funding_utxo_vout,
                        format_number(channel_funding_utxo_value)
                    );
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

    Ok(ChannelFundingUtxo {
        txid: channel_funding_utxo_txid,
        vout: channel_funding_utxo_vout,
        value: channel_funding_utxo_value,
        address: channel_funding_address,
    })
}

fn create_channel(
    channel_id: ChannelId,
    funding_utxo: &ChannelFundingUtxo,
) -> (Open, ChannelCommitment, SecretKey) {
    println!("\n=== Creating Channel from Channel-Funding Transaction ===");

    // Generate test keys for channel participants
    use bitcoin::secp256k1::{Secp256k1, SecretKey, XOnlyPublicKey};
    let secp = Secp256k1::new();
    let sender_sk = SecretKey::from_slice(&[1u8; 32])
        .expect("32-byte array should always be a valid SecretKey");
    let receiver_sk = SecretKey::from_slice(&[2u8; 32])
        .expect("32-byte array should always be a valid SecretKey");
    let sender_pubkey = XOnlyPublicKey::from_keypair(&sender_sk.keypair(&secp)).0;
    let receiver_pubkey = XOnlyPublicKey::from_keypair(&receiver_sk.keypair(&secp)).0;

    let sender_revocation_secret =
        SecretKey::from_slice(&[3u8; 32]).expect("valid sender revocation secret");
    let receiver_revocation_secret =
        SecretKey::from_slice(&[4u8; 32]).expect("valid receiver revocation secret");
    let initial_channel_state = Open::new(
        sender_pubkey,
        receiver_pubkey,
        funding_utxo.value,
        sender_revocation_secret,
        receiver_revocation_secret,
    );
    let channel_commitment = compute_open_commitment(channel_id, &initial_channel_state);
    println!("Channel ID: {:?}", channel_id);
    println!(
        "Initial channel state: sender={}, receiver={}",
        format_number(initial_channel_state.sender_balance),
        format_number(initial_channel_state.receiver_balance)
    );
    println!("Channel commitment: {:?}", channel_commitment);
    println!(
        "Channel created using channel-funding UTXO: txid={}, vout={}, amount={} sats",
        funding_utxo.txid,
        funding_utxo.vout,
        format_number(funding_utxo.value)
    );

    (initial_channel_state, channel_commitment, sender_sk)
}

fn perform_channel_transfers(
    initial_state: &Open,
    zkp_config: &merkle_morph::zkp::types::StarkConfig,
    channel_id: ChannelId,
    sender_sk: &SecretKey,
) -> Result<Open> {
    println!("\n=== Unidirectional State Channel Transfers ===");

    let transfer1_amount = TransferAmount::new(30_000_000)?;
    let transfer1_result =
        apply_transfer(channel_id, initial_state, &transfer1_amount, sender_sk, zkp_config)?;

    println!("Transfer 1: {} sats from sender to receiver", format_number(*transfer1_amount));
    println!(
        "  New state: sender={}, receiver={}, nonce={}",
        format_number(transfer1_result.new_state.sender_balance),
        format_number(transfer1_result.new_state.receiver_balance),
        transfer1_result.new_state.nonce
    );

    let transfer2_amount = TransferAmount::new(20_000_000)?;
    let transfer2_result = apply_transfer(
        channel_id,
        &transfer1_result.new_state,
        &transfer2_amount,
        sender_sk,
        zkp_config,
    )?;

    println!("Transfer 2: {} sats from sender to receiver", format_number(*transfer2_amount));
    println!(
        "  New state: sender={}, receiver={}, nonce={}",
        format_number(transfer2_result.new_state.sender_balance),
        format_number(transfer2_result.new_state.receiver_balance),
        transfer2_result.new_state.nonce
    );

    let final_channel_state = transfer2_result.new_state;
    println!(
        "Final channel state: sender={}, receiver={}",
        format_number(final_channel_state.sender_balance),
        format_number(final_channel_state.receiver_balance)
    );

    Ok(final_channel_state)
}

fn close_channel(channel_state: &Open) -> Result<CooperativeClosing> {
    println!("\n=== Closing Channel and Creating Settlement Transactions ===");

    // Use cooperative close to transition from Open to CooperativeClosing
    let channel_id = [0u8; 32]; // Dummy channel_id for closing
    let estimated_fee = 1000u64;
    let closing_state = apply_cooperative_close(channel_state, estimated_fee, channel_id)?;

    println!(
        "Channel closed. Final balances: sender={}, receiver={}, total_fee={}",
        format_number(closing_state.sender_balance),
        format_number(closing_state.receiver_balance),
        format_number(closing_state.total_fee)
    );

    Ok(closing_state)
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
    println!("Wallet ID: {:?}", wallet_id);
    println!("Wallet commitment: {:?}", wallet_commitment);

    let mut wallet_commitments = BTreeMap::new();
    wallet_commitments.insert(wallet_id, wallet_commitment);

    let subtree = compute_subtree_root(config, &wallet_commitments, wallet_id, wallet_id)?;
    println!("Subtree root: {:?}", subtree.root);
    println!("Subtree wallet ID range: {:?}", subtree.wallet_id_range);

    let global_root = compose_to_global_root(std::slice::from_ref(&subtree))?;
    println!("Global root: {:?}", global_root);

    let global_state = GlobalState::with_root_and_nonce(global_root, 0);
    println!("Global state created with root and nonce=0");

    println!("Generating ZKP proof for global root composition...");
    let proof = prove_global_root_composition(config, &[subtree])?;
    println!("✓ ZKP proof generated successfully");

    println!("Verifying ZKP proof...");
    verify_global_root_composition(config, global_state.wallets_root, &proof)?;
    println!("✓ ZKP proof verified successfully");

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

    let channel_funding_utxo_obj = Utxo::new(
        funding_utxo.txid,
        funding_utxo.vout,
        funding_utxo.value,
        funding_utxo.address.clone(),
    );

    let sender_output = Utxo::new(
        bitcoin::Txid::from_byte_array([0u8; 32]),
        0,
        closed_state.sender_balance,
        wallet_info.sender_address.clone(),
    );

    let receiver_output = Utxo::new(
        bitcoin::Txid::from_byte_array([0u8; 32]),
        0,
        closed_state.receiver_balance,
        wallet_info.receiver_address.clone(),
    );

    let estimated_fee = 1000u64;
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
            wallet_info.sender_address.clone(),
        );
        settlement_outputs.push(change_output.clone());
        println!(
            "  Expected change output: {} sats back to sender",
            format_number(expected_change)
        );
    }

    let settlement_tx =
        BitcoinTransaction::new(vec![channel_funding_utxo_obj.clone()], settlement_outputs.clone());

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

    if !settlement_tx.is_valid() {
        anyhow::bail!(
            "Settlement transaction is invalid: inputs ({}) < outputs ({})",
            format_number(channel_funding_utxo_obj.value),
            format_number(
                total_outputs + if expected_change > dust_threshold { expected_change } else { 0 }
            )
        );
    }
    println!("Settlement transaction passes basic validation (inputs >= outputs + fees)");

    println!("\n=== Creating and Broadcasting Settlement Transaction ===");

    let estimated_fee_sats = 2000u64;
    let available_for_outputs = funding_utxo.value.saturating_sub(estimated_fee_sats);

    let total_desired_outputs = closed_state.sender_balance + closed_state.receiver_balance;

    let (sender_output_sats, receiver_output_sats) = calculate_close_outputs(
        closed_state.sender_balance,
        closed_state.receiver_balance,
        estimated_fee_sats,
    )?;

    let total_outputs_after_fees = sender_output_sats + receiver_output_sats;
    if total_outputs_after_fees > available_for_outputs {
        let actual_available = funding_utxo.value.saturating_sub(total_desired_outputs);
        if actual_available < estimated_fee_sats {
            println!(
                "  Warning: Fee estimate ({} sats) may be insufficient. Available after outputs: {} sats",
                format_number(estimated_fee_sats),
                format_number(actual_available)
            );
        }
    }

    println!(
        "  Original balances: sender={}, receiver={}",
        format_number(closed_state.sender_balance),
        format_number(closed_state.receiver_balance)
    );
    println!(
        "  Outputs after fee deduction: sender={}, receiver={}",
        format_number(sender_output_sats),
        format_number(receiver_output_sats)
    );

    let sender_output_amount = sender_output_sats as f64 / 100_000_000.0;
    let receiver_output_amount = receiver_output_sats as f64 / 100_000_000.0;

    let outputs = vec![
        serde_json::json!({ wallet_info.sender_address_str.clone(): sender_output_amount }),
        serde_json::json!({ wallet_info.receiver_address_str.clone(): receiver_output_amount }),
    ];

    let inputs = vec![serde_json::json!({
        "txid": funding_utxo.txid.to_string(),
        "vout": funding_utxo.vout
    })];

    let psbt_options = serde_json::json!({
        "feeRate": 0.0001,
        "includeWatching": true,
        "lockUnspents": false,
        "replaceable": false,
    });

    // Retry logic with exponential backoff for intermittent connection issues
    let max_retries = 3;
    let mut last_error = None;
    let mut response_opt = None;

    for attempt in 0..max_retries {
        match client
            .wallet_create_funded_psbt(
                Some(inputs.clone()),
                outputs.clone(),
                Some(0),
                Some(psbt_options.clone()),
                Some(false),
                None,
            )
            .await
        {
            Ok(resp) => {
                response_opt = Some(resp);
                break;
            }
            Err(e) => {
                last_error = Some(e);
                if attempt < max_retries - 1 {
                    let delay_ms = 100 * (attempt + 1);
                    tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                }
            }
        }
    }

    let response = response_opt.ok_or_else(|| {
        anyhow::anyhow!(
            "Failed to call wallet_create_funded_psbt after {} attempts: {:?}",
            max_retries,
            last_error
        )
    })?;
    let psbt = response.psbt;

    println!("Created PSBT for settlement transaction");

    let signed_resp = client
        .wallet_process_psbt(psbt, Some(true), Some("ALL".to_string()), Some(true), Some(true))
        .await?;
    let signed_psbt = signed_resp.psbt;

    let finalized_resp = client.finalize_psbt(signed_psbt, Some(true)).await?;
    let hex = finalized_resp
        .hex
        .ok_or_else(|| anyhow::anyhow!("Failed to get hex from finalized PSBT"))?;

    println!("Settlement transaction finalized");

    let txid_resp = client.send_raw_transaction(hex, None, None).await?;
    let txid_str = txid_resp.value.clone();
    println!("Settlement transaction broadcasted! TXID: {}", txid_str);

    let _generate_result =
        client.generate_to_address(1, block_reward_address.clone(), Some(2000)).await?;
    println!("Block mined to confirm settlement transaction");

    let txid_parsed = txid_str.parse::<bitcoin::Txid>()?;
    let tx_hex_resp = client.get_raw_transaction(txid_parsed, Some(0), None).await?;
    let tx_hex = tx_hex_resp.value;

    let decoded_tx = client.decode_raw_transaction(tx_hex, None).await?;

    let mut total_input: u64 = 0;
    let mut found_funding_utxo = false;
    if let Some(vins) = decoded_tx.vin.as_array() {
        for vin in vins {
            if let Some(txid_in_str) = vin["txid"].as_str() {
                if let Some(vout_in) = vin["vout"].as_u64() {
                    let prev_txid = txid_in_str.parse::<bitcoin::Txid>()?;

                    if prev_txid == funding_utxo.txid && vout_in == funding_utxo.vout as u64 {
                        found_funding_utxo = true;
                        println!(
                            "✓ Settlement transaction uses channel funding UTXO (txid={}, vout={})",
                            funding_utxo.txid, funding_utxo.vout
                        );
                    }

                    let prev_tx_hex_resp =
                        client.get_raw_transaction(prev_txid, Some(0), None).await?;
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

    let final_sender_balance_resp = client
        .get_received_by_address(
            wallet_info.sender_address.clone().assume_checked(),
            Some(0),
            Some(false),
        )
        .await?;
    let final_sender_balance = final_sender_balance_resp.value;
    let final_sender_balance_sats = (final_sender_balance * 100_000_000.0) as u64;
    let final_receiver_balance_resp = client
        .get_received_by_address(
            wallet_info.receiver_address.clone().assume_checked(),
            Some(0),
            Some(false),
        )
        .await?;
    let final_receiver_balance = final_receiver_balance_resp.value;
    let final_receiver_balance_sats = (final_receiver_balance * 100_000_000.0) as u64;

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

    let closed_channel_state = close_channel(&final_channel_state)?;

    let final_channel_commitment =
        compute_cooperative_closing_commitment(channel_id, &closed_channel_state);

    prove_and_verify_global_state(
        &zkp_config,
        test_wallet_id,
        channel_id,
        final_channel_commitment,
        "Global ZKP: Proving Final (Closed) Channel State",
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
