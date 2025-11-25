//! Trace generation for subtree root validity proofs
//!
//! This module provides functions for generating execution traces
//! for subtree root validity proofs. The trace represents the SMT
//! building process from start_depth to max_depth.

use std::collections::BTreeMap;

use p3_baby_bear::{GenericPoseidon2LinearLayersBabyBear, Poseidon2BabyBear};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_poseidon2_air::generate_trace_rows;
use p3_symmetric::Permutation;

use crate::global::commitment::{build_smt_node_with, MerkleMorphV0Config, Poseidon2Hasher};
use crate::global::get_bit_at_depth;
use crate::global::smt::{SmtConfig, SmtHasher};
use crate::types::{WalletCommitment, WalletId};
use crate::zkp::poseidon2_common::{
    poseidon2_air_num_cols, Poseidon2Constants, POSEIDON2_HALF_FULL_ROUNDS, POSEIDON2_OUTPUT_SIZE,
    POSEIDON2_PARTIAL_ROUNDS, POSEIDON2_RATE, POSEIDON2_SBOX_DEGREE, POSEIDON2_SBOX_REGISTERS,
    POSEIDON2_WIDTH,
};
use crate::zkp::subtree::poseidon2_air::{column_offsets, create_poseidon2_constants_and_params};
use crate::zkp::types::{bytes32_to_fields, Trace, Val};
use crate::{Bytes32, Result};

/// Type alias for zero traces tuple to reduce type complexity
type ZeroTraces = (Vec<Vec<Val>>, Vec<Vec<Val>>);

/// Represents a single SMT node in the trace
#[derive(Clone, Debug)]
enum SMTNode {
    /// Leaf node with wallet ID and commitment
    Leaf {
        wallet_id: WalletId,
        wallet_commitment: WalletCommitment,
        depth: u8,
        computed_root: Bytes32,
    },
    /// Internal node with left and right children
    Internal { left_child: Bytes32, right_child: Bytes32, depth: u8, computed_root: Bytes32 },
}

/// Build trace matrix for subtree root validity proof
///
/// The trace contains multiple rows (one per SMT node, padded to power-of-2).
///
/// # Trace Structure
///
/// Each row represents one SMT node (leaf or internal) with the following column layout:
/// * Columns 0-7: wallet_id (leaf nodes only, 8 fields)
/// * Columns 8-15: wallet_commitment (leaf nodes only, 8 fields)
/// * Columns 16-23: left_child_root (internal nodes, 8 fields)
/// * Columns 24-31: right_child_root (internal nodes, 8 fields)
/// * Columns 32-39: computed_root (8 fields)
/// * Columns 40-47: depth (1 field, rest padding)
/// * Columns 48+: Poseidon2 AIR columns for leaf/internal node hashing
///
/// Padding rows after the last node have zero values and stable computed_root.
pub(super) fn build_subtree_trace(
    wallet_commitments: &BTreeMap<WalletId, WalletCommitment>,
    min_id: WalletId,
    max_id: WalletId,
    start_depth: u8,
) -> Result<Trace> {
    let total_cols = column_offsets::total_cols();
    const MIN_ROWS: usize = 8; // Minimum rows needed (power of 2)

    let mut filtered = BTreeMap::new();
    for (id, comm) in wallet_commitments.iter() {
        if *id >= min_id && *id <= max_id {
            filtered.insert(*id, *comm);
        }
    }

    let hasher = Poseidon2Hasher;
    let config = MerkleMorphV0Config;
    let nodes = collect_smt_nodes(&filtered, start_depth, &hasher, &config)?;

    if nodes.is_empty() {
        let num_rows = MIN_ROWS;
        let mut values = Vec::with_capacity(num_rows * total_cols);

        let constants = create_poseidon2_constants_and_params();
        let zero = hasher.zero_hash();

        let (internal_zero_traces, leaf_zero_traces) =
            generate_zero_traces(&config, &constants, zero)?;

        let first_row =
            create_zero_padding_row(total_cols, zero, &internal_zero_traces, &leaf_zero_traces)?;

        (0..num_rows).for_each(|_| {
            values.extend_from_slice(&first_row);
        });

        return Ok(RowMajorMatrix::new(values, total_cols));
    }

    let expected_root =
        build_smt_node_with(&filtered, start_depth, &Poseidon2Hasher, &MerkleMorphV0Config);

    if let Some(first_node) = nodes.first() {
        let computed_root = match first_node {
            SMTNode::Internal { computed_root, depth, .. } => {
                if *depth != start_depth {
                    return Err(crate::Error::Zkp(crate::errors::ZkpError::TraceGenerationFailed(
                        format!(
                            "First node depth {} does not match start_depth {}",
                            depth, start_depth
                        ),
                    )));
                }
                *computed_root
            }
            SMTNode::Leaf { computed_root, depth, .. } => {
                if *depth != start_depth {
                    return Err(crate::Error::Zkp(crate::errors::ZkpError::TraceGenerationFailed(
                        format!(
                            "First node depth {} does not match start_depth {}",
                            depth, start_depth
                        ),
                    )));
                }
                *computed_root
            }
        };

        if computed_root != expected_root {
            return Err(crate::Error::Zkp(crate::errors::ZkpError::TraceGenerationFailed(
                format!(
                    "Root mismatch at start_depth {}: collect_smt_nodes computed {:?}, build_smt_node_with computed {:?}",
                    start_depth, computed_root, expected_root
                ),
            )));
        }
    } else {
        return Err(crate::Error::Zkp(crate::errors::ZkpError::TraceGenerationFailed(
            "No nodes collected from non-empty subtree".to_string(),
        )));
    }

    let constants = create_poseidon2_constants_and_params();

    let mut values = Vec::with_capacity(nodes.len().max(MIN_ROWS) * total_cols);

    for node in &nodes {
        let row = build_node_row(node, &constants, &config)?;
        values.extend_from_slice(&row);
    }

    let current_rows = values.len() / total_cols;
    let num_rows = current_rows.max(MIN_ROWS).next_power_of_two();
    // Ensure we always have at least one padding row so the last row has the correct root
    // This is necessary because the constraint checks the root on the last row
    let num_rows = if num_rows == current_rows { num_rows * 2 } else { num_rows };
    let num_padding = num_rows - current_rows;

    if num_padding > 0 && current_rows > 0 {
        // Use the expected_root directly for padding rows to ensure consistency
        // This is the root that was verified to match the first node
        let zero = hasher.zero_hash();
        let (internal_zero_traces, leaf_zero_traces) =
            generate_zero_traces(&config, &constants, zero)?;

        for _ in 0..num_padding {
            let padding_row = create_zero_padding_row(
                total_cols,
                expected_root,
                &internal_zero_traces,
                &leaf_zero_traces,
            )?;
            values.extend_from_slice(&padding_row);
        }
    } else if num_padding > 0 {
        let padding_row = vec![Val::ZERO; total_cols];
        for _ in 0..num_padding {
            values.extend_from_slice(&padding_row);
        }
    }

    Ok(RowMajorMatrix::new(values, total_cols))
}

/// Split wallets by their bit value at the given depth
fn split_wallets_by_depth(
    wallet_commitments: &BTreeMap<WalletId, WalletCommitment>,
    depth: u8,
) -> (BTreeMap<WalletId, WalletCommitment>, BTreeMap<WalletId, WalletCommitment>) {
    let mut left_wallets = BTreeMap::new();
    let mut right_wallets = BTreeMap::new();

    for (wallet_id, wallet_commitment) in wallet_commitments.iter() {
        let bit_value = get_bit_at_depth(wallet_id, depth);
        if bit_value == 0 {
            left_wallets.insert(*wallet_id, *wallet_commitment);
        } else {
            right_wallets.insert(*wallet_id, *wallet_commitment);
        }
    }

    (left_wallets, right_wallets)
}

/// Build SMT and collect all nodes in depth-first order
///
/// # Invariant
/// At any depth d (including max_depth), if multiple wallets exist, they must be split by their
/// bit at depth d BEFORE checking termination conditions. The termination check (single wallet
/// at max_depth) applies AFTER the split operation. This ensures wallets differing only at
/// max_depth can be correctly processed.
fn collect_smt_nodes(
    wallet_commitments: &BTreeMap<WalletId, WalletCommitment>,
    depth: u8,
    hasher: &Poseidon2Hasher,
    config: &MerkleMorphV0Config,
) -> Result<Vec<SMTNode>> {
    let max_depth = config.max_depth();
    let mut nodes = Vec::new();

    if wallet_commitments.is_empty() {
        return Ok(nodes);
    }

    // Split wallets by their bit at this depth FIRST, before checking termination conditions
    // This ensures wallets differing only at max_depth can still be split correctly
    let (left_wallets, right_wallets) = split_wallets_by_depth(wallet_commitments, depth);

    // After splitting, check if we're at max_depth
    if depth == max_depth {
        // At max_depth, after splitting, each branch should have at most one wallet
        if left_wallets.len() > 1 || right_wallets.len() > 1 {
            return Err(crate::Error::Zkp(crate::errors::ZkpError::TraceGenerationFailed(
                format!(
                    "Invalid SMT: multiple wallets at max_depth {} after splitting. Left: {}, Right: {}",
                    max_depth, left_wallets.len(), right_wallets.len()
                ),
            )));
        }

        // Handle left branch (if any)
        if let Some((wallet_id, wallet_commitment)) = left_wallets.iter().next() {
            let leaf_hash =
                hasher.hash_leaf(config.leaf_domain_tag(), *wallet_id, *wallet_commitment);
            nodes.push(SMTNode::Leaf {
                wallet_id: *wallet_id,
                wallet_commitment: *wallet_commitment,
                depth,
                computed_root: leaf_hash,
            });
        }

        // Handle right branch (if any)
        if let Some((wallet_id, wallet_commitment)) = right_wallets.iter().next() {
            let leaf_hash =
                hasher.hash_leaf(config.leaf_domain_tag(), *wallet_id, *wallet_commitment);
            nodes.push(SMTNode::Leaf {
                wallet_id: *wallet_id,
                wallet_commitment: *wallet_commitment,
                depth,
                computed_root: leaf_hash,
            });
        }

        // If we have both left and right, we need an internal node to combine them
        if !left_wallets.is_empty() && !right_wallets.is_empty() {
            let left_child = match &nodes[0] {
                SMTNode::Leaf { computed_root, .. } => *computed_root,
                SMTNode::Internal { computed_root, .. } => *computed_root,
            };
            let right_child = match &nodes[1] {
                SMTNode::Leaf { computed_root, .. } => *computed_root,
                SMTNode::Internal { computed_root, .. } => *computed_root,
            };
            let computed_root =
                hasher.hash_internal(config.internal_domain_tag(), left_child, right_child);

            // Replace the two leaf nodes with: internal node, then left leaf, then right leaf
            let left_leaf = nodes.remove(0);
            let right_leaf = nodes.remove(0);
            nodes.insert(0, SMTNode::Internal { left_child, right_child, depth, computed_root });
            nodes.push(left_leaf);
            nodes.push(right_leaf);
        }

        return Ok(nodes);
    }

    let mut left_nodes = collect_smt_nodes(&left_wallets, depth + 1, hasher, config)?;
    let mut right_nodes = collect_smt_nodes(&right_wallets, depth + 1, hasher, config)?;

    let left_child = if let Some(
        SMTNode::Leaf { computed_root, .. } | SMTNode::Internal { computed_root, .. },
    ) = left_nodes.first()
    {
        *computed_root
    } else {
        hasher.zero_hash()
    };

    let right_child = if let Some(
        SMTNode::Leaf { computed_root, .. } | SMTNode::Internal { computed_root, .. },
    ) = right_nodes.first()
    {
        *computed_root
    } else {
        hasher.zero_hash()
    };

    let computed_root = hasher.hash_internal(config.internal_domain_tag(), left_child, right_child);

    nodes.push(SMTNode::Internal { left_child, right_child, depth, computed_root });

    nodes.append(&mut left_nodes);
    nodes.append(&mut right_nodes);

    Ok(nodes)
}

/// Converts an SMT node into a complete execution trace row for zero-knowledge proof verification.
///
/// This function transforms a high-level SMT node (leaf or internal) into a detailed execution
/// trace that captures every step of the Poseidon2 hash computation. The ZKP circuit needs these
/// intermediate computation steps to verify that the hash was computed correctly, not just that
/// the inputs and outputs match. Each row in the trace matrix represents one node in the SMT,
/// with all the cryptographic computation details laid out in a format the proof system can verify.
fn build_node_row(
    node: &SMTNode,
    constants: &Poseidon2Constants,
    config: &MerkleMorphV0Config,
) -> Result<Vec<Val>> {
    let total_cols = column_offsets::total_cols();
    let mut row = vec![Val::ZERO; total_cols];

    match node {
        SMTNode::Leaf { wallet_id, wallet_commitment, depth, computed_root } => {
            let wallet_id_fields = bytes32_to_fields(*wallet_id);
            row[column_offsets::WALLET_ID_START..column_offsets::WALLET_ID_END]
                .copy_from_slice(&wallet_id_fields);

            let commitment_fields = bytes32_to_fields(*wallet_commitment);
            row[column_offsets::WALLET_COMMITMENT_START..column_offsets::WALLET_COMMITMENT_END]
                .copy_from_slice(&commitment_fields);

            let root_fields = bytes32_to_fields(*computed_root);
            row[column_offsets::COMPUTED_ROOT_START..column_offsets::COMPUTED_ROOT_END]
                .copy_from_slice(&root_fields);

            row[column_offsets::DEPTH_START] = Val::new(*depth as u32);

            let hasher = Poseidon2Hasher;
            let zero_hash = hasher.zero_hash();
            let zero_fields = bytes32_to_fields(zero_hash);
            row[column_offsets::LEFT_CHILD_ROOT_START..column_offsets::LEFT_CHILD_ROOT_END]
                .copy_from_slice(&zero_fields);
            row[column_offsets::RIGHT_CHILD_ROOT_START..column_offsets::RIGHT_CHILD_ROOT_END]
                .copy_from_slice(&zero_fields);

            let hasher = Poseidon2Hasher;
            let computed_root_for_trace =
                hasher.hash_leaf(config.leaf_domain_tag(), *wallet_id, *wallet_commitment);

            if computed_root_for_trace != *computed_root {
                return Err(crate::Error::Zkp(crate::errors::ZkpError::TraceGenerationFailed(
                    format!("Leaf hash mismatch at depth {}", depth),
                )));
            }

            let mut leaf_input_bytes = Vec::new();
            leaf_input_bytes.extend_from_slice(config.leaf_domain_tag());
            leaf_input_bytes.extend_from_slice(&wallet_id[..]);
            leaf_input_bytes.extend_from_slice(&wallet_commitment[..]);

            let (leaf_traces, computed_output) = generate_multi_permutation_traces(
                &leaf_input_bytes,
                &constants.external_constants,
                &constants.internal_constants,
                &constants.round_constants,
            )?;

            let expected_fields = bytes32_to_fields(computed_root_for_trace);
            if computed_output != expected_fields {
                return Err(crate::Error::Zkp(crate::errors::ZkpError::TraceGenerationFailed(
                    format!("Leaf output mismatch at depth {}", depth),
                )));
            }

            let poseidon2_cols = poseidon2_air_num_cols();
            let expected_total_cols = column_offsets::LEAF_PERMUTATIONS * poseidon2_cols;
            let actual_total_cols: usize = leaf_traces.iter().map(|t| t.len()).sum();
            if expected_total_cols != actual_total_cols {
                return Err(crate::Error::Zkp(crate::errors::ZkpError::TraceGenerationFailed(
                    format!(
                        "Leaf trace dimension mismatch at depth {}: expected {} cols ({} perms * {} cols), got {} cols. Number of traces: {}, trace lengths: {:?}",
                        depth, expected_total_cols, column_offsets::LEAF_PERMUTATIONS, poseidon2_cols, actual_total_cols,
                        leaf_traces.len(),
                        leaf_traces.iter().map(|t| t.len()).collect::<Vec<_>>()
                    ),
                )));
            }
            copy_traces_to_row(&mut row, &leaf_traces, column_offsets::LEAF_POSEIDON2_START)?;

            let mut internal_zero_input_bytes = Vec::new();
            internal_zero_input_bytes.extend_from_slice(config.internal_domain_tag());
            internal_zero_input_bytes.extend_from_slice(&zero_hash[..]);
            internal_zero_input_bytes.extend_from_slice(&zero_hash[..]);

            let (internal_zero_traces, _) = generate_multi_permutation_traces(
                &internal_zero_input_bytes,
                &constants.external_constants,
                &constants.internal_constants,
                &constants.round_constants,
            )?;

            let poseidon2_cols = poseidon2_air_num_cols();
            let expected_zero_cols = column_offsets::INTERNAL_NODE_PERMUTATIONS * poseidon2_cols;
            let actual_zero_cols: usize = internal_zero_traces.iter().map(|t| t.len()).sum();
            if expected_zero_cols != actual_zero_cols {
                return Err(crate::Error::Zkp(crate::errors::ZkpError::TraceGenerationFailed(
                    format!(
                        "Zero-input internal trace dimension mismatch at depth {}: expected {} cols, got {} cols",
                        depth, expected_zero_cols, actual_zero_cols
                    ),
                )));
            }
            copy_traces_to_row(
                &mut row,
                &internal_zero_traces,
                column_offsets::internal_node_poseidon2_start(),
            )?;
        }
        SMTNode::Internal { left_child, right_child, depth, computed_root } => {
            let hasher = Poseidon2Hasher;
            let zero_hash = hasher.zero_hash();

            let left_fields = bytes32_to_fields(*left_child);
            row[column_offsets::LEFT_CHILD_ROOT_START..column_offsets::LEFT_CHILD_ROOT_END]
                .copy_from_slice(&left_fields);

            let right_fields = bytes32_to_fields(*right_child);
            row[column_offsets::RIGHT_CHILD_ROOT_START..column_offsets::RIGHT_CHILD_ROOT_END]
                .copy_from_slice(&right_fields);

            let root_fields = bytes32_to_fields(*computed_root);
            row[column_offsets::COMPUTED_ROOT_START..column_offsets::COMPUTED_ROOT_END]
                .copy_from_slice(&root_fields);

            row[column_offsets::DEPTH_START] = Val::new(*depth as u32);

            let hasher = Poseidon2Hasher;
            let computed_root_for_trace =
                hasher.hash_internal(config.internal_domain_tag(), *left_child, *right_child);

            if computed_root_for_trace != *computed_root {
                return Err(crate::Error::Zkp(crate::errors::ZkpError::TraceGenerationFailed(
                    format!(
                        "Internal node hash mismatch at depth {}: stored={:?}, recomputed={:?}",
                        depth, computed_root, computed_root_for_trace
                    ),
                )));
            }

            let mut internal_input_bytes = Vec::new();
            internal_input_bytes.extend_from_slice(config.internal_domain_tag());
            internal_input_bytes.extend_from_slice(&left_child[..]);
            internal_input_bytes.extend_from_slice(&right_child[..]);

            let (internal_traces, computed_output) = generate_multi_permutation_traces(
                &internal_input_bytes,
                &constants.external_constants,
                &constants.internal_constants,
                &constants.round_constants,
            )?;

            let expected_fields = bytes32_to_fields(computed_root_for_trace);
            if computed_output != expected_fields {
                return Err(crate::Error::Zkp(crate::errors::ZkpError::TraceGenerationFailed(
                    format!("Internal node output mismatch at depth {}", depth),
                )));
            }

            let poseidon2_cols = poseidon2_air_num_cols();
            let expected_total_cols = column_offsets::INTERNAL_NODE_PERMUTATIONS * poseidon2_cols;
            let actual_total_cols: usize = internal_traces.iter().map(|t| t.len()).sum();
            if expected_total_cols != actual_total_cols {
                return Err(crate::Error::Zkp(crate::errors::ZkpError::TraceGenerationFailed(
                    format!(
                        "Internal trace dimension mismatch at depth {}: expected {} cols ({} perms * {} cols), got {} cols. Number of traces: {}, trace lengths: {:?}",
                        depth, expected_total_cols, column_offsets::INTERNAL_NODE_PERMUTATIONS, poseidon2_cols, actual_total_cols,
                        internal_traces.len(),
                        internal_traces.iter().map(|t| t.len()).collect::<Vec<_>>()
                    ),
                )));
            }
            copy_traces_to_row(
                &mut row,
                &internal_traces,
                column_offsets::internal_node_poseidon2_start(),
            )?;

            let mut leaf_zero_input_bytes = Vec::new();
            leaf_zero_input_bytes.extend_from_slice(config.leaf_domain_tag());
            leaf_zero_input_bytes.extend_from_slice(&zero_hash[..]); // zero wallet_id
            leaf_zero_input_bytes.extend_from_slice(&zero_hash[..]); // zero wallet_commitment

            let (leaf_zero_traces, _) = generate_multi_permutation_traces(
                &leaf_zero_input_bytes,
                &constants.external_constants,
                &constants.internal_constants,
                &constants.round_constants,
            )?;

            let poseidon2_cols = poseidon2_air_num_cols();
            let expected_zero_cols = column_offsets::LEAF_PERMUTATIONS * poseidon2_cols;
            let actual_zero_cols: usize = leaf_zero_traces.iter().map(|t| t.len()).sum();
            if expected_zero_cols != actual_zero_cols {
                return Err(crate::Error::Zkp(crate::errors::ZkpError::TraceGenerationFailed(
                    format!(
                        "Zero-input leaf trace dimension mismatch at depth {}: expected {} cols, got {} cols",
                        depth, expected_zero_cols, actual_zero_cols
                    ),
                )));
            }
            copy_traces_to_row(&mut row, &leaf_zero_traces, column_offsets::LEAF_POSEIDON2_START)?;
        }
    }

    Ok(row)
}

/// Generate zero traces for both internal and leaf nodes
fn generate_zero_traces(
    config: &MerkleMorphV0Config,
    constants: &Poseidon2Constants,
    zero: Bytes32,
) -> Result<ZeroTraces> {
    let mut internal_input_bytes = Vec::new();
    internal_input_bytes.extend_from_slice(config.internal_domain_tag());
    internal_input_bytes.extend_from_slice(&zero[..]);
    internal_input_bytes.extend_from_slice(&zero[..]);

    let (internal_zero_traces, _) = generate_multi_permutation_traces(
        &internal_input_bytes,
        &constants.external_constants,
        &constants.internal_constants,
        &constants.round_constants,
    )?;

    let mut leaf_zero_input_bytes = Vec::new();
    leaf_zero_input_bytes.extend_from_slice(config.leaf_domain_tag());
    leaf_zero_input_bytes.extend_from_slice(&zero[..]); // zero wallet_id
    leaf_zero_input_bytes.extend_from_slice(&zero[..]); // zero wallet_commitment

    let (leaf_zero_traces, _) = generate_multi_permutation_traces(
        &leaf_zero_input_bytes,
        &constants.external_constants,
        &constants.internal_constants,
        &constants.round_constants,
    )?;

    Ok((internal_zero_traces, leaf_zero_traces))
}

/// Create a padding row with zero traces and a specified root
fn create_zero_padding_row(
    total_cols: usize,
    root: Bytes32,
    internal_zero_traces: &[Vec<Val>],
    leaf_zero_traces: &[Vec<Val>],
) -> Result<Vec<Val>> {
    let mut padding_row = vec![Val::ZERO; total_cols];

    // Copy traces first
    copy_traces_to_row(&mut padding_row, leaf_zero_traces, column_offsets::LEAF_POSEIDON2_START)?;
    copy_traces_to_row(
        &mut padding_row,
        internal_zero_traces,
        column_offsets::internal_node_poseidon2_start(),
    )?;

    // Then set the root to ensure it's not overwritten
    let root_fields = bytes32_to_fields(root);
    padding_row[column_offsets::COMPUTED_ROOT_START..column_offsets::COMPUTED_ROOT_END]
        .copy_from_slice(&root_fields);

    Ok(padding_row)
}

fn generate_multi_permutation_traces(
    input_bytes: &[u8],
    external_constants: &p3_poseidon2::ExternalLayerConstants<Val, 16>,
    internal_constants: &[Val],
    constants: &p3_poseidon2_air::RoundConstants<Val, 16, 4, 20>,
) -> Result<(Vec<Vec<Val>>, [Val; 8])> {
    type Perm = Poseidon2BabyBear<POSEIDON2_WIDTH>;

    let perm = Perm::new(external_constants.clone(), internal_constants.to_vec());

    let mut fields = Vec::new();
    for chunk in input_bytes.chunks(4) {
        let mut arr = [0u8; 4];
        arr[..chunk.len()].copy_from_slice(chunk);
        let u32_val = u32::from_le_bytes(arr);
        fields.push(Val::new(u32_val));
    }

    let mut state = [Val::ZERO; POSEIDON2_WIDTH];
    let mut input_iter = fields.into_iter();
    let mut traces = Vec::new();

    'outer: loop {
        let mut absorbed_count = 0;
        for i in 0..POSEIDON2_RATE {
            if let Some(x) = input_iter.next() {
                state[i] = x;
                absorbed_count += 1;
            } else {
                if absorbed_count > 0 {
                    let input_state: [Val; POSEIDON2_WIDTH] = state;
                    traces
                        .push(generate_poseidon2_trace_row_with_constants(input_state, constants)?);
                    perm.permute_mut(&mut state);
                }
                break 'outer;
            }
        }

        let input_state: [Val; POSEIDON2_WIDTH] = state;
        traces.push(generate_poseidon2_trace_row_with_constants(input_state, constants)?);
        perm.permute_mut(&mut state);
    }

    let mut output = [Val::ZERO; POSEIDON2_OUTPUT_SIZE];
    output.copy_from_slice(&state[..POSEIDON2_OUTPUT_SIZE]);

    Ok((traces, output))
}

fn generate_poseidon2_trace_row_with_constants(
    input: [Val; POSEIDON2_WIDTH],
    constants: &p3_poseidon2_air::RoundConstants<Val, 16, 4, 20>,
) -> Result<Vec<Val>> {
    let trace = generate_trace_rows::<
        Val,
        GenericPoseidon2LinearLayersBabyBear,
        { POSEIDON2_WIDTH },
        POSEIDON2_SBOX_DEGREE,
        POSEIDON2_SBOX_REGISTERS,
        POSEIDON2_HALF_FULL_ROUNDS,
        POSEIDON2_PARTIAL_ROUNDS,
    >(vec![input], constants, 0);

    if trace.height() != 1 {
        return Err(crate::Error::Zkp(crate::errors::ZkpError::TraceGenerationFailed(format!(
            "generate_trace_rows returned {} rows, expected 1",
            trace.height()
        ))));
    }
    let expected_cols = poseidon2_air_num_cols();
    let actual_cols = trace.width();
    if expected_cols != actual_cols {
        return Err(crate::Error::Zkp(crate::errors::ZkpError::TraceGenerationFailed(format!(
            "Trace has {} cols, expected {}",
            actual_cols, expected_cols
        ))));
    }

    let row_slice = trace.row_slice(0).expect("Trace should have at least one row");
    Ok(row_slice.to_vec())
}

/// Copy traces into a row starting at the given offset
fn copy_traces_to_row(row: &mut [Val], traces: &[Vec<Val>], initial_offset: usize) -> Result<()> {
    let poseidon2_cols = poseidon2_air_num_cols();
    let mut offset = initial_offset;
    for (i, trace) in traces.iter().enumerate() {
        if offset + trace.len() > row.len() {
            return Err(crate::Error::Zkp(crate::errors::ZkpError::TraceGenerationFailed(
                format!(
                    "Trace {} would overflow row: offset={}, trace_len={}, row_len={}",
                    i,
                    offset,
                    trace.len(),
                    row.len()
                ),
            )));
        }
        if trace.len() != poseidon2_cols {
            return Err(crate::Error::Zkp(crate::errors::ZkpError::TraceGenerationFailed(
                format!(
                    "Trace {} has {} cols, expected {} cols (permutation {})",
                    i,
                    trace.len(),
                    poseidon2_cols,
                    i
                ),
            )));
        }
        row[offset..offset + trace.len()].copy_from_slice(trace);
        offset += trace.len();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use p3_matrix::Matrix;

    use super::*;

    #[test]
    fn test_build_subtree_trace() {
        let empty_commitments = BTreeMap::new();
        let min_id = [0u8; 32];
        let max_id = [0u8; 32];
        let start_depth = 0u8;

        let empty_result = build_subtree_trace(&empty_commitments, min_id, max_id, start_depth);

        assert!(empty_result.is_ok());
        let empty_trace = empty_result.expect("empty trace should be valid");
        assert_eq!(empty_trace.height(), 8);
        assert!(empty_trace.width() > 0);

        let mut single_commitments = BTreeMap::new();
        let single_wallet_id = [1u8; 32];
        let single_wallet_commitment = [2u8; 32];
        single_commitments.insert(single_wallet_id, single_wallet_commitment);

        let single_result = build_subtree_trace(
            &single_commitments,
            single_wallet_id,
            single_wallet_id,
            start_depth,
        );

        assert!(single_result.is_ok());
        let single_trace = single_result.expect("single trace should be valid");
        assert!(single_trace.height() >= 8);
        assert!(single_trace.width() > 0);

        let mut multi_commitments = BTreeMap::new();
        let mut min_id_multi = [0u8; 32];
        // Set first bit to 0 (MSB of first byte)
        min_id_multi[0] = 0b00000000;
        let mut max_id_multi = [0u8; 32];
        // Set first bit to 1 (MSB of first byte) so they differ at depth 0
        max_id_multi[0] = 0b10000000;
        let min_commitment = [10u8; 32];
        let max_commitment = [20u8; 32];
        multi_commitments.insert(min_id_multi, min_commitment);
        multi_commitments.insert(max_id_multi, max_commitment);

        let multi_result =
            build_subtree_trace(&multi_commitments, min_id_multi, max_id_multi, start_depth);

        assert!(multi_result.is_ok());
        let multi_trace = multi_result.expect("multi trace should be valid");
        assert!(multi_trace.height() >= 8);
        assert!(multi_trace.width() > 0);

        let mut filtered_out_commitments = BTreeMap::new();
        let out_of_range_id = [255u8; 32];
        let out_of_range_commitment = [100u8; 32];
        filtered_out_commitments.insert(out_of_range_id, out_of_range_commitment);

        let filtered_result =
            build_subtree_trace(&filtered_out_commitments, min_id, max_id, start_depth);

        assert!(filtered_result.is_ok());
        let filtered_trace = filtered_result.expect("filtered trace should be valid");
        assert_eq!(filtered_trace.height(), 8);
        assert!(filtered_trace.width() > 0);
    }
}
