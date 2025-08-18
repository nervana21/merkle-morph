# Overpass Framework with Perfect Mathematical Composability (PMC)

Original Author: Brandon "Cryptskii" Ramsay

## Table of Contents
1. [Introduction](#1-introduction)
2. [Perfect Mathematical Composability (PMC)](#2-perfect-mathematical-composability-pmc)
   1. [Definition and Fundamental Concepts](#21-definition-and-fundamental-concepts)
   2. [Category-Theoretic Formalization](#22-category-theoretic-formalization)
3. [Core Definitions](#3-core-definitions)
4. [Integration of PMC with Categorical Structures](#4-integration-of-pmc-with-categorical-structures)
5. [Category-Theoretic Constructs in Merkle Morph](#5-category-theoretic-constructs-in-merkle-morph)
6. [Implementing the Constructs in Code](#6-implementing-the-constructs-in-code)
7. [Integrating PMC with Code-Level Constructs](#7-integrating-pmc-with-code-level-constructs)
8. [Concept-to-Code Mapping](#8-concept-to-code-mapping)

---

## 1. Introduction
Merkle Morph is a Bitcoin layer 2 proposal. It embodies **Perfect Mathematical Composability (PMC)**, a design principle that requires that every state transition be accompanied by a proof of validity. PMC enables individual components to be developed, verified, and reasoned about in isolation while guaranteeing that the fully composed system remains coherent.

This document borrows heavily from Ramsay's original paper, mapping every construct to its Merkle Morph implementation so that researchers and developers can move seamlessly between theory and code. The original proof-of-concept implementation can be found at [TPSjunkie/overpass_poc](https://github.com/TPSjunkie/overpass_poc).

---

## 2. Perfect Mathematical Composability (PMC)

### 2.1 Definition and Fundamental Concepts
**Definition 1 (Perfect Mathematical Composability).** A system exhibits PMC when every state transition is provably valid. Formally:

$$
\forall s \in S, \forall t \in T: \text{Valid}(t(s)) \iff \exists p \text{ such that } \text{Verify}(p, s, t(s)) = 1
$$

Where:
- $S$ is the set of system states.
- $T$ is the set of valid transitions.
- $p$ is a zero-knowledge proof that certifies the transition.

Requiring a proof for each transition guarantees that the composed system cannot enter an invalid state.

### 2.2 Category-Theoretic Formalization
Category theory captures the structural relationships enforced by PMC. Rather than implementing a single abstract `CompositionMetadata` type, Merkle Morph uses concrete Rust types that embody the mathematical concept. Each category (channels, wallets, global) has its own concrete state types and transition functions that satisfy the mathematical properties required by PMC.

#### Channel Category
- **Objects**: Channel states are concrete Rust types: `Open`, `CooperativeClosing`, `ForceClosingPending`, and `Closed`. Each state holds pubkeys, revocation pubkeys/secrets, balances, nonce, metadata, timeout configuration, and the commitment.
- **Morphisms**: State transitions are pure functions: `apply_transfer` / `apply_transfer_state_only`, `apply_cooperative_close`, `apply_cooperative_close_with_fee_contributions`, `apply_force_close`, and `apply_recover`. Each transition advances the nonce, enforces balance/timelock invariants, and recomputes the commitment; proof-generating transitions are paired with `prove_channel_transition`.
- **Identity**: An unchanged `Open` state acts as the identity morphism (no-op transition).
- **Composition**: Transitions compose by sequential application: `apply_transfer(apply_transfer(state, amount1), amount2)` is equivalent to a single transfer of `amount1 + amount2`.

- **Objects**: Wallet states use the `WalletState` type which contains a map of channel commitments indexed by channel ID, plus a Poseidon2 hash-chain wallet commitment.
- **Morphisms**: Wallet transitions use `WalletTransition` operations (`InsertChannel`, `RemoveChannel`) applied via `apply_insert_channel`, `apply_remove_channel`, and `apply_operation`. Each operation recomputes the wallet commitment with `compute_commitment_from_channels`.
- **Identity**: An unchanged `WalletState` acts as the identity morphism.
- **Composition**: Wallet operations compose by sequential application, with commitments recomputed at each step.

#### Global Category
- **Objects**: Global states are the `GlobalState` type, containing the Sparse Merkle Tree (SMT) root of all wallet commitments.
- **Morphisms**: Global transitions aggregate wallet updates into the SMT root via `compose_subtree_roots`, `compose_to_global_root`, and `update_wallet_commitments`, with proofs verified in the global verifier. Subtrees must be non-overlapping and are optionally anchored to Bitcoin via the anchoring module.
- **Identity**: An unchanged `GlobalState` acts as the identity morphism.
- **Composition**: Global composition uses SMT subtree composition, with proofs verified at each level.
- **Terminal Property**: Every wallet morphism factors uniquely through the global root via the SMT utilities.

#### BitcoinTransactionCategory (BTX)
- **Objects**: UTXO sets describing Bitcoin transaction states.
- **Morphisms**: transitions consuming valid inputs and producing outputs under UTXO rules.
- **Identity & Composition**: empty transactions act as identities; sequential valid transactions compose into new morphisms.
- **Implementation status**: fully implemented with state structures, transition logic, commitment computation, and Bitcoin Core consensus validation via `verify_bitcoin_transaction`.

---

## 3. Core Definitions

### 3.1 CompositionMetadata (Mathematical Abstraction)
**Definition 2.** In the original Overpass paper, `CompositionMetadata` objects are mathematical triples `C = (label, type_id, data)` describing morphisms between composite types.

**Implementation Note:** Merkle Morph does not implement a single `CompositionMetadata` type. Instead, the mathematical concept is embodied by concrete Rust types in each category:

- **Channel morphisms**: Channel state types (`Open`, `CooperativeClosing`, `ForceClosingPending`, `Closed`) with transition functions (`apply_transfer`, `apply_cooperative_close`, `apply_force_close`, `apply_recover`). The "label" is implicit in the transition type, "type_id" is the channel state type, and "data" includes balances, nonce, and commitment.

- **Wallet morphisms**: `WalletState` with `WalletTransition` operations (`InsertChannel`, `RemoveChannel`). The "label" is the `WalletTransition` variant, "type_id" is `WalletState`, and "data" includes the channel ID and commitment.

- **Global morphisms**: `GlobalState` with SMT composition operations. The "label" is implicit in the composition operation, "type_id" is `GlobalState`, and "data" includes wallet commitments and the SMT root.

Each concrete type provides type-safe composition operations that enforce associativity and preserve proofs, satisfying the mathematical requirements of the `CompositionMetadata` abstraction.

### 3.2 Morphisms
**Definition 3.** A morphism $f: A \to B$ is valid iff:
- $\text{type}(A) = \text{type}(B)$ (type preservation), and
- there exists $p$ such that $\text{Verify}(p, A, B) = 1$ (proof existence).

### 3.3 Composition Rules
For morphisms $f: A \to B$ and $g: B \to C$, the composite $g \circ f: A \to C$ must satisfy:
- Type consistency: $\text{type}(A) = \text{type}(B) = \text{type}(C)$
- Data concatenation: $\text{data}(g \circ f) = \text{concat}(\text{data}(f), \text{data}(g))$
- Label propagation: $\text{label}(g \circ f) = \text{label}(f) + \text{label}(g)$

### 3.4 Category Structure
The system forms a category $\mathcal{C}$ where:
1. Objects are concrete state types (channel states, `WalletState`, `GlobalState`, `BitcoinTransaction`).
2. Morphisms are valid transitions (channel transition functions, wallet operations, global composition).
3. Identities preserve state (unchanged states act as identity morphisms).
4. Composition is associative and proof-preserving (sequential application of transitions with proof verification).

### 3.5 Derived Categories
- **Channel Category ($\mathcal{C}$)**: objects are channel states; morphisms are valid channel transitions.
- **Wallet Category ($\mathcal{W}$)**: objects are wallet states; morphisms are valid wallet transitions.

### 3.6 Universal Properties
1. **Terminal Object**: the global state is terminal.
2. **Pullbacks**: channels pull back to wallets to ensure consistency.
3. **Pushouts**: wallet updates push forward into the global state.
4. **Products**: independent channel updates behave like categorical products.

### 3.7 Functors
- **Channel Embedding**: $F: \mathcal{C} \to \mathcal{W}$
- **Wallet Projection**: $G: \mathcal{W} \to \mathcal{S}$, where $\mathcal{S}$ is the category of global states.

### 3.8 Cone Constructions
A cone over a diagram $D: J \to \mathcal{C}$ consists of a vertex $V$ plus morphisms $f_j: V \to D(j)$ such that every diagram commutes. Composition cones combine multiple states into a single vertex while preserving proofs.

**Theorem 1 (Cone Composition).** Two cones `K1` and `K2` with compatible bases compose if they share the same type and a proof exists verifying the composition.

A **limit cone** is the terminal cone over a diagram, representing the canonical composite state.

---

## 4. Integration of PMC with Categorical Structures

### 4.1 Foundational Integration
**Definition 4.** A category $\mathcal{C}$ is a PMC-category when every composable pair of morphisms admits a proof of valid composition:

$$
\forall f, g \in \text{Mor}(\mathcal{C}), \quad f \circ g \text{ exists } \iff \exists p \text{ such that } \text{Verify}(p, f, g) = 1
$$

### 4.2 PMC Cone Construction
A PMC-cone $K = (V, \{f_i\}, \text{type\_id}, \text{proofs})$ stores the vertex, the family of proofs, and the type ID. Every pair of morphisms inside the cone must have a witness proof showing their joint validity.

### 4.3 Integration Properties
1. **Morphism Composition**: a composition is valid iff a proof exists.
2. **Cone Composition**: cones compose only when a proof of compatibility is provided.
3. **Proof Propagation**: every morphism in a PMC-cone carries an explicit proof.

### 4.4 Structural Relationships
**Theorem 2 (PMC Coherence).** If a PMC-cone $K$ is valid, then every morphism inside $K$ possesses a proof recorded in the cone's proof set.

### 4.5 PMC Cone Operations
- **Proof concatenation**: $p_{f \circ g} = \text{concat}(p_f, p_g)$.
- **Cone verification**: $\text{Valid}(K)$ iff $\text{Verify}(p_f, f) = 1$ for every $f$ in $K$.
- **State composition**: $\text{Compose}(s_1, s_2)$ is realized via the vertex of the PMC-cone spanning $s_1$ and $s_2$.

### 4.6 Practical Significance
- Guarantees that every composition is provably correct.
- Maintains structural coherence across multiple subsystems.
- Enables modular verification pipelines while keeping the global system secure.

---

## 5. Category-Theoretic Constructs in Merkle Morph

### 5.1 System Categories and Relationships
The Overpass framework combines three principal categories:
1. `BTX`: Bitcoin transaction states.
2. `WalletState`: wallet-level aggregates.
3. `GlobalState`: global summaries.

The composition is $\mathcal{C} = \text{BTX} \circ \text{WalletState} \circ \text{GlobalState}$, ensuring that PMC is preserved from transactions up to the global root. The Merkle Morph implementation operates with channel states (`Open`, `CooperativeClosing`, `ForceClosingPending`, `Closed`), `WalletState`, `GlobalState`, and `BitcoinTransaction` (BTX), where channels compose into wallets, wallets compose into the global root, and Bitcoin transactions can anchor the global state.

### 5.2 Functors and Natural Transformations
- **Functors** map objects and morphisms between categories while preserving identity and composition.
- **Natural transformations** $\eta: F \Rightarrow G$ provide structure-preserving bridges between functors. For any morphism $f: X \to Y$, the diagram built from $F(f)$ and $G(f)$ commutes via $\eta_X$ and $\eta_Y$.

*Example.* A functor $F: \text{BTX} \to \text{WalletState}$ would map Bitcoin transactions to wallet updates. A natural transformation $\eta$ would ensure that proofs generated on BTX objects remain valid when interpreted as wallet morphisms. The BTX category is implemented in `btx/` with full Bitcoin Core consensus validation support.

### 5.3 Monoidal Categories and Tensor Products
- A **monoidal category** $(\mathcal{C}, \otimes, I)$ supports a tensor product for parallel composition plus unit object $I$.
- In Merkle Morph, the tensor product combines multiple state transitions across the implemented categories (channel states, `WalletState`, `GlobalState`, `BitcoinTransaction`) so that independent state transitions can be processed simultaneously while still producing verifiable proofs. At the implementation level, this is realized through concrete types: channel states (`Open`, `CooperativeClosing`, `ForceClosingPending`, `Closed`), `WalletState`, `GlobalState`, and `BitcoinTransaction` (BTX). These concrete types preserve the mathematical structure of `CompositionMetadata` while maintaining type safety.

---

## 6. Implementing the Constructs in Code

### 6.1 Concrete Types vs. Mathematical Abstraction

The original Overpass paper defines `CompositionMetadata` as a mathematical abstraction `C = (label, type_id, data)`. Merkle Morph does not implement a single `CompositionMetadata` type. Instead, each category uses concrete Rust types that embody this concept:

**Channel Category:**
- **State types**: `Open`, `CooperativeClosing`, `ForceClosingPending`, `Closed`
- **Transition functions**: `apply_transfer` / `apply_transfer_state_only`, `apply_cooperative_close`, `apply_cooperative_close_with_fee_contributions`, `apply_force_close`, `apply_recover`
- **What this represents**: The mathematical "label" is the transition function name, "type_id" is the channel state type, and "data" includes balances, nonce, commitment, metadata, revocation secrets/pubkeys, and timeout configuration.

**Wallet Category:**
- **State type**: `WalletState`
- **Transition type**: `WalletTransition` enum with `InsertChannel` and `RemoveChannel` variants
- **Transition functions**: `apply_insert_channel`, `apply_remove_channel`, `apply_operation`
- **What this represents**: The mathematical "label" is the `WalletTransition` variant, "type_id" is `WalletState`, and "data" includes the channel ID and commitment.

**Global Category:**
- **State type**: `GlobalState`
- **Composition functions**: `compute_subtree_root`, `compose_subtree_roots`, `compose_to_global_root`, `update_wallet_commitments`
- **What this represents**: The mathematical "label" is implicit in the composition operation, "type_id" is `GlobalState`, and "data" includes wallet commitments and the SMT root.

Each concrete type provides type-safe composition operations that enforce associativity and preserve proofs at compile time, satisfying the mathematical requirements of the `CompositionMetadata` abstraction without requiring a single unified type.

### 6.2 Channel States as Categorical Objects
The channel category uses a state machine with four distinct state types, each representing a different phase of the channel lifecycle:

```rust
// Channel lifecycle enum for type-level documentation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelLifecycle {
    Open, CooperativeClosing, ForceClosingPending, Closed,
}

// Active channel state
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Open {
    pub sender_pubkey: XOnlyPublicKey,
    pub receiver_pubkey: XOnlyPublicKey,
    pub sender_revocation_pubkey: XOnlyPublicKey,
    pub receiver_revocation_pubkey: XOnlyPublicKey,
    pub sender_revocation_secret: [u8; 32],
    pub receiver_revocation_secret: [u8; 32],
    pub sender_balance: u64,
    pub receiver_balance: u64,
    pub nonce: u32,
    pub commitment: ChannelCommitment,
    pub metadata: Vec<u8>,
    pub timeout_blocks: u16,
}

// Channel being closed cooperatively
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CooperativeClosing {
    pub sender_pubkey: XOnlyPublicKey,
    pub receiver_pubkey: XOnlyPublicKey,
    pub total_capacity: u64,
    pub sender_balance: u64,
    pub receiver_balance: u64,
    pub total_fee: u64,
    pub sender_contribution: u64,
    pub receiver_contribution: u64,
    pub nonce: u32,
    pub commitment: ChannelCommitment,
}

// Channel force closed, waiting for CSV timeout
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForceClosingPending {
    pub sender_pubkey: XOnlyPublicKey,
    pub receiver_pubkey: XOnlyPublicKey,
    pub total_capacity: u64,
    pub sender_balance: u64,
    pub receiver_balance: u64,
    pub total_fee: u64,
    pub nonce: u32,
    pub commitment: ChannelCommitment,
    pub timeout_blocks: u16,
}

// Permanently closed channel
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Closed {
    pub sender_pubkey: XOnlyPublicKey,
    pub receiver_pubkey: XOnlyPublicKey,
    pub total_capacity: u64,
    pub sender_balance: u64,
    pub receiver_balance: u64,
    pub nonce: u32,
    pub commitment: ChannelCommitment,
}

// Channel transitions are handled by pure functions:
// - apply_transfer / apply_transfer_state_only: Open -> Open (transfers funds, checks metadata size)
// - apply_cooperative_close: Open -> CooperativeClosing (funder pays fees)
// - apply_cooperative_close_with_fee_contributions: Open -> CooperativeClosing (dual fee split)
// - apply_force_close: Open -> ForceClosingPending (force closure with CSV timeout)
// - apply_recover: ForceClosingPending -> Closed (recovery after timeout)
// All operations advance the nonce and recompute the commitment; proofful paths pair with prove_channel_transition
```

`Open` stores per-state revocation pubkeys/secrets (used for penalty/revocation-style claims) plus a configurable CSV `timeout_blocks` (defaulting to `FORCE_CLOSE_TIMEOUT_BLOCKS`). Force-close and recover transitions enforce these timelocks.

### 6.3 WalletState as a Categorical Object
```rust
// From wallet/state.rs
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default)]
pub struct WalletState {
    pub id: WalletId,
    pub channels: BTreeMap<ChannelId, ChannelCommitment>,
    pub commitment: WalletCommitment,
}

impl WalletState {
    pub fn new(wallet_id: WalletId) -> Self {
        Self {
            id: wallet_id,
            channels: BTreeMap::new(),
            commitment: WalletCommitment::default(),
        }
    }

    pub fn from_channels(
        wallet_id: WalletId,
        channels: BTreeMap<ChannelId, ChannelCommitment>,
    ) -> Self {
        Self {
            id: wallet_id,
            channels,
            commitment: WalletCommitment::default(),
        }
    }
}

// Wallet transitions are handled by pure functions in wallet/transition.rs:
// - apply_insert_channel: adds or updates a channel commitment (bounded by MAX_CHANNELS)
// - apply_remove_channel: removes a channel commitment
// - apply_operation: dispatch helper
// All operations recompute the wallet commitment via compute_commitment_from_channels (Poseidon2 hash chain)
```

### 6.4 GlobalState as the Terminal Object
```rust
// From global/state.rs
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct GlobalState {
    pub wallets_root: Bytes32,
    pub changes: WalletCommitments,
    pub nonce: u32,
}

impl GlobalState {
    pub fn new() -> Self {
        Self {
            wallets_root: [0u8; 32],
            changes: WalletCommitments::new(),
            nonce: 0,
        }
    }

    pub fn with_root_and_nonce(root: Bytes32, nonce: u32) -> Self {
        Self {
            wallets_root: root,
            changes: WalletCommitments::new(),
            nonce,
        }
    }

    pub fn with_commitments(
        root: Bytes32,
        changes: WalletCommitments,
        nonce: u32,
    ) -> Self {
        Self {
            wallets_root: root,
            changes,
            nonce,
        }
    }
}

// Global state composition is handled by functions in global/commitment/mod.rs:
// - compose_to_global_root: aggregates wallet commitments into the global SMT root
// - verify_global_root: verifies proofs linking wallet updates to global state
//
// Bitcoin anchoring is implemented via OP_RETURN transactions (see global/anchor.rs):
// - encode_op_return_data: encodes global root and nonce for Bitcoin OP_RETURN output
// - decode_op_return_data: decodes OP_RETURN data back to global root and nonce
// - BitcoinAnchoring trait: interface for anchoring global roots to Bitcoin blockchain
//
// The changes field stores commitments that changed in this transition.
// Invariant: only contains wallet IDs controlled by the local system.
```

### 6.5 BitcoinTransactionCategory (BTX)
```rust
// From btx/state.rs
use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, OutPoint, ScriptBuf, Sequence, Txid, Witness};

// Represents a Bitcoin UTXO (Unspent Transaction Output)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Utxo {
    pub txid: Txid,
    pub index: u32,
    pub value: u64,
    pub address: Address<NetworkUnchecked>,
    pub script_pubkey: Option<ScriptBuf>,  // Optional explicit script
}

// Full input data with scripts and witnesses
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxInputData {
    pub utxo: Utxo,
    pub script_sig: ScriptBuf,    // Unlocking script for legacy
    pub witness: Witness,          // Witness data for SegWit
    pub sequence: Sequence,
}

// Represents a Bitcoin transaction with full script data
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitcoinTransaction {
    pub version: Version,
    pub lock_time: LockTime,
    pub inputs_data: Vec<TxInputData>,  // Full input data with scripts
    pub outputs: Vec<Utxo>,             // Output UTXOs
}

impl BitcoinTransaction {
    // Creates transaction with empty scripts (for simple cases)
    pub fn new(inputs: Vec<Utxo>, outputs: Vec<Utxo>) -> Self { ... }

    // Creates transaction with full script data
    pub fn with_scripts(
        version: Version,
        lock_time: LockTime,
        inputs_data: Vec<TxInputData>,
        outputs: Vec<Utxo>,
    ) -> Self { ... }
}

// From btx/transition.rs
// Identity morphism: empty transaction
pub fn empty() -> BitcoinTransaction {
    BitcoinTransaction::new(vec![], vec![])
}

// Simplified validation: checks value balance (allows fees)
pub fn is_valid(tx: &BitcoinTransaction) -> bool {
    if tx.inputs_data.is_empty() && tx.outputs.is_empty() {
        return true; // Empty transactions are valid (identity)
    }
    let total_in: u64 = tx.inputs_data.iter().map(|id| id.utxo.value).sum();
    let total_out: u64 = tx.outputs.iter().map(|u| u.value).sum();
    total_in >= total_out
}

// Composition: concatenates inputs and outputs, preserves script data
pub fn compose(
    tx1: &BitcoinTransaction,
    tx2: &BitcoinTransaction,
) -> Result<BitcoinTransaction> {
    // Validates both transactions, concatenates inputs/outputs,
    // preserves script data, and verifies the composed transaction
    // Returns Err(BtxError::InvalidTransaction) if either is invalid
    // Returns Err(BtxError::InvalidComposition) if composition fails
}

// Full Bitcoin Core consensus validation
use bitcoin::{OutPoint, Transaction, TxOut};

pub fn verify_bitcoin_transaction<S>(
    tx: &Transaction,
    spent_outputs: S,
) -> Result<()>
where
    S: FnMut(&OutPoint) -> Option<TxOut>,
{
    // Uses bitcoin::consensus::verify_transaction for full script validation,
    // signature verification, and all Bitcoin Core consensus rules
    // Returns Err(BtxError::InvalidTransaction) on validation failure
}
```

The BTX category is fully implemented with:
- **State structures**: `Utxo`, `TxInputData`, and `BitcoinTransaction` types using the `bitcoin` crate with full script support
- **Transition logic**: `empty()`, `is_valid()`, `compose()`, `apply_transaction()`, `validate_consensus_rules()`, `validate_p2tr_witnesses()`, and `verify_bitcoin_transaction()` for full Bitcoin Core consensus validation
- **Commitment computation**: Poseidon2-based commitments over transaction state
- **Script utilities**: Script building and validation for P2PKH, P2SH, SegWit, Taproot, and multisig
- **Timelock support**: CSV timelock validation for force close transactions

---

## 7. Integrating PMC with Code-Level Constructs

### 7.1 System Categories and PMC
Each category in Merkle Morph enforces PMC by requiring proofs for every morphism. For example, a wallet transition $t: W \to W'$ must carry a proof $p_t$ that validates the change before it can be propagated to the global root.

### 7.2 PMC-Preserving Functors
A functor $F: \mathcal{C} \to \mathcal{D}$ is PMC-preserving if it maps valid morphisms in $\mathcal{C}$ to valid morphisms in $\mathcal{D}$ while also transforming their proofs into proofs understood by $\mathcal{D}$.

**Proposition.** If $F$ is PMC-preserving, then for every morphism $f$ there exists a proof $p_{F(f)}$ verifying $F(f)$ in the target category.

### 7.3 Integration Overview
Combining PMC with the categorical abstractions yields:
- **Formal verification**: every state transition is proven.
- **Modularity**: categories can be implemented and audited independently.
- **Scalability**: compositional structures parallelize naturally via tensor products and cone operations.
- **Consistency**: categorical laws ensure stable behavior across the stack.

---

## 8. Concept-to-Code Mapping

| Concept | Repo constructs | Mapping notes |
| --- | --- | --- |
| Perfect Mathematical Composability (Definition 1, §2.1) | [`channel/transition/mod.rs`](../src/channel/transition/mod.rs)<br>[`zkp/channel/mod.rs`](../src/zkp/channel/mod.rs)<br>[`zkp/wallet/aggregation.rs`](../src/zkp/wallet/aggregation.rs)<br>[`zkp/global/verifier.rs`](../src/zkp/global/verifier.rs) | Channel transitions (`apply_transfer` / `apply_transfer_state_only`, `apply_cooperative_close`, `apply_cooperative_close_with_fee_contributions`, `apply_force_close`, `apply_recover`) are accepted only when `prove_channel_transition` succeeds; wallet aggregation requires proofs for every channel, and global verification composes subtree roots so every morphism carries a witness. All proofs are implemented as STARK proofs using Plonky3. |
| CompositionMetadata (Definitions 2 & 6.1) | [`channel/state/mod.rs`](../src/channel/state/mod.rs)<br>[`channel/transition/mod.rs`](../src/channel/transition/mod.rs)<br>[`wallet/state.rs`](../src/wallet/state.rs)<br>[`wallet/transition.rs`](../src/wallet/transition.rs)<br>[`wallet/operation.rs`](../src/wallet/operation.rs)<br>[`global/state.rs`](../src/global/state.rs)<br>[`global/commitment/mod.rs`](../src/global/commitment/mod.rs) | Implemented via concrete Rust types rather than a single `CompositionMetadata` struct: channel states with revocation data and per-channel `timeout_blocks`, wallet transitions/operations, and `GlobalState` SMT composition all provide type-safe composition with embedded metadata. |
| Channel category & morphisms (§3.2–3.5, §6.2) | [`channel/state/mod.rs`](../src/channel/state/mod.rs)<br>[`channel/state/open.rs`](../src/channel/state/open.rs)<br>[`channel/state/cooperative_closing.rs`](../src/channel/state/cooperative_closing.rs)<br>[`channel/state/force_closing_pending.rs`](../src/channel/state/force_closing_pending.rs)<br>[`channel/state/closed.rs`](../src/channel/state/closed.rs)<br>[`channel/transition/mod.rs`](../src/channel/transition/mod.rs)<br>[`channel/commitment/mod.rs`](../src/channel/commitment/mod.rs) | Channels use a four-state machine (`Open`, `CooperativeClosing`, `ForceClosingPending`, `Closed`) with morphisms (`apply_transfer` / `apply_transfer_state_only`, `apply_cooperative_close`, `apply_cooperative_close_with_fee_contributions`, `apply_force_close`, `apply_recover`) that maintain revocation data, enforce per-channel `timeout_blocks`, and recompute commitments for each hop. |
| Wallet category & morphisms (§3.2–3.5, §6.3) | [`wallet/transition.rs`](../src/wallet/transition.rs)<br>[`wallet/operation.rs`](../src/wallet/operation.rs)<br>[`wallet/commitment.rs`](../src/wallet/commitment.rs) | Wallet morphisms (`insert_channel`, `remove_channel`) implement categorical composition; `compute_commitment_from_channels` hashes channel commitments in sorted order, enforces `MAX_CHANNELS`, and updates the wallet commitment on every mutation. |
| WalletState (§6.3) | [`wallet/state.rs`](../src/wallet/state.rs)<br>[`wallet/transition.rs`](../src/wallet/transition.rs)<br>[`wallet/commitment.rs`](../src/wallet/commitment.rs)<br>[`wallet/operation.rs`](../src/wallet/operation.rs) | Wallet objects, insert/remove morphisms, `MAX_CHANNELS` guardrails, and Poseidon2 hash-chain commitment recomputation mirror the wallet category design. |
| GlobalState (§6.4) | [`global/state.rs`](../src/global/state.rs)<br>[`global/commitment/mod.rs`](../src/global/commitment/mod.rs)<br>[`global/anchor.rs`](../src/global/anchor.rs)<br>[`zkp/global/verifier.rs`](../src/zkp/global/verifier.rs) | Global state roots, SMT composition (`compute_subtree_root`, `compose_subtree_roots`, `compose_to_global_root`, `update_wallet_commitments`), OP_RETURN-based Bitcoin anchoring (`encode_op_return_data` / `decode_op_return_data` and `BitcoinAnchoring`), and proof verification with non-overlapping subtree enforcement realize the terminal object. |
| BitcoinTransactionCategory (BTX) (§6.5) | [`btx/state.rs`](../src/btx/state.rs)<br>[`btx/transition.rs`](../src/btx/transition.rs)<br>[`btx/commitment.rs`](../src/btx/commitment.rs)<br>[`btx/script.rs`](../src/btx/script.rs)<br>[`btx/timelock.rs`](../src/btx/timelock.rs)<br>[`btx/conversion.rs`](../src/btx/conversion.rs)<br>[`btx/mod.rs`](../src/btx/mod.rs) | `Utxo`, `TxInputData`, and `BitcoinTransaction` types with full script support, transition functions (`empty`, `is_valid`, `compose`, `apply_transaction`, `validate_consensus_rules`, `validate_consensus_rules_with_height`, `validate_with_scripts`, `validate_p2tr_witnesses`), Poseidon2 commitment computation, Bitcoin Core consensus verification via `verify_bitcoin_transaction`, script utilities for P2PKH/P2SH/SegWit/Taproot/multisig, and CSV timelock support. |
| Universal properties (terminal object, pullbacks, pushouts, products; §3.6) | [`global/state.rs`](../src/global/state.rs)<br>[`global/commitment/mod.rs`](../src/global/commitment/mod.rs)<br>[`zkp/wallet/aggregation.rs`](../src/zkp/wallet/aggregation.rs) | Global root serves as the terminal object; wallet/channel aggregation code provides the mechanical pullbacks/pushouts, and global composition enforces non-overlapping subtree ranges. |
| Functors F/G (channel embedding & wallet projection; §§3.7 & 5.2) | [`wallet/commitment.rs::compute_commitment_from_channels`](../src/wallet/commitment.rs)<br>[`wallet/transition.rs`](../src/wallet/transition.rs)<br>[`global/commitment/mod.rs::compose_to_global_root`](../src/global/commitment/mod.rs) | Object parts of the functors are deterministic commitment maps (channels → wallets via `compute_commitment_from_channels`, wallets → global via `compose_to_global_root`), and morphism parts are wallet/global transitions that only accept STARK-proven updates, preserving identities and composition even without an explicit `Functor` trait. |
| Cone constructions & PMC-cones (Theorems 1–2; §§3.8 & 4.2) | [`global/commitment/mod.rs::SubtreeRoot`](../src/global/commitment/mod.rs)<br>[`global/commitment/mod.rs::compose_to_global_root`](../src/global/commitment/mod.rs)<br>[`zkp/global/verifier.rs`](../src/zkp/global/verifier.rs) | Subtree roots plus global composition mirror cone vertices, and `verify_global_root` enforces the proof obligations required by PMC-cones. |
| PMC operations (proof concatenation & propagation; §§4.5 & 7) | [`zkp/wallet/aggregation.rs`](../src/zkp/wallet/aggregation.rs)<br>[`zkp/global/verifier.rs`](../src/zkp/global/verifier.rs)<br>[`zkp/channel/mod.rs`](../src/zkp/channel/mod.rs) | Aggregation verifies per-channel STARK proofs (generated via Plonky3) and enforces that every wallet channel has a corresponding proof/sender-auth pair before composing wallets and global roots, providing the proof propagation guarantees outlined for PMC. |


