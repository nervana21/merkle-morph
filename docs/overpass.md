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
The Merkle Morph implementation of the Overpass framework is a Bitcoin layer 2 proposal. At the heart of Merkle Morph lies **Perfect Mathematical Composability (PMC)**, a design principle that requires every state transition to be accompanied by a proof of correctness. PMC enables individual components to be developed, verified, and reasoned about in isolation while guaranteeing that the fully composed system remains coherent.

This document borrows heavily from Ramsay's original paper, mapping every construct to its Merkle Morph implementation so that researchers and developers can move seamlessly between theory and code.

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
Category theory captures the structural relationships enforced by PMC.

#### CompositionMetadata
- **Morphisms**: in Merkle Morph, `CompositionMetadata` is realized through concrete types rather than a generic wrapper. Channel morphisms are implemented as `ChannelState` transitions via `apply_transfer` / `apply_close` in [`channel/transition.rs`](../src/channel/transition.rs). Wallet morphisms use `WalletState` and `WalletInput` in [`wallet/transition.rs`](../src/wallet/transition.rs). Global morphisms operate on `GlobalState` in [`global/state.rs`](../src/global/state.rs).
- **Identity**: the identity morphism is represented by unchanged state/commitment pairs. For channels, this is an untouched `ChannelState`; for wallets, an unchanged `WalletState`; for global state, an unchanged `GlobalState`.
- **Composition**: composition is realized by chaining type-specific operations (`apply_transfer`, `insert_channel`, etc.), which enforce associativity and type safety at compile time.

#### WalletState
- **Objects**: wallet states (`WalletState` in [`wallet/state.rs`](../src/wallet/state.rs)), each summarizing channel information via a hash chain commitment.
- **Morphisms**: channel updates that move the wallet between valid states (see [`wallet/transition.rs`](../src/wallet/transition.rs) and `WalletInput`).
- **Universal Role**: wallets mediate between per-channel states and the global root by recomputing commitments in [`wallet/commitment.rs`](../src/wallet/commitment.rs).

#### GlobalState
- **Objects**: aggregated global states represented by the global SMT root (`GlobalState` in [`global/state.rs`](../src/global/state.rs)).
- **Morphisms**: proofs that link wallet updates to the global state (verified in [`zkp/global/verifier.rs`](../src/zkp/global/verifier.rs)).
- **Terminal Property**: every wallet morphism factors uniquely through the global root via the SMT utilities in [`global/commitment.rs`](../src/global/commitment.rs).

#### BitcoinTransactionCategory (BTX)
- **Objects**: UTXO sets describing Bitcoin transaction states (implemented in [`btx/state.rs`](../src/btx/state.rs)).
- **Morphisms**: transitions consuming valid inputs and producing outputs under UTXO rules (implemented in [`btx/transition.rs`](../src/btx/transition.rs)).
- **Identity & Composition**: empty transactions act as identities; sequential valid transactions compose into new morphisms.
- **Implementation status**: fully implemented in [`btx/`](../src/btx/) with state structures, transition logic, commitment computation, and Bitcoin Core consensus validation via `verify_bitcoin_transaction`.

---

## 3. Core Definitions

### 3.1 CompositionMetadata
**Definition 2.** `CompositionMetadata` objects are triples `C = (label, type_id, data)` describing morphisms between composite types. In the Merkle Morph codebase, this mathematical abstraction is implemented through concrete Rust types rather than a generic wrapper struct. Channel morphisms are realized as `ChannelState` transitions (with commitments, `TransferAmount`, nonce, balances) in [`channel/state.rs`](../src/channel/state.rs) and [`channel/transition.rs`](../src/channel/transition.rs). Wallet morphisms use `WalletState` and `WalletInput` in [`wallet/state.rs`](../src/wallet/state.rs) and [`wallet/transition.rs`](../src/wallet/transition.rs). Global morphisms operate on `GlobalState` in [`global/state.rs`](../src/global/state.rs).

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
1. Objects are `CompositionMetadata` instances.
2. Morphisms are valid transitions.
3. Identities preserve state.
4. Composition is associative and proof-preserving.

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
1. `BTX`: Bitcoin transaction states (implemented in [`btx/`](../src/btx/)).
2. `WalletState`: wallet-level aggregates (implemented in [`wallet/state.rs`](../src/wallet/state.rs)).
3. `GlobalState`: global summaries (implemented in [`global/state.rs`](../src/global/state.rs)).

The composition is $\mathcal{C} = \text{BTX} \circ \text{WalletState} \circ \text{GlobalState}$, ensuring that PMC is preserved from transactions up to the global root. The Merkle Morph implementation operates with `ChannelState` (payment channels), `WalletState`, `GlobalState`, and `BitcoinTransaction` (BTX), where channels compose into wallets, wallets compose into the global root, and Bitcoin transactions can anchor the global state.

### 5.2 Functors and Natural Transformations
- **Functors** map objects and morphisms between categories while preserving identity and composition.
- **Natural transformations** $\eta: F \Rightarrow G$ provide structure-preserving bridges between functors. For any morphism $f: X \to Y$, the diagram built from $F(f)$ and $G(f)$ commutes via $\eta_X$ and $\eta_Y$.

*Example.* A functor $F: \text{BTX} \to \text{WalletState}$ would map Bitcoin transactions to wallet updates. A natural transformation $\eta$ would ensure that proofs generated on BTX objects remain valid when interpreted as wallet morphisms. The BTX category is implemented in [`btx/`](../src/btx/) with full Bitcoin Core consensus validation support.

### 5.3 Monoidal Categories and Tensor Products
- A **monoidal category** $(\mathcal{C}, \otimes, I)$ supports a tensor product for parallel composition plus unit object $I$.
- In Merkle Morph, the tensor product combines multiple state transitions across the implemented categories (`ChannelState`, `WalletState`, `GlobalState`, `BitcoinTransaction`) so that independent state transitions can be processed simultaneously while still producing verifiable proofs. At the implementation level, this is realized through concrete types: `ChannelState` (for payment channel state transitions), `WalletState`, `GlobalState`, and `BitcoinTransaction` (BTX). These concrete types preserve the mathematical structure of `CompositionMetadata` while maintaining type safety.

---

## 6. Implementing the Constructs in Code

### 6.1 CompositionMetadata Implementation

The codebase implements the `CompositionMetadata` concept through concrete Rust types:

- **Channel morphisms**: `ChannelState` with transitions via `apply_transfer` / `apply_close` in [`channel/transition.rs`](../src/channel/transition.rs)
- **Wallet morphisms**: `WalletState` with `WalletInput` operations in [`wallet/transition.rs`](../src/wallet/transition.rs)
- **Global morphisms**: `GlobalState` with SMT composition in [`global/commitment.rs`](../src/global/commitment.rs)

Each concrete type provides type-safe composition operations that enforce associativity and preserve proofs, satisfying the mathematical requirements of `CompositionMetadata`.

### 6.2 ChannelState as a Categorical Object
```rust
// From channel/state.rs
#[derive(Debug, Clone)]
pub struct ChannelState {
    pub sender_balance: u64,
    pub receiver_balance: u64,
    pub metadata: Vec<u8>,
    pub nonce: u32,
    pub is_closed: bool,
    pub commitment: ChannelCommitment,
}

impl ChannelState {
    pub fn new(sender_balance: u64) -> Self {
        Self {
            sender_balance,
            receiver_balance: 0,
            metadata: vec![],
            nonce: 0,
            is_closed: false,
            commitment: ChannelCommitment::default(),
        }
    }
}

// Channel transitions are handled by pure functions in channel/transition.rs:
// - apply_transfer: transfers funds from sender to receiver
// - apply_close: closes the channel and prevents further operations
// All operations update the nonce and recompute the commitment
```

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
// - insert_channel: adds or updates a channel commitment
// - remove_channel: removes a channel commitment
// - apply_input: applies a WalletInput operation
// All operations recompute the wallet commitment via compute_commitment
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

// Global state composition is handled by functions in global/commitment.rs:
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
use bitcoin::{Address, Txid};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Utxo {
    pub txid: Txid,
    pub index: u32,
    pub value: u64,
    pub address: Address<NetworkUnchecked>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitcoinTransaction {
    pub inputs: Vec<Utxo>,
    pub outputs: Vec<Utxo>,
}

impl BitcoinTransaction {
    pub fn new(inputs: Vec<Utxo>, outputs: Vec<Utxo>) -> Self {
        Self { inputs, outputs }
    }
}

// From btx/transition.rs
// Identity morphism: empty transaction
pub fn empty() -> BitcoinTransaction {
    BitcoinTransaction::new(vec![], vec![])
}

// Simplified validation: checks value balance (allows fees)
pub fn is_valid(tx: &BitcoinTransaction) -> bool {
    if tx.inputs.is_empty() && tx.outputs.is_empty() {
        return true; // Empty transactions are valid (identity)
    }
    let total_in: u64 = tx.inputs.iter().map(|u| u.value).sum();
    let total_out: u64 = tx.outputs.iter().map(|u| u.value).sum();
    total_in >= total_out
}

// Composition: concatenates inputs and outputs
pub fn compose(
    tx1: &BitcoinTransaction,
    tx2: &BitcoinTransaction,
) -> Result<BitcoinTransaction> {
    // Validates both transactions, concatenates inputs/outputs,
    // and verifies the composed transaction is still valid
    // Returns Err(BtxError::InvalidTransaction) if either is invalid
    // Returns Err(BtxError::InvalidComposition) if composition fails
    // ...
}

// Full Bitcoin Core consensus validation
// From btx/transition.rs
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
    // ...
}
```

The BTX category is partially implemented in [`btx/`](../src/btx/) with:
- **State structures** ([`btx/state.rs`](../src/btx/state.rs)): `Utxo` and `BitcoinTransaction` types using the `bitcoin` crate
- **Transition logic** ([`btx/transition.rs`](../src/btx/transition.rs)): `empty()`, `is_valid()`, `compose()`, `apply_transaction()`, and `verify_bitcoin_transaction()` for full Bitcoin Core consensus validation
- **Commitment computation** ([`btx/commitment.rs`](../src/btx/commitment.rs)): Poseidon2-based commitments over transaction state

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

| Concept (doc ref) | Repo construct(s) | Mapping status / notes |
| --- | --- | --- |
| Perfect Mathematical Composability (Definition 1, §2.1) | [`channel/transition.rs`](../src/channel/transition.rs)<br>[`zkp/channel/mod.rs`](../src/zkp/channel/mod.rs)<br>[`zkp/wallet/aggregation.rs`](../src/zkp/wallet/aggregation.rs)<br>[`zkp/global/verifier.rs`](../src/zkp/global/verifier.rs) | Channel transitions (`apply_transfer`) are only accepted when `prove_channel_transition` succeeds; wallet/global verifiers propagate those proofs, satisfying the PMC requirement that every morphism carries a witness. All proofs are implemented as STARK proofs using Plonky3. |
| CompositionMetadata (Definitions 2 & 6.1) | [`channel/state.rs`](../src/channel/state.rs)<br>[`channel/transition.rs`](../src/channel/transition.rs)<br>[`wallet/state.rs`](../src/wallet/state.rs)<br>[`wallet/transition.rs`](../src/wallet/transition.rs)<br>[`global/state.rs`](../src/global/state.rs) | The `CompositionMetadata` concept is implemented through concrete Rust types. Channel morphisms use `ChannelState` and transitions; wallet morphisms use `WalletState` and `WalletInput`; global morphisms use `GlobalState`. |
| Channel category & morphisms (§3.2–3.5, §6.2) | [`channel/state.rs`](../src/channel/state.rs)<br>[`channel/transition.rs`](../src/channel/transition.rs)<br>[`channel/commitment.rs`](../src/channel/commitment.rs) | Channels, their morphisms (`apply_transfer`, `apply_close`), and commitments form the concrete category for per-channel state. |
| Wallet category & morphisms (§3.2–3.5, §6.3) | [`wallet/transition.rs`](../src/wallet/transition.rs)<br>[`wallet/input.rs`](../src/wallet/input.rs)<br>[`wallet/commitment.rs`](../src/wallet/commitment.rs) | Wallet morphisms (`insert_channel`, `remove_channel`) correspond to categorical composition, with commitments enforcing associativity. |
| WalletState (§6.3) | [`wallet/state.rs`](../src/wallet/state.rs)<br>[`wallet/transition.rs`](../src/wallet/transition.rs)<br>[`wallet/commitment.rs`](../src/wallet/commitment.rs)<br>[`wallet/input.rs`](../src/wallet/input.rs) | These modules provide the wallet objects, morphisms (insert/remove), and commitment recomputation that the paper attributes to the wallet category. |
| GlobalState (§6.4) | [`global/state.rs`](../src/global/state.rs)<br>[`global/commitment.rs`](../src/global/commitment.rs)<br>[`global/anchor.rs`](../src/global/anchor.rs)<br>[`zkp/global/verifier.rs`](../src/zkp/global/verifier.rs) | Global state roots, SMT composition, OP_RETURN-based Bitcoin anchoring (via `encode_op_return_data`/`decode_op_return_data` and `BitcoinAnchoring` trait), and proof verification collectively realize the terminal object described in the paper. |
| BitcoinTransactionCategory (BTX) (§6.5) | [`btx/state.rs`](../src/btx/state.rs)<br>[`btx/transition.rs`](../src/btx/transition.rs)<br>[`btx/commitment.rs`](../src/btx/commitment.rs)<br>[`btx/mod.rs`](../src/btx/mod.rs) | To be implemented with `Utxo` and `BitcoinTransaction` types, transition functions (`empty`, `is_valid`, `compose`, `apply_transaction`), commitment computation using Poseidon2, and full Bitcoin Core consensus validation via `verify_bitcoin_transaction` which uses `bitcoin::consensus::verify_transaction` for script execution, signature verification, and all consensus rules. |
| Universal properties (terminal object, pullbacks, pushouts, products; §3.6) | [`global/state.rs`](../src/global/state.rs)<br>[`global/commitment.rs`](../src/global/commitment.rs)<br>[`zkp/wallet/aggregation.rs`](../src/zkp/wallet/aggregation.rs) | The global root acts as the terminal object; wallet/channel aggregation code provides the mechanical pullbacks/pushouts, although no formal trait layer encodes those laws. |
| Functors F/G (channel embedding & wallet projection; §§3.7 & 5.2) | [`wallet/commitment.rs::compute_commitment`](../src/wallet/commitment.rs)<br>[`wallet/transition.rs`](../src/wallet/transition.rs)<br>[`global/commitment.rs::compute_root`](../src/global/commitment.rs) | The object parts of the functors are implemented by deterministic commitment maps (channels → wallets via `compute_commitment`, wallets → global via `compute_root`), while the morphism parts are realized by wallet/global transitions that only accept STARK-proven updates; together they preserve identities, composition, and proofs in the sense required by PMC, even though there is no explicit `Functor` trait. |
| Cone constructions & PMC-cones (Theorems 1–2; §§3.8 & 4.2) | [`global/commitment.rs::SubtreeRoot`](../src/global/commitment.rs)<br>[`global/commitment.rs::compose_to_global_root`](../src/global/commitment.rs)<br>[`zkp/global/verifier.rs`](../src/zkp/global/verifier.rs) | Subtree roots plus global composition mirror cone vertices, and `verify_global_root` enforces the proof obligations required by PMC-cones. |
| PMC operations (proof concatenation & propagation; §§4.5 & 7) | [`zkp/wallet/aggregation.rs`](../src/zkp/wallet/aggregation.rs)<br>[`zkp/global/verifier.rs`](../src/zkp/global/verifier.rs)<br>[`zkp/channel/mod.rs`](../src/zkp/channel/mod.rs) | Aggregation verifies per-channel STARK proofs (generated via Plonky3) before composing wallets and global roots, providing the proof propagation guarantees outlined for PMC. |


