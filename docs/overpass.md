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
- **Objects**: Channel states (`Open`, `CooperativeClosing`, `ForceClosingPending`, `Closed`) with pubkeys, revocation data, balances, nonce, metadata, timeout configuration, and commitments.
- **Morphisms**: Pure transition functions that advance nonce, enforce invariants, and recompute commitments. Proof-generating paths pair with `prove_channel_transition`.
- **Identity**: Unchanged `Open` state acts as identity morphism.
- **Composition**: Sequential application; e.g., `apply_transfer(apply_transfer(state, amount1), amount2)` ≡ single transfer of `amount1 + amount2`.

#### Wallet Category
- **Objects**: `WalletState` aggregates channel commitments with Poseidon2 hash-chain commitment.
- **Morphisms**: `WalletTransition` operations (`InsertChannel`, `RemoveChannel`) via `apply_insert_channel`, `apply_remove_channel`, `apply_operation`. Commitment recomputed via `compute_commitment_from_channels`; proofs via `prove_wallet_transition`.
- **Identity**: Unchanged `WalletState` acts as identity morphism.
- **Composition**: Sequential application with commitment recomputation at each step.

#### Global Category
- **Objects**: `GlobalState` contains SMT root of all wallet commitments.
- **Morphisms**: SMT composition via `compose_subtree_roots`, `compose_to_global_root`, `update_wallet_commitments`. Proofs verified via `verify_global_root()`. Bitcoin blockchain anchoring via P2A.
- **Identity**: Unchanged `GlobalState` acts as identity morphism.
- **Composition**: SMT subtree composition with proof verification at each level.
- **Terminal Property**: Every wallet morphism factors uniquely through the global root.

#### BitcoinTransactionCategory (BTX)
- **Objects**: UTXO sets describing Bitcoin transaction states.
- **Morphisms**: transitions consuming valid inputs and producing outputs under UTXO rules.
- **Identity & Composition**: empty transactions act as identities; sequential valid transactions compose into new morphisms.


---

## 3. Core Definitions

### 3.1 CompositionMetadata
**Definition 2.** In the original paper, `CompositionMetadata` objects are mathematical triples `C = (label, type_id, data)` describing morphisms between composite types.

In Merkle Morph this mathematical construct is embodied by concrete Rust types in each category:

- **Channel morphisms**: Channel state types with transition functions. The "label" is the transition function name, "type_id" is the channel state type, and "data" includes balances, nonce, commitment, metadata, revocation secrets/pubkeys, and timeout configuration.

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
2. **Pullbacks**: channel aggregation into wallets via `verify_channel_aggregation()` ensures channel proofs match wallet commitments.
3. **Pushouts**: wallet updates propagate to global state via `update_wallet_commitments()` and SMT composition.
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
A PMC-cone $K = (V, \{f_i\}, \mathrm{type\_id}, \mathrm{proofs})$ stores the vertex, the family of proofs, and the type ID. Every pair of morphisms inside the cone must have a witness proof showing their joint validity.

### 4.3 Integration Properties
1. **Morphism Composition**: a composition is valid iff a proof exists
2. **Cone Composition**: cones compose only when a proof of compatibility is provided
3. **Proof Propagation**: every morphism in a PMC-cone carries an explicit proof

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
This framework combines three principal categories:
1. `BTX`: Bitcoin transaction states
2. `WalletState`: wallet-level aggregates
3. `GlobalState`: global summaries

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

The original paper defines `CompositionMetadata` as a mathematical abstraction `C = (label, type_id, data)`. In Merkle Morph each category uses concrete Rust types that embody this concept:

- **Channel Category**: State types (`Open`, `CooperativeClosing`, `ForceClosingPending`, `Closed`) with transition functions. The "label" is the transition function name, "type_id" is the channel state type, and "data" includes balances, nonce, commitment, metadata, revocation secrets/pubkeys, and timeout configuration.

- **Wallet Category**: `WalletState` with `WalletTransition` operations (`InsertChannel`, `RemoveChannel`). The "label" is the `WalletTransition` variant, "type_id" is `WalletState`, and "data" includes the channel ID and commitment.

- **Global Category**: `GlobalState` with SMT composition operations. The "label" is implicit in the composition operation, "type_id" is `GlobalState`, and "data" includes wallet commitments and the SMT root.

Each concrete type provides type-safe composition operations that enforce associativity and preserve proofs at compile time, satisfying the mathematical requirements of the `CompositionMetadata` abstraction without requiring a single unified type.

### 6.2 Channel States as Categorical Objects
The channel category uses a state machine with four distinct state types:

- **`Open`**: Active channel with sender/receiver pubkeys, revocation pubkeys/secrets, balances, nonce, commitment, metadata, and configurable `timeout_blocks`
- **`CooperativeClosing`**: Channel being closed cooperatively with fee allocation
- **`ForceClosingPending`**: Force-closed channel waiting for CSV timeout
- **`Closed`**: Permanently closed channel

Transition functions: `apply_transfer`/`apply_transfer_state_only`, `apply_cooperative_close`, `apply_cooperative_close_with_fee_contributions`, `apply_force_close`, `apply_recover`. All transitions advance the nonce, enforce invariants, and recompute commitments. Proof-generating paths pair with `prove_channel_transition`.

### 6.3 WalletState as a Categorical Object
`WalletState` aggregates channel commitments under a wallet ID, computing a Poseidon2 hash-chain commitment via `compute_commitment_from_channels`.

Transition functions: `apply_insert_channel`, `apply_remove_channel`, `apply_operation`. Operations use `WalletTransition` enum (`InsertChannel`, `RemoveChannel`) and enforce `MAX_CHANNELS` limits.

### 6.4 GlobalState as the Terminal Object
`GlobalState` maintains the SMT root of all wallet commitments. The `changes` field stores local wallet commitments that changed in this transition (only wallets controlled by the local system).

SMT composition functions: `compute_subtree_root`, `compose_subtree_roots`, `compose_to_global_root`, `update_wallet_commitments`. Partition-level composition via `compose_partition_roots`. Proof verification via `verify_global_root()`. Bitcoin anchoring via P2A Taproot outputs with multi-party anchoring support.

#### Witness-Based Verification and Uniqueness Invariant
The **uniqueness invariant** enforces that for any `(wallet_id, prev_global_root)` pair, at most one wallet update may be accepted, preventing double-spending and state inconsistencies in partitioned systems.

`GlobalTransitionWitness` packages transition verification data: `prev_root`, `next_root`, `wallet_id`, old and new wallet commitments, Merkle proofs for both states, and a transition hash. Witnesses are keyed by `(wallet_id, prev_root)` to enforce the uniqueness invariant.

`TransitionWitnessCache` maintains an in-memory cache tracking witnesses by their key. During batch verification, a shared `TransitionWitnessCache` ensures no wallet is updated twice from the same starting state, even when updates appear in different partitions. Witnesses are generated during `update_wallet_commitments()` and verified during `verify_batch_with_cache()`.

### 6.5 BitcoinTransactionCategory (BTX)
BTX implements Bitcoin transactions as categorical morphisms:

- **State structures**: `Utxo`, `TxInputData`, `BitcoinTransaction` with full script support
- **Transition logic**: `empty()`, `is_valid()`, `compose()`, `apply_transaction()`, `validate_transaction_structure()`, `validate_consensus_rules_with_height()`, `validate_with_scripts()`, `validate_p2tr_witnesses()`, `verify_bitcoin_transaction()` for full Bitcoin Core consensus validation
- **Commitment computation**: Poseidon2-based via `compute_btx_commitment()` and `compute_commitment()`
- **Script utilities**: P2TR and P2A script support via `detect_script_type()`, `validate_segwit_spend()`, `validate_taproot_multisig_spend()`. Note: outputs must be P2TR or P2A; legacy/SegWit inputs are allowed.
- **Timelock support**: CSV validation via `compute_sequence_for_blocks()`, `extract_csv_blocks()`, `validate_csv_timelock()`
- **Chain oracle**: `ChainOracle` trait and `MockChainOracle` for chain state queries

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

This table maps mathematical concepts to their implementation. For detailed function lists and type definitions, see the referenced sections.

| Concept | Modules |
| --- | --- |
| [Perfect Mathematical Composability](#21-definition-and-fundamental-concepts) | `zkp/channel/`, `zkp/wallet/`, `zkp/global/` |
| [CompositionMetadata](#31-compositionmetadata) | `channel/`, `wallet/`, `global/` |
| [Channel category](#62-channel-states-as-categorical-objects) | `channel/state/`, `channel/transition/`, `channel/commitment/` |
| [Wallet category](#63-walletstate-as-a-categorical-object) | `wallet/state.rs`, `wallet/transition.rs`, `wallet/commitment.rs` |
| [GlobalState](#64-globalstate-as-the-terminal-object) | `global/state.rs`, `global/commitment/`, `global/anchor/` |
| [BitcoinTransactionCategory](#65-bitcointransactioncategory-btx) | `btx/` |
| [Universal properties](#36-universal-properties) | `global/commitment/`, `zkp/wallet/aggregation.rs` |
| [Functors](#37-functors) | `wallet/commitment.rs`, `global/commitment/subtree.rs` |
| [Cone constructions & PMC-cones](#38-cone-constructions) | `global/commitment/types.rs`, `global/commitment/subtree.rs` |
| [PMC operations](#45-pmc-cone-operations) | `zkp/` |


