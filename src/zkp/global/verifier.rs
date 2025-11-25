//! Global-level proof verification
//!
//! Verifies that wallet proofs are valid and that wallet commitments
//! are correctly composed into the global root. Global state
//! transitions are anchored to Bitcoin to ensure global ordering.
//! Also provides zero-knowledge proof verification for global root composition.

use std::collections::BTreeMap;

use p3_uni_stark::verify;

use crate::errors::ZkpError::{InvalidAir, ProofVerificationFailed};
use crate::global::commitment::{compose_to_global_root, compute_subtree_root, SubtreeRoot};
use crate::global::GlobalState;
use crate::types::{WalletCommitment, WalletId};
use crate::wallet::commitment::compute_commitment_from_channels;
use crate::wallet::WalletState;
use crate::zkp::global::air::GlobalRootCompositionAir;
use crate::zkp::subtree::{verify_subtree_root_validity, SubtreeRootPublicInput};
use crate::zkp::verifier_common::build_public_values_from_id_and_commitment;
use crate::zkp::{verify_wallet_commitment, WalletPublicInputs};
use crate::{Bytes32, Proof, Result, StarkConfig};

/// A collection of wallets with their proofs
///
/// This type represents wallets that are being verified directly (with full state and proofs)
/// at the global level. A single wallet is represented as a collection with one entry.
///
/// # Examples
///
/// ```no_run
/// use merkle_morph::zkp::global::{WalletsWithProofs, verify_global_root};
/// use merkle_morph::zkp::types::create_config;
/// use merkle_morph::zkp::prove_wallet_commitment;
/// use merkle_morph::wallet::WalletState;
/// use merkle_morph::global::GlobalState;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = create_config()?;
/// let mut wallets_with_proofs = WalletsWithProofs::new();
/// let wallet = WalletState::new([0u8; 32]);
/// let proof = prove_wallet_commitment(&config, &wallet)?;
/// wallets_with_proofs.insert([0u8; 32], wallet, proof);
/// # Ok(())
/// # }
/// ```
#[derive(Default)]
pub struct WalletsWithProofs {
    inner: BTreeMap<WalletId, (WalletState, Proof)>,
}

impl std::fmt::Debug for WalletsWithProofs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalletsWithProofs").field("len", &self.inner.len()).finish()
    }
}

impl WalletsWithProofs {
    /// Creates a new empty collection of wallets with proofs
    pub fn new() -> Self { Self { inner: BTreeMap::new() } }

    /// Inserts a wallet with proof into the collection
    ///
    /// # Arguments
    /// * `wallet_id` - The wallet identifier
    /// * `state` - The wallet state
    /// * `proof` - The zero-knowledge proof for the wallet commitment
    pub fn insert(&mut self, wallet_id: WalletId, state: WalletState, proof: Proof) {
        self.inner.insert(wallet_id, (state, proof));
    }

    /// Inserts a wallet with proof into the collection with validation
    ///
    /// Validates that the proof is valid for the given wallet state before insertion.
    ///
    /// # Arguments
    /// * `config` - STARK configuration for proof verification
    /// * `wallet_id` - The wallet identifier
    /// * `state` - The wallet state
    /// * `proof` - The zero-knowledge proof for the wallet commitment
    ///
    /// # Returns
    /// * `Ok(())` - If the proof is valid and the wallet was inserted
    /// * `Err` - If the proof verification fails
    pub fn try_insert(
        &mut self,
        config: &StarkConfig,
        wallet_id: WalletId,
        state: WalletState,
        proof: Proof,
    ) -> Result<()> {
        let wallet_commitment = compute_commitment_from_channels(state.id, &state.channels)?;
        let public_inputs = WalletPublicInputs { wallet_id, wallet_commitment };
        verify_wallet_commitment(config, &public_inputs, &proof)?;
        self.inner.insert(wallet_id, (state, proof));
        Ok(())
    }

    /// Returns `true` if the collection is empty
    pub fn is_empty(&self) -> bool { self.inner.is_empty() }

    /// Returns the number of wallets with proofs in the collection
    pub fn len(&self) -> usize { self.inner.len() }

    /// Returns an iterator over the wallets with proofs
    ///
    /// The iterator yields tuples of `(wallet_id, (state, proof))`.
    pub fn iter(&self) -> impl Iterator<Item = (&WalletId, &(WalletState, Proof))> {
        self.inner.iter()
    }

    /// Returns a reference to the wallet state and proof for a given wallet ID
    pub fn get(&self, wallet_id: &WalletId) -> Option<&(WalletState, Proof)> {
        self.inner.get(wallet_id)
    }
}

impl IntoIterator for WalletsWithProofs {
    type Item = (WalletId, (WalletState, Proof));
    type IntoIter = std::collections::btree_map::IntoIter<WalletId, (WalletState, Proof)>;

    fn into_iter(self) -> Self::IntoIter { self.inner.into_iter() }
}

impl<'a> IntoIterator for &'a WalletsWithProofs {
    type Item = (&'a WalletId, &'a (WalletState, Proof));
    type IntoIter = std::collections::btree_map::Iter<'a, WalletId, (WalletState, Proof)>;

    fn into_iter(self) -> Self::IntoIter { self.inner.iter() }
}

impl From<BTreeMap<WalletId, (WalletState, Proof)>> for WalletsWithProofs {
    fn from(inner: BTreeMap<WalletId, (WalletState, Proof)>) -> Self { Self { inner } }
}

impl From<WalletsWithProofs> for BTreeMap<WalletId, (WalletState, Proof)> {
    fn from(wallets_with_proofs: WalletsWithProofs) -> Self { wallets_with_proofs.inner }
}

/// Verify global root
///
/// Verifies that wallet commitments compose correctly into the global root.
///
/// Takes wallet states and proofs for wallets to verify directly (with full state/proofs),
/// along with optional subtree roots for other wallet ID ranges. Composes these into the
/// global root and verifies against the global state.
///
/// The function verifies:
/// 1. All wallet proofs are valid
/// 2. Subtree roots can be composed to form the global root
/// 3. The computed global root matches the global state root
/// 4. Optionally, the root matches the blockchain-anchored root
///
/// # Arguments
/// * `config` - STARK configuration for proof verification
/// * `global_state` - Global state with the anchored root to verify against
/// * `wallets_with_proofs` - Collection of wallets with proofs to verify directly
/// * `subtree_roots` - Subtree roots for other wallet ID ranges (empty if only verifying wallets with proofs)
/// * `blockchain_root` - Optional blockchain-anchored root to verify against
///
/// # Returns
/// Ok if all verifications pass, Err otherwise
///
/// # Examples
///
/// ```no_run
/// use merkle_morph::zkp::global::{verify_global_root, WalletsWithProofs};
/// use merkle_morph::zkp::types::create_config;
/// use merkle_morph::zkp::prove_wallet_commitment;
/// use merkle_morph::global::GlobalState;
/// use merkle_morph::wallet::WalletState;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = create_config()?;
/// let global_state = GlobalState::default();
/// let mut wallets_with_proofs = WalletsWithProofs::new();
/// let wallet = WalletState::new([0u8; 32]);
/// let proof = prove_wallet_commitment(&config, &wallet)?;
/// wallets_with_proofs.insert([0u8; 32], wallet, proof);
///
/// verify_global_root(&config, &global_state, &wallets_with_proofs, &[], None)?;
/// # Ok(())
/// # }
/// ```
pub fn verify_global_root(
    config: &StarkConfig,
    global_state: &GlobalState,
    wallets_with_proofs: &WalletsWithProofs,
    subtree_roots: &[SubtreeRoot],
    blockchain_root: Option<crate::types::Bytes32>,
) -> Result<()> {
    // Verify all wallet proofs
    for (wallet_id, (state, proof)) in wallets_with_proofs.iter() {
        let wallet_commitment: WalletCommitment =
            compute_commitment_from_channels(state.id, &state.channels)?;
        let public_inputs = WalletPublicInputs { wallet_id: *wallet_id, wallet_commitment };
        verify_wallet_commitment(config, &public_inputs, proof)?;
    }

    // Create individual subtrees for each local wallet with proof
    let mut all_subtrees = Vec::new();
    for (wallet_id, (state, _proof)) in wallets_with_proofs.iter() {
        let wallet_commitment: WalletCommitment =
            compute_commitment_from_channels(state.id, &state.channels)?;
        let mut wallet_map = BTreeMap::new();
        wallet_map.insert(*wallet_id, wallet_commitment);
        let subtree = compute_subtree_root(config, &wallet_map, *wallet_id, *wallet_id)?;
        all_subtrees.push(subtree);
    }

    // Verify subtree proofs for pre-computed subtree roots
    // Only verify subtrees that have proofs (composed subtrees have None)
    for subtree in subtree_roots.iter() {
        if let Some(proof) = &subtree.validity_proof {
            let public_inputs: SubtreeRootPublicInput = subtree.root;
            verify_subtree_root_validity(config, proof.as_ref(), &public_inputs)?;
        }
    }

    // Add pre-computed subtree roots for wallet ID ranges not verified with full proofs
    all_subtrees.extend_from_slice(subtree_roots);
    all_subtrees.sort_by_key(|s| s.wallet_id_range.0);

    // Verify no subtree overlaps
    for pair in all_subtrees.windows(2) {
        if pair[0].wallet_id_range.1 > pair[1].wallet_id_range.0 {
            return Err(InvalidAir.into());
        }
    }

    // Compose all subtrees to get the global root
    let computed_root = compose_to_global_root(&all_subtrees)?;

    if computed_root != global_state.wallets_root {
        return Err(InvalidAir.into());
    }

    if let Some(blockchain_root) = blockchain_root {
        if computed_root != blockchain_root {
            return Err(InvalidAir.into());
        }
    }

    Ok(())
}

/// Verify a zero-knowledge proof for global root composition
///
/// This function verifies that subtree roots were correctly composed into a global root.
/// The proof demonstrates that the global root is the result of composing the subtree roots
/// following the Sparse Merkle Tree (SMT) structure with Poseidon2 hashing.
///
/// # Arguments
/// * `config` - Proof system configuration (`StarkConfig`)
/// * `global_root` - The global root to verify
/// * `proof` - Zero-knowledge proof to verify
///
/// # Returns
/// * `Ok(())` - If the proof is valid
/// * `Err(ZkpError::ProofVerificationFailed)` - If the proof verification fails
pub fn verify_global_root_composition(
    config: &StarkConfig,
    global_root: Bytes32,
    proof: &Proof,
) -> Result<()> {
    let air = GlobalRootCompositionAir::new();
    let public_values = build_public_values_from_id_and_commitment([0u8; 32], global_root);

    verify(config, &air, proof, &public_values).map_err(|_| ProofVerificationFailed)?;

    Ok(())
}

/// Builder for global root verification
///
/// Provides a fluent API for constructing complex verification scenarios.
/// This makes it easier to build up verification requests with multiple
/// wallets with proofs and subtree roots.
///
/// # Examples
///
/// ```no_run
/// use merkle_morph::zkp::global::GlobalRootVerifier;
/// use merkle_morph::zkp::types::create_config;
/// use merkle_morph::zkp::prove_wallet_commitment;
/// use merkle_morph::global::GlobalState;
/// use merkle_morph::wallet::WalletState;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = create_config()?;
/// let global_state = GlobalState::default();
///
/// let wallet1 = WalletState::new([1u8; 32]);
/// let proof1 = prove_wallet_commitment(&config, &wallet1)?;
/// let wallet2 = WalletState::new([2u8; 32]);
/// let proof2 = prove_wallet_commitment(&config, &wallet2)?;
///
/// GlobalRootVerifier::new(&config, &global_state)
///     .with_wallet_proof([1u8; 32], wallet1, proof1)
///     .with_wallet_proof([2u8; 32], wallet2, proof2)
///     .verify()?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct GlobalRootVerifier<'a> {
    config: &'a StarkConfig,
    global_state: &'a GlobalState,
    wallets_with_proofs: WalletsWithProofs,
    subtree_roots: Vec<SubtreeRoot>,
    blockchain_root: Option<crate::types::Bytes32>,
}

impl<'a> GlobalRootVerifier<'a> {
    /// Creates a new `GlobalRootVerifier` builder
    ///
    /// # Arguments
    /// * `config` - STARK configuration for proof verification
    /// * `global_state` - Global state with the anchored root to verify against
    pub fn new(config: &'a StarkConfig, global_state: &'a GlobalState) -> Self {
        Self {
            config,
            global_state,
            wallets_with_proofs: WalletsWithProofs::new(),
            subtree_roots: Vec::new(),
            blockchain_root: None,
        }
    }

    /// Adds a single wallet with proof to the verification
    ///
    /// # Arguments
    /// * `wallet_id` - The wallet identifier
    /// * `state` - The wallet state
    /// * `proof` - The zero-knowledge proof for the wallet
    ///
    /// # Returns
    /// `self` for method chaining
    pub fn with_wallet_proof(
        mut self,
        wallet_id: WalletId,
        state: WalletState,
        proof: Proof,
    ) -> Self {
        self.wallets_with_proofs.insert(wallet_id, state, proof);
        self
    }

    /// Adds multiple wallets with proofs to the verification
    ///
    /// # Arguments
    /// * `wallets_with_proofs` - Collection of wallets with proofs to add
    ///
    /// # Returns
    /// `self` for method chaining
    pub fn with_wallets_with_proofs(mut self, wallets_with_proofs: WalletsWithProofs) -> Self {
        for (wallet_id, (state, proof)) in wallets_with_proofs.into_iter() {
            self.wallets_with_proofs.insert(wallet_id, state, proof);
        }
        self
    }

    /// Adds a single subtree root to the verification
    ///
    /// # Arguments
    /// * `subtree` - The subtree root to add
    ///
    /// # Returns
    /// `self` for method chaining
    pub fn with_subtree_root(mut self, subtree: SubtreeRoot) -> Self {
        self.subtree_roots.push(subtree);
        self
    }

    /// Adds multiple subtree roots to the verification
    ///
    /// # Arguments
    /// * `subtrees` - Slice of subtree roots to add
    ///
    /// # Returns
    /// `self` for method chaining
    pub fn with_subtree_roots(mut self, subtrees: &[SubtreeRoot]) -> Self {
        self.subtree_roots.extend_from_slice(subtrees);
        self
    }

    /// Sets the blockchain root to verify against
    ///
    /// # Arguments
    /// * `root` - The blockchain-anchored root
    ///
    /// # Returns
    /// `self` for method chaining
    pub fn with_blockchain_root(mut self, root: crate::types::Bytes32) -> Self {
        self.blockchain_root = Some(root);
        self
    }

    /// Executes the verification
    ///
    /// # Returns
    /// Ok if all verifications pass, Err otherwise
    pub fn verify(self) -> Result<()> {
        verify_global_root(
            self.config,
            self.global_state,
            &self.wallets_with_proofs,
            &self.subtree_roots,
            self.blockchain_root,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::global::commitment::{compose_to_global_root, compute_subtree_root};
    use crate::wallet::commitment::compute_commitment_from_channels;
    use crate::zkp::global::prover::prove_global_root_composition;
    use crate::zkp::prove_wallet_commitment;
    use crate::zkp::types::create_config;

    fn create_test_config() -> StarkConfig { create_config().expect("Should create config") }

    fn create_test_wallet_with_proof(
        config: &StarkConfig,
        wallet_id: u8,
        channels: &[(u8, u8)],
    ) -> (WalletState, Proof) {
        let mut map = BTreeMap::new();
        for (cid, comm) in channels.iter() {
            let mut channel_id = [0u8; 32];
            channel_id[31] = *cid;

            let mut channel_commitment = [0u8; 32];
            channel_commitment[31] = *comm;

            map.insert(channel_id, channel_commitment);
        }
        let mut wallet = WalletState::from_channels([wallet_id; 32], map);
        wallet.commitment = compute_commitment_from_channels(wallet.id, &wallet.channels)
            .expect("should compute commitment");

        let proof =
            prove_wallet_commitment(config, &wallet).expect("Should generate proof for wallet");

        (wallet, proof)
    }

    fn create_test_global_state(
        wallet_commitments: &BTreeMap<WalletId, crate::types::WalletCommitment>,
    ) -> GlobalState {
        let config = create_test_config();
        let mut subtrees = Vec::new();
        for (wallet_id, commitment) in wallet_commitments.iter() {
            let mut wallet_map = BTreeMap::new();
            wallet_map.insert(*wallet_id, *commitment);
            let subtree = compute_subtree_root(&config, &wallet_map, *wallet_id, *wallet_id)
                .expect("Should compute subtree");
            subtrees.push(subtree);
        }
        subtrees.sort_by_key(|s| s.wallet_id_range.0);
        let wallets_root =
            compose_to_global_root(&subtrees).expect("Should compose to global root");
        let nonce = wallet_commitments.len() as u32;
        GlobalState::with_root_and_nonce(wallets_root, nonce)
    }

    #[test]
    fn test_verify_global_root() {
        let config = create_test_config();

        // Success case: Only wallets with proofs, no subtree_roots, no blockchain_root
        {
            let (wallet1, proof1) = create_test_wallet_with_proof(&config, 1, &[(10, 20)]);
            let mut wallets_with_proofs = WalletsWithProofs::new();
            wallets_with_proofs.insert(wallet1.id, wallet1.clone(), proof1);

            let mut wallet_commitments = BTreeMap::new();
            wallet_commitments.insert(wallet1.id, wallet1.commitment);
            let global_state = create_test_global_state(&wallet_commitments);

            verify_global_root(&config, &global_state, &wallets_with_proofs, &[], None)
                .expect("Should verify successfully with only wallets with proofs");
        }

        // Success case: Only wallets with proofs, with matching blockchain_root
        {
            let (wallet1, proof1) = create_test_wallet_with_proof(&config, 2, &[(11, 21)]);
            let mut wallets_with_proofs = WalletsWithProofs::new();
            wallets_with_proofs.insert(wallet1.id, wallet1.clone(), proof1);

            let mut wallet_commitments = BTreeMap::new();
            wallet_commitments.insert(wallet1.id, wallet1.commitment);
            let global_state = create_test_global_state(&wallet_commitments);
            let blockchain_root = global_state.wallets_root;

            verify_global_root(
                &config,
                &global_state,
                &wallets_with_proofs,
                &[],
                Some(blockchain_root),
            )
            .expect("Should verify successfully with matching blockchain_root");
        }

        // Success case: Wallets with proofs + non-overlapping subtree_roots
        {
            let (wallet1, proof1) = create_test_wallet_with_proof(&config, 3, &[(12, 22)]);
            let (wallet2, proof2) = create_test_wallet_with_proof(&config, 4, &[(13, 23)]);
            let mut wallets_with_proofs = WalletsWithProofs::new();
            wallets_with_proofs.insert(wallet1.id, wallet1.clone(), proof1);
            wallets_with_proofs.insert(wallet2.id, wallet2.clone(), proof2);

            // Create subtree for wallet ID range [10, 10] (non-overlapping with proven wallets 3 and 4)
            let mut other_wallet_commitments = BTreeMap::new();
            let (other_wallet, _) = create_test_wallet_with_proof(&config, 10, &[(14, 24)]);
            other_wallet_commitments.insert(other_wallet.id, other_wallet.commitment);
            let subtree = compute_subtree_root(
                &config,
                &other_wallet_commitments,
                other_wallet.id,
                other_wallet.id,
            )
            .expect("Should compute subtree root");

            let mut wallet_commitments = BTreeMap::new();
            wallet_commitments.insert(wallet1.id, wallet1.commitment);
            wallet_commitments.insert(wallet2.id, wallet2.commitment);
            wallet_commitments.insert(other_wallet.id, other_wallet.commitment);
            let global_state = create_test_global_state(&wallet_commitments);

            verify_global_root(&config, &global_state, &wallets_with_proofs, &[subtree], None)
                .expect("Should verify successfully with wallets with proofs and non-overlapping subtree_roots");
        }

        // Success case: Wallets with proofs + subtree_roots with matching blockchain_root
        {
            let (wallet1, proof1) = create_test_wallet_with_proof(&config, 5, &[(15, 25)]);
            let mut wallets_with_proofs = WalletsWithProofs::new();
            wallets_with_proofs.insert(wallet1.id, wallet1.clone(), proof1);

            // Create subtree for wallet ID range [20, 20] (non-overlapping)
            let mut other_wallet_commitments = BTreeMap::new();
            let (other_wallet, _) = create_test_wallet_with_proof(&config, 20, &[(16, 26)]);
            other_wallet_commitments.insert(other_wallet.id, other_wallet.commitment);
            let subtree = compute_subtree_root(
                &config,
                &other_wallet_commitments,
                other_wallet.id,
                other_wallet.id,
            )
            .expect("Should compute subtree root");

            let mut wallet_commitments = BTreeMap::new();
            wallet_commitments.insert(wallet1.id, wallet1.commitment);
            wallet_commitments.insert(other_wallet.id, other_wallet.commitment);
            let global_state = create_test_global_state(&wallet_commitments);
            let blockchain_root = global_state.wallets_root;

            verify_global_root(
                &config,
                &global_state,
                &wallets_with_proofs,
                &[subtree],
                Some(blockchain_root),
            )
                .expect("Should verify successfully with wallets with proofs, subtree_roots and matching blockchain_root");
        }

        // Error case: Invalid wallet proof (wrong wallet_id)
        {
            let (wallet1, _) = create_test_wallet_with_proof(&config, 6, &[(17, 27)]);
            let (_wallet2, proof2) = create_test_wallet_with_proof(&config, 7, &[(18, 28)]);
            let mut wallets_with_proofs = WalletsWithProofs::new();
            // Use proof2 (for wallet2) with wallet1 (wrong wallet_id)
            wallets_with_proofs.insert(wallet1.id, wallet1.clone(), proof2);

            let mut wallet_commitments = BTreeMap::new();
            wallet_commitments.insert(wallet1.id, wallet1.commitment);
            let global_state = create_test_global_state(&wallet_commitments);

            let result =
                verify_global_root(&config, &global_state, &wallets_with_proofs, &[], None);
            assert!(result.is_err(), "Should fail with invalid wallet proof");
        }

        // Error case: Overlapping subtrees
        {
            let (wallet1, proof1) = create_test_wallet_with_proof(&config, 8, &[(19, 29)]);
            let mut wallets_with_proofs = WalletsWithProofs::new();
            wallets_with_proofs.insert(wallet1.id, wallet1.clone(), proof1);

            // Create overlapping subtrees: [10, 15] and [12, 20] where 15 > 12
            let mut subtree1_wallets = BTreeMap::new();
            let (subtree1_wallet, _) = create_test_wallet_with_proof(&config, 10, &[(20, 30)]);
            subtree1_wallets.insert(subtree1_wallet.id, subtree1_wallet.commitment);
            let mut wallet_id_min = [0u8; 32];
            wallet_id_min[31] = 10;
            let mut wallet_id_max = [0u8; 32];
            wallet_id_max[31] = 15;
            let subtree1 =
                compute_subtree_root(&config, &subtree1_wallets, wallet_id_min, wallet_id_max)
                    .expect("Should compute subtree root");

            let mut subtree2_wallets = BTreeMap::new();
            let (subtree2_wallet, _) = create_test_wallet_with_proof(&config, 12, &[(21, 31)]);
            subtree2_wallets.insert(subtree2_wallet.id, subtree2_wallet.commitment);
            let mut wallet_id_min2 = [0u8; 32];
            wallet_id_min2[31] = 12;
            let mut wallet_id_max2 = [0u8; 32];
            wallet_id_max2[31] = 20;
            let subtree2 =
                compute_subtree_root(&config, &subtree2_wallets, wallet_id_min2, wallet_id_max2)
                    .expect("Should compute subtree root");

            let mut wallet_commitments = BTreeMap::new();
            wallet_commitments.insert(wallet1.id, wallet1.commitment);
            let global_state = create_test_global_state(&wallet_commitments);

            let result = verify_global_root(
                &config,
                &global_state,
                &wallets_with_proofs,
                &[subtree1, subtree2],
                None,
            );
            assert!(result.is_err(), "Should fail with overlapping subtrees");
        }

        // Error case: Root mismatch with global_state
        {
            let (wallet1, proof1) = create_test_wallet_with_proof(&config, 9, &[(22, 32)]);
            let mut wallets_with_proofs = WalletsWithProofs::new();
            wallets_with_proofs.insert(wallet1.id, wallet1.clone(), proof1);

            // Create global_state with wrong root
            let wrong_root = [0xFFu8; 32];
            let global_state = GlobalState::with_root_and_nonce(wrong_root, 1);

            let result =
                verify_global_root(&config, &global_state, &wallets_with_proofs, &[], None);
            assert!(result.is_err(), "Should fail when root doesn't match global_state");
        }

        // Error case: Root mismatch with blockchain_root
        {
            let (wallet1, proof1) = create_test_wallet_with_proof(&config, 11, &[(23, 33)]);
            let mut wallets_with_proofs = WalletsWithProofs::new();
            wallets_with_proofs.insert(wallet1.id, wallet1.clone(), proof1);

            let mut wallet_commitments = BTreeMap::new();
            wallet_commitments.insert(wallet1.id, wallet1.commitment);
            let global_state = create_test_global_state(&wallet_commitments);

            // Provide wrong blockchain_root
            let wrong_blockchain_root = [0xAAu8; 32];

            let result = verify_global_root(
                &config,
                &global_state,
                &wallets_with_proofs,
                &[],
                Some(wrong_blockchain_root),
            );
            assert!(result.is_err(), "Should fail when root doesn't match blockchain_root");
        }
    }

    #[test]
    fn test_global_root_verifier_builder() {
        let config = create_test_config();

        // Test builder with single wallet
        {
            let (wallet1, proof1) = create_test_wallet_with_proof(&config, 13, &[(25, 35)]);
            let mut wallet_commitments = BTreeMap::new();
            wallet_commitments.insert(wallet1.id, wallet1.commitment);
            let global_state = create_test_global_state(&wallet_commitments);

            GlobalRootVerifier::new(&config, &global_state)
                .with_wallet_proof(wallet1.id, wallet1.clone(), proof1)
                .verify()
                .expect("Should verify successfully with builder");
        }

        // Test builder with multiple wallets
        {
            let (wallet1, proof1) = create_test_wallet_with_proof(&config, 14, &[(26, 36)]);
            let (wallet2, proof2) = create_test_wallet_with_proof(&config, 15, &[(27, 37)]);
            let mut wallet_commitments = BTreeMap::new();
            wallet_commitments.insert(wallet1.id, wallet1.commitment);
            wallet_commitments.insert(wallet2.id, wallet2.commitment);
            let global_state = create_test_global_state(&wallet_commitments);

            GlobalRootVerifier::new(&config, &global_state)
                .with_wallet_proof(wallet1.id, wallet1.clone(), proof1)
                .with_wallet_proof(wallet2.id, wallet2.clone(), proof2)
                .verify()
                .expect("Should verify successfully with multiple wallets");
        }

        // Test builder with subtree
        {
            let (wallet1, proof1) = create_test_wallet_with_proof(&config, 16, &[(28, 38)]);
            let mut other_wallet_commitments = BTreeMap::new();
            let (other_wallet, _) = create_test_wallet_with_proof(&config, 30, &[(40, 50)]);
            other_wallet_commitments.insert(other_wallet.id, other_wallet.commitment);
            let subtree = compute_subtree_root(
                &config,
                &other_wallet_commitments,
                other_wallet.id,
                other_wallet.id,
            )
            .expect("Should compute subtree root");

            let mut wallet_commitments = BTreeMap::new();
            wallet_commitments.insert(wallet1.id, wallet1.commitment);
            wallet_commitments.insert(other_wallet.id, other_wallet.commitment);
            let global_state = create_test_global_state(&wallet_commitments);

            GlobalRootVerifier::new(&config, &global_state)
                .with_wallet_proof(wallet1.id, wallet1.clone(), proof1)
                .with_subtree_root(subtree)
                .verify()
                .expect("Should verify successfully with subtree");
        }

        // Test builder with blockchain root
        {
            let (wallet1, proof1) = create_test_wallet_with_proof(&config, 17, &[(29, 39)]);
            let mut wallet_commitments = BTreeMap::new();
            wallet_commitments.insert(wallet1.id, wallet1.commitment);
            let global_state = create_test_global_state(&wallet_commitments);
            let blockchain_root = global_state.wallets_root;

            GlobalRootVerifier::new(&config, &global_state)
                .with_wallet_proof(wallet1.id, wallet1.clone(), proof1)
                .with_blockchain_root(blockchain_root)
                .verify()
                .expect("Should verify successfully with blockchain root");
        }
    }

    #[test]
    fn test_verify_global_root_composition() {
        let config = create_test_config();

        let mut commitments = BTreeMap::new();
        commitments.insert([1u8; 32], [2u8; 32]);
        let subtree = compute_subtree_root(&config, &commitments, [1u8; 32], [1u8; 32])
            .expect("Should compute subtree");

        let proof = prove_global_root_composition(&config, std::slice::from_ref(&subtree))
            .expect("Should generate proof");

        let global_root = compose_to_global_root(&[subtree]).expect("Should compute global root");

        verify_global_root_composition(&config, global_root, &proof)
            .expect("Should verify valid proof");
    }

    #[test]
    fn test_verify_global_root_composition_fails_wrong_root() {
        let config = create_test_config();

        let mut commitments = BTreeMap::new();
        commitments.insert([1u8; 32], [2u8; 32]);
        let subtree = compute_subtree_root(&config, &commitments, [1u8; 32], [1u8; 32])
            .expect("Should compute subtree");

        let proof =
            prove_global_root_composition(&config, &[subtree]).expect("Should generate proof");

        let wrong_root = [0xFFu8; 32];

        assert!(
            verify_global_root_composition(&config, wrong_root, &proof).is_err(),
            "Verification should fail with wrong root"
        );
    }
}
