//! Type definitions for global commitment operations

use std::sync::Arc;

use crate::types::{Bytes32, WalletId};
use crate::zkp::types::Proof;

/// Subtree root for incremental verification
///
/// Represents a subtree of the global Sparse Merkle Tree at a specific depth range.
/// The subtree root is computed starting from `start_depth` and not from depth 0,
/// allowing proper composition with other subtrees. This enables verifying only
/// specific wallet ranges while using pre-computed roots for others, then composing
/// them all to verify the global root.
#[derive(Clone)]
pub struct SubtreeRoot {
    /// The subtree root hash (computed from start_depth, not depth 0)
    pub root: Bytes32,
    /// Inclusive range of wallet IDs covered by this subtree
    /// (min_id, max_id) - both endpoints are inclusive
    pub wallet_id_range: (WalletId, WalletId),
    /// The depth at which this subtree starts (0 = from root, increases down the tree)
    /// All wallets in this subtree share the same bit pattern up to start_depth-1
    pub start_depth: u8,
    /// Zero-knowledge proof that this subtree root is valid.
    /// `None` for composed subtrees (which don't have individual proofs).
    pub validity_proof: Option<Arc<Proof>>,
}

impl std::fmt::Debug for SubtreeRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubtreeRoot")
            .field("root", &self.root)
            .field("wallet_id_range", &self.wallet_id_range)
            .field("start_depth", &self.start_depth)
            .field("validity_proof", &"<proof>")
            .finish()
    }
}

impl PartialEq for SubtreeRoot {
    fn eq(&self, other: &Self) -> bool {
        self.root == other.root
            && self.wallet_id_range == other.wallet_id_range
            && self.start_depth == other.start_depth
        // Note: We don't compare proofs in PartialEq as they may differ even for the same subtree
    }
}

impl Eq for SubtreeRoot {}

/// Merkle inclusion proof for a wallet commitment
///
/// A proof that a specific wallet commitment is included in the global root.
/// The proof consists of sibling hashes along the path from the leaf to the root.
/// Each element in the path represents the sibling hash at that depth level.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleProof {
    /// Sibling hashes along the path from leaf to root (depth 0 to max_depth-1)
    /// For each depth, contains the hash of the sibling node (the opposite child)
    pub path: Vec<Bytes32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fmt() {
        let root = [1u8; 32];
        let wallet_id_range = ([2u8; 32], [3u8; 32]);
        let start_depth = 5u8;
        let subtree_root = SubtreeRoot { root, wallet_id_range, start_depth, validity_proof: None };

        let formatted = format!("{:?}", subtree_root);

        assert!(formatted.contains("SubtreeRoot"));
        assert!(formatted.contains("root"));
        assert!(formatted.contains("wallet_id_range"));
        assert!(formatted.contains("start_depth"));
        assert!(formatted.contains("<proof>"));
    }

    #[test]
    fn test_eq() {
        let root1 = [1u8; 32];
        let root2 = [2u8; 32];
        let wallet_id_range1 = ([3u8; 32], [4u8; 32]);
        let wallet_id_range2 = ([5u8; 32], [6u8; 32]);
        let start_depth1 = 7u8;
        let start_depth2 = 8u8;

        let subtree1 = SubtreeRoot {
            root: root1,
            wallet_id_range: wallet_id_range1,
            start_depth: start_depth1,
            validity_proof: None,
        };

        let subtree2 = SubtreeRoot {
            root: root1,
            wallet_id_range: wallet_id_range1,
            start_depth: start_depth1,
            validity_proof: None,
        };

        let subtree3 = SubtreeRoot {
            root: root2,
            wallet_id_range: wallet_id_range1,
            start_depth: start_depth1,
            validity_proof: None,
        };

        let subtree4 = SubtreeRoot {
            root: root1,
            wallet_id_range: wallet_id_range2,
            start_depth: start_depth1,
            validity_proof: None,
        };

        let subtree5 = SubtreeRoot {
            root: root1,
            wallet_id_range: wallet_id_range1,
            start_depth: start_depth2,
            validity_proof: None,
        };

        assert!(subtree1 == subtree2);
        assert!(!(subtree1 == subtree3));
        assert!(!(subtree1 == subtree4));
        assert!(!(subtree1 == subtree5));
    }
}
