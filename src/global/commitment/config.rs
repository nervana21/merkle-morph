//! Configuration implementations for SMT operations

use crate::global::smt::SmtConfig;

/// Merkle Morph v0 configuration for SMT operations
///
/// This struct implements the [`SmtConfig`] trait with the domain tags and
/// parameters specified by the Merkle Morph v0 protocol.
#[derive(Clone, Copy, Debug, Default)]
pub struct MerkleMorphV0Config;

impl SmtConfig for MerkleMorphV0Config {
    fn leaf_domain_tag(&self) -> &[u8] { b"MM_WLT_v0" }

    fn internal_domain_tag(&self) -> &[u8] { b"MM_GLOBAL_v0" }

    fn max_depth(&self) -> u8 {
        255 // 256-bit wallet IDs, 0-indexed depth
    }
}

/// Default config instance (Merkle Morph v0)
pub(crate) const DEFAULT_CONFIG: MerkleMorphV0Config = MerkleMorphV0Config;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leaf_domain_tag() {
        let config = MerkleMorphV0Config;
        assert_eq!(config.leaf_domain_tag(), b"MM_WLT_v0");
    }

    #[test]
    fn test_internal_domain_tag() {
        let config = MerkleMorphV0Config;
        assert_eq!(config.internal_domain_tag(), b"MM_GLOBAL_v0");
    }

    #[test]
    fn test_max_depth() {
        let config = MerkleMorphV0Config;
        assert_eq!(config.max_depth(), 255);
    }
}
