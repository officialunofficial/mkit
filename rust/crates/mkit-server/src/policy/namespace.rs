use std::collections::BTreeSet;

use mkit_core::repo_identity::Namespace;

/// Namespaces served for writes (SPEC-TRANSPORT-CONNECT §7.5).
/// A denial cannot be overridden by an authorizer (SPEC-SERVER §6.2).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NamespacePolicy {
    /// Only these owner namespaces may receive writes. The default is empty.
    Allowlist(BTreeSet<Namespace>),
    /// Every self-certifying namespace may receive writes. D27 requires
    /// non-default admission unless the operator explicitly accepts the risk.
    Any {
        /// Permit default admission despite new keys resetting namespace quotas.
        unsafe_without_admission: bool,
    },
}

impl Default for NamespacePolicy {
    fn default() -> Self {
        Self::Allowlist(BTreeSet::new())
    }
}
