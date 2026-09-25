//! Write-quota value types.
//!
//! Defined here, ahead of the quota logic, so the storage traits and the
//! protocol logic can build against one shared set of types. The
//! evaluation function and the default limits join this module later in M0.

use mkit_core::hash::to_hex;

use crate::repo::NamespaceKey;

/// Limits for one fixed quota window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotaLimits {
    /// Window length in milliseconds.
    pub window_ms: i64,
    /// Most write operations allowed per window.
    pub max_ops: u32,
    /// Most bytes allowed per window.
    pub max_bytes: u64,
}

/// Usage recorded in the current window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotaState {
    /// Window start, Unix epoch milliseconds.
    pub window_start: i64,
    /// Operations counted so far.
    pub ops: u32,
    /// Bytes counted so far.
    pub bytes: u64,
}

/// The key a quota is counted under. In M0 that is one signer within one
/// namespace (planner default Q14); the per-namespace aggregate lands in M1.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct QuotaScope(String);

impl QuotaScope {
    /// The scope for `signer` in `ns`: `"<namespace>\n<signer hex>"`.
    #[must_use]
    pub fn for_signer(ns: &NamespaceKey, signer: &[u8; 32]) -> Self {
        Self(format!("{}\n{}", ns.as_str(), to_hex(signer)))
    }

    /// The scope key as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signer_scope_is_namespace_newline_hex() {
        let ns = NamespaceKey::deployment_default();
        let scope = QuotaScope::for_signer(&ns, &[0xab; 32]);
        assert_eq!(scope.as_str(), format!("root\n{}", "ab".repeat(32)));
        assert_ne!(scope, QuotaScope::for_signer(&ns, &[0xac; 32]));
    }
}
