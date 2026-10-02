//! Deployment ref policy (SPEC-SERVER §9.7): per-ref allowed operation
//! signers and fast-forward-only rules. Programmatic only; native and Worker
//! embedders validate rules before constructing their pipelines.

use std::collections::BTreeSet;

use mkit_attest::grant::{RefPattern, packmap_head};

use crate::error::ServerError;

/// One rule: every ref its pattern matches. Overlapping rules all apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefRule {
    /// The refs the rule covers. A packmap ref is covered through its
    /// head, so no pattern names one.
    pub pattern: RefPattern,
    /// Raw Ed25519 keys of the authenticated operation signers that may
    /// move a matching ref, the owner included; `None` places no limit.
    /// Overlapping rules intersect.
    pub allowed_signers: Option<BTreeSet<[u8; 32]>>,
    /// A matching ref may only fast-forward or be created, for every
    /// principal. It needs indexed mode.
    pub fast_forward_only: bool,
}

/// The deployment's ref rules ([`crate::pipeline::PipelineConfig::ref_policy`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RefPolicy {
    rules: Vec<RefRule>,
}

/// The rule name a ref is matched under: a packmap ref by its head (D5).
fn rule_name(ref_name: &str) -> String {
    packmap_head(ref_name).unwrap_or_else(|| ref_name.to_owned())
}

impl RefPolicy {
    /// Validate patterns and the required indexed fast-forward capability.
    /// # Errors
    /// A malformed pattern or a fast-forward rule without indexed mode.
    pub fn validate_for_indexed(&self, indexed: bool) -> Result<(), ServerError> {
        self.validate()?;
        if self.has_fast_forward_rule() && !indexed {
            return Err(ServerError::invalid_argument(
                "fast-forward-only ref rules require indexed mode",
            ));
        }
        Ok(())
    }
    /// A policy of `rules`.
    #[must_use]
    pub fn new(rules: Vec<RefRule>) -> Self {
        Self { rules }
    }

    /// Whether any rule is fast-forward-only.
    pub(crate) fn has_fast_forward_rule(&self) -> bool {
        self.rules.iter().any(|rule| rule.fast_forward_only)
    }

    /// Startup validation: every pattern is its own parse, so none names a
    /// packmap ref or a malformed name.
    pub(crate) fn validate(&self) -> Result<(), ServerError> {
        for rule in &self.rules {
            if RefPattern::parse(&rule.pattern.to_string()).as_ref() != Ok(&rule.pattern) {
                return Err(ServerError::invalid_argument("invalid ref policy pattern"));
            }
        }
        Ok(())
    }

    /// Whether the authenticated `signer` may move `ref_name`. A matching
    /// signer rule with no auth v2 signer (`None`) denies.
    pub(crate) fn signer_allowed(&self, ref_name: &str, signer: Option<&[u8; 32]>) -> bool {
        let name = rule_name(ref_name);
        self.rules
            .iter()
            .filter(|rule| rule.pattern.matches(&name))
            .filter_map(|rule| rule.allowed_signers.as_ref())
            .all(|allowed| signer.is_some_and(|key| allowed.contains(key)))
    }

    /// Whether a matching rule makes `ref_name` fast-forward-only. Packmaps
    /// have no ancestry, so only their head is checked.
    pub(crate) fn fast_forward_only(&self, ref_name: &str) -> bool {
        packmap_head(ref_name).is_none()
            && self
                .rules
                .iter()
                .any(|rule| rule.fast_forward_only && rule.pattern.matches(ref_name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(pattern: &str, signers: Option<&[[u8; 32]]>, ff: bool) -> RefRule {
        RefRule {
            pattern: RefPattern::parse(pattern).unwrap(),
            allowed_signers: signers.map(|keys| keys.iter().copied().collect()),
            fast_forward_only: ff,
        }
    }

    #[test]
    fn overlapping_signer_rules_intersect_and_packmaps_follow_their_head() {
        let (a, b, c) = ([1; 32], [2; 32], [3; 32]);
        let policy = RefPolicy::new(vec![
            rule("refs/heads/*", Some(&[a, b]), false),
            rule("refs/heads/main", Some(&[b, c]), true),
        ]);
        assert!(policy.validate().is_ok());
        assert!(policy.signer_allowed("refs/heads/main", Some(&b)));
        assert!(!policy.signer_allowed("refs/heads/main", Some(&a)));
        assert!(!policy.signer_allowed("refs/heads/main", Some(&c)));
        assert!(!policy.signer_allowed("refs/heads/main", None));
        assert!(!policy.signer_allowed("refs/mkit/packmap/main", Some(&a)));
        assert!(policy.signer_allowed("refs/mkit/packmap/main", Some(&b)));
        assert!(policy.signer_allowed("refs/tags/v1", None));
        assert!(policy.fast_forward_only("refs/heads/main"));
        assert!(!policy.fast_forward_only("refs/mkit/packmap/main"));
        assert!(!policy.fast_forward_only("refs/heads/dev"));
        // A signer-free rule never denies a missing signer.
        let ff_only = RefPolicy::new(vec![rule("refs/heads/main", None, true)]);
        assert!(ff_only.signer_allowed("refs/heads/main", None));
    }

    #[test]
    fn a_pattern_naming_a_packmap_ref_is_refused_at_startup() {
        let policy = RefPolicy::new(vec![RefRule {
            pattern: RefPattern::Exact("refs/mkit/packmap/main".into()),
            allowed_signers: None,
            fast_forward_only: true,
        }]);
        assert!(policy.validate().is_err());
    }
}
