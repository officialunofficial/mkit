//! Domain-separated commitments to fact values, used by [`RequiredGuard::Row`].
//!
//! A commitment is a semantic comparison token, not a wire or storage format.
//! Every field is length- or tag-prefixed, so two different values never share
//! an input stream. The encoding may change with the crate version, so a host
//! never persists a commitment: it recomputes it from the fact it observes.
//!
//! [`RequiredGuard::Row`]: super::RequiredGuard::Row

use super::{AuthorityFact, AuthorityMode, GrantFact, Observed};
use crate::evidence::Revision;
use mkit_core::hash::{Hash, Hasher};

/// An incremental, domain-separated commitment.
pub(crate) struct Commit(Hasher);

impl Commit {
    pub(crate) fn new(domain: &str) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(b"mkit-primitives/guard-row/v1\0");
        hasher.update(&(domain.len() as u64).to_le_bytes());
        hasher.update(domain.as_bytes());
        Self(hasher)
    }
    pub(crate) fn u8(&mut self, value: u8) -> &mut Self {
        self.0.update(&[value]);
        self
    }
    pub(crate) fn bool(&mut self, value: bool) -> &mut Self {
        self.u8(u8::from(value))
    }
    pub(crate) fn u64(&mut self, value: u64) -> &mut Self {
        self.0.update(&value.to_le_bytes());
        self
    }
    pub(crate) fn hash(&mut self, value: &Hash) -> &mut Self {
        self.0.update(value);
        self
    }
    pub(crate) fn revision(&mut self, value: &Revision) -> &mut Self {
        self.hash(&value.0)
    }
    pub(crate) fn bytes(&mut self, value: &[u8]) -> &mut Self {
        self.u64(value.len() as u64);
        self.0.update(value);
        self
    }
    pub(crate) fn opt_hash(&mut self, value: Option<&Hash>) -> &mut Self {
        match value {
            Some(hash) => self.u8(1).hash(hash),
            None => self.u8(0),
        }
    }
    pub(crate) fn hashes(&mut self, values: &[Hash]) -> &mut Self {
        self.u64(values.len() as u64);
        for value in values {
            self.hash(value);
        }
        self
    }
    pub(crate) fn finish(&self) -> Hash {
        self.0.finalize()
    }
}

/// Map an observation to its commitment, keeping the revision or absence.
pub(crate) fn observe<T>(
    observed: &Observed<T>,
    commit: impl FnOnce(&T) -> Hash,
) -> Observed<Hash> {
    match observed {
        Observed::Absent(revision) => Observed::Absent(*revision),
        Observed::Present { value, revision } => Observed::Present {
            value: commit(value),
            revision: *revision,
        },
    }
}

/// A revision-only observation: its commitment is the revision itself.
pub(crate) fn revision_row(revision: Revision) -> Observed<Hash> {
    Observed::Present {
        value: revision.0,
        revision,
    }
}

/// Commitment to an authority observation (used inside composite rows).
pub(crate) fn authority(commit: &mut Commit, fact: &AuthorityFact) {
    commit
        .hash(&fact.namespace.0)
        .u8(match fact.mode {
            AuthorityMode::SelfCertifying => 0,
            AuthorityMode::Authority => 1,
        })
        .revision(&fact.generation)
        .bool(fact.ready);
}

/// Commitment to a grant observation (used inside composite rows).
pub(crate) fn grant(commit: &mut Commit, fact: &GrantFact) {
    commit
        .hash(&fact.namespace.0)
        .hash(&fact.grant)
        .revision(&fact.epoch)
        .u8(match fact.presence {
            None => 0,
            Some(false) => 1,
            Some(true) => 2,
        });
}
