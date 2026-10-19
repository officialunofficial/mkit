//! Pure ref decisions under the transport and server acceptance contracts.
//!
//! Hosts acquire authoritative observations and immutable ancestry evidence.
//! No physical key, codec, routing, or transaction callback enters this module.
//! Compare every returned guard atomically with all effects. A changed fact
//! requires fresh acquisition and redecision under the original authorization
//! and admission binding.

mod basis;
pub(crate) mod checks;
mod complete;
pub(crate) mod decide;
mod publication;
#[cfg(test)]
mod tests;

pub(super) use complete::compatible;
pub use complete::{
    GUARD_REQUIREMENTS_VERSION, check_guard_completeness, effect_guard_kinds, guard_kind,
    required_guard_kinds, validate_guard_kind,
};
pub use decide::decide_ref_write;
pub use publication::{RefPublication, decide_ref_publication};

use super::{AuthorityMode, NamespaceId, PublishedSourceFence, RefName, Snapshot};
use crate::evidence::{RepositoryId, Revision};
use mkit_core::{hash::Hash, refs::RefWriteCondition};

/// Shape and decision order of a ref operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RefWriteKind {
    /// One creation or update.
    Update,
    /// Two ref changes decided under the first change's outcome class. Any
    /// two valid names decide — canonical packmap/head pairing is a server
    /// option under SPEC-TRANSPORT-CONNECT §4, not a decision precondition.
    Advance,
    /// One deletion; only an exact match is permitted.
    Delete,
    /// Paired deletion; both exact matches must hold.
    DeletePair,
}

/// One validated-shape ref change; grammar is checked with the core helper.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RefChange {
    /// Served ref name.
    pub name: RefName,
    /// Original expectation, including unconditional overwrite.
    pub condition: RefWriteCondition,
    /// Desired target; absence denotes deletion.
    pub target: Option<Hash>,
}

impl RefChange {
    /// Build from every field. The struct is `#[non_exhaustive]`: hosts
    /// construct it here and may assign any public field afterwards.
    #[must_use]
    pub const fn new(name: RefName, condition: RefWriteCondition, target: Option<Hash>) -> Self {
        Self {
            name,
            condition,
            target,
        }
    }
}

/// Original commit-fenced authorization; never replaced after a guard loss.
///
/// The host authorizes signer keys by policy, using the key set at this generation.
/// Every key addition, removal, or revocation must advance the generation so the
/// commit-time Authority guard catches races (SPEC-PRIMITIVE-EVIDENCE §1.2).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuthorityBinding {
    /// Namespace that the host authenticated and authorized.
    pub namespace: NamespaceId,
    /// Original authorization mode.
    pub mode: AuthorityMode,
    /// Original generation.
    pub generation: Revision,
}

impl AuthorityBinding {
    /// Build from every field. The struct is `#[non_exhaustive]`: hosts
    /// construct it here and may assign any public field afterwards.
    #[must_use]
    pub const fn new(namespace: NamespaceId, mode: AuthorityMode, generation: Revision) -> Self {
        Self {
            namespace,
            mode,
            generation,
        }
    }
}

/// Original scoped grant identity and epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct GrantBinding {
    /// Owning namespace.
    pub namespace: NamespaceId,
    /// Exact grant identity.
    pub grant: Hash,
    /// Original grant epoch.
    pub epoch: Revision,
}

impl GrantBinding {
    /// Build from every field. The struct is `#[non_exhaustive]`: hosts
    /// construct it here and may assign any public field afterwards.
    #[must_use]
    pub const fn new(namespace: NamespaceId, grant: Hash, epoch: Revision) -> Self {
        Self {
            namespace,
            grant,
            epoch,
        }
    }
}

/// Exact immutable ref proposal seen by custom admission.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AdmittedRef {
    /// Served ref name.
    pub name: RefName,
    /// Original proposed target.
    pub target: Option<Hash>,
    /// Presence observed when admission ran.
    pub prior_present: bool,
}

impl AdmittedRef {
    /// Build from every field. The struct is `#[non_exhaustive]`: hosts
    /// construct it here and may assign any public field afterwards.
    #[must_use]
    pub const fn new(name: RefName, target: Option<Hash>, prior_present: bool) -> Self {
        Self {
            name,
            target,
            prior_present,
        }
    }
}

/// Original custom admission binding, independent of token encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AdmissionBinding {
    /// Existing host commitment to the exact admitted effects; no new domain.
    pub effects: Hash,
}

impl AdmissionBinding {
    /// Build from every field. The struct is `#[non_exhaustive]`: hosts
    /// construct it here and may assign any public field afterwards.
    #[must_use]
    pub const fn new(effects: Hash) -> Self {
        Self { effects }
    }
}

/// Repository-local immutable ancestry evidence acquired by the host.
///
/// A proven result follows commit/remix parents only, never remix sources;
/// a tag proves descent only from itself. The host verifies immutable bytes
/// and supplies every mutable membership/denial dependency in the snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AncestryFact {
    /// Exact repository, preventing cross-repository substitution.
    pub repository: RepositoryId,
    /// Subject head ref.
    pub name: RefName,
    /// Exact observed current value used by the proof.
    pub from: Hash,
    /// Exact proposed new value.
    pub to: Hash,
    /// Acquired proof classification.
    pub result: AncestryResult,
}

impl AncestryFact {
    /// Build from every field. The struct is `#[non_exhaustive]`: hosts
    /// construct it here and may assign any public field afterwards.
    #[must_use]
    pub const fn new(
        repository: RepositoryId,
        name: RefName,
        from: Hash,
        to: Hash,
        result: AncestryResult,
    ) -> Self {
        Self {
            repository,
            name,
            from,
            to,
            result,
        }
    }
}

/// Ancestry acquisition distinguishes a final denial from membership lag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AncestryResult {
    /// Complete repository-local ancestry proof.
    Descendant,
    /// Complete proof of non-descent or exhausted policy traversal bound.
    Denied,
    /// Retryable membership visibility lag; never durable replay.
    MembershipLag,
}

/// Which deployment policy applies to the operation's head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct PolicyRequirement {
    /// An allowed-signer intersection applies, including an empty intersection.
    pub signer_restricted: bool,
    /// A grant requires ancestry even without deployment fast-forward policy.
    pub grant_fast_forward: bool,
}

impl PolicyRequirement {
    /// Build from every field. The struct is `#[non_exhaustive]`: hosts
    /// construct it here and may assign any public field afterwards.
    #[must_use]
    pub const fn new(signer_restricted: bool, grant_fast_forward: bool) -> Self {
        Self {
            signer_restricted,
            grant_fast_forward,
        }
    }
}

/// Replay identity already authenticated at ingress by the host.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RefReplay {
    /// Exact scope.
    pub scope: super::ReplayScope,
    /// Authenticated operation fingerprint.
    pub fingerprint: Hash,
    /// Original replay retention timestamp; never extends envelope validity.
    pub expires_ms: u64,
}

impl RefReplay {
    /// Build from every field. The struct is `#[non_exhaustive]`: hosts
    /// construct it here and may assign any public field afterwards.
    #[must_use]
    pub const fn new(scope: super::ReplayScope, fingerprint: Hash, expires_ms: u64) -> Self {
        Self {
            scope,
            fingerprint,
            expires_ms,
        }
    }
}

/// Original request's repository-membership visibility classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MembershipWindow {
    /// A missing member can still be delayed repository membership visibility.
    WithinLag,
    /// Original request's visibility window has elapsed; never renewed by retry.
    Elapsed,
}

/// Applicable mutable categories; unacquired applicable facts are not absence.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RefRequirements<'a> {
    /// Original authority, when authority fencing applies.
    pub authority: Option<AuthorityBinding>,
    /// Original grant, when scoped authorization applies.
    pub grant: Option<GrantBinding>,
    /// Original incarnation when lifecycle enforcement applies.
    pub incarnation: Option<Revision>,
    /// Applicable policy; `None` means the host configured no policy.
    pub policy: Option<PolicyRequirement>,
    /// Original custom admission proposal.
    pub admission: Option<AdmissionBinding>,
    /// Membership keys relied on by content or ancestry acquisition.
    pub members: &'a [Hash],
    /// Whether a non-delete head must be a verified Commit, Remix or Tag member.
    pub indexed_head: bool,
    /// Whether a missing member remains inside the host's original visibility window.
    /// The host computes this from its existing request-time rule, without renewal.
    pub membership_window: MembershipWindow,
    /// Whether denial and inspection facts were relied on.
    pub denial: bool,
    /// Whether the resulting publication state was relied on.
    pub publication: bool,
    /// Separate published-source pre-apply fence, repeated on every attempt.
    pub source: Option<&'a PublishedSourceFence>,
    /// Existing business validity cap; no scheduling allowance is invented here.
    pub valid_through_ms: Option<u64>,
}

impl RefRequirements<'_> {
    /// No applicable mutable category: no authority, grant, incarnation,
    /// policy, admission, members, denial, publication, source fence or
    /// validity cap. Assign the public fields that apply. The struct is
    /// `#[non_exhaustive]`.
    #[must_use]
    pub const fn new(membership_window: MembershipWindow) -> Self {
        Self {
            authority: None,
            grant: None,
            incarnation: None,
            policy: None,
            admission: None,
            members: &[],
            indexed_head: false,
            membership_window,
            denial: false,
            publication: false,
            source: None,
            valid_through_ms: None,
        }
    }
}

/// Bounded input to a ref decision. Ticket consumption is a separate decision.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RefWriteRequest<'a> {
    /// Exact destination repository.
    pub repository: RepositoryId,
    /// Authenticated operation identity when mutable admission facts apply.
    pub operation: Option<super::OperationId>,
    /// Request shape.
    pub kind: RefWriteKind,
    /// One update, or the exact ordered packmap/head pair.
    pub changes: &'a [RefChange],
    /// Immutable original custom-admission proposal; empty for default admission.
    pub admitted: &'a [AdmittedRef],
    /// Immutable authorized ref-presence constraint, if scoped grants require it.
    pub presence: Option<(RefName, bool)>,
    /// Authenticated envelope signer; other identity kinds have no signer.
    pub signer: Option<Hash>,
    /// Original replay identity for a signed write.
    pub replay: Option<RefReplay>,
    /// Applicable host capabilities and bindings.
    pub required: RefRequirements<'a>,
    /// Repository-local ancestry observations, when needed.
    pub ancestry: &'a [AncestryFact],
    /// Explicit business instant for already-established validity bounds.
    pub now_ms: u64,
}

impl<'a> RefWriteRequest<'a> {
    /// A request with no operation identity, admitted proposal, presence
    /// constraint, signer, replay binding or ancestry evidence. Assign the
    /// public fields that apply. The struct is `#[non_exhaustive]`.
    #[must_use]
    pub const fn new(
        repository: RepositoryId,
        kind: RefWriteKind,
        changes: &'a [RefChange],
        required: RefRequirements<'a>,
        now_ms: u64,
    ) -> Self {
        Self {
            repository,
            operation: None,
            kind,
            changes,
            admitted: &[],
            presence: None,
            signer: None,
            replay: None,
            required,
            ancestry: &[],
            now_ms,
        }
    }
}

/// Explicit finite execution ceilings, independent of protocol maxima.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RefDecisionLimits {
    /// Maximum acquired facts, including unused facts validated for ambiguity.
    pub facts: u32,
    /// Maximum returned atomic guards.
    pub guards: u32,
    /// Cumulative input name, signer-set, denial-set and public-message bytes.
    pub bytes: u64,
    /// Cumulative comparisons and validation work.
    pub work: u64,
    /// Maximum owned terminal/public refusal message bytes.
    pub public_message_bytes: u32,
}

impl RefDecisionLimits {
    /// Build from every field. The struct is `#[non_exhaustive]`: hosts
    /// construct it here and may assign any public field afterwards.
    #[must_use]
    pub const fn new(
        facts: u32,
        guards: u32,
        bytes: u64,
        work: u64,
        public_message_bytes: u32,
    ) -> Self {
        Self {
            facts,
            guards,
            bytes,
            work,
            public_message_bytes,
        }
    }
}

/// Exact reference comparison for mutation tests and host conformance.
///
/// This acquires and commits nothing. A real adapter performs this comparison
/// in its transaction and discharges source fences separately before each apply.
/// Unknown guard categories fail closed at the host mapping boundary.
#[must_use]
pub fn guards_match(
    guarded: &super::Guarded<super::WriteDecision>,
    current: &Snapshot,
    now_ms: u64,
) -> bool {
    if guarded.repository() != current.repository {
        return false;
    }
    if checks::ambiguous(current) {
        return false;
    }
    guarded
        .required_guards()
        .iter()
        .all(|guard| checks::matches(guard, current, now_ms))
}
