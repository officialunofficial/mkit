//! Lowering of fork facts into owned, typed guards.
//!
//! Every fork decision returns a [`Guarded`](crate::decision::Guarded) value.
//! Its required guards are derived here from the facts the decision read, so
//! a host compares typed rows instead of a whole borrowed snapshot. Rows with
//! a typed fact of their own (authority, grant, lifecycle) use the typed
//! guards; the others are [`RequiredGuard::Row`] values carrying the
//! observation revision and the commitment to the fact value.

use super::{
    FinalForkSourceProof, ForkActivationFacts, ForkAdmission, ForkAdvanceFacts, ForkAdvancePhase,
    ForkAttempt, ForkBinding, ForkCompletionFacts, ForkEmptiness, ForkFacts, ForkJob, ForkJobState,
    ForkLifecycleProtection, ForkName, ForkObservation, ForkPermission, ForkPlan, ForkQuota,
    ForkRefusal, ForkReplay, ForkReservation, ForkResult, ForkTerminal, ForkVisibility,
    ForkWitness, SourceAccess,
};
use crate::decision::commit::{self, Commit, observe, revision_row};
use crate::decision::{
    AuthorityFact, GuardRow, Guarded, NamespaceId, Observed, PublicationFact, RequiredGuard,
    RequiredSourceFence,
};
use crate::evidence::{RepositoryId, Revision};
use mkit_core::hash::Hash;

fn visibility(commit: &mut Commit, value: ForkVisibility) {
    commit.u8(match value {
        ForkVisibility::Public => 0,
        ForkVisibility::Private => 1,
    });
}
fn access(commit: &mut Commit, value: &SourceAccess) {
    commit.hash(&value.principal);
    visibility(commit, value.visibility);
    commit
        .revision(&value.visibility_revision)
        .revision(&value.authorization_revision);
}
fn publication(commit: &mut Commit, value: &PublicationFact) {
    commit
        .revision(&value.generation)
        .u64(value.sequence)
        .u64(value.published_prefix)
        .u64(value.deletion_boundary)
        .opt_hash(value.head.as_ref())
        .opt_hash(value.packmap.as_ref());
}
fn refusal(commit: &mut Commit, value: ForkRefusal) {
    commit.u8(match value {
        ForkRefusal::SourceNotFound => 0,
        ForkRefusal::DestinationNotEmpty => 1,
        ForkRefusal::PermissionDenied => 2,
        ForkRefusal::VisibilityMismatch => 3,
        ForkRefusal::ReservationSettled => 4,
        ForkRefusal::Expired => 5,
        ForkRefusal::QuotaExceeded => 6,
        ForkRefusal::BindingMismatch => 7,
    });
}
fn result(commit: &mut Commit, value: &ForkResult) {
    commit
        .bytes(value.branch.0.as_bytes())
        .hash(&value.source.0)
        .u64(value.source_sequence)
        .hash(&value.tip)
        .hash(&value.packmap)
        .u64(value.packs)
        .u64(value.bytes)
        .u64(value.index_entries)
        .hash(&value.pack_digest)
        .revision(&value.destination_generation);
}
fn terminal(commit: &mut Commit, value: &ForkTerminal) {
    match value {
        ForkTerminal::Accepted(saved) => {
            commit.u8(0);
            result(commit, saved);
        }
        ForkTerminal::Refused(reason) => {
            commit.u8(1);
            refusal(commit, *reason);
        }
    }
}
fn binding(commit: &mut Commit, value: &ForkBinding) {
    commit
        .hash(&value.source.0)
        .revision(&value.source_incarnation)
        .bytes(value.branch.0.as_bytes());
    publication(commit, &value.publication);
    access(commit, &value.source_access);
    commit
        .hash(&value.destination.0)
        .revision(&value.destination_generation);
    visibility(commit, value.destination_visibility);
}
fn attempt(commit: &mut Commit, value: &ForkAttempt) {
    commit.hash(&value.operation.0);
    commit.opt_hash(value.reservation.as_ref().map(|r| &r.0));
    commit
        .hash(&value.replay.0)
        .hash(&value.fingerprint)
        .u64(value.expires_ms);
    commit::authority(commit, &value.authority);
    match &value.grant {
        Some(grant) => {
            commit.u8(1);
            commit::grant(commit, grant);
        }
        None => {
            commit.u8(0);
        }
    }
    commit.bool(value.authority_fencing);
}
fn witness(commit: &mut Commit, value: Option<&ForkWitness>) {
    match value {
        Some(w) => {
            commit
                .u8(1)
                .revision(&w.generation)
                .u64(w.sequence)
                .bool(w.published)
                .bool(w.held)
                .bool(w.boundary);
        }
        None => {
            commit.u8(0);
        }
    }
}

impl ForkPlan {
    /// Commitment to the sealed plan: binding, full inventories and result.
    #[must_use]
    pub const fn commitment(&self) -> Hash {
        self.commitment
    }
    pub(super) fn compute_commitment(
        binding_fact: &ForkBinding,
        packs: &[super::ForkInventory],
        result_fact: &ForkResult,
    ) -> Hash {
        let mut c = Commit::new("fork-plan");
        binding(&mut c, binding_fact);
        result(&mut c, result_fact);
        c.u64(packs.len() as u64);
        for pack in packs {
            c.hash(&pack.pack)
                .hash(&pack.descriptor)
                .u64(pack.bytes)
                .u64(pack.index_entries)
                .hashes(&pack.dependencies);
        }
        c.finish()
    }
}
impl ForkAttempt {
    /// Commitment to the signed request identity and recorded authorization.
    #[must_use]
    pub fn commitment(&self) -> Hash {
        let mut c = Commit::new("fork-attempt");
        attempt(&mut c, self);
        c.finish()
    }
}
impl ForkJobState {
    fn commit_into(&self, c: &mut Commit) {
        match self {
            Self::Staged {
                packs,
                revision,
                last_effect,
            } => {
                c.u8(0).u64(*packs).revision(revision).u64(*last_effect);
            }
            Self::Terminal(saved) => {
                c.u8(1);
                terminal(c, saved);
            }
        }
    }
}
impl ForkJob<'_> {
    /// Commitment to the plan, original attempt, lifetime and state.
    #[must_use]
    pub fn commitment(&self) -> Hash {
        let mut c = Commit::new("fork-job");
        c.hash(&self.plan.commitment());
        attempt(&mut c, &self.attempt);
        c.u64(self.expires_ms);
        self.state.commit_into(&mut c);
        c.finish()
    }
}
impl ForkEmptiness {
    /// Commitment to every emptiness count and the staged-set digest.
    #[must_use]
    pub fn commitment(&self) -> Hash {
        let mut c = Commit::new("fork-emptiness");
        c.u64(self.refs)
            .u64(self.visible_members)
            .u64(self.staged_members)
            .hash(&self.staged_pack_digest)
            .opt_hash(self.staged_owner.as_ref().map(|o| &o.0))
            .bool(self.writes_enabled);
        c.finish()
    }
}
impl ForkName {
    /// Commitment to the registration and declared visibility.
    #[must_use]
    pub fn commitment(&self) -> Hash {
        let mut c = Commit::new("fork-name");
        c.opt_hash(self.registered_by.as_ref().map(|o| &o.0));
        match self.declared_visibility {
            Some(v) => {
                c.u8(1);
                visibility(&mut c, v);
            }
            None => {
                c.u8(0);
            }
        }
        c.finish()
    }
}
impl ForkPermission {
    /// Commitment to the operation, source access and create/write permission.
    #[must_use]
    pub fn commitment(&self) -> Hash {
        let mut c = Commit::new("fork-permission");
        c.hash(&self.operation.0);
        access(&mut c, &self.source_access);
        visibility(&mut c, self.destination_visibility);
        c.bool(self.create).bool(self.write);
        c.finish()
    }
}
impl ForkAdmission<'_> {
    /// Commitment to the admitted plan, owner, charge and byte counts.
    #[must_use]
    pub fn commitment(&self) -> Hash {
        let mut c = Commit::new("fork-admission");
        c.hash(&self.plan.commitment()).hash(&self.operation.0);
        c.opt_hash(self.reservation.as_ref().map(|r| &r.0));
        c.u64(self.declared_bytes).u64(self.new_to_repo_bytes);
        match &self.charge {
            Some(charge) => c.u8(1).revision(charge),
            None => c.u8(0),
        };
        c.finish()
    }
}
impl ForkQuota {
    /// Commitment to the debit receipt and applicable window.
    #[must_use]
    pub fn commitment(&self) -> Hash {
        let mut c = Commit::new("fork-quota");
        c.hash(&self.operation.0)
            .revision(&self.charge)
            .u64(self.bytes)
            .u64(self.used_bytes)
            .u64(self.byte_limit)
            .u64(self.used_operations)
            .u64(self.operation_limit);
        c.finish()
    }
}
impl ForkReservation {
    /// Commitment to the reservation state.
    #[must_use]
    pub fn commitment(&self) -> Hash {
        let mut c = Commit::new("fork-reservation");
        match self {
            Self::Pending {
                operation,
                destination,
                expires_ms,
            } => {
                c.u8(0)
                    .hash(&operation.0)
                    .hash(&destination.0)
                    .u64(*expires_ms);
            }
            Self::Settled(saved) => {
                c.u8(1);
                terminal(&mut c, saved);
            }
            Self::ReplayRace { owner } => {
                c.u8(2).hash(&owner.0);
            }
        }
        c.finish()
    }
}
impl ForkReplay {
    /// Commitment to the replay slot state.
    #[must_use]
    pub fn commitment(&self) -> Hash {
        let mut c = Commit::new("fork-replay");
        match self {
            Self::InFlight {
                operation,
                fingerprint,
            } => {
                c.u8(0).hash(&operation.0).hash(fingerprint);
            }
            Self::Recorded {
                fingerprint,
                result: saved,
            } => {
                c.u8(1).hash(fingerprint);
                terminal(&mut c, saved);
            }
        }
        c.finish()
    }
}

fn row(repository: RepositoryId, row: GuardRow, expected: Observed<Hash>) -> RequiredGuard {
    RequiredGuard::Row {
        repository,
        row,
        expected,
    }
}
/// A fork row fact with a value commitment.
trait RowFact {
    fn row_commitment(&self) -> Hash;
}
macro_rules! row_fact {
    ($($ty:ty),* $(,)?) => {$(
        impl RowFact for $ty {
            fn row_commitment(&self) -> Hash {
                self.commitment()
            }
        }
    )*};
}
row_fact!(
    ForkJob<'_>,
    ForkEmptiness,
    ForkName,
    ForkPermission,
    ForkAdmission<'_>,
    ForkQuota,
    ForkReservation,
    ForkReplay,
);
fn fact_row<T: RowFact>(
    repository: RepositoryId,
    row_id: GuardRow,
    fact: Option<&Observed<T>>,
) -> Option<RequiredGuard> {
    fact.map(|observed| {
        row(
            repository,
            row_id,
            observe(observed, RowFact::row_commitment),
        )
    })
}
fn observation(observed: ForkObservation) -> Observed<Hash> {
    match observed {
        // Revision-only observations have no absence revision of their own.
        ForkObservation::Absent => Observed::Absent(Revision([0; 32])),
        ForkObservation::Present(revision) => revision_row(revision),
    }
}

impl ForkFacts<'_> {
    /// The guards these facts yield: one per acquired destination fact.
    ///
    /// A decision requires exactly these guards (plus its validity bound).
    /// A host that re-acquires the facts at its atomic boundary derives the
    /// live guards with this method and compares them with `guards_hold`.
    #[must_use]
    pub fn guards(&self) -> Vec<RequiredGuard> {
        let repository = self.repository;
        let namespace = self.request.authority.namespace.clone();
        let mut out = vec![
            row(
                repository,
                GuardRow::ForkRequest,
                Observed::Present {
                    value: self.request.commitment(),
                    revision: Revision(self.request.fingerprint),
                },
            ),
            row(
                repository,
                GuardRow::ForkApply,
                Observed::Present {
                    value: {
                        let mut c = Commit::new("fork-apply");
                        c.u64(self.acceptance_point);
                        c.finish()
                    },
                    revision: self.apply_attempt,
                },
            ),
        ];
        out.extend(fact_row(repository, GuardRow::ForkJob, self.job.as_ref()));
        out.extend(fact_row(
            repository,
            GuardRow::ForkEmptiness,
            self.emptiness.as_ref(),
        ));
        out.extend(fact_row(repository, GuardRow::ForkName, self.name.as_ref()));
        out.extend(
            self.lifecycle
                .as_ref()
                .map(|expected| RequiredGuard::Repository {
                    id: repository,
                    expected: expected.clone(),
                }),
        );
        out.extend(fact_row(
            repository,
            GuardRow::ForkPermission,
            self.permission.as_ref(),
        ));
        out.extend(
            self.authority
                .as_ref()
                .map(|expected| RequiredGuard::Authority {
                    namespace: scope_of(expected, |f: &AuthorityFact| &f.namespace, &namespace),
                    expected: expected.clone(),
                }),
        );
        out.extend(self.grant.as_ref().map(|expected| RequiredGuard::Grant {
            namespace: scope_of(expected, |f| &f.namespace, &namespace),
            expected: expected.clone(),
        }));
        out.extend(fact_row(
            repository,
            GuardRow::ForkAdmission,
            self.admission.as_ref(),
        ));
        out.extend(fact_row(
            repository,
            GuardRow::ForkQuota,
            self.quota.as_ref(),
        ));
        out.extend(fact_row(
            repository,
            GuardRow::ForkReservation,
            self.reservation.as_ref(),
        ));
        out.extend(fact_row(
            repository,
            GuardRow::ForkReplay,
            self.replay.as_ref(),
        ));
        out
    }
}

/// The scope key a typed guard names: the observed fact's own, or for an
/// authoritative absence the namespace the attempt recorded.
fn scope_of<T>(
    observed: &Observed<T>,
    key: impl Fn(&T) -> &NamespaceId,
    fallback: &NamespaceId,
) -> NamespaceId {
    match observed {
        Observed::Present { value, .. } => key(value).clone(),
        Observed::Absent(_) => fallback.clone(),
    }
}

impl ForkAdvanceFacts {
    /// The guards these facts yield: durable progress, both authority
    /// observations, the epoch fence when enabled, and the reservation fence.
    #[must_use]
    pub fn guards(&self) -> Vec<RequiredGuard> {
        let repository = self.destination;
        let mut out = vec![
            row(
                repository,
                GuardRow::ForkProgress,
                Observed::Present {
                    value: {
                        let mut c = Commit::new("fork-progress");
                        c.hash(&self.binding)
                            .u8(match self.progress.phase {
                                ForkAdvancePhase::Preparing => 0,
                                ForkAdvancePhase::Accepted => 1,
                                ForkAdvancePhase::Complete => 2,
                                ForkAdvancePhase::Failed => 3,
                            })
                            .u64(self.progress.cursor)
                            .u64(u64::from(self.progress.part))
                            .u64(self.construction_expires_ms);
                        c.finish()
                    },
                    revision: self.progress.revision,
                },
            ),
            row(
                repository,
                GuardRow::ForkRecordedAuthority,
                observation(self.recorded_authority),
            ),
            row(
                repository,
                GuardRow::ForkAuthority,
                observation(self.authority),
            ),
        ];
        if let Some(epoch) = &self.grant_epoch {
            out.push(row(
                repository,
                GuardRow::ForkRecordedEpoch,
                observation(epoch.recorded),
            ));
            out.push(row(
                repository,
                GuardRow::ForkEpoch,
                observation(epoch.current),
            ));
        }
        if let Some(fence) = &self.reservation {
            out.push(row(
                repository,
                GuardRow::ForkReservationRecorded(fence.reservation.clone()),
                revision_row(fence.expected),
            ));
            out.push(row(
                repository,
                GuardRow::ForkReservationCurrent(fence.reservation.clone()),
                observation(fence.current),
            ));
        }
        out
    }
}

fn lifecycle_guards(
    repository: RepositoryId,
    protection: &ForkLifecycleProtection,
    out: &mut Vec<RequiredGuard>,
) {
    let mut c = Commit::new("fork-lifecycle-profile");
    match protection {
        ForkLifecycleProtection::NotOffered => {
            c.u8(0);
        }
        ForkLifecycleProtection::Managed {
            expected_incarnation,
            current,
        } => {
            c.u8(1)
                .revision(expected_incarnation)
                .bool(current.is_some());
            if let Some(expected) = current {
                out.push(RequiredGuard::Repository {
                    id: repository,
                    expected: expected.clone(),
                });
            }
        }
    }
    out.push(row(
        repository,
        GuardRow::ForkLifecycleProfile,
        Observed::Present {
            value: c.finish(),
            revision: Revision([0; 32]),
        },
    ));
}

fn accepted_row(
    repository: RepositoryId,
    revision: Revision,
    expected: &ForkResult,
    accepted: Option<&ForkResult>,
    packs: &[Hash],
) -> RequiredGuard {
    let mut c = Commit::new("fork-accepted");
    result(&mut c, expected);
    match accepted {
        Some(saved) => {
            c.u8(1);
            result(&mut c, saved);
        }
        None => {
            c.u8(0);
        }
    }
    c.hashes(packs);
    row(
        repository,
        GuardRow::ForkAccepted,
        Observed::Present {
            value: c.finish(),
            revision,
        },
    )
}

impl ForkActivationFacts<'_> {
    /// The guards these facts yield: the advance guards, the lifecycle
    /// protection, the retained accepted result and inventory, the membership
    /// unit's witnesses, and the destination clearance proof with the denial
    /// revision it was acquired under. The proof deadline is a validity bound
    /// added by the decision.
    #[must_use]
    pub fn guards(&self) -> Vec<RequiredGuard> {
        let repository = self.advance.destination;
        let mut out = self.advance.guards();
        lifecycle_guards(repository, &self.lifecycle, &mut out);
        out.push(accepted_row(
            repository,
            self.advance.progress.revision,
            self.expected_result,
            self.accepted_result,
            self.inherited_packs,
        ));
        let unit = self.unit;
        let mut c = Commit::new("fork-unit");
        c.hash(&unit.pack).revision(&unit.inherited_revision);
        witness(&mut c, Some(&unit.expected));
        witness(&mut c, unit.live.as_ref());
        witness(&mut c, unit.published.as_ref());
        c.u8(match unit.context {
            super::ForkPairContext::Initial => 0,
            super::ForkPairContext::AfterGuardLoss => 1,
        });
        out.push(row(
            repository,
            GuardRow::ForkUnit(unit.pack),
            Observed::Present {
                value: c.finish(),
                revision: unit.inherited_revision,
            },
        ));
        if let Some(proof) = self.proof {
            let mut c = Commit::new("fork-proof");
            c.hash(&proof.destination.0)
                .hash(&proof.binding)
                .revision(&proof.progress_revision)
                .hash(&proof.pack)
                .revision(&proof.apply_attempt)
                .u64(proof.valid_through_ms);
            out.push(row(
                repository,
                GuardRow::ForkProof(proof.pack),
                Observed::Present {
                    value: c.finish(),
                    revision: proof.apply_attempt,
                },
            ));
            out.push(row(
                repository,
                GuardRow::ForkDenial(proof.pack),
                revision_row(proof.denial_revision),
            ));
        }
        out
    }
}

impl ForkCompletionFacts<'_> {
    /// The guards these facts yield: the advance guards, the lifecycle
    /// protection, the retained accepted result, and the proposed completion
    /// with its barrier owner.
    #[must_use]
    pub fn guards(&self) -> Vec<RequiredGuard> {
        let repository = self.advance.destination;
        let mut out = self.advance.guards();
        lifecycle_guards(repository, &self.lifecycle, &mut out);
        out.push(accepted_row(
            repository,
            self.advance.progress.revision,
            self.expected_result,
            self.accepted_result,
            &[],
        ));
        let mut c = Commit::new("fork-completion");
        c.u64(self.completed_cursor)
            .u64(u64::from(self.completed_part))
            .u64(self.completed_packs)
            .hash(&self.completed_digest)
            .hash(&self.expected_barrier_owner);
        out.push(row(
            repository,
            GuardRow::ForkCompletion,
            Observed::Present {
                value: c.finish(),
                revision: self.advance.progress.revision,
            },
        ));
        out
    }
}

/// Seal a fork decision with its guards and optional source proof.
pub(super) fn seal<D>(
    repository: RepositoryId,
    decision: D,
    guards: Vec<RequiredGuard>,
    valid_through_ms: Option<u64>,
    source: Option<&FinalForkSourceProof>,
) -> Guarded<D> {
    let mut required = guards;
    if let Some(instant_ms) = valid_through_ms {
        required.push(RequiredGuard::ValidThrough { instant_ms });
    }
    Guarded::from_parts(
        repository,
        decision,
        required,
        source
            .map(|proof| RequiredSourceFence::Fork(Box::new(proof.clone())))
            .into_iter()
            .collect(),
    )
}

/// The final source proof a fork acceptance decision requires, when it
/// reached the source fence. It is a separate pre-apply check, never an
/// atomic destination comparison.
#[must_use]
pub fn fork_source_proof<D>(guarded: &Guarded<D>) -> Option<&FinalForkSourceProof> {
    guarded
        .source_fences()
        .iter()
        .find_map(|fence| match fence {
            RequiredSourceFence::Fork(proof) => Some(proof.as_ref()),
            _ => None,
        })
}
