//! Fact-mutation harness for guard completeness (test-only).
//!
//! The emitted-guard tests can only mutate a fact whose guard the decision
//! already emitted, so they cannot find a fact the decision reads but forgot to
//! guard. This harness mutates the *snapshot* instead: for every acquired fact
//! it produces every single-field variant, and for each variant it redecides.
//! Whenever the redecision differs from the original, `guards_match(original,
//! mutated)` must be false. An unguarded dependency shows up as a mutation that
//! changes the decision while every guard still compares equal.

use super::{
    AccountingFact, AdmissionFact, AuthorityFact, AuthorityMode, DenialFact, GrantFact, Guarded,
    LifecycleFact, LifecycleState, MembershipObservation, NamespaceId, Observed, OperationId,
    PermanentCode, PermanentRefusal, PolicyFact, PresenceDelta, PublicationFact, RefName,
    ReplayFact, ReplayScope, ReplayState, ReservationAbortReason, ReservationAccounting,
    ReservationFact, ReservationId, ReservationOp, ReservationTerminal, ReservationTerminalKind,
    Snapshot, StorageFact, TerminalResult, TicketFact, TicketId, WriteDecision,
    ref_write::guards_match,
};
use crate::{
    error::Failure,
    evidence::{MemberFact, PackSource, RepositoryId, Revision, SourceBinding},
};
use mkit_core::{hash::Hash, object::ObjectType};

/// Single-field variants of a fact.
pub(crate) trait Vary: Sized {
    fn variants(&self) -> Vec<Self>;
    /// A present value to substitute for an authoritative absence.
    fn sample() -> Self;
}

fn flip(bytes: &[u8; 32]) -> [u8; 32] {
    let mut out = *bytes;
    out[0] ^= 0xa5;
    out
}

impl Vary for Hash {
    fn variants(&self) -> Vec<Self> {
        vec![flip(self)]
    }
    fn sample() -> Self {
        [0x5a; 32]
    }
}
impl Vary for Revision {
    fn variants(&self) -> Vec<Self> {
        vec![Revision(flip(&self.0))]
    }
    fn sample() -> Self {
        Revision([0x6b; 32])
    }
}
impl Vary for u64 {
    fn variants(&self) -> Vec<Self> {
        vec![self.wrapping_add(1)]
    }
    fn sample() -> Self {
        7
    }
}
impl Vary for bool {
    fn variants(&self) -> Vec<Self> {
        vec![!*self]
    }
    fn sample() -> Self {
        true
    }
}

/// Apply `vary` to a copy of `value` for every variant of one field.
fn field<T: Clone, F: Vary + Clone>(value: &T, get: impl Fn(&mut T) -> &mut F, out: &mut Vec<T>) {
    let mut probe = value.clone();
    let current = get(&mut probe).clone();
    for variant in current.variants() {
        let mut next = value.clone();
        *get(&mut next) = variant;
        out.push(next);
    }
}

impl<T: Vary + Clone> Vary for Observed<T> {
    fn variants(&self) -> Vec<Self> {
        match self {
            Self::Absent(revision) => {
                let mut out: Vec<_> = revision.variants().into_iter().map(Self::Absent).collect();
                out.push(Self::Present {
                    value: T::sample(),
                    revision: *revision,
                });
                out
            }
            Self::Present { value, revision } => {
                let mut out: Vec<_> = revision
                    .variants()
                    .into_iter()
                    .map(|revision| Self::Present {
                        value: value.clone(),
                        revision,
                    })
                    .collect();
                out.extend(value.variants().into_iter().map(|value| Self::Present {
                    value,
                    revision: *revision,
                }));
                out.push(Self::Absent(*revision));
                out
            }
        }
    }
    fn sample() -> Self {
        Self::Present {
            value: T::sample(),
            revision: Revision::sample(),
        }
    }
}

impl Vary for ReplayFact {
    fn variants(&self) -> Vec<Self> {
        let mut out = Vec::new();
        out.push(Self {
            scope: ReplayScope(flip(&self.scope.0)),
            ..self.clone()
        });
        field(self, |f| &mut f.fingerprint, &mut out);
        field(self, |f| &mut f.expires_ms, &mut out);
        match &self.state {
            ReplayState::InFlight { resumable } => {
                out.push(Self {
                    state: ReplayState::InFlight {
                        resumable: !*resumable,
                    },
                    ..self.clone()
                });
                out.push(Self {
                    state: ReplayState::Committed(TerminalResult::Applied(Vec::new())),
                    ..self.clone()
                });
            }
            ReplayState::Committed(_) => {
                out.push(Self {
                    state: ReplayState::InFlight { resumable: false },
                    ..self.clone()
                });
                out.push(Self {
                    state: ReplayState::Committed(TerminalResult::Rejected(PermanentRefusal {
                        code: PermanentCode::NotFound,
                        public_message: "x".into(),
                    })),
                    ..self.clone()
                });
            }
        }
        out
    }
    fn sample() -> Self {
        Self {
            scope: ReplayScope([8; 32]),
            fingerprint: [9; 32],
            expires_ms: 1,
            state: ReplayState::InFlight { resumable: false },
        }
    }
}

impl Vary for AuthorityFact {
    fn variants(&self) -> Vec<Self> {
        let mut out = vec![Self {
            namespace: NamespaceId(flip(&self.namespace.0)),
            ..self.clone()
        }];
        out.push(Self {
            mode: if self.mode == AuthorityMode::Authority {
                AuthorityMode::SelfCertifying
            } else {
                AuthorityMode::Authority
            },
            ..self.clone()
        });
        field(self, |f| &mut f.generation, &mut out);
        field(self, |f| &mut f.ready, &mut out);
        out
    }
    fn sample() -> Self {
        Self {
            namespace: NamespaceId([7; 32]),
            mode: AuthorityMode::Authority,
            generation: Revision::sample(),
            ready: true,
        }
    }
}

impl Vary for GrantFact {
    fn variants(&self) -> Vec<Self> {
        let mut out = vec![Self {
            namespace: NamespaceId(flip(&self.namespace.0)),
            ..self.clone()
        }];
        field(self, |f| &mut f.grant, &mut out);
        field(self, |f| &mut f.epoch, &mut out);
        out.push(Self {
            presence: match self.presence {
                None => Some(true),
                Some(value) => Some(!value),
            },
            ..self.clone()
        });
        out.push(Self {
            presence: None,
            ..self.clone()
        });
        out
    }
    fn sample() -> Self {
        Self {
            namespace: NamespaceId([7; 32]),
            grant: [8; 32],
            epoch: Revision::sample(),
            presence: None,
        }
    }
}

impl Vary for LifecycleFact {
    fn variants(&self) -> Vec<Self> {
        let mut out = Vec::new();
        field(self, |f| &mut f.incarnation, &mut out);
        for state in [
            LifecycleState::Active,
            LifecycleState::Deleting,
            LifecycleState::Deleted,
        ] {
            if state != self.state {
                out.push(Self {
                    state,
                    ..self.clone()
                });
            }
        }
        out
    }
    fn sample() -> Self {
        Self {
            incarnation: Revision::sample(),
            state: LifecycleState::Active,
        }
    }
}

impl Vary for PublicationFact {
    fn variants(&self) -> Vec<Self> {
        let mut out = Vec::new();
        field(self, |f| &mut f.generation, &mut out);
        field(self, |f| &mut f.sequence, &mut out);
        field(self, |f| &mut f.published_prefix, &mut out);
        field(self, |f| &mut f.deletion_boundary, &mut out);
        out.push(Self {
            head: Some(self.head.map_or([1; 32], |head| flip(&head))),
            ..self.clone()
        });
        out.push(Self {
            packmap: Some(self.packmap.map_or([2; 32], |head| flip(&head))),
            ..self.clone()
        });
        out
    }
    fn sample() -> Self {
        Self {
            generation: Revision::sample(),
            sequence: 3,
            published_prefix: 2,
            deletion_boundary: 0,
            head: Some([1; 32]),
            packmap: Some([2; 32]),
        }
    }
}

impl Vary for DenialFact {
    fn variants(&self) -> Vec<Self> {
        let mut out = Vec::new();
        for which in 0..3 {
            let mut next = self.clone();
            let set = match which {
                0 => &mut next.objects,
                1 => &mut next.packs,
                _ => &mut next.held,
            };
            if set.is_empty() {
                set.push([0x77; 32]);
            } else {
                set.clear();
            }
            out.push(next);
        }
        out
    }
    fn sample() -> Self {
        Self {
            objects: vec![[0x77; 32]],
            packs: Vec::new(),
            held: Vec::new(),
        }
    }
}

impl Vary for PolicyFact {
    fn variants(&self) -> Vec<Self> {
        let mut out = Vec::new();
        field(self, |f| &mut f.fast_forward, &mut out);
        field(self, |f| &mut f.revision, &mut out);
        out.push(Self {
            allowed_signers: Vec::new(),
            ..self.clone()
        });
        let mut wider = self.clone();
        wider.allowed_signers.push([0x44; 32]);
        out.push(wider);
        out
    }
    fn sample() -> Self {
        Self {
            allowed_signers: vec![[5; 32]],
            fast_forward: false,
            revision: Revision::sample(),
        }
    }
}

impl Vary for AdmissionFact {
    fn variants(&self) -> Vec<Self> {
        let mut out = Vec::new();
        out.push(Self {
            operation: OperationId(flip(&self.operation.0)),
            ..self.clone()
        });
        field(self, |f| &mut f.effects, &mut out);
        out.push(Self {
            presence: Vec::new(),
            ..self.clone()
        });
        let mut changed = self.clone();
        if let Some(delta) = changed.presence.first_mut() {
            delta.before = !delta.before;
            out.push(changed);
        }
        let mut extra = self.clone();
        extra.presence.push(PresenceDelta {
            name: RefName("refs/heads/other".into()),
            before: false,
            after: true,
        });
        out.push(extra);
        out
    }
    fn sample() -> Self {
        Self {
            operation: OperationId([6; 32]),
            effects: [8; 32],
            presence: Vec::new(),
            reservation: None,
        }
    }
}

impl Vary for AccountingFact {
    fn variants(&self) -> Vec<Self> {
        let mut out = Vec::new();
        field(self, |f| &mut f.scope, &mut out);
        field(self, |f| &mut f.window, &mut out);
        field(self, |f| &mut f.bytes, &mut out);
        field(self, |f| &mut f.byte_limit, &mut out);
        field(self, |f| &mut f.operations, &mut out);
        field(self, |f| &mut f.operation_limit, &mut out);
        out
    }
    fn sample() -> Self {
        Self {
            scope: [1; 32],
            window: Revision::sample(),
            bytes: 0,
            byte_limit: 10,
            operations: 0,
            operation_limit: 10,
        }
    }
}

impl Vary for StorageFact {
    fn variants(&self) -> Vec<Self> {
        let mut out = Vec::new();
        field(self, |f| &mut f.stored_bytes, &mut out);
        field(self, |f| &mut f.version, &mut out);
        out
    }
    fn sample() -> Self {
        Self {
            stored_bytes: 1,
            version: 1,
        }
    }
}

impl Vary for TicketFact {
    fn variants(&self) -> Vec<Self> {
        let mut out = Vec::new();
        out.push(Self {
            ticket: TicketId(flip(&self.ticket.0)),
            ..self.clone()
        });
        out.push(Self {
            repository: RepositoryId(flip(&self.repository.0)),
            ..self.clone()
        });
        out.push(Self {
            name: RefName("refs/heads/other".into()),
            ..self.clone()
        });
        field(self, |f| &mut f.signer, &mut out);
        out.push(Self {
            pack: PackSource {
                id: flip(&self.pack.id),
                ..self.pack
            },
            ..self.clone()
        });
        out.push(Self {
            pack: PackSource {
                len: self.pack.len + 1,
                ..self.pack
            },
            ..self.clone()
        });
        out.push(Self {
            pack: PackSource {
                binding: SourceBinding(flip(&self.pack.binding.0)),
                ..self.pack
            },
            ..self.clone()
        });
        field(self, |f| &mut f.part_bytes, &mut out);
        field(self, |f| &mut f.created_ms, &mut out);
        field(self, |f| &mut f.expires_ms, &mut out);
        out.push(Self {
            expires_ms: 0,
            ..self.clone()
        });
        out.push(Self {
            reservation: ReservationId(flip(&self.reservation.0)),
            ..self.clone()
        });
        out.push(Self {
            authority_generation: Some(
                self.authority_generation
                    .map_or(Revision::sample(), |g| Revision(flip(&g.0))),
            ),
            ..self.clone()
        });
        out.push(Self {
            authority_generation: None,
            ..self.clone()
        });
        out.push(Self {
            upload_session: Some(self.upload_session.clone().map_or(vec![1], |mut session| {
                session.push(1);
                session
            })),
            ..self.clone()
        });
        out
    }
    fn sample() -> Self {
        Self {
            ticket: TicketId([1; 32]),
            repository: RepositoryId([1; 32]),
            name: RefName("refs/heads/main".into()),
            signer: [5; 32],
            pack: PackSource {
                id: [3; 32],
                len: 9,
                binding: SourceBinding([4; 32]),
            },
            part_bytes: 1,
            created_ms: 1,
            expires_ms: 10_000,
            reservation: ReservationId([2; 32]),
            authority_generation: None,
            upload_session: None,
        }
    }
}

impl Vary for ReservationFact {
    fn variants(&self) -> Vec<Self> {
        match self {
            Self::Pending {
                repository,
                created_ms,
                reconcile_ms,
                op,
            } => vec![
                Self::Pending {
                    repository: RepositoryId(flip(&repository.0)),
                    created_ms: *created_ms,
                    reconcile_ms: *reconcile_ms,
                    op: *op,
                },
                Self::Pending {
                    repository: *repository,
                    created_ms: created_ms + 1,
                    reconcile_ms: *reconcile_ms,
                    op: *op,
                },
                Self::Pending {
                    repository: *repository,
                    created_ms: *created_ms,
                    reconcile_ms: reconcile_ms + 1,
                    op: *op,
                },
                Self::Pending {
                    repository: *repository,
                    created_ms: *created_ms,
                    reconcile_ms: *reconcile_ms,
                    op: if *op == ReservationOp::Write {
                        ReservationOp::Read
                    } else {
                        ReservationOp::Write
                    },
                },
                Self::Ticketed(TicketId([1; 32])),
            ],
            Self::Ticketed(id) => vec![
                Self::Ticketed(TicketId(flip(&id.0))),
                Self::Terminal(ReservationTerminal {
                    repository: RepositoryId([1; 32]),
                    occurred_ms: 1,
                    kind: ReservationTerminalKind::Expired,
                }),
            ],
            Self::Terminal(terminal) => vec![
                Self::Terminal(ReservationTerminal {
                    occurred_ms: terminal.occurred_ms + 1,
                    ..terminal.clone()
                }),
                Self::Terminal(ReservationTerminal {
                    repository: RepositoryId(flip(&terminal.repository.0)),
                    ..terminal.clone()
                }),
                Self::Terminal(ReservationTerminal {
                    kind: ReservationTerminalKind::Aborted {
                        reason: ReservationAbortReason::Internal,
                        detail: "x".into(),
                    },
                    ..terminal.clone()
                }),
                Self::Terminal(ReservationTerminal {
                    kind: ReservationTerminalKind::Committed {
                        refs: Vec::new(),
                        accounting: ReservationAccounting {
                            bytes_stored: 1,
                            new_to_repository: 1,
                            new_to_store: 1,
                        },
                    },
                    ..terminal.clone()
                }),
                Self::Ticketed(TicketId([1; 32])),
            ],
        }
    }
    fn sample() -> Self {
        Self::Ticketed(TicketId([1; 32]))
    }
}

impl Vary for MemberFact {
    fn variants(&self) -> Vec<Self> {
        let mut out = Vec::new();
        out.push(Self {
            repository: RepositoryId(flip(&self.repository.0)),
            ..self.clone()
        });
        field(self, |f| &mut f.incarnation, &mut out);
        out.push(Self {
            kind: if self.kind == ObjectType::Blob {
                ObjectType::Commit
            } else {
                ObjectType::Blob
            },
            ..self.clone()
        });
        field(self, |f| &mut f.canonical_len, &mut out);
        out.push(Self {
            supplier: PackSource {
                id: flip(&self.supplier.id),
                ..self.supplier
            },
            ..self.clone()
        });
        out.push(Self {
            canonical_binding: SourceBinding(flip(&self.canonical_binding.0)),
            ..self.clone()
        });
        field(self, |f| &mut f.revision, &mut out);
        out.push(Self {
            delta_depth: self.delta_depth + 1,
            ..self.clone()
        });
        field(self, |f| &mut f.published, &mut out);
        field(self, |f| &mut f.held, &mut out);
        out
    }
    fn sample() -> Self {
        Self {
            repository: RepositoryId([1; 32]),
            incarnation: Revision::sample(),
            object: [4; 32],
            kind: ObjectType::Commit,
            canonical_len: 1,
            supplier: PackSource {
                id: [10; 32],
                len: 100,
                binding: SourceBinding([11; 32]),
            },
            canonical_binding: SourceBinding([12; 32]),
            revision: Revision::sample(),
            delta_depth: 0,
            published: true,
            held: false,
        }
    }
}

/// Every single-field variant of every acquired fact in `snapshot`.
pub(crate) fn mutations(snapshot: &Snapshot) -> Vec<(String, Snapshot)> {
    let mut out = Vec::new();
    for (i, (_, observed)) in snapshot.refs.iter().enumerate() {
        for variant in observed.variants() {
            let mut next = snapshot.clone();
            next.refs[i].1 = variant;
            out.push((format!("refs[{i}]"), next));
        }
    }
    for (i, (_, observed)) in snapshot.tickets.iter().enumerate() {
        for variant in observed.variants() {
            let mut next = snapshot.clone();
            next.tickets[i].1 = variant;
            out.push((format!("tickets[{i}]"), next));
        }
    }
    for (i, (_, observed)) in snapshot.reservations.iter().enumerate() {
        for variant in observed.variants() {
            let mut next = snapshot.clone();
            next.reservations[i].1 = variant;
            out.push((format!("reservations[{i}]"), next));
        }
    }
    for (i, member) in snapshot.members.iter().enumerate() {
        for variant in member.observed.variants() {
            let mut next = snapshot.clone();
            next.members[i] = MembershipObservation {
                object: member.object,
                observed: variant,
            };
            out.push((format!("members[{i}]"), next));
        }
    }
    macro_rules! single {
        ($field:ident) => {
            if let Some(observed) = &snapshot.$field {
                for variant in observed.variants() {
                    let mut next = snapshot.clone();
                    next.$field = Some(variant);
                    out.push((stringify!($field).to_owned(), next));
                }
            }
        };
    }
    single!(replay);
    single!(authority);
    single!(grant);
    single!(lifecycle);
    single!(denial);
    single!(policy);
    single!(admission);
    single!(accounting);
    single!(storage);
    single!(publication);
    out
}

/// Assert that no single fact change can alter the decision while every guard
/// still compares equal. `decide` must be pure over the snapshot. A mutation
/// that makes the facts contradictory is a host error with no decision, and is
/// not counted.
///
/// Returns how many mutations changed the decision, so a scenario that never
/// exercises a guard cannot pass vacuously.
#[track_caller]
pub(crate) fn assert_guards_cover(
    label: &str,
    snapshot: &Snapshot,
    now_ms: u64,
    decide: impl Fn(&Snapshot) -> Result<Guarded<WriteDecision>, Failure>,
) -> usize {
    let original = decide(snapshot).unwrap_or_else(|e| panic!("{label}: original decision: {e:?}"));
    assert!(
        guards_match(&original, snapshot, now_ms),
        "{label}: the original snapshot must satisfy its own guards"
    );
    let mut changed = 0;
    let mut gaps = Vec::new();
    for (fact, mutated) in mutations(snapshot) {
        // A mutation that makes the facts contradictory fails validation and
        // yields no decision at all, so it has no decision to differ from.
        let Ok(redecided) = decide(&mutated) else {
            continue;
        };
        if redecided.decision() == original.decision() {
            continue;
        }
        changed += 1;
        if guards_match(&original, &mutated, now_ms) {
            gaps.push(fact);
        }
    }
    assert!(
        gaps.is_empty(),
        "{label}: decision changed while every guard still matched; unguarded facts: {gaps:?}"
    );
    changed
}
