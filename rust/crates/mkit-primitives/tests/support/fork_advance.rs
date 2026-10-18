//! Fixed-size trusted-fact stand-ins and bounded activation fuzz replay.
//!
//! A real adapter authenticates snapshots and acquires destination proofs. These
//! deterministic builders exercise composition; they do not establish provenance.
use mkit_core::hash::Hasher;
use mkit_primitives::{
    decision::{LifecycleFact, LifecycleState, Observed, RefName, guards_hold},
    evidence::{RepositoryId, Revision},
    fork::{
        ForkActivationDecision, ForkActivationFacts, ForkActivationLimits, ForkAdvanceFacts,
        ForkAdvancePhase, ForkClearanceProof, ForkEpochFence, ForkLifecycleProtection,
        ForkMembershipUnit, ForkObservation, ForkPairContext, ForkProgress, ForkReservationFence,
        ForkResult, ForkWitness, decide_fork_activation, decide_fork_advance,
    },
};

/// Largest accepted fuzz input. Larger inputs are ignored before any allocation.
pub const MAX_INPUT_BYTES: usize = 64 * 1024;
/// Complete sorted inherited set for the small semantic fixture.
pub const PACKS: [[u8; 32]; 2] = [[7; 32], [8; 32]];
/// Finite ceilings, including both branch comparisons and inventory hashing.
pub const LIMITS: ForkActivationLimits = ForkActivationLimits::new(4, 128, 1024);
/// Deterministic logical observation identity, with no durable encoding.
#[must_use]
pub const fn revision(n: u8) -> Revision {
    Revision([n; 32])
}
/// Accepted job with an expired construction deadline and prunable protection.
#[must_use]
pub fn advance() -> ForkAdvanceFacts {
    {
        let mut v = ForkAdvanceFacts::new(
            [1; 32],
            RepositoryId([2; 32]),
            ForkProgress::new(ForkAdvancePhase::Accepted, 0, 0, revision(3)),
            100,
        );
        v.recorded_authority = ForkObservation::Absent;
        v.authority = ForkObservation::Absent;
        v.grant_epoch = Some(ForkEpochFence::new(
            ForkObservation::Present(revision(4)),
            ForkObservation::Present(revision(4)),
        ));
        v.reservation = Some(ForkReservationFence::new(
            mkit_primitives::decision::ReservationId([5; 32]),
            revision(5),
            ForkObservation::Present(revision(5)),
        ));
        v
    }
}
/// Exact saved terminal response of the two-pack fixture.
#[must_use]
pub fn result() -> ForkResult {
    let mut digest = Hasher::new();
    for pack in PACKS {
        digest.update(&pack);
    }
    ForkResult::new(
        RefName("main".into()),
        RepositoryId([6; 32]),
        9,
        [10; 32],
        [8; 32],
        2,
        42,
        3,
        digest.finalize(),
        revision(1),
    )
}
/// First membership unit before either destination witness is installed.
#[must_use]
pub fn unit() -> ForkMembershipUnit {
    ForkMembershipUnit::new(
        [7; 32],
        revision(3),
        ForkWitness::new(revision(1), 0, true, false, false),
        None,
        None,
        ForkPairContext::Initial,
    )
}
/// Scoped destination proof stand-in. Production hosts must acquire its evidence.
#[must_use]
pub fn proof() -> ForkClearanceProof {
    ForkClearanceProof::new(
        RepositoryId([2; 32]),
        [1; 32],
        revision(3),
        [7; 32],
        revision(12),
        200,
        revision(13),
    )
}
/// Build facts borrowing exact immutable result and caller-owned observations.
#[must_use]
pub fn facts<'a>(
    advance: &'a ForkAdvanceFacts,
    result: &'a ForkResult,
    unit: &'a ForkMembershipUnit,
    proof: &'a ForkClearanceProof,
) -> ForkActivationFacts<'a> {
    {
        let mut v = ForkActivationFacts::new(advance, result, &PACKS, unit);
        v.lifecycle = ForkLifecycleProtection::NotOffered;
        v.accepted_result = Some(result);
        v.proof = Some(proof);
        v
    }
}

struct FuzzCase {
    lifecycle: ForkLifecycleProtection,
    advance: ForkAdvanceFacts,
    expected: ForkResult,
    accepted: ForkResult,
    unit: ForkMembershipUnit,
    proof: ForkClearanceProof,
    packs: Vec<[u8; 32]>,
    now: u64,
    limits: ForkActivationLimits,
    has_accepted: bool,
    has_proof: bool,
}
impl FuzzCase {
    fn new() -> Self {
        let expected = result();
        Self {
            lifecycle: ForkLifecycleProtection::NotOffered,
            advance: advance(),
            accepted: expected.clone(),
            expected,
            unit: unit(),
            proof: proof(),
            packs: PACKS.to_vec(),
            now: 100,
            limits: LIMITS,
            has_accepted: true,
            has_proof: true,
        }
    }
    fn mutate(&mut self, opcode: u8, value: u8) {
        match opcode % 21 {
            0..=3 => mutate_progress(&mut self.advance, opcode % 21, value),
            4 => self.has_accepted = value & 1 == 0,
            5 => self.accepted.tip[0] = value,
            6 => self.has_proof = value & 1 == 0,
            7 => match value % 5 {
                0 => self.proof.binding[0] ^= 1,
                1 => self.proof.destination.0[0] ^= 1,
                2 => self.proof.progress_revision = revision(value),
                3 => self.proof.pack[0] ^= 1,
                _ => self.proof.valid_through_ms = u64::from(value),
            },
            8..=10 => mutate_witness(&mut self.unit, opcode % 21, value),
            11 => match value % 4 {
                0 => self.packs.reverse(),
                1 => self.packs.clear(),
                2 => {
                    if self.packs.len() < 4 {
                        self.packs.push([value; 32]);
                    }
                }
                _ => {
                    if let Some(pack) = self.packs.first_mut() {
                        pack[0] = value;
                    }
                }
            },
            12 => self.now = [0, 100, 200, 201, u64::MAX][usize::from(value % 5)],
            13 => self.limits.work = u64::from(value),
            14 => self.expected.branch.0 = "x".repeat(usize::from(value % 129)),
            15 => self.accepted.branch.0 = "y".repeat(usize::from(value % 129)),
            16 => self.advance.progress.revision = revision(value),
            17 => self.unit.inherited_revision = revision(value),
            18 => self.limits.packs = u64::from(value % 5),
            19 => self.unit.pack = [value; 32],
            _ => self.lifecycle = lifecycle_mutation(value),
        }
    }
    fn facts(&self) -> ForkActivationFacts<'_> {
        {
            let mut v =
                ForkActivationFacts::new(&self.advance, &self.expected, &self.packs, &self.unit);
            v.lifecycle = self.lifecycle.clone();
            v.accepted_result = self.has_accepted.then_some(&self.accepted);
            v.proof = self.has_proof.then_some(&self.proof);
            v
        }
    }
    fn assert_install_eligible(&self) {
        assert_eq!(self.advance.progress.phase, ForkAdvancePhase::Accepted);
        assert!(self.has_accepted && self.accepted == self.expected);
        assert_eq!(self.advance.recorded_authority, self.advance.authority);
        assert!(
            self.advance
                .grant_epoch
                .as_ref()
                .is_none_or(|e| e.recorded == e.current)
        );
        assert!(self.has_proof && self.now <= self.proof.valid_through_ms);
        assert_eq!(self.proof.destination, self.advance.destination);
        assert_eq!(self.proof.binding, self.advance.binding);
        assert_eq!(self.proof.progress_revision, self.advance.progress.revision);
        assert_eq!(self.proof.pack, self.unit.pack);
        assert!(self.unit.live.is_none() && self.unit.published.is_none());
        assert_eq!(self.unit.context, ForkPairContext::Initial);
        assert!(self.packs.contains(&self.unit.pack));
        if let ForkLifecycleProtection::Managed {
            expected_incarnation,
            current,
        } = &self.lifecycle
        {
            assert!(
                matches!(current, Some(Observed::Present { value, .. }) if value.state == LifecycleState::Active && value.incarnation == *expected_incarnation)
            );
        }
    }
}
fn lifecycle_mutation(value: u8) -> ForkLifecycleProtection {
    if value.is_multiple_of(6) {
        return ForkLifecycleProtection::NotOffered;
    }
    ForkLifecycleProtection::Managed {
        expected_incarnation: revision(1),
        current: match value % 6 {
            1 => None,
            2 => Some(Observed::Absent(revision(value))),
            _ => Some(Observed::Present {
                value: LifecycleFact::new(
                    revision(if value % 6 == 5 { 99 } else { 1 }),
                    if value % 6 == 4 {
                        LifecycleState::Deleting
                    } else {
                        LifecycleState::Active
                    },
                ),
                revision: revision(value),
            }),
        },
    }
}
fn mutate_progress(advance: &mut ForkAdvanceFacts, opcode: u8, value: u8) {
    match opcode {
        0 => {
            advance.progress.phase = match value % 4 {
                0 => ForkAdvancePhase::Preparing,
                1 => ForkAdvancePhase::Accepted,
                2 => ForkAdvancePhase::Complete,
                _ => ForkAdvancePhase::Failed,
            }
        }
        1 => {
            advance.authority = if value & 1 == 0 {
                ForkObservation::Absent
            } else {
                ForkObservation::Present(revision(value))
            }
        }
        2 => {
            advance.grant_epoch = match value % 3 {
                0 => None,
                1 => Some(ForkEpochFence::new(
                    ForkObservation::Absent,
                    ForkObservation::Absent,
                )),
                _ => Some(ForkEpochFence::new(
                    ForkObservation::Absent,
                    ForkObservation::Present(revision(value)),
                )),
            }
        }
        _ => {
            advance.reservation = match value % 3 {
                0 => None,
                _ => Some(ForkReservationFence::new(
                    mkit_primitives::decision::ReservationId([5; 32]),
                    revision(5),
                    if value % 3 == 1 {
                        ForkObservation::Absent
                    } else {
                        ForkObservation::Present(revision(5))
                    },
                )),
            }
        }
    }
}
fn mutate_witness(unit: &mut ForkMembershipUnit, opcode: u8, value: u8) {
    match opcode {
        8 => {
            let witness = if value & 2 == 0 {
                None
            } else {
                Some(unit.expected)
            };
            if value & 1 == 0 {
                unit.live = witness;
            } else {
                unit.published = witness;
            }
        }
        9 => {
            let mut foreign = unit.expected;
            match value % 5 {
                0 => foreign.generation = revision(99),
                1 => foreign.sequence = 1,
                2 => foreign.published = false,
                3 => foreign.held = true,
                _ => foreign.boundary = !foreign.boundary,
            }
            unit.live = Some(foreign);
        }
        _ => {
            unit.context = if value & 1 == 0 {
                ForkPairContext::Initial
            } else {
                ForkPairContext::AfterGuardLoss
            }
        }
    }
}

/// Replay hostile typed facts with bounded memory and deterministic decisions.
///
/// At most four pack IDs and two branch names of at most 128 bytes are retained.
/// Input never controls a loop allocation or an unbounded result. The independent
/// oracle checks that installing membership requires exact acceptance, authority,
/// a scoped current proof, valid inherited identity, and two absent witnesses.
///
/// # Panics
/// Panics if repeated decisions disagree, a returned guard rejects its own input,
/// or membership installation violates the independent eligibility oracle.
pub fn fuzz_fork_advance(data: &[u8]) {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }
    let mut case = FuzzCase::new();
    for chunk in data.chunks(2) {
        case.mutate(chunk[0], chunk.get(1).copied().unwrap_or(0));
    }
    let facts = case.facts();
    let first = decide_fork_activation(&facts, case.now, case.limits);
    let second = decide_fork_activation(&facts, case.now, case.limits);
    assert_eq!(
        first.as_ref().map(|g| *g.decision()),
        second.as_ref().map(|g| *g.decision())
    );
    let progress = decide_fork_advance(&case.advance, case.now);
    assert_eq!(
        *progress.decision(),
        *decide_fork_advance(&case.advance, case.now).decision()
    );
    if let Ok(guard) = first {
        assert!(guards_hold(&guard, &facts.guards(), case.now));
        if *guard.decision() == ForkActivationDecision::Install {
            case.assert_install_eligible();
        }
    }
}
