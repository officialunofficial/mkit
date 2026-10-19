//! Decide a missing ref without acquiring or committing through a runtime.
use mkit_core::refs::RefWriteCondition;
use mkit_primitives::{
    decision::{
        Observed, RefName, Snapshot, WriteDecision,
        ref_write::{
            MembershipWindow, RefChange, RefDecisionLimits, RefRequirements, RefWriteKind,
            RefWriteRequest, check_guard_completeness, decide_ref_write, guards_match,
        },
    },
    evidence::{RepositoryId, Revision},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let condition = RefWriteCondition::Missing;
    let current = None;
    let new = [4; 32];
    let repository = RepositoryId([1; 32]);
    let name = RefName("refs/heads/main".into());
    let changes = [RefChange::new(name.clone(), condition, Some(new))];
    let request = {
        let mut v = RefWriteRequest::new(
            repository,
            RefWriteKind::Update,
            &changes,
            {
                let mut v = RefRequirements::new(MembershipWindow::Elapsed);
                v.authority = None;
                v.grant = None;
                v.incarnation = None;
                v.policy = None;
                v.admission = None;
                v.members = &[];
                v.indexed_head = false;
                v.denial = false;
                v.publication = false;
                v.source = None;
                v.valid_through_ms = None;
                v
            },
            0,
        );
        v.operation = None;
        v.admitted = &[];
        v.presence = None;
        v.signer = None;
        v.replay = None;
        v.ancestry = &[];
        v
    };
    let snapshot = {
        let mut v = Snapshot::new(repository);
        v.refs = vec![(
            name,
            current.map_or(Observed::Absent(Revision([0; 32])), |value| {
                Observed::Present {
                    value,
                    revision: Revision(value),
                }
            }),
        )];
        v.replay = None;
        v.tickets = vec![];
        v.reservations = vec![];
        v.authority = None;
        v.grant = None;
        v.lifecycle = None;
        v.members = vec![];
        v.denial = None;
        v.policy = None;
        v.admission = None;
        v.accounting = None;
        v.storage = None;
        v.publication = None;
        v.basis = vec![];
        v
    };
    let limits = RefDecisionLimits::new(16, 8, 4096, 16384, 512);
    let decision = decide_ref_write(&request, &snapshot, limits)?;
    assert!(matches!(decision.decision(), WriteDecision::Apply(_)));
    check_guard_completeness(&decision, decision.required_guards())?;
    assert!(guards_match(&decision, &snapshot, 0));
    // A real host lowers the sealed artifact and compares the guard atomically
    // with the ref effect and every other composed acceptance effect.
    Ok(())
}
