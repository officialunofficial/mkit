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
    let changes = [RefChange {
        name: name.clone(),
        condition,
        target: Some(new),
    }];
    let request = RefWriteRequest {
        repository,
        operation: None,
        kind: RefWriteKind::Update,
        changes: &changes,
        admitted: &[],
        presence: None,
        signer: None,
        replay: None,
        ancestry: &[],
        now_ms: 0,
        required: RefRequirements {
            authority: None,
            grant: None,
            incarnation: None,
            policy: None,
            admission: None,
            members: &[],
            indexed_head: false,
            membership_window: MembershipWindow::Elapsed,
            denial: false,
            publication: false,
            source: None,
            valid_through_ms: None,
        },
    };
    let snapshot = Snapshot {
        repository,
        refs: vec![(
            name,
            current.map_or(Observed::Absent(Revision([0; 32])), |value| {
                Observed::Present {
                    value,
                    revision: Revision(value),
                }
            }),
        )],
        replay: None,
        tickets: vec![],
        reservations: vec![],
        authority: None,
        grant: None,
        lifecycle: None,
        members: vec![],
        denial: None,
        policy: None,
        admission: None,
        accounting: None,
        publication: None,
        storage: None,
        basis: vec![],
    };
    let limits = RefDecisionLimits {
        facts: 16,
        guards: 8,
        bytes: 4096,
        work: 16384,
        public_message_bytes: 512,
    };
    let decision = decide_ref_write(&request, &snapshot, limits)?;
    assert!(matches!(decision.decision(), WriteDecision::Apply(_)));
    check_guard_completeness(&decision, decision.required_guards())?;
    assert!(guards_match(&decision, &snapshot, 0));
    // A real host lowers the sealed artifact and compares the guard atomically
    // with the ref effect and every other composed acceptance effect.
    Ok(())
}
