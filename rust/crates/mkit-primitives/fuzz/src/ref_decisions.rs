//! Fixed-size hostile ref models; this defines no wire format.
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

/// Compare bounded CAS decisions and their exact guards to an independent oracle.
/// Trailing input is deliberately irrelevant to the fixed-size semantic model.
///
/// # Panics
/// Panics when a decision disagrees with the independent oracle, omits a guard,
/// accepts a mutated dependency, exceeds its limits, or changes on repetition.
#[allow(clippy::too_many_lines)]
pub fn check(data: &[u8]) {
    super::ticketed::check(data);
    let byte = |i| data.get(i).copied().unwrap_or(0);
    let old = [3; 32];
    let new = [4; 32];
    let condition = match byte(0) % 3 {
        0 => RefWriteCondition::Any,
        1 => RefWriteCondition::Missing,
        _ => RefWriteCondition::Match(old),
    };
    let current = match byte(1) % 3 {
        0 => None,
        1 => Some(old),
        _ => Some(new),
    };
    let expected = match condition {
        RefWriteCondition::Any => true,
        RefWriteCondition::Missing => current.is_none(),
        RefWriteCondition::Match(value) => current == Some(value),
    };
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
    let mut snapshot = {
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
    let decision = decide_ref_write(&request, &snapshot, limits).expect("bounded valid model");
    assert_eq!(
        matches!(decision.decision(), WriteDecision::Apply(_)),
        expected
    );
    let repeated = decide_ref_write(&request, &snapshot, limits).expect("bounded valid model");
    assert_eq!(decision.decision(), repeated.decision());
    assert_eq!(decision.required_guards(), repeated.required_guards());
    assert_eq!(decision.source_fences(), repeated.source_fences());
    assert!(guards_match(&decision, &snapshot, 0));
    check_guard_completeness(&decision, decision.required_guards())
        .expect("complete emitted guards");
    if condition != RefWriteCondition::Any {
        assert!(check_guard_completeness(&decision, &[]).is_err());
        snapshot.refs[0].1 = Observed::Present {
            value: [99; 32],
            revision: Revision([99; 32]),
        };
        assert!(!guards_match(&decision, &snapshot, 0));
    }
    let mut bounded = limits;
    bounded.facts = 0;
    assert!(decide_ref_write(&request, &snapshot, bounded).is_err());
}

#[cfg(test)]
mod tests {
    #[test]
    fn seeded_ref_transitions() {
        super::super::replay_seeds(super::check);
        let mut state = 0x5b8d_9f1b_u64;
        for _ in 0..4096 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            super::check(&state.to_le_bytes());
        }
    }
}
