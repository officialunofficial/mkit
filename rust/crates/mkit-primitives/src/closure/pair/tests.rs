//! Pair-machine semantics, refusal mapping, and checkpoint equivalence.

use super::*;
use crate::evidence::{ProfileId, RulesetId};
use std::collections::BTreeMap;

fn id(n: u8) -> Hash {
    [n; 32]
}
const REPO: RepositoryId = RepositoryId([9; 32]);
const VIEW: Revision = Revision([8; 32]);
const RULESET: RulesetBinding = RulesetBinding {
    ruleset: RulesetId(1),
    profile: ProfileId::Indexed,
};
const LIMITS: PairLimits = PairLimits {
    chain: 16,
    packs: 16,
    discovered: 32,
    dependencies: 32,
    suppliers: 16,
    cleared: 16,
    max_delta_depth: 4,
    work: 1_000_000,
};
fn cfg() -> PairCheckpointCfg {
    PairCheckpointCfg { max_bytes: 1 << 20 }
}

/// A scripted host answering machine requests from frozen tables.
type NodeRow = (Option<Hash>, Vec<Hash>, bool);
type FactRow = (Hash, ObjectType, Vec<Hash>, Vec<Hash>, Option<Hash>);
#[derive(Default)]
struct Host {
    nodes: BTreeMap<Hash, NodeRow>,
    objects: BTreeMap<Hash, FactRow>,
    cleared: Option<(Vec<Hash>, Vec<Hash>)>,
    bases: BTreeMap<Hash, BaseFact>,
    /// Every emitted request, in order, for oracle comparison.
    log: Vec<PairRequest>,
}
fn leak(ids: &[Hash]) -> &'static [Hash] {
    Box::leak(ids.to_vec().into_boxed_slice())
}
impl Host {
    fn answer(&self, request: &PairRequest) -> PairResponse<'static> {
        match *request {
            PairRequest::PackmapNode { request, pack, .. } => PairResponse::PackmapNode {
                request,
                pack,
                value: self.nodes.get(&pack).map_or(Acquisition::Absent, |node| {
                    Acquisition::Present(PackmapNode {
                        prev: node.0,
                        packs: leak(&node.1),
                        boundary: node.2,
                    })
                }),
            },
            PairRequest::Boundary { request } => PairResponse::Boundary {
                request,
                value: self.cleared.as_ref().map_or(Acquisition::Absent, |set| {
                    Acquisition::Present(ClearedSet {
                        objects: leak(&set.0),
                        suppliers: leak(&set.1),
                    })
                }),
            },
            PairRequest::Object {
                request, object, ..
            } => PairResponse::Object {
                request,
                object,
                value: self
                    .objects
                    .get(&object)
                    .map_or(Acquisition::Absent, |fact| {
                        Acquisition::Present(ObjectFact {
                            pack: fact.0,
                            kind: fact.1,
                            children: leak(&fact.2),
                            suppliers: leak(&fact.3),
                            base: fact.4,
                        })
                    }),
            },
            PairRequest::Base {
                request, object, ..
            } => PairResponse::Base {
                request,
                object,
                value: self
                    .bases
                    .get(&object)
                    .map_or(Acquisition::Absent, |fact| Acquisition::Present(*fact)),
            },
        }
    }
}

/// The outstanding request, cloned so the host can answer it.
fn next_request(walker: &mut PairWalker) -> PairRequest {
    match walker.step() {
        Ok(PairStep::Request(request)) => request.clone(),
        other => panic!("expected a request, got {other:?}"),
    }
}
/// Drive a walker to completion or failure, answering every request.
fn run(walker: &mut PairWalker, host: &mut Host) -> Result<PairCoverage, Failure> {
    for _ in 0..10_000 {
        match walker.step()? {
            PairStep::Progress => {}
            PairStep::Covered(coverage) => return Ok(coverage),
            PairStep::Request(request) => {
                host.log.push(request.clone());
                let response = host.answer(request);
                walker.answer(response)?;
            }
        }
    }
    panic!("pair walk exceeded its transition bound");
}
fn fresh(pair: ResultingPair, additions: &[Hash]) -> PairWalker {
    PairWalker::new(pair, additions, REPO, VIEW, RULESET, LIMITS, true, 1).unwrap()
}
fn fail(walker: &mut PairWalker, host: &mut Host) -> (FailureCode, Option<PairCheck>) {
    let error = run(walker, host).unwrap_err();
    (error.code, walker.failure_context())
}
/// Request kind plus its semantic fields, omitting run-bound identities.
fn shape(request: &PairRequest) -> (u8, Option<Hash>, Option<Hash>, bool, bool, u32) {
    match request {
        PairRequest::PackmapNode { pack, addition, .. } => {
            (0, Some(*pack), None, *addition, false, 0)
        }
        PairRequest::Boundary { .. } => (1, None, None, false, false, 0),
        PairRequest::Object {
            object,
            head,
            restricted,
            ..
        } => (2, Some(*object), None, *head, *restricted, 0),
        PairRequest::Base {
            origin,
            object,
            depth,
            ..
        } => (3, Some(*origin), Some(*object), false, false, *depth),
    }
}

#[test]
fn requirement_matrix_covers_every_write_and_surface() {
    for (inspectors, takedown, custom_policy) in
        (0..8).map(|bits| (bits & 1 != 0, bits & 2 != 0, bits & 4 != 0))
    {
        let config = PairConfig {
            inspectors,
            takedown,
            custom_policy,
        };
        assert_eq!(
            pair_requirement(config, PairWrite::Deletion),
            PairRequirement::Exempt(PairExemption::Deletion)
        );
        let expected = if inspectors || takedown || custom_policy {
            PairRequirement::Required
        } else {
            PairRequirement::Exempt(PairExemption::ImmediateUninspected)
        };
        assert_eq!(pair_requirement(config, PairWrite::Advance), expected);
    }
}

#[test]
fn paired_chain_and_walk_cover_dependencies_and_suppliers() {
    let pair = ResultingPair {
        head: Some(id(10)),
        packmap: Some(id(1)),
        branch: true,
    };
    let mut host = Host::default();
    host.nodes.insert(id(1), (None, vec![id(2)], false));
    host.objects.insert(
        id(10),
        (id(2), ObjectType::Commit, vec![id(11)], vec![], None),
    );
    host.objects
        .insert(id(11), (id(2), ObjectType::Tree, vec![], vec![], None));
    let mut walker = fresh(pair, &[id(1)]);
    let coverage = run(&mut walker, &mut host).unwrap();
    assert_eq!(coverage.coverage(), Coverage::ResultingPair);
    assert_eq!(coverage.pair(), pair);
    assert_eq!(coverage.repository(), REPO);
    assert_eq!(coverage.view(), VIEW);
    assert_eq!(coverage.ruleset(), RULESET);
    assert_eq!(coverage.dependencies(), &[id(1), id(2)]);
    assert!(coverage.external_suppliers().is_empty());
    let shapes: Vec<_> = host.log.iter().map(shape).collect();
    assert_eq!(
        shapes,
        vec![
            (0, Some(id(1)), None, true, false, 0),
            (2, Some(id(10)), None, true, true, 0),
            (2, Some(id(11)), None, false, true, 0),
        ]
    );
}

#[test]
fn resumed_unpaired_branch_head_is_still_refused() {
    let pair = ResultingPair {
        head: Some(id(10)),
        packmap: None,
        branch: true,
    };
    let walker = fresh(pair, &[]);
    let bytes = walker.checkpoint().unwrap();
    let expected = PairResume {
        pair,
        additions: &[],
        repository: REPO,
        view: VIEW,
        ruleset: RULESET,
        limits: LIMITS,
        honor_cleared: true,
    };
    let mut resumed = PairWalker::resume(&bytes, cfg(), &expected, 7).unwrap();
    let error = resumed.step().unwrap_err();
    assert_eq!(error.code, FailureCode::MissingClosure);
    assert_eq!(resumed.failure_context(), Some(PairCheck::UnpairedHead));
}
#[test]
fn unpaired_branch_head_and_unrestricted_nonbranch_walk() {
    let pair = ResultingPair {
        head: Some(id(10)),
        packmap: None,
        branch: true,
    };
    let mut walker = fresh(pair, &[]);
    let mut host = Host::default();
    assert_eq!(
        fail(&mut walker, &mut host),
        (FailureCode::MissingClosure, Some(PairCheck::UnpairedHead))
    );
    // A non-branch ref pair without a packmap walks live members unrestricted.
    let pair = ResultingPair {
        head: Some(id(10)),
        packmap: None,
        branch: false,
    };
    let mut host = Host::default();
    host.objects.insert(
        id(10),
        (id(77), ObjectType::Tag, vec![id(11)], vec![], None),
    );
    host.objects
        .insert(id(11), (id(78), ObjectType::Blob, vec![], vec![], None));
    let mut walker = fresh(pair, &[]);
    let coverage = run(&mut walker, &mut host).unwrap();
    assert_eq!(coverage.dependencies(), &[id(77), id(78)]);
    let shapes: Vec<_> = host.log.iter().map(shape).collect();
    assert_eq!(
        shapes,
        vec![
            (2, Some(id(10)), None, true, false, 0),
            (2, Some(id(11)), None, false, false, 0),
        ]
    );
}

#[test]
fn chain_repeat_fails_in_step_not_answer() {
    let pair = ResultingPair {
        head: None,
        packmap: Some(id(1)),
        branch: true,
    };
    let mut host = Host::default();
    host.nodes.insert(id(1), (Some(id(1)), vec![], false));
    let mut walker = fresh(pair, &[]);
    let request = next_request(&mut walker);
    walker.answer(host.answer(&request)).unwrap();
    assert_eq!(walker.step().unwrap_err().code, FailureCode::PackmapCycle);
    assert_eq!(
        walker.failure_context(),
        Some(PairCheck::ChainRepeat { pack: id(1) })
    );
}

#[test]
fn chain_absent_for_addition_and_member_alike() {
    for additions in [vec![id(1)], vec![]] {
        let pair = ResultingPair {
            head: None,
            packmap: Some(id(1)),
            branch: true,
        };
        let mut walker = fresh(pair, &additions);
        let mut host = Host::default();
        assert_eq!(
            fail(&mut walker, &mut host),
            (
                FailureCode::MissingClosure,
                Some(PairCheck::ChainNode { pack: id(1) })
            )
        );
    }
}

#[test]
fn restricted_fact_outside_chain_packs_refuses() {
    let pair = ResultingPair {
        head: Some(id(10)),
        packmap: Some(id(1)),
        branch: true,
    };
    let mut host = Host::default();
    host.nodes.insert(id(1), (None, vec![id(2)], false));
    let mut walker = fresh(pair, &[]);
    let request = next_request(&mut walker);
    walker.answer(host.answer(&request)).unwrap();
    let request = next_request(&mut walker);
    let PairRequest::Object { request, .. } = request else {
        panic!("head request")
    };
    assert_eq!(
        walker
            .answer(PairResponse::Object {
                request,
                object: id(10),
                value: Acquisition::Present(ObjectFact {
                    pack: id(9),
                    kind: ObjectType::Commit,
                    children: &[],
                    suppliers: &[],
                    base: None,
                }),
            })
            .unwrap_err()
            .code,
        FailureCode::InvalidResponse
    );
}

#[test]
fn non_history_head_and_missing_object_refuse() {
    for kind in [ObjectType::Blob, ObjectType::ChunkedBlob] {
        let pair = ResultingPair {
            head: Some(id(10)),
            packmap: Some(id(1)),
            branch: true,
        };
        let mut host = Host::default();
        host.nodes.insert(id(1), (None, vec![id(2)], false));
        host.objects
            .insert(id(10), (id(2), kind, vec![], vec![], None));
        let mut walker = fresh(pair, &[]);
        assert_eq!(
            fail(&mut walker, &mut host),
            (
                FailureCode::WrongKind,
                Some(PairCheck::Head { object: id(10) })
            )
        );
    }
    let pair = ResultingPair {
        head: Some(id(10)),
        packmap: Some(id(1)),
        branch: true,
    };
    let mut host = Host::default();
    host.nodes.insert(id(1), (None, vec![id(2)], false));
    let mut walker = fresh(pair, &[]);
    assert_eq!(
        fail(&mut walker, &mut host),
        (
            FailureCode::MissingClosure,
            Some(PairCheck::Object { object: id(10) })
        )
    );
}

#[test]
fn cleared_head_is_still_requested_and_cleared_skips_walk() {
    let pair = ResultingPair {
        head: Some(id(10)),
        packmap: Some(id(1)),
        branch: true,
    };
    for honor_cleared in [true, false] {
        let mut host = Host::default();
        host.nodes.insert(id(1), (None, vec![id(2)], true));
        host.objects.insert(
            id(10),
            (
                id(2),
                ObjectType::Commit,
                vec![id(11), id(12)],
                vec![],
                None,
            ),
        );
        host.objects.insert(
            id(11),
            (id(2), ObjectType::Tree, vec![id(12)], vec![], None),
        );
        host.objects
            .insert(id(12), (id(2), ObjectType::Blob, vec![], vec![], None));
        host.cleared = Some((vec![id(10), id(11)], vec![id(2), id(3)]));
        let mut walker =
            PairWalker::new(pair, &[], REPO, VIEW, RULESET, LIMITS, honor_cleared, 1).unwrap();
        let coverage = run(&mut walker, &mut host).unwrap();
        let objects: Vec<_> = host
            .log
            .iter()
            .filter_map(|request| match request {
                PairRequest::Object { object, .. } => Some(*object),
                _ => None,
            })
            .collect();
        if honor_cleared {
            assert_eq!(objects, vec![id(10), id(12)]);
            assert!(matches!(host.log[1], PairRequest::Boundary { .. }));
            assert_eq!(coverage.external_suppliers(), &[id(2), id(3)]);
        } else {
            assert_eq!(objects, vec![id(10), id(11), id(12)]);
            assert!(
                !host
                    .log
                    .iter()
                    .any(|r| matches!(r, PairRequest::Boundary { .. }))
            );
            assert!(coverage.external_suppliers().is_empty());
        }
    }
}

#[test]
fn unsorted_or_oversized_cleared_set_refuses() {
    let pair = ResultingPair {
        head: None,
        packmap: Some(id(1)),
        branch: true,
    };
    for set in [
        (vec![id(2), id(1)], vec![]),
        (vec![id(1)], vec![id(3), id(2)]),
        (vec![id(1), id(1)], vec![]),
    ] {
        let mut host = Host::default();
        host.nodes.insert(id(1), (None, vec![], true));
        host.cleared = Some(set);
        let mut walker = fresh(pair, &[]);
        assert_eq!(
            run(&mut walker, &mut host).unwrap_err().code,
            FailureCode::InvalidResponse
        );
    }
    let mut host = Host::default();
    host.nodes.insert(id(1), (None, vec![], true));
    host.cleared = Some(((0u8..20).map(id).collect::<Vec<_>>(), vec![]));
    let mut walker = fresh(pair, &[]);
    let error = run(&mut walker, &mut host).unwrap_err();
    assert_eq!(error.code, FailureCode::ResourceLimit);
    assert_eq!(
        walker.failure_context(),
        Some(PairCheck::Bound(PairBound::Cleared))
    );
}

#[test]
fn base_hops_cap_and_external_supplier_rule() {
    let pair = ResultingPair {
        head: Some(id(10)),
        packmap: Some(id(1)),
        branch: true,
    };
    let mut host = Host::default();
    host.nodes.insert(id(1), (None, vec![id(2)], false));
    host.objects.insert(
        id(10),
        (
            id(2),
            ObjectType::Commit,
            vec![],
            vec![id(30)],
            Some(id(20)),
        ),
    );
    // 20 in the origin pack (not a supplier), 21 in pack 3 (supplier),
    // 22 back in the origin pack, 23 in pack 4 terminating.
    host.bases.insert(
        id(20),
        BaseFact {
            pack: id(2),
            base: Some(id(21)),
        },
    );
    host.bases.insert(
        id(21),
        BaseFact {
            pack: id(3),
            base: Some(id(22)),
        },
    );
    host.bases.insert(
        id(22),
        BaseFact {
            pack: id(2),
            base: Some(id(23)),
        },
    );
    host.bases.insert(
        id(23),
        BaseFact {
            pack: id(4),
            base: None,
        },
    );
    let mut walker = fresh(pair, &[]);
    let coverage = run(&mut walker, &mut host).unwrap();
    assert_eq!(coverage.dependencies(), &[id(1), id(2)]);
    assert_eq!(coverage.external_suppliers(), &[id(3), id(4), id(30)]);
    assert!(matches!(
        host.log.last(),
        Some(PairRequest::Base {
            origin,
            object,
            depth: 3,
            ..
        }) if *origin == id(2) && *object == id(23)
    ));
    // Over the cap the next hop refuses inside step, before any request.
    host.bases.insert(
        id(23),
        BaseFact {
            pack: id(4),
            base: Some(id(24)),
        },
    );
    let limits = PairLimits {
        max_delta_depth: 3,
        ..LIMITS
    };
    let mut walker = PairWalker::new(pair, &[], REPO, VIEW, RULESET, limits, true, 1).unwrap();
    let error = run(&mut walker, &mut host).unwrap_err();
    assert_eq!(error.code, FailureCode::DeltaChainTooDeep);
    assert_eq!(
        walker.failure_context(),
        Some(PairCheck::Base {
            object: id(23),
            depth: 3
        })
    );
    // An absent base is its own refusal.
    let mut host = Host::default();
    host.nodes.insert(id(1), (None, vec![id(2)], false));
    host.objects.insert(
        id(10),
        (id(2), ObjectType::Commit, vec![], vec![], Some(id(20))),
    );
    let mut walker = fresh(pair, &[]);
    assert_eq!(
        fail(&mut walker, &mut host),
        (
            FailureCode::ExternalBaseAbsent,
            Some(PairCheck::Base {
                object: id(20),
                depth: 0
            })
        )
    );
}

#[test]
fn every_bound_trips_at_and_only_at_its_limit() {
    chain_and_pack_bounds();
    frontier_and_supplier_bounds();
}
fn chain_and_pack_bounds() {
    let pair = |root| ResultingPair {
        head: None,
        packmap: Some(root),
        branch: true,
    };
    for (n, ok) in [(16usize, true), (17, false)] {
        let mut host = Host::default();
        for i in 0..n {
            let prev = (i + 1 < n).then(|| id(u8::try_from(i).unwrap() + 2));
            host.nodes
                .insert(id(u8::try_from(i).unwrap() + 1), (prev, vec![], false));
        }
        let mut walker = fresh(pair(id(1)), &[]);
        assert_eq!(run(&mut walker, &mut host).is_ok(), ok, "chain {n}");
        if !ok {
            assert_eq!(
                walker.failure_context(),
                Some(PairCheck::Bound(PairBound::Chain))
            );
        }
    }
    let mut host = Host::default();
    host.nodes
        .insert(id(1), (None, (10u8..27).map(id).collect(), false));
    let mut walker = fresh(pair(id(1)), &[]);
    assert_eq!(
        run(&mut walker, &mut host).unwrap_err().code,
        FailureCode::ResourceLimit
    );
    assert_eq!(
        walker.failure_context(),
        Some(PairCheck::Bound(PairBound::Packs))
    );
}
fn frontier_and_supplier_bounds() {
    let limits = PairLimits {
        discovered: 3,
        ..LIMITS
    };
    let mut host = Host::default();
    host.nodes.insert(id(1), (None, vec![id(2)], false));
    host.objects.insert(
        id(10),
        (
            id(2),
            ObjectType::Commit,
            vec![id(11), id(12), id(13)],
            vec![],
            None,
        ),
    );
    let mut walker = PairWalker::new(
        ResultingPair {
            head: Some(id(10)),
            packmap: Some(id(1)),
            branch: true,
        },
        &[],
        REPO,
        VIEW,
        RULESET,
        limits,
        true,
        1,
    )
    .unwrap();
    let error = run(&mut walker, &mut host).unwrap_err();
    assert_eq!(error.code, FailureCode::ResourceLimit);
    assert_eq!(
        walker.failure_context(),
        Some(PairCheck::Bound(PairBound::Discovered))
    );
    let limits = PairLimits {
        suppliers: 1,
        ..LIMITS
    };
    let mut host = Host::default();
    host.nodes.insert(id(1), (None, vec![id(2)], false));
    host.objects.insert(
        id(10),
        (
            id(2),
            ObjectType::Commit,
            vec![],
            vec![id(30), id(31)],
            None,
        ),
    );
    let mut walker = PairWalker::new(
        ResultingPair {
            head: Some(id(10)),
            packmap: Some(id(1)),
            branch: true,
        },
        &[],
        REPO,
        VIEW,
        RULESET,
        limits,
        true,
        1,
    )
    .unwrap();
    assert_eq!(
        run(&mut walker, &mut host).unwrap_err().code,
        FailureCode::ResourceLimit
    );
    assert_eq!(
        walker.failure_context(),
        Some(PairCheck::Bound(PairBound::Suppliers))
    );
    let limits = PairLimits { work: 0, ..LIMITS };
    let mut walker = PairWalker::new(
        ResultingPair {
            head: None,
            packmap: Some(id(1)),
            branch: true,
        },
        &[],
        REPO,
        VIEW,
        RULESET,
        limits,
        true,
        1,
    )
    .unwrap();
    assert_eq!(walker.step().unwrap_err().code, FailureCode::ResourceLimit);
    assert_eq!(
        walker.failure_context(),
        Some(PairCheck::Bound(PairBound::Work))
    );
}

#[test]
fn stale_unsolicited_duplicate_and_mismatched_responses_refuse() {
    let pair = ResultingPair {
        head: None,
        packmap: Some(id(1)),
        branch: true,
    };
    let mut walker = fresh(pair, &[]);
    let first = next_request(&mut walker);
    // A repeated step returns the identical request.
    assert_eq!(next_request(&mut walker), first);
    let PairRequest::PackmapNode { request, .. } = first else {
        panic!()
    };
    // Stale id, mismatched echo, and wrong variant each refuse and poison.
    for response in [
        PairResponse::PackmapNode {
            request: RequestId {
                generation: request.generation + 1,
                ..request
            },
            pack: id(1),
            value: Acquisition::Absent,
        },
        PairResponse::PackmapNode {
            request,
            pack: id(9),
            value: Acquisition::Absent,
        },
        PairResponse::Boundary {
            request,
            value: Acquisition::Absent,
        },
    ] {
        assert_eq!(
            walker.answer(response).unwrap_err().code,
            FailureCode::InvalidResponse
        );
        assert_eq!(
            walker.step().unwrap_err().code,
            FailureCode::InvalidResponse
        );
        walker = fresh(pair, &[]);
        let _ = next_request(&mut walker);
    }
    // Unavailable input is its own code and poisons.
    let mut walker = fresh(pair, &[]);
    let request = next_request(&mut walker);
    let PairRequest::PackmapNode { request, pack, .. } = request else {
        panic!()
    };
    assert_eq!(
        walker
            .answer(PairResponse::PackmapNode {
                request,
                pack,
                value: Acquisition::Unavailable,
            })
            .unwrap_err()
            .code,
        FailureCode::UnavailableInput
    );
    assert!(walker.checkpoint().is_err());
    assert_eq!(
        walker.step().unwrap_err().code,
        FailureCode::InvalidResponse
    );
}

/// The same scripted pair, uninterrupted and checkpoint/resumed after every
/// quiescent answer, produces identical request shapes and results.
#[test]
fn checkpoint_and_resume_reproduce_the_uninterrupted_run() {
    let pair = ResultingPair {
        head: Some(id(10)),
        packmap: Some(id(1)),
        branch: true,
    };
    let additions = &[id(1)];
    let build = |host: &mut Host| {
        host.nodes.insert(id(1), (Some(id(2)), vec![id(3)], true));
        host.nodes.insert(id(2), (None, vec![id(3), id(4)], false));
        host.cleared = Some((vec![id(11)], vec![id(5)]));
        host.objects.insert(
            id(10),
            (
                id(3),
                ObjectType::Commit,
                vec![id(11), id(12)],
                vec![],
                Some(id(20)),
            ),
        );
        host.objects.insert(
            id(12),
            (id(4), ObjectType::Tree, vec![id(13)], vec![id(6)], None),
        );
        host.objects
            .insert(id(13), (id(4), ObjectType::Blob, vec![], vec![], None));
        host.bases.insert(
            id(20),
            BaseFact {
                pack: id(7),
                base: None,
            },
        );
    };
    let expected = PairResume {
        pair,
        additions,
        repository: REPO,
        view: VIEW,
        ruleset: RULESET,
        limits: LIMITS,
        honor_cleared: true,
    };
    let mut host = Host::default();
    build(&mut host);
    let mut walker = fresh(pair, additions);
    let coverage = run(&mut walker, &mut host).unwrap();
    let reference: Vec<_> = host.log.iter().map(shape).collect();
    assert_eq!(coverage.dependencies(), &[id(1), id(2), id(3), id(4)]);
    assert_eq!(coverage.external_suppliers(), &[id(5), id(6), id(7)]);

    let mut host = Host::default();
    build(&mut host);
    let mut walker = fresh(pair, additions);
    let mut log = Vec::new();
    let mut generation = 2u64;
    // Resume at several points. Each resume re-requests the boundary once,
    // as the cleared set is host state outside the checkpoint.
    let mut resumes = 0;
    let mut outcome = None;
    for _ in 0..10_000 {
        match walker.step().unwrap() {
            PairStep::Progress => {}
            PairStep::Covered(done) => {
                outcome = Some(done);
                break;
            }
            PairStep::Request(request) => {
                log.push(request.clone());
                let response = host.answer(request);
                walker.answer(response).unwrap();
                if resumes < 8
                    && let Ok(bytes) = walker.checkpoint()
                {
                    PairWalker::validate_checkpoint(&bytes, cfg()).unwrap();
                    walker = PairWalker::resume(&bytes, cfg(), &expected, generation).unwrap();
                    generation += 1;
                    resumes += 1;
                }
            }
        }
    }
    let coverage = outcome.unwrap_or_else(|| panic!("resumed walk exceeded its transition bound"));
    let shapes: Vec<_> = log.iter().map(shape).collect();
    // The resumed run issues the same chain and walk requests; the boundary
    // load repeats once per resume that crosses it, exactly as the reference
    // resumable path reloads the cleared set per slice.
    let core: Vec<_> = reference.iter().filter(|s| s.0 != 1).collect();
    let resumed_log: Vec<_> = shapes.iter().filter(|s| s.0 != 1).collect();
    assert_eq!(resumed_log, core);
    assert!(
        log.iter()
            .any(|r| matches!(r, PairRequest::Boundary { .. }))
    );
    assert_eq!(coverage.dependencies(), &[id(1), id(2), id(3), id(4)]);
    assert_eq!(coverage.external_suppliers(), &[id(5), id(6), id(7)]);
}

#[test]
fn resume_refuses_every_expected_mismatch_and_corruption() {
    let pair = ResultingPair {
        head: Some(id(10)),
        packmap: Some(id(1)),
        branch: true,
    };
    let mut host = Host::default();
    host.nodes.insert(id(1), (Some(id(2)), vec![id(3)], true));
    host.nodes.insert(id(2), (None, vec![id(3)], false));
    host.cleared = Some((vec![id(11)], vec![id(5)]));
    host.objects.insert(
        id(10),
        (id(3), ObjectType::Commit, vec![id(11)], vec![], None),
    );
    let mut walker = fresh(pair, &[]);
    for _ in 0..3 {
        let request = next_request(&mut walker);
        walker.answer(host.answer(&request)).unwrap();
    }
    let bytes = walker.checkpoint().unwrap();
    let expected = PairResume {
        pair,
        additions: &[],
        repository: REPO,
        view: VIEW,
        ruleset: RULESET,
        limits: LIMITS,
        honor_cleared: true,
    };
    let _ = PairWalker::resume(&bytes, cfg(), &expected, 7).unwrap();
    for wrong in [
        PairResume {
            pair: ResultingPair {
                head: Some(id(9)),
                ..pair
            },
            ..expected.clone()
        },
        PairResume {
            pair: ResultingPair {
                branch: false,
                ..pair
            },
            ..expected.clone()
        },
        PairResume {
            additions: &[id(1)],
            ..expected.clone()
        },
        PairResume {
            repository: RepositoryId([0; 32]),
            ..expected.clone()
        },
        PairResume {
            view: Revision([0; 32]),
            ..expected.clone()
        },
        PairResume {
            ruleset: RulesetBinding {
                ruleset: RulesetId(2),
                ..RULESET
            },
            ..expected.clone()
        },
        PairResume {
            limits: PairLimits { chain: 9, ..LIMITS },
            ..expected.clone()
        },
        PairResume {
            honor_cleared: false,
            ..expected
        },
    ] {
        assert_eq!(
            PairWalker::resume(&bytes, cfg(), &wrong, 7)
                .unwrap_err()
                .code,
            FailureCode::InvalidCheckpoint
        );
    }
}
#[test]
fn checkpoint_decode_refuses_corruption() {
    let pair = ResultingPair {
        head: Some(id(10)),
        packmap: Some(id(1)),
        branch: true,
    };
    let mut host = Host::default();
    host.nodes.insert(id(1), (Some(id(2)), vec![id(3)], true));
    host.nodes.insert(id(2), (None, vec![id(3)], false));
    host.cleared = Some((vec![id(11)], vec![id(5)]));
    host.objects.insert(
        id(10),
        (id(3), ObjectType::Commit, vec![id(11)], vec![], None),
    );
    let mut walker = fresh(pair, &[]);
    for _ in 0..3 {
        let request = next_request(&mut walker);
        walker.answer(host.answer(&request)).unwrap();
    }
    let bytes = walker.checkpoint().unwrap();
    // Corrupt bytes: version, flags, checksum, truncation, trailing byte.
    for (offset, value) in [(0usize, 2u8), (68, 0xe0), (bytes.len() - 1, 0)] {
        let mut bad = bytes.clone();
        bad[offset] = value;
        assert_eq!(
            PairWalker::validate_checkpoint(&bad, cfg())
                .unwrap_err()
                .code,
            FailureCode::InvalidCheckpoint
        );
    }
    for len in 0..bytes.len().min(80) {
        assert!(PairWalker::validate_checkpoint(&bytes[..len], cfg()).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(PairWalker::validate_checkpoint(&trailing, cfg()).is_err());
    assert_eq!(
        PairWalker::validate_checkpoint(
            &bytes,
            PairCheckpointCfg {
                max_bytes: u32::try_from(bytes.len()).unwrap() - 1
            }
        )
        .unwrap_err()
        .code,
        FailureCode::InvalidCheckpoint
    );
    // Checkpointing refuses with an outstanding request.
    let mut walker = fresh(pair, &[]);
    let _ = next_request(&mut walker);
    assert_eq!(
        walker.checkpoint().unwrap_err().code,
        FailureCode::InvalidResponse
    );
    // Clone rollback: a poisoned answer leaves the copy usable.
    let mut walker = fresh(pair, &[]);
    let snapshot = walker.clone();
    let request = next_request(&mut walker);
    let PairRequest::PackmapNode { request, .. } = request else {
        panic!()
    };
    assert!(
        walker
            .answer(PairResponse::PackmapNode {
                request: RequestId {
                    generation: 99,
                    sequence: request.sequence
                },
                pack: id(1),
                value: Acquisition::Absent,
            })
            .is_err()
    );
    let mut rolled = snapshot;
    let mut host = Host::default();
    host.nodes.insert(id(1), (None, vec![id(3)], false));
    host.objects
        .insert(id(10), (id(3), ObjectType::Commit, vec![], vec![], None));
    assert!(run(&mut rolled, &mut host).is_ok());
}

/// Checkpoint fixtures: frozen bytes authored once, never regenerated.
mod fixtures {
    use super::*;
    use mkit_core::hash::domain_digest;

    const DOMAIN: &[u8] = b"mkit-pair-checkpoint:v1";
    const NAMES: [&str; 12] = [
        "pair-minimal",
        "pair-walk",
        "pair-base-cursor",
        "pair-boundary",
        "pair-bad-version",
        "pair-bad-flag",
        "pair-trailing",
        "pair-bad-checksum",
        "pair-unsorted",
        "pair-queue-overlap",
        "pair-count-over",
        "pair-cursor-in-chain",
    ];

    /// Body offsets of the counted lists, discovered by walking the format.
    fn lists(body: &[u8]) -> Vec<(usize, u32)> {
        let mut position = 1 + 32 + 32 + 4 + 1 + 1;
        let flags = body[70];
        if flags & 1 != 0 {
            position += 32;
        }
        if flags & 2 != 0 {
            position += 32;
        }
        position += 7 * 4 + 8 + 1;
        if body[position] == 1 {
            position += 33;
        } else {
            position += 1;
        }
        if body[position] == 1 {
            position += 1 + 32 + 32 + 4;
        } else {
            position += 1;
        }
        position += 8;
        let mut out = Vec::new();
        for _ in 0..7 {
            let count = u32::from_le_bytes(body[position..position + 4].try_into().unwrap());
            out.push((position, count));
            position += 4 + count as usize * 32;
        }
        assert_eq!(position, body.len());
        out
    }
    fn fix(mut bytes: Vec<u8>) -> Vec<u8> {
        let len = bytes.len() - 32;
        let checksum = domain_digest(DOMAIN, &bytes[..len]);
        bytes.truncate(len);
        bytes.extend_from_slice(&checksum);
        bytes
    }
    fn tail(body: &[u8]) -> Vec<u8> {
        let mut out = body.to_vec();
        out.extend_from_slice(&domain_digest(DOMAIN, body));
        out
    }

    /// Walkers checkpointed at each documented phase.
    fn states() -> BTreeMap<&'static str, Vec<u8>> {
        let mut out = BTreeMap::new();
        // Minimal: nothing answered; chain phase at the packmap tip.
        let pair = ResultingPair {
            head: Some(id(10)),
            packmap: Some(id(1)),
            branch: true,
        };
        let walker = fresh(pair, &[id(1), id(9)]);
        out.insert("pair-minimal", walker.checkpoint().unwrap());
        // Walk phase: chain done, head visited with children queued.
        let mut host = Host::default();
        host.nodes.insert(id(1), (None, vec![id(2)], false));
        host.objects.insert(
            id(10),
            (
                id(2),
                ObjectType::Commit,
                vec![id(11), id(12)],
                vec![id(5)],
                None,
            ),
        );
        let mut walker = fresh(pair, &[id(1)]);
        for _ in 0..2 {
            let request = next_request(&mut walker);
            walker.answer(host.answer(&request)).unwrap();
        }
        out.insert("pair-walk", walker.checkpoint().unwrap());
        // Base-cursor phase after an object answer carrying a delta base.
        let mut host = Host::default();
        host.nodes.insert(id(1), (None, vec![id(2)], false));
        host.objects.insert(
            id(10),
            (id(2), ObjectType::Commit, vec![], vec![], Some(id(20))),
        );
        let mut walker = fresh(pair, &[id(1)]);
        for _ in 0..2 {
            let request = next_request(&mut walker);
            walker.answer(host.answer(&request)).unwrap();
        }
        let bytes = walker.checkpoint().unwrap();
        out.insert("pair-base-cursor", bytes);
        // Boundary: cleared set applied; populated lists at their counts.
        let mut host = Host::default();
        host.nodes
            .insert(id(1), (Some(id(2)), vec![id(3), id(4)], true));
        host.nodes.insert(id(2), (None, vec![id(4)], false));
        host.cleared = Some((vec![id(11)], vec![id(5), id(6)]));
        host.objects.insert(
            id(10),
            (
                id(3),
                ObjectType::Commit,
                vec![id(11), id(12)],
                vec![id(7)],
                None,
            ),
        );
        let mut walker = fresh(pair, &[id(1)]);
        for _ in 0..4 {
            let request = next_request(&mut walker);
            walker.answer(host.answer(&request)).unwrap();
        }
        out.insert("pair-boundary", walker.checkpoint().unwrap());
        out
    }
    /// Malformed variants of the representative walk checkpoint.
    fn malformed(walk: &[u8]) -> BTreeMap<&'static str, Vec<u8>> {
        let mut out = BTreeMap::new();
        let body_len = walk.len() - 32;
        let mut bad = walk.to_vec();
        bad[0] = 2;
        out.insert("pair-bad-version", fix(bad));
        let mut bad = walk.to_vec();
        bad[69] |= 0xe0;
        out.insert("pair-bad-flag", fix(bad));
        let mut trailing = walk[..body_len].to_vec();
        trailing.push(0);
        out.insert("pair-trailing", tail(&trailing));
        let mut bad = walk.to_vec();
        *bad.last_mut().unwrap() ^= 1;
        out.insert("pair-bad-checksum", bad);
        let offsets = lists(&walk[..body_len]);
        // dependencies is list index 4 with two entries; swap breaks strict order.
        let (at, count) = offsets[4];
        assert!(count >= 2);
        let mut bad = walk.to_vec();
        for b in 0..32 {
            bad.swap(at + 4 + b, at + 36 + b);
        }
        out.insert("pair-unsorted", fix(bad));
        // queue is list index 6: overwrite its first id with a visited one.
        let (qat, qcount) = offsets[6];
        let (vat, _) = offsets[3];
        assert!(qcount >= 1);
        let mut bad = walk.to_vec();
        bad[qat + 4..qat + 36].copy_from_slice(&walk[vat + 4..vat + 36]);
        out.insert("pair-queue-overlap", fix(bad));
        // dependencies is list index 4: claim the maximum count.
        let (dat, _) = offsets[4];
        let mut bad = walk.to_vec();
        bad[dat..dat + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        out.insert("pair-count-over", fix(bad));
        // A cursor tagged present while the phase says chain.
        let all = states();
        let minimal = &all["pair-minimal"];
        let mbody = minimal[..minimal.len() - 32].to_vec();
        let cursor_at = {
            let mut position = 1 + 32 + 32 + 4 + 1 + 1 + 32 + 32 + 7 * 4 + 8 + 1;
            position += if mbody[position] == 1 { 33 } else { 1 };
            position
        };
        assert_eq!(mbody[cursor_at], 0);
        let mut bad = mbody[..cursor_at].to_vec();
        bad.push(1);
        bad.extend_from_slice(&id(7));
        bad.extend_from_slice(&id(8));
        bad.extend_from_slice(&0u32.to_le_bytes());
        bad.extend_from_slice(&mbody[cursor_at + 1..]);
        out.insert("pair-cursor-in-chain", tail(&bad));
        out
    }

    #[test]
    fn frozen_checkpoints_match_the_encoder_and_refuse_malformed() {
        let states = states();
        for (name, bytes) in &states {
            let fixture = format!("fixtures/closure/{name}.bin");
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(&fixture);
            assert_eq!(
                &std::fs::read(&path).unwrap()[..],
                &bytes[..],
                "{name} drifted"
            );
        }
        for (name, bytes) in malformed(&states["pair-walk"]) {
            let fixture = format!("fixtures/closure/{name}.bin");
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(&fixture);
            assert_eq!(
                &std::fs::read(&path).unwrap()[..],
                &bytes[..],
                "{name} drifted"
            );
            assert_eq!(
                PairWalker::validate_checkpoint(&bytes, cfg())
                    .unwrap_err()
                    .code,
                FailureCode::InvalidCheckpoint,
                "{name} decoded"
            );
        }
        // Every valid checkpoint resumes under its recorded binding.
        let pair = ResultingPair {
            head: Some(id(10)),
            packmap: Some(id(1)),
            branch: true,
        };
        let expected = PairResume {
            pair,
            additions: &[id(1), id(9)],
            repository: REPO,
            view: VIEW,
            ruleset: RULESET,
            limits: LIMITS,
            honor_cleared: true,
        };
        let minimal = &states["pair-minimal"];
        let _ = PairWalker::resume(minimal, cfg(), &expected, 9).unwrap();
    }

    #[test]
    #[ignore = "writes frozen fixture bytes once"]
    fn dump_fixture_bytes() {
        let mut all = states();
        let walk = all["pair-walk"].clone();
        all.extend(malformed(&walk));
        for name in NAMES {
            eprintln!("{name} {}", hex(&all[name]));
        }
    }
    fn hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push(char::from(HEX[usize::from(b >> 4)]));
            out.push(char::from(HEX[usize::from(b & 15)]));
        }
        out
    }
}

/// Seeded random DAGs against an independent breadth-first oracle: visit order,
/// dependencies, and external suppliers must agree exactly.
#[test]
fn seeded_dag_matches_independent_bfs_oracle() {
    let mut seed = 0x9e37_79b9u64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for case in 0..24 {
        let objects = 8 + (next() % 12) as u8;
        let mut host = Host::default();
        let mut edges: Vec<(Hash, Vec<Hash>)> = Vec::new();
        for n in 0..objects {
            let object = id(n + 1);
            let mut children = Vec::new();
            for _ in 0..(next() % 3) {
                let child = id(1 + u8::try_from(next() % u64::from(objects)).unwrap());
                if child != object {
                    children.push(child);
                }
            }
            let suppliers = (0..(next() % 2)).map(|_| id(40 + n)).collect::<Vec<_>>();
            let base = (next() % 5 == 0).then(|| id(50 + u8::try_from(next() % 4).unwrap()));
            host.objects.insert(
                object,
                (
                    id(20 + u8::try_from(next() % 4).unwrap()),
                    ObjectType::Commit,
                    children.clone(),
                    suppliers,
                    base,
                ),
            );
            edges.push((object, children));
        }
        for n in 0..4u8 {
            let base = id(50 + n);
            host.bases.insert(
                base,
                BaseFact {
                    pack: id(60 + u8::try_from(next() % 3).unwrap()),
                    base: None,
                },
            );
        }
        // Two-node chain listing all supplier packs.
        let packs: Vec<Hash> = (0..4).map(|n| id(20 + n)).collect();
        host.nodes
            .insert(id(1), (Some(id(2)), packs.clone(), false));
        host.nodes.insert(id(2), (None, vec![id(90)], false));
        let pair = ResultingPair {
            head: Some(id(1)),
            packmap: Some(id(1)),
            branch: true,
        };
        let mut walker = fresh(pair, &[]);
        let coverage = run(&mut walker, &mut host).unwrap();

        let (order, deps, suppliers) = bfs_oracle(&host, &packs);
        let requested: Vec<Hash> = host
            .log
            .iter()
            .filter_map(|request| match request {
                PairRequest::Object { object, .. } => Some(*object),
                _ => None,
            })
            .collect();
        assert_eq!(requested, order, "visit order, case {case}");
        assert_eq!(
            coverage.dependencies(),
            &deps.into_iter().collect::<Vec<_>>(),
            "dependencies, case {case}"
        );
        assert_eq!(
            coverage.external_suppliers(),
            &suppliers.into_iter().collect::<Vec<_>>(),
            "suppliers, case {case}"
        );
    }
}

/// Oracle: breadth-first over the same table with first-occurrence dedupe.
fn bfs_oracle(host: &Host, packs: &[Hash]) -> (Vec<Hash>, BTreeSet<Hash>, BTreeSet<Hash>) {
    let mut order = Vec::new();
    let mut explored = BTreeSet::new();
    let mut queue = VecDeque::from([id(1)]);
    let mut deps = BTreeSet::from([id(1), id(2), id(90)]);
    deps.extend(packs.iter().copied());
    let mut suppliers = BTreeSet::new();
    let mut cursors: VecDeque<(Hash, Hash, u32)> = VecDeque::new();
    while let Some(object) = queue.pop_front() {
        if !explored.insert(object) {
            continue;
        }
        let fact = &host.objects[&object];
        deps.insert(fact.0);
        suppliers.extend(fact.3.iter().copied());
        for child in &fact.2 {
            queue.push_back(*child);
        }
        if let Some(base) = fact.4 {
            cursors.push_back((fact.0, base, 0));
        }
        order.push(object);
    }
    while let Some((origin, base, depth)) = cursors.pop_front() {
        assert!(depth < 4);
        let fact = host.bases[&base];
        if fact.pack != origin {
            suppliers.insert(fact.pack);
        }
        if let Some(next) = fact.base {
            cursors.push_back((origin, next, depth + 1));
        }
    }
    (order, deps, suppliers)
}

#[test]
fn clearance_advance_takes_sets_only_from_matching_coverage() {
    use crate::decision::{ClearanceAdvance, ClearanceState, OperationId};
    let pair = ResultingPair {
        head: Some(id(10)),
        packmap: Some(id(1)),
        branch: true,
    };
    let mut host = Host::default();
    host.nodes.insert(id(1), (None, vec![id(2)], false));
    host.objects
        .insert(id(10), (id(2), ObjectType::Commit, vec![], vec![], None));
    let coverage = run(&mut fresh(pair, &[id(1)]), &mut host).unwrap();
    let advance = |head, packmap| ClearanceAdvance {
        sequence: 1,
        generation: 1,
        operation: OperationId([1; 32]),
        head,
        packmap,
        state: ClearanceState::Cleared,
        additions: &[],
        dependencies: &[],
        external_suppliers: &[],
        obligations: &[],
        obligation_revisions: &[],
        takedown_complete: false,
        flagged: false,
        revision: VIEW,
    };
    let taken = advance(Some(id(10)), Some(id(1)))
        .with_pair(REPO, &coverage)
        .unwrap();
    assert_eq!(taken.dependencies, coverage.dependencies());
    assert_eq!(taken.external_suppliers, coverage.external_suppliers());
    for refused in [
        advance(Some(id(11)), Some(id(1))).with_pair(REPO, &coverage),
        advance(Some(id(10)), Some(id(3))).with_pair(REPO, &coverage),
        advance(Some(id(10)), Some(id(1))).with_pair(RepositoryId([7; 32]), &coverage),
    ] {
        assert_eq!(refused.unwrap_err().code, FailureCode::InvalidResponse);
    }
}
