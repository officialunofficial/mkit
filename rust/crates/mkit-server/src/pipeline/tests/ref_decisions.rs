//! Full physical-plan parity against the frozen planner, not just ref values.
use super::*;

fn request<'a>(name: &'a RepoName, refs: &'a [RefUpdate]) -> WriteRequest<'a> {
    WriteRequest {
        namespace: NamespaceKey::deployment_default(),
        repo: name,
        denial_ids: None,
        denial_packs: &[],
        fork_barrier: false,
        authority_store: AuthorityStore::Guarded,
        authority_generation: None,
        kind: if refs.len() == 1 {
            WriteKind::UpdateRef
        } else {
            WriteKind::AdvanceRefs
        },
        refs,
        resolved_ref_updates: &[],
        ref_index: None,
        replay: None,
        charges: &[],
        namespace_charge: None,
        grant: None,
        lease: None,
        layout_version: false,
        mark_repo_known: false,
        begin: None,
        advance: None,
        implicit: None,
        rejection: None,
        publication: None,
        pending: None,
    }
}

fn parity(req: &WriteRequest<'_>, snap: &Snapshot) {
    let clock = clock_at(5, None);
    let actual = plan_write(req, snap, &clock);
    let expected = plan::reference::plan_write(req, snap, &clock);
    match (actual, expected) {
        (Ok(actual), Ok(expected)) => assert_eq!(actual, expected),
        (Err(actual), Err(expected)) => {
            assert_eq!(actual.code(), expected.code());
            assert_eq!(actual.public_message(), expected.public_message());
            assert_eq!(actual.abort_cause(), expected.abort_cause());
        }
        (actual, expected) => panic!("different plans: actual={actual:?} reference={expected:?}"),
    }
}

#[test]
fn portable_ref_planner_full_cas_admission_grant_and_replay_matrix() {
    let name = repo_name();
    let mut cases = 0;
    for pair in [false, true] {
        for first in [Any, Missing, Match(A)] {
            for second in [Any, Missing, Match(A)] {
                if !pair && second != Any {
                    continue;
                }
                for first_current in [None, Some(A), Some(B)] {
                    for second_current in [None, Some(A), Some(B)] {
                        if !pair && second_current.is_some() {
                            continue;
                        }
                        for admission in 0..4 {
                            for granted_presence in [None, Some(false), Some(true)] {
                                for signed in [false, true] {
                                    let refs = if pair {
                                        vec![upd(PACKMAP, first, C), upd(HEAD, second, C)]
                                    } else {
                                        vec![upd(HEAD, first, C)]
                                    };
                                    let mut req = request(&name, &refs);
                                    let mut values = Vec::new();
                                    for (update, current) in
                                        refs.iter().zip([first_current, second_current])
                                    {
                                        if let Some(value) = current {
                                            values.push(ref_value(&update.name, value));
                                        }
                                    }
                                    let resolved: Vec<_> = if admission == 0 {
                                        vec![]
                                    } else {
                                        refs.iter()
                                            .zip([first_current, second_current])
                                            .map(|(update, current)| {
                                                let before = current.is_some() ^ (admission == 2);
                                                ResolvedRefUpdate::new(
                                                    update.name.clone(),
                                                    Some(if admission == 3 { A } else { C }),
                                                    if before {
                                                        RefEffect::Replace
                                                    } else {
                                                        RefEffect::Create
                                                    },
                                                )
                                            })
                                            .collect()
                                    };
                                    req.resolved_ref_updates = &resolved;
                                    req.grant =
                                        granted_presence.map(|present| crate::op::GrantRef {
                                            id: [9; 32],
                                            epoch: 0,
                                            presence_requirement: Some(if present {
                                                crate::op::PresenceRequirement::Present(HEAD.into())
                                            } else {
                                                crate::op::PresenceRequirement::Absent(HEAD.into())
                                            }),
                                        });
                                    req.replay = signed.then(replay);
                                    let charges = [charge(100)];
                                    req.charges = if signed { &charges } else { &[] };
                                    parity(&req, &snapshot(&req, &values));
                                    cases += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    assert_eq!(cases, 2_160);
}

#[test]
fn portable_ref_planner_preserves_first_conflict_before_unexamined_corruption() {
    let name = repo_name();
    let refs = [upd(PACKMAP, Match(A), C), upd(HEAD, Match(A), C)];
    let mut req = request(&name, &refs);
    req.replay = Some(replay());
    let values = [
        ref_value(PACKMAP, B),
        (keys::ref_key(&name, HEAD), Value::new(vec![0xff])),
    ];
    parity(&req, &snapshot(&req, &values));
    let values = [
        ref_value(PACKMAP, A),
        (keys::ref_key(&name, HEAD), Value::new(vec![0xff])),
    ];
    parity(&req, &snapshot(&req, &values));
}

#[test]
fn portable_ref_planner_preserves_authority_quota_and_delete_precedence() {
    let name = repo_name();
    for current in [None, Some(A), Some(B)] {
        for authority in [None, Some(0), Some(1)] {
            for limit in [0, 100] {
                let refs = [RefUpdate {
                    name: HEAD.into(),
                    condition: Match(A),
                    new: None,
                }];
                let mut req = request(&name, &refs);
                req.authority_generation = authority;
                req.replay = Some(replay());
                let charges = [charge(limit)];
                req.charges = &charges;
                let values: Vec<_> = current
                    .map(|value| ref_value(HEAD, value))
                    .into_iter()
                    .collect();
                parity(&req, &snapshot(&req, &values));
            }
        }
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn portable_ref_planner_preserves_generic_and_noncanonical_shapes() {
    let name = repo_name();
    let delete = |condition| RefUpdate {
        name: HEAD.into(),
        condition,
        new: None,
    };
    let delete_named = |name: &str, condition| RefUpdate {
        name: name.into(),
        condition,
        new: None,
    };
    // Protocol-admitted shapes the planner must answer either way: pairs are
    // positional, so unmatched, reversed, and repeated names decide portably
    // (SPEC-TRANSPORT-CONNECT §4). Shapes the wire rejects or no procedure
    // emits — unconditional or MISSING deletes and extra updates — keep the
    // generic CAS decision. Guard order, conflict precedence, and outcomes
    // must match on both paths.
    let cases: Vec<Vec<RefUpdate>> = vec![
        vec![delete(Any)],
        vec![delete(Missing)],
        vec![upd(HEAD, Missing, A), upd(HEAD, Missing, A)],
        vec![delete(Match(A)), delete(Match(A))],
        vec![upd(HEAD, Missing, A), upd(PACKMAP, Missing, C)],
        vec![
            upd("refs/heads/f", Missing, A),
            upd("refs/heads/g", Missing, B),
        ],
        vec![upd(PACKMAP, Missing, C), delete_named(HEAD, Match(A))],
        vec![
            delete_named(HEAD, Match(A)),
            delete_named(PACKMAP, Match(A)),
        ],
        vec![delete(Any), upd(PACKMAP, Missing, C)],
        vec![
            upd(HEAD, Missing, A),
            upd(PACKMAP, Missing, C),
            upd("refs/heads/g", Missing, B),
        ],
        vec![upd("heads/f", Missing, A)],
        vec![upd("refs/x", Missing, A)],
    ];
    let mut comparisons = 0;
    for refs in cases {
        for first_current in [None, Some(A), Some(B)] {
            for second_current in [None, Some(A), Some(B)] {
                if refs.len() < 2 && second_current.is_some() {
                    continue;
                }
                for third_current in [None, Some(A)] {
                    if refs.len() < 3 && third_current.is_some() {
                        continue;
                    }
                    // Resolved effects: none, matching, wrong prior, partial
                    // coverage, and a duplicate name the portable contract
                    // rejects but the planner's `find` tolerates.
                    for resolved_mode in 0..5 {
                        for granted_presence in [None, Some(false), Some(true)] {
                            let currents = [first_current, second_current, third_current];
                            let mut values = std::collections::BTreeMap::new();
                            let mut resolved = Vec::new();
                            for (position, (update, current)) in
                                refs.iter().zip(currents).enumerate()
                            {
                                if let Some(value) = current {
                                    values.insert(update.name.clone(), value);
                                }
                                if resolved_mode == 0
                                    || (resolved_mode == 3 && position != 0)
                                    || resolved
                                        .iter()
                                        .any(|r: &ResolvedRefUpdate| r.name == update.name)
                                {
                                    continue;
                                }
                                let present = if resolved_mode == 2 {
                                    current.is_none()
                                } else {
                                    current.is_some()
                                };
                                let effect = match (update.new, present) {
                                    (Some(_), false) => RefEffect::Create,
                                    (Some(_), true) => RefEffect::Replace,
                                    (None, false) => RefEffect::NoChange,
                                    (None, true) => RefEffect::Delete,
                                };
                                resolved.push(ResolvedRefUpdate::new(
                                    update.name.clone(),
                                    update.new,
                                    effect,
                                ));
                                if resolved_mode == 4 {
                                    resolved.push(ResolvedRefUpdate::new(
                                        update.name.clone(),
                                        update.new,
                                        effect,
                                    ));
                                }
                            }
                            let mut req = request(&name, &refs);
                            req.resolved_ref_updates = &resolved;
                            req.grant = granted_presence.map(|present| crate::op::GrantRef {
                                id: [9; 32],
                                epoch: 0,
                                presence_requirement: Some(if present {
                                    crate::op::PresenceRequirement::Present(HEAD.into())
                                } else {
                                    crate::op::PresenceRequirement::Absent(HEAD.into())
                                }),
                            });
                            let values: Vec<_> = values
                                .into_iter()
                                .map(|(name, value)| ref_value(&name, value))
                                .collect();
                            parity(&req, &snapshot(&req, &values));
                            comparisons += 1;
                        }
                    }
                }
            }
        }
    }
    assert_eq!(comparisons, 1_395);
}

#[test]
#[allow(clippy::too_many_lines)]
fn publication_lowering_matches_frozen_planner_including_partial_deletion() {
    use crate::store::publication::{Clearance, Pair, Publication};
    let repository = repo();
    let source = SinglePartition.ref_shard(&repository, HEAD);
    for pair in [false, true] {
        for deleted in [false, true] {
            for sequence in [0, 1, 3, 64, u64::MAX] {
                for prefix in [0, sequence] {
                    for publishable in [false, true] {
                        let refs = if pair {
                            vec![
                                RefUpdate {
                                    name: PACKMAP.into(),
                                    condition: Match(A),
                                    new: (!deleted).then_some(C),
                                },
                                RefUpdate {
                                    name: HEAD.into(),
                                    condition: Match(A),
                                    new: (!deleted).then_some(B),
                                },
                            ]
                        } else {
                            vec![RefUpdate {
                                name: HEAD.into(),
                                condition: Match(A),
                                new: (!deleted).then_some(B),
                            }]
                        };
                        let state = Publication {
                            sequence,
                            published: prefix,
                            boundary: 0,
                            generation: 7,
                            value: Pair {
                                head: Some(A),
                                packmap: Some(C),
                            },
                        };
                        let mut prepared = clearance::immediate(
                            Pair {
                                head: (!deleted).then_some(B),
                                packmap: if pair {
                                    (!deleted).then_some(C)
                                } else {
                                    Some(A)
                                },
                            },
                            [0; 32],
                            vec![],
                        );
                        if !publishable {
                            prepared.state = Clearance::Pending;
                        }
                        let mut req = request(&repository.name, &refs);
                        req.namespace = repository.namespace.clone();
                        req.publication = Some(clearance::PublicationWrite {
                            repo: &repository,
                            source: &source,
                            shards: &SinglePartition,
                            prepared: Some(&prepared),
                            bound: Some(clearance::PreparedAt::of(&state)),
                        });
                        let values = vec![
                            ref_value(HEAD, A),
                            ref_value(PACKMAP, A),
                            (
                                keys::publication(&repository.name, HEAD),
                                state.encode().unwrap(),
                            ),
                        ];
                        parity(&req, &snapshot(&req, &values));
                    }
                }
            }
        }
    }
}
