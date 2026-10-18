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
        denial_ref: None,
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

/// A ticketed advance through the composed decision must produce the same
/// physical batch (or error) as the frozen reference planner: pending
/// stability, replay answers, ticket rows, reservation closures, storage
/// counting and outbox rows all compared byte-for-byte.
#[allow(clippy::too_many_lines)] // One sweep nests every fate/pending/replay dimension.
#[test]
fn ticketed_advance_parity_sweep() {
    use crate::store::{ReservationV1, codec, codec::TicketV1};
    let repo = repo();
    let single = SinglePartition;
    let d34 = D34Shards;
    let signer = [7; 32];
    let mut cases = 0_u32;
    let changed = [
        ResolvedRefUpdate::new(PACKMAP.into(), Some(B), RefEffect::Replace),
        ResolvedRefUpdate::new(HEAD.into(), Some(C), RefEffect::Replace),
    ];
    // ticket row fates in request order
    for (count_storage, partitioned) in [(false, false), (true, false), (true, true)] {
        let shards: &dyn ShardMap = if partitioned { &d34 } else { &single };
        for source_at_coordinator in [false, true] {
            let source = if source_at_coordinator {
                shards.coordinator(&repo.namespace)
            } else {
                shards.ref_shard(&repo, HEAD)
            };
            for fate in 0..7_u8 {
                for replay_case in 0..4_u8 {
                    for pending_case in 0..3_u8 {
                        for generation in [None, Some(0), Some(1)] {
                            let reservations = ["s:parity-0", "s:parity-1"];
                            let ids: Vec<_> = reservations
                                .iter()
                                .map(|rid| crate::store::tickets::ticket_id(rid))
                                .collect();
                            let mut tickets: Vec<_> = ids
                                .iter()
                                .zip(&reservations)
                                .enumerate()
                                .map(|(i, (_id, rid))| {
                                    let mut pack_id = [0; 32];
                                    pack_id[0] = 0x40 + u8::try_from(i).unwrap();
                                    TicketV1 {
                                        authority_generation: Some(0),
                                        repo: repo.name.clone(),
                                        ref_name: HEAD.into(),
                                        signer,
                                        pack_id,
                                        bytes: 32 + i as u64,
                                        part_size: 8 * 1024 * 1024,
                                        created_at_ms: (T0 - 1_000) as u64,
                                        expires_at_ms: (T0 + 60_000) as u64,
                                        reservation_id: (*rid).to_owned(),
                                        upload_session: None,
                                    }
                                })
                                .collect();
                            let mut ticket_present = [true, true];
                            match fate {
                                // Second ticket expired but decodable.
                                1 => {
                                    tickets[1].created_at_ms = 0;
                                    tickets[1].expires_at_ms = 1;
                                }
                                // Second ticket signed by someone else.
                                2 => tickets[1].signer = [9; 32],
                                // First ticket row absent.
                                3 => ticket_present[0] = false,
                                // 4: second reservation row holds a pending write.
                                // 5: second reservation row absent.
                                6 => {
                                    tickets[0].created_at_ms = 0;
                                    tickets[0].expires_at_ms = 1;
                                }
                                _ => {}
                            }
                            let advance = advance::AdvanceWrite {
                                ids: &ids,
                                signer,
                                head_ref: HEAD,
                                repo_id: &repo,
                                repository: REPO,
                                source: &source,
                                shards,
                                count_storage,
                            };
                            let refs = [upd(PACKMAP, Missing, B), upd(HEAD, Missing, C)];
                            let replay = replay();
                            let pending_value =
                                codec::encode_reservation(&ReservationV1::Pending {
                                    repository: REPO.into(),
                                    created_at_ms: ms(T0),
                                    reconcile_at_ms: ms(T0) + 60_000,
                                    op: codec::PendingOp::Write,
                                    procedure: codec::StoredProcedure::AdvanceRefs,
                                });
                            let pending = reservation::PendingGuard {
                                rid: "s:parity-pending".into(),
                                key: keys::reservation("s:parity-pending").unwrap(),
                                value: pending_value.clone(),
                                apply_deadline_ms: ms(T0) + 10_000,
                                repository: REPO.into(),
                                procedure: codec::StoredProcedure::AdvanceRefs,
                            };
                            let mut req = request(&repo.name, &refs);
                            req.kind = WriteKind::AdvanceRefs;
                            req.advance = Some(advance.clone());
                            req.authority_generation = generation;
                            req.replay = (replay_case > 0).then_some(replay);
                            req.pending = match pending_case {
                                1 | 2 => Some(&pending),
                                _ => None,
                            };
                            let mut snap = snapshot(&req, &[]);
                            for (i, ticket) in tickets.iter().enumerate() {
                                if ticket_present[i] {
                                    snap.insert(
                                        keys::ticket(&ids[i]),
                                        Some(codec::encode_ticket(ticket)),
                                    );
                                }
                            }
                            for key in advance::detail_keys(&snap, &advance).unwrap() {
                                if !snap.contains(&key) {
                                    snap.insert(key, None);
                                }
                            }
                            for (i, ticket) in tickets.iter().enumerate() {
                                if !ticket_present[i] {
                                    continue;
                                }
                                snap.insert(
                                    keys::ticket_index(&repo.name, HEAD, &ticket.pack_id, &signer)
                                        .unwrap(),
                                    Some(codec::encode_ref_id(&ids[i])),
                                );
                                let reservation = match (fate, i) {
                                    (4, 1) => ReservationV1::Pending {
                                        repository: REPO.into(),
                                        created_at_ms: ms(T0),
                                        reconcile_at_ms: ms(T0) + 60_000,
                                        op: codec::PendingOp::Write,
                                        procedure: codec::StoredProcedure::AdvanceRefs,
                                    },
                                    (5, 1) => {
                                        snap.insert(
                                            keys::reservation(&ticket.reservation_id).unwrap(),
                                            None,
                                        );
                                        continue;
                                    }
                                    _ => ReservationV1::Ticketed { ticket_id: ids[i] },
                                };
                                snap.insert(
                                    keys::reservation(&ticket.reservation_id).unwrap(),
                                    Some(codec::encode_reservation(&reservation)),
                                );
                            }
                            snap.insert(
                                keys::tickets_per_ref(&repo.name, HEAD).unwrap(),
                                Some(codec::encode_u64(ids.len() as u64)),
                            );
                            snap.insert(
                                keys::tickets_per_signer(&repo.name, HEAD, &signer).unwrap(),
                                Some(codec::encode_u64(ids.len() as u64)),
                            );
                            if count_storage {
                                snap.insert(
                                    keys::repo_storage(&repo.name),
                                    Some(crate::store::repo_storage::initial_counter()),
                                );
                            }
                            match replay_case {
                                0 => req.replay = None,
                                1 => {}
                                2 => snap.insert(
                                    keys::replay(&replay.scope),
                                    Some(codec::encode_replay_record(
                                        &crate::replay::ReplayRecord {
                                            fingerprint: replay.fingerprint,
                                            expires_at_ms: replay.expires_at_ms,
                                            state: crate::replay::ReplayState::InFlight {
                                                resumable: false,
                                            },
                                        },
                                    )),
                                ),
                                _ => snap.insert(
                                    keys::replay(&replay.scope),
                                    Some(codec::encode_replay_record(
                                        &crate::replay::ReplayRecord {
                                            fingerprint: if fate == 0 {
                                                replay.fingerprint
                                            } else {
                                                [0xf0; 32]
                                            },
                                            expires_at_ms: replay.expires_at_ms,
                                            state: crate::replay::ReplayState::Committed(
                                                crate::replay::StoredResult::AdvanceRefs(
                                                    mkit_core::protocol::AdvanceOutcome::Committed,
                                                ),
                                            ),
                                        },
                                    )),
                                ),
                            }
                            if pending_case == 1 {
                                snap.insert(pending.key.clone(), Some(pending.value.clone()));
                            } else if pending_case == 2 {
                                snap.insert(
                                    pending.key.clone(),
                                    Some(codec::encode_reservation(&ReservationV1::Pending {
                                        repository: REPO.into(),
                                        created_at_ms: ms(T0) + 7,
                                        reconcile_at_ms: ms(T0) + 60_000,
                                        op: codec::PendingOp::Write,
                                        procedure: codec::StoredProcedure::AdvanceRefs,
                                    })),
                                );
                            }
                            parity(&req, &snap);
                            if fate == 0
                                && replay_case < 2
                                && pending_case == 0
                                && generation != Some(1)
                            {
                                // The admitted refs no longer match the snapshot (admission
                                // saw both refs present; neither is). The ticketed decision
                                // must answer exactly like the reference planner: a retryable
                                // ref conflict, never an in-flight replay race.
                                req.resolved_ref_updates = &changed;
                                parity(&req, &snap);
                                let error = plan_write(&req, &snap, &clock_at(5, None))
                                    .expect_err("admitted ref changed after admission");
                                assert_eq!(error.code(), Code::Aborted);
                                assert_eq!(
                                    error.public_message(),
                                    "ref changed after admission; retry"
                                );
                                assert_eq!(error.abort_cause(), Some(AbortCause::RefConflict));
                                req.resolved_ref_updates = &[];
                            }
                            // Competing faults preserve the reference's examined prefix:
                            // pending/replay, ticket order, then ref order.
                            for key in [
                                keys::ref_key(&repo.name, HEAD),
                                keys::ticket(&ids[1]),
                                keys::reservation(reservations[1]).unwrap(),
                                keys::repo_storage(&repo.name),
                            ] {
                                let mut corrupt = snap.clone();
                                corrupt.insert(key, Some(Value::new(vec![0xff])));
                                parity(&req, &corrupt);
                            }
                            let mut conflict = snap.clone();
                            conflict.insert(
                                keys::ref_key(&repo.name, PACKMAP),
                                Some(codec::encode_ref_id(&A)),
                            );
                            conflict.insert(
                                keys::ref_key(&repo.name, HEAD),
                                Some(Value::new(vec![0xff])),
                            );
                            parity(&req, &conflict);
                            cases += 1;
                        }
                    }
                }
            }
        }
    }
    assert_eq!(cases, 1512);
}

#[test]
fn recorded_policy_denial_commits_only_while_its_pinned_ref_value_holds() {
    let name = repo_name();
    let rejection = crate::replay::StoredRejection::new(
        Code::PermissionDenied,
        "non-fast-forward update not allowed on this ref",
    )
    .unwrap();
    for pinned in [Some(A), None] {
        let mut req = request(&name, &[]);
        req.kind = WriteKind::UpdateRef;
        req.replay = Some(replay());
        req.rejection = Some(&rejection);
        req.denial_ref = Some((HEAD, pinned));
        let snap = snapshot(&req, &[]);
        let Planned::Apply(plan) = plan_write(&req, &snap, &clock_at(5, None)).unwrap() else {
            panic!("a recorded denial commits its replay record");
        };
        let key = keys::ref_key(&name, HEAD);
        let expected = pinned.map_or(Precondition::Absent(key.clone()), |value| {
            Precondition::Equals(key.clone(), codec::encode_ref_id(&value))
        });
        assert!(
            plan.batch.preconditions.contains(&expected),
            "the stored refusal must compare the ref value it was decided on"
        );
        assert!(
            plan.batch
                .writes
                .iter()
                .all(|write| !matches!(write, Write::Put(k, _) | Write::Delete(k) if *k == key)),
            "a denial never writes the ref"
        );
        parity(&req, &snap);
        // Without a pinned value (an explicit MATCH or MISSING expectation, or a
        // signer rule) no ref row is compared.
        req.denial_ref = None;
        let Planned::Apply(unpinned) = plan_write(&req, &snap, &clock_at(5, None)).unwrap() else {
            panic!("a recorded denial commits its replay record");
        };
        assert!(!unpinned.batch.preconditions.contains(&expected));
    }
}
