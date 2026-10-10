use super::*;
use crate::pipeline::{D34Shards, SinglePartition};
use crate::{Batch, BatchOutcome, MemoryKv, NamespaceKey};
use futures_executor::block_on;
fn repo() -> RepoId {
    RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new("r").unwrap(),
    }
}
fn advance(value: u8, state: Clearance) -> Advance {
    Advance {
        sequence: 1,
        generation: 0,
        value: Pair {
            head: Some([value; 32]),
            packmap: Some([value + 1; 32]),
        },
        additions: vec![[value + 2; 32]],
        dependencies: vec![],
        external_bases: vec![],
        obligations: vec![],
        state,
        operation: [value; 32],
    }
}
async fn apply(
    kv: &MemoryKv,
    shards: &dyn ShardMap,
    name: &str,
    record: Advance,
    deleted: bool,
) -> Publication {
    let repo = repo();
    let p = shards.ref_shard(&repo, name);
    let old = kv
        .get(&p, &keys::publication(&repo.name, &sequence_ref(name)))
        .await
        .unwrap();
    let os = kv.get(&p, &keys::outbox_sequence()).await.unwrap();
    let oc = kv.get(&p, &keys::outcome_backlog()).await.unwrap();
    let mut outbox = OutboxBuilder::new(os.as_ref(), oc.as_ref()).unwrap();
    let mut b = Batch::new();
    let state = append(
        &repo,
        name,
        &p,
        shards,
        old.as_ref(),
        record,
        deleted,
        &mut b.preconditions,
        &mut b.writes,
        &mut outbox,
    )
    .unwrap();
    outbox.relay_at(1);
    outbox
        .try_finish(&mut b.preconditions, &mut b.writes)
        .unwrap();
    assert_eq!(kv.apply(&p, b).await.unwrap(), BatchOutcome::Committed);
    state
}
async fn finish(
    kv: &MemoryKv,
    shards: &dyn ShardMap,
    name: &str,
    sequence: u64,
    status: Clearance,
) -> Publication {
    let repo = repo();
    let p = shards.ref_shard(&repo, name);
    let name = sequence_ref(name);
    let sr = kv
        .get(&p, &keys::publication(&repo.name, &name))
        .await
        .unwrap()
        .unwrap();
    let ar = kv
        .get(&p, &keys::advance(&repo.name, &name, sequence))
        .await
        .unwrap()
        .unwrap();
    let mut changed = Advance::decode(&ar).unwrap();
    changed.state = status;
    let state = Publication::decode(Some(&sr)).unwrap();
    let eligible = prefix(kv, &p, &repo.name, &name, &state, &changed)
        .await
        .unwrap();
    let os = kv.get(&p, &keys::outbox_sequence()).await.unwrap();
    let oc = kv.get(&p, &keys::outcome_backlog()).await.unwrap();
    let mut o = OutboxBuilder::new(os.as_ref(), oc.as_ref()).unwrap();
    let mut b = Batch::new();
    clear(
        &repo,
        &name,
        &p,
        shards,
        &sr,
        &ar,
        &changed,
        eligible,
        &mut b.preconditions,
        &mut b.writes,
        &mut o,
    )
    .unwrap();
    o.relay_at(2);
    o.try_finish(&mut b.preconditions, &mut b.writes).unwrap();
    assert_eq!(kv.apply(&p, b).await.unwrap(), BatchOutcome::Committed);
    read(kv, &p, &repo.name, &name).await.unwrap()
}
#[test]
fn out_of_order_membership_does_not_skip_the_pointer() {
    block_on(async {
        let kv = MemoryKv::default();
        let s = SinglePartition;
        apply(
            &kv,
            &s,
            "refs/heads/main",
            advance(1, Clearance::Pending),
            false,
        )
        .await;
        apply(
            &kv,
            &s,
            "refs/heads/main",
            advance(4, Clearance::Pending),
            false,
        )
        .await;
        assert_eq!(
            finish(&kv, &s, "refs/heads/main", 2, Clearance::Cleared)
                .await
                .published,
            0
        );
        let r = repo();
        let p = s.ref_shard(&r, "refs/heads/main");
        let raw = kv
            .get(&p, &keys::membership(&r.name, &[6; 32]))
            .await
            .unwrap()
            .unwrap();
        assert!(Witness::decode(&raw).unwrap().published);
        assert!(
            kv.get(&p, &keys::published_ref(&r.name, "refs/heads/main"))
                .await
                .unwrap()
                .is_none()
        );
        let state = finish(&kv, &s, "refs/heads/main", 1, Clearance::Cleared).await;
        assert_eq!(state.published, 2);
        assert_eq!(state.value, advance(4, Clearance::Cleared).value);
    });
}
#[test]
fn deletion_and_recreation_preserve_sequence_and_old_membership() {
    block_on(async {
        let kv = MemoryKv::default();
        let s = SinglePartition;
        apply(
            &kv,
            &s,
            "refs/heads/main",
            advance(1, Clearance::Pending),
            false,
        )
        .await;
        let mut deletion = advance(3, Clearance::Cleared);
        deletion.value = Pair::default();
        deletion.additions.clear();
        let deleted = apply(&kv, &s, "refs/mkit/packmap/main", deletion, true).await;
        assert_eq!((deleted.sequence, deleted.boundary), (2, 2));
        assert_eq!(
            apply(
                &kv,
                &s,
                "refs/heads/main",
                advance(5, Clearance::Pending),
                false
            )
            .await
            .sequence,
            3
        );
        let late = finish(&kv, &s, "refs/heads/main", 1, Clearance::Cleared).await;
        assert_eq!(late.value, Pair::default());
        assert_eq!(late.published, 2);
        let r = repo();
        let p = s.ref_shard(&r, "refs/heads/main");
        assert!(
            Witness::decode(
                &kv.get(&p, &keys::membership(&r.name, &[3; 32]))
                    .await
                    .unwrap()
                    .unwrap()
            )
            .unwrap()
            .published
        );
        assert_eq!(
            finish(&kv, &s, "refs/heads/main", 3, Clearance::Cleared)
                .await
                .published,
            3
        );
    });
}
#[test]
fn paired_names_share_one_persistent_sequence() {
    block_on(async {
        let kv = MemoryKv::default();
        let s = D34Shards;
        assert_eq!(
            apply(
                &kv,
                &s,
                "refs/heads/main",
                advance(1, Clearance::Cleared),
                false
            )
            .await
            .sequence,
            1
        );
        assert_eq!(
            apply(
                &kv,
                &s,
                "refs/mkit/packmap/main",
                advance(4, Clearance::Cleared),
                false
            )
            .await
            .sequence,
            2
        );
        assert_eq!(
            apply(
                &kv,
                &s,
                "refs/tags/v1",
                advance(7, Clearance::Cleared),
                false
            )
            .await
            .sequence,
            1
        );
    });
}
#[test]
fn witness_codec_golden_and_fail_closed() {
    let w = Witness {
        generation: 2,
        sequence: 3,
        published: true,
        held: false,
        boundary: false,
    };
    assert_eq!(
        w.encode().as_bytes(),
        &[1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3]
    );
    assert_eq!(Witness::decode(&w.encode()).unwrap(), w);
    assert!(!w.visible(false, 1));
    assert!(w.visible(false, 2));
    assert!(!Witness { held: true, ..w }.visible(true, 2));
    for bytes in [vec![2; 19], vec![1; 18], vec![1, 2, 0]] {
        assert!(Witness::decode(&Value::new(bytes)).is_err());
    }
    // A fork flags its inherited packmap head with one trailing byte; no
    // other length or trailing value decodes.
    let flagged = Witness {
        boundary: true,
        ..w
    };
    let mut expected = w.encode().as_bytes().to_vec();
    expected.push(1);
    assert_eq!(flagged.encode().as_bytes(), expected.as_slice());
    assert_eq!(Witness::decode(&flagged.encode()).unwrap(), flagged);
    for trailing in [0_u8, 2] {
        let mut bytes = w.encode().as_bytes().to_vec();
        bytes.push(trailing);
        assert!(Witness::decode(&Value::new(bytes)).is_err());
    }
    let mut long = expected.clone();
    long.push(1);
    assert!(Witness::decode(&Value::new(long)).is_err());
}

#[test]
#[ignore = "WP-5.5c (post-launch): hold authority, see R-198/R-200"]
fn releasing_one_advance_must_preserve_another_hold_on_the_same_pack() {
    block_on(async {
        let kv = MemoryKv::default();
        let shards = SinglePartition;
        let r = repo();
        let p = shards.ref_shard(&r, "refs/heads/main");
        let first = advance(1, Clearance::Held);
        apply(&kv, &shards, "refs/heads/main", first.clone(), false).await;
        apply(&kv, &shards, "refs/heads/main", first, false).await;
        finish(&kv, &shards, "refs/heads/main", 1, Clearance::Cleared).await;
        let raw = kv
            .get(&p, &keys::membership(&r.name, &[3; 32]))
            .await
            .unwrap()
            .unwrap();
        let witness = Witness::decode(&raw).unwrap();
        assert!(
            witness.held,
            "releasing advance 1 erased advance 2's retained hold: {witness:?}"
        );
    });
}
#[test]
fn advance_codec_rejects_unresolved_obligations_and_unknown_fields() {
    let mut a = advance(1, Clearance::Cleared);
    a.obligations.push(Obligation {
        id: [1; 32],
        state: Clearance::Pending,
    });
    assert!(a.encode().is_err());
    a.state = Clearance::Pending;
    assert_eq!(Advance::decode(&a.encode().unwrap()).unwrap(), a);
    assert!(Publication::decode(Some(&Value::new(b"\x01{\"unknown\":true}".to_vec()))).is_err());
}

#[test]
fn durable_cross_ref_and_external_base_rechecks_need_no_client_traffic() {
    block_on(async {
        use crate::rt::ManualClock;
        use crate::timers::publication_recheck::PublicationRecheck;
        use crate::timers::{TickBudget, TimerRegistry, run_due};
        use std::sync::Arc;
        let clock = Arc::new(ManualClock::new(0));
        let kv = Arc::new(MemoryKv::with_clock(clock.clone()));
        let s = SinglePartition;
        let r = repo();
        let p = s.ref_shard(&r, "refs/heads/b");
        let mut b = advance(4, Clearance::Pending);
        b.dependencies = vec![[3; 32]];
        b.external_bases = vec![[3; 32]];
        apply(&kv, &s, "refs/heads/b", b, false).await;
        let registry = TimerRegistry::new().register(PublicationRecheck { target: kv.clone() });
        let budget = TickBudget::default();
        assert_eq!(
            run_due(&kv, &p, &registry, clock.as_ref(), 0, &budget)
                .await
                .unwrap()
                .fired,
            1
        );
        assert_eq!(
            read(&kv, &p, &r.name, "refs/heads/b")
                .await
                .unwrap()
                .published,
            0
        );
        apply(
            &kv,
            &s,
            "refs/heads/a",
            advance(1, Clearance::Cleared),
            false,
        )
        .await;
        // Restart: reconstruct the registry from durable rows, no request to B.
        let registry = TimerRegistry::new().register(PublicationRecheck { target: kv.clone() });
        clock.set(5_000);
        assert_eq!(
            run_due(&kv, &p, &registry, clock.as_ref(), 5_000, &budget)
                .await
                .unwrap()
                .fired,
            1
        );
        assert_eq!(
            read(&kv, &p, &r.name, "refs/heads/b")
                .await
                .unwrap()
                .published,
            1
        );
        assert!(
            Witness::decode(
                &kv.get(&p, &keys::membership(&r.name, &[6; 32]))
                    .await
                    .unwrap()
                    .unwrap()
            )
            .unwrap()
            .published
        );
    });
}

#[test]
fn own_additions_never_satisfy_an_external_delta_dependency() {
    block_on(async {
        use crate::rt::ManualClock;
        use crate::timers::publication_recheck::PublicationRecheck;
        use crate::timers::{TickBudget, TimerRegistry, run_due};
        let kv = std::sync::Arc::new(MemoryKv::with_clock(std::sync::Arc::new(ManualClock::new(
            0,
        ))));
        let s = SinglePartition;
        let r = repo();
        let p = s.ref_shard(&r, "refs/heads/main");
        let mut a = advance(1, Clearance::Pending);
        a.external_bases = a.additions.clone();
        apply(&kv, &s, "refs/heads/main", a, false).await;
        let registry = TimerRegistry::new().register(PublicationRecheck { target: kv.clone() });
        run_due(
            &kv,
            &p,
            &registry,
            &ManualClock::new(0),
            0,
            &TickBudget::default(),
        )
        .await
        .unwrap();
        assert_eq!(
            read(&kv, &p, &r.name, "refs/heads/main")
                .await
                .unwrap()
                .published,
            0
        );
        let timer = keys::timer(
            RECHECK_MS,
            crate::timers::registry::kinds::PUBLICATION_RECHECK.get(),
            keys::advance(&r.name, "refs/heads/main", 1).as_bytes(),
        );
        assert!(kv.get(&p, &timer).await.unwrap().is_some());
    });
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "Keeps delayed relay ordering and restarted durable rechecks in one regression"
)]
fn d34_delayed_cross_ref_delta_relays_wake_durable_work_after_restart() {
    block_on(async {
        use crate::relay::{NoHook, RelayBudget, RelayHandler};
        use crate::rt::ManualClock;
        use crate::timers::publication_recheck::PublicationRecheck;
        use crate::timers::{TickBudget, TimerRegistry, run_due};
        use std::sync::Arc;
        let clock = Arc::new(ManualClock::new(0));
        let kv = Arc::new(MemoryKv::with_clock(clock.clone()));
        let shards = D34Shards;
        let repository = repo();
        let blocked_source = shards.ref_shard(&repository, "refs/heads/b");
        let mut blocked = advance(4, Clearance::Pending);
        blocked.dependencies = vec![[3; 32]];
        blocked.external_bases = vec![[9; 32]];
        apply(&kv, &shards, "refs/heads/b", blocked, false).await;
        let tick = |at| clock.set(at);
        let budget = TickBudget::default();
        let rechecks = TimerRegistry::new().register(PublicationRecheck { target: kv.clone() });
        run_due(&kv, &blocked_source, &rechecks, clock.as_ref(), 0, &budget)
            .await
            .unwrap();
        apply(
            &kv,
            &shards,
            "refs/heads/a",
            advance(1, Clearance::Cleared),
            false,
        )
        .await;
        apply(
            &kv,
            &shards,
            "refs/heads/c",
            advance(7, Clearance::Cleared),
            false,
        )
        .await;
        let relays = TimerRegistry::new().register(RelayHandler {
            target: kv.clone(),
            hook: NoHook,
            budget: RelayBudget::default(),
        });
        // Deliver C before A: no global ordering across source refs is assumed.
        tick(5_000);
        let source_c = shards.ref_shard(&repository, "refs/heads/c");
        run_due(&kv, &source_c, &relays, clock.as_ref(), 5_000, &budget)
            .await
            .unwrap();
        run_due(
            &kv,
            &blocked_source,
            &rechecks,
            clock.as_ref(),
            5_000,
            &budget,
        )
        .await
        .unwrap();
        assert_eq!(
            read(&kv, &blocked_source, &repository.name, "refs/heads/b")
                .await
                .unwrap()
                .published,
            0
        );
        // A'shards authoritative membership alone cannot bypass its delayed projection.
        assert!(
            kv.get(
                &shards.ref_shard(&repository, "refs/heads/a"),
                &keys::membership(&repository.name, &[3; 32])
            )
            .await
            .unwrap()
            .is_some()
        );
        tick(10_000);
        let source_a = shards.ref_shard(&repository, "refs/heads/a");
        run_due(&kv, &source_a, &relays, clock.as_ref(), 10_000, &budget)
            .await
            .unwrap();
        let restarted = TimerRegistry::new().register(PublicationRecheck { target: kv.clone() });
        run_due(
            &kv,
            &blocked_source,
            &restarted,
            clock.as_ref(),
            10_000,
            &budget,
        )
        .await
        .unwrap();
        let state = read(&kv, &blocked_source, &repository.name, "refs/heads/b")
            .await
            .unwrap();
        assert_eq!((state.published, state.sequence), (1, 1));
        assert_eq!(state.value, advance(4, Clearance::Cleared).value);
        let timer = keys::timer(
            15_000,
            crate::timers::registry::kinds::PUBLICATION_RECHECK.get(),
            keys::advance(&repository.name, "refs/heads/b", 1).as_bytes(),
        );
        assert!(kv.get(&blocked_source, &timer).await.unwrap().is_none());
    });
}

#[test]
fn completed_obligation_free_advances_do_not_accumulate_retained_work() {
    block_on(async {
        let kv = MemoryKv::default();
        let repository = repo();
        let source = SinglePartition.ref_shard(&repository, "refs/heads/main");
        for value in 1..=64 {
            let state = apply(
                &kv,
                &SinglePartition,
                "refs/heads/main",
                advance(value, Clearance::Cleared),
                false,
            )
            .await;
            assert_eq!(state.sequence, state.published);
            assert!(
                kv.get(
                    &source,
                    &keys::advance(&repository.name, "refs/heads/main", state.sequence)
                )
                .await
                .unwrap()
                .is_none()
            );
        }
        let mut retained = advance(65, Clearance::Cleared);
        retained.obligations.push(Obligation {
            id: [9; 32],
            state: Clearance::Cleared,
        });
        let state = apply(&kv, &SinglePartition, "refs/heads/main", retained, false).await;
        assert!(
            kv.get(
                &source,
                &keys::advance(&repository.name, "refs/heads/main", state.sequence)
            )
            .await
            .unwrap()
            .is_some()
        );
    });
}

#[test]
fn fully_published_maximum_sequence_has_an_empty_prefix() {
    block_on(async {
        let repository = repo();
        let source = SinglePartition.ref_shard(&repository, "refs/heads/main");
        let state = Publication {
            sequence: u64::MAX,
            published: u64::MAX,
            boundary: u64::MAX,
            generation: 0,
            value: Pair::default(),
        };
        assert_eq!(
            Publication::decode(Some(&state.encode().unwrap())).unwrap(),
            state
        );
        // A late verdict can still clear retained membership below a deletion boundary.
        let changed = advance(1, Clearance::Cleared);
        assert_eq!(
            prefix(
                &MemoryKv::default(),
                &source,
                &repository.name,
                "refs/heads/main",
                &state,
                &changed
            )
            .await
            .unwrap(),
            (u64::MAX, Pair::default())
        );
    });
}
