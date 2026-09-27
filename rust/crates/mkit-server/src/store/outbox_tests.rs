use futures_executor::block_on;
use mkit_core::hash::hash;

use super::*;
use crate::memory::MemoryKv;
use crate::repo::NamespaceKey;
use crate::store::codec::AbortReason;
use crate::store::{BatchOutcome, NamespaceStore};

fn partition() -> Partition {
    Partition::Namespace(NamespaceKey::deployment_default())
}

fn apply(store: &MemoryKv, batch: Batch) -> BatchOutcome {
    block_on(store.apply(&partition(), batch)).unwrap()
}

fn get(store: &MemoryKv, key: &Key) -> Option<Value> {
    block_on(store.get(&partition(), key)).unwrap()
}

fn ticketed() -> Value {
    codec::encode_reservation(&ReservationV1::Ticketed { ticket_id: [1; 32] })
}

fn expired() -> Terminal {
    Terminal::new(ReservationV1::Expired {
        repository: "repo".into(),
        occurred_at_ms: 200,
    })
    .unwrap()
}

fn finish(builder: OutboxBuilder) -> Batch {
    let mut batch = Batch::new();
    builder
        .try_finish(&mut batch.preconditions, &mut batch.writes)
        .unwrap();
    batch
}

fn relay_rows(batch: &Batch) -> Vec<(u64, RelayV1)> {
    batch
        .writes
        .iter()
        .filter_map(|w| match w {
            Write::Put(key, value) => match keys::parse(key) {
                Some(keys::ParsedKey::Relay(seq)) => {
                    Some((seq, codec::decode_relay(value).unwrap()))
                }
                _ => None,
            },
            Write::Delete(_) => None,
        })
        .collect()
}

#[test]
fn synthetic_id_has_fixed_golden_charset_and_length() {
    assert_eq!(
        synthetic_reservation_id(&[0xab; 32]),
        format!("s:{}", "ab".repeat(32))
    );
    let id = synthetic_reservation_id(&hash(b"replay scope"));
    assert_eq!(id.len(), 66);
    assert!(keys::reservation(&id).is_ok());
}

#[test]
fn reserve_rejects_an_observed_duplicate_and_guards_absence_otherwise() {
    let store = MemoryKv::default();
    let rid = "reservation-1";
    let key = keys::reservation(rid).unwrap();
    // An id the caller already observed is a duplicate, reported as an
    // error rather than planned into a batch that can only fail.
    let mut builder = OutboxBuilder::new(None, None).unwrap();
    builder.reserve(rid, [2; 32], Some(&ticketed()));
    let (mut pre, mut writes) = (Vec::new(), Vec::new());
    assert!(matches!(
        builder.try_finish(&mut pre, &mut writes),
        Err(StoreError::Invalid(_))
    ));
    // Unobserved, it is guarded by Absent, so a concurrent row still
    // fails the batch; the reservation never counts toward the backlog.
    assert_eq!(
        apply(&store, Batch::new().put(key.clone(), ticketed())),
        BatchOutcome::Committed
    );
    let mut builder = OutboxBuilder::new(None, None).unwrap();
    builder.reserve(rid, [2; 32], None);
    let batch = finish(builder);
    assert_eq!(batch.preconditions, vec![Precondition::Absent(key.clone())]);
    assert_eq!(batch.writes.len(), 1);
    assert!(matches!(
        apply(&store, batch),
        BatchOutcome::PreconditionFailed { .. }
    ));
    assert_eq!(get(&store, &key), Some(ticketed()));
    assert_eq!(get(&store, &keys::outcome_backlog()), None);
    assert_eq!(get(&store, &keys::outbox_sequence()), None);
}

#[test]
fn sequence_is_monotonic_across_builders_and_guarded_once_per_batch() {
    let store = MemoryKv::default();
    let mut builder = OutboxBuilder::new(None, None).unwrap();
    for rid in ["one", "two"] {
        builder.outcome(rid, &ticketed(), expired());
        assert_eq!(
            apply(
                &store,
                Batch::new().put(keys::reservation(rid).unwrap(), ticketed())
            ),
            BatchOutcome::Committed
        );
    }
    let first = finish(builder);
    assert_eq!(
        first
            .preconditions
            .iter()
            .filter(|p| matches!(p, Precondition::Absent(k) if *k == keys::outbox_sequence()))
            .count(),
        1
    );
    assert_eq!(
        first
            .writes
            .iter()
            .filter(|w| matches!(w, Write::Put(k, _) if *k == keys::outbox_sequence()))
            .count(),
        1
    );
    assert_eq!(apply(&store, first), BatchOutcome::Committed);
    assert_eq!(
        get(&store, &keys::outbox_sequence()),
        Some(codec::encode_u64(2))
    );
    for (seq, rid) in [(1, "one"), (2, "two")] {
        assert_eq!(
            get(&store, &keys::outcome_pending(seq, rid).unwrap()),
            Some(Value::default())
        );
    }
    let os = get(&store, &keys::outbox_sequence());
    let oc = get(&store, &keys::outcome_backlog());
    let mut builder = OutboxBuilder::new(os.as_ref(), oc.as_ref()).unwrap();
    builder.outcome("three", &ticketed(), expired());
    assert_eq!(
        apply(
            &store,
            Batch::new().put(keys::reservation("three").unwrap(), ticketed())
        ),
        BatchOutcome::Committed
    );
    let second = finish(builder);
    assert!(second.preconditions.contains(&Precondition::Equals(
        keys::outbox_sequence(),
        codec::encode_u64(2)
    )));
    assert_eq!(apply(&store, second), BatchOutcome::Committed);
    assert_eq!(
        get(&store, &keys::outbox_sequence()),
        Some(codec::encode_u64(3))
    );
    assert_eq!(
        get(&store, &keys::outcome_pending(3, "three").unwrap()),
        Some(Value::default())
    );
}

#[test]
fn backlog_bytes_are_exact_after_outcomes_and_each_ack() {
    let store = MemoryKv::default();
    let mut builder = OutboxBuilder::new(None, None).unwrap();
    let rids = ["short", "longer-reservation-id"];
    builder.outcome(rids[0], &ticketed(), expired());
    builder.outcome(
        rids[1],
        &ticketed(),
        Terminal::new(ReservationV1::Aborted {
            repository: "repo".into(),
            occurred_at_ms: 200,
            reason: AbortReason::Abandoned,
            detail: "diagnostic".repeat(20),
        })
        .unwrap(),
    );
    for rid in rids {
        assert_eq!(
            apply(
                &store,
                Batch::new().put(keys::reservation(rid).unwrap(), ticketed())
            ),
            BatchOutcome::Committed
        );
    }
    assert_eq!(apply(&store, finish(builder)), BatchOutcome::Committed);
    let values: Vec<_> = rids
        .iter()
        .map(|rid| get(&store, &keys::reservation(rid).unwrap()).unwrap())
        .collect();
    let sizes: Vec<_> = rids
        .iter()
        .zip(&values)
        .map(|(rid, value)| {
            (keys::reservation(rid).unwrap().as_bytes().len() + value.as_bytes().len()) as u64
        })
        .collect();
    let before = get(&store, &keys::outcome_backlog()).unwrap();
    assert_eq!(
        codec::decode_backlog(&before).unwrap(),
        Backlog {
            rows: 2,
            bytes: sizes.iter().sum()
        }
    );
    for (i, rid) in rids.iter().enumerate() {
        let oc = get(&store, &keys::outcome_backlog());
        let mut batch = Batch::new();
        plan_ack(
            rid,
            &values[i],
            u64::try_from(i + 1).unwrap(),
            oc.as_ref(),
            &mut batch.preconditions,
            &mut batch.writes,
        )
        .unwrap();
        assert_eq!(apply(&store, batch), BatchOutcome::Committed);
        assert_eq!(get(&store, &keys::reservation(rid).unwrap()), None);
        assert_eq!(
            get(
                &store,
                &keys::outcome_pending(u64::try_from(i + 1).unwrap(), rid).unwrap()
            ),
            None
        );
        if i == 0 {
            assert_eq!(
                codec::decode_backlog(&get(&store, &keys::outcome_backlog()).unwrap()).unwrap(),
                Backlog {
                    rows: 1,
                    bytes: sizes[1]
                }
            );
        } else {
            assert_eq!(get(&store, &keys::outcome_backlog()), None);
        }
    }
    assert_eq!(
        get(&store, &keys::outbox_sequence()),
        Some(codec::encode_u64(2))
    );
}

#[test]
fn relay_groups_by_target_sorts_deduplicates_and_excludes_backlog() {
    let target = Partition::Coordinator(NamespaceKey::deployment_default());
    let other = partition();
    let a = (keys::reservation("a").unwrap(), ticketed());
    let b = (keys::reservation("b").unwrap(), ticketed());
    let mut builder = OutboxBuilder::new(None, None).unwrap();
    builder.relay(&target, vec![b.clone(), a.clone()]);
    builder.relay(&target, vec![a.clone()]);
    builder.relay(&other, vec![a.clone()]);
    builder.relay(&other, vec![]);
    let batch = finish(builder);
    let rows = relay_rows(&batch);
    assert_eq!(rows.len(), 2);
    assert_eq!(
        rows.iter().map(|(seq, _)| *seq).collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert_eq!(
        rows.iter()
            .find(|(_, row)| row.target == target)
            .unwrap()
            .1
            .puts,
        vec![a.clone(), b]
    );
    assert_eq!(
        rows.iter()
            .find(|(_, row)| row.target == other)
            .unwrap()
            .1
            .puts,
        vec![a]
    );
    assert!(
        !batch
            .writes
            .iter()
            .any(|w| matches!(w, Write::Put(k, _) if *k == keys::outcome_backlog()))
    );
    assert_eq!(
        batch.preconditions,
        vec![Precondition::Absent(keys::outbox_sequence())]
    );
}

#[test]
fn terminal_outcome_cannot_replace_terminal_or_be_ticketed() {
    assert!(Terminal::new(ReservationV1::Ticketed { ticket_id: [1; 32] }).is_err());
    let terminal = codec::encode_reservation(&ReservationV1::Expired {
        repository: "repo".into(),
        occurred_at_ms: 200,
    });
    let mut builder = OutboxBuilder::new(None, None).unwrap();
    builder.outcome("already-terminal", &terminal, expired());
    let mut batch = Batch::new().require(Precondition::NotAfter(500));
    let before = batch.clone();
    assert!(
        builder
            .try_finish(&mut batch.preconditions, &mut batch.writes)
            .is_err()
    );
    assert_eq!(batch, before);
}

#[test]
fn stale_ticketed_snapshot_cannot_replace_a_committed_terminal_outcome() {
    let store = MemoryKv::default();
    assert_eq!(
        apply(
            &store,
            Batch::new().put(keys::reservation("rid").unwrap(), ticketed())
        ),
        BatchOutcome::Committed
    );
    let mut first = OutboxBuilder::new(None, None).unwrap();
    let mut stale = OutboxBuilder::new(None, None).unwrap();
    first.outcome("rid", &ticketed(), expired());
    stale.outcome(
        "rid",
        &ticketed(),
        Terminal::new(ReservationV1::Aborted {
            repository: "repo".into(),
            occurred_at_ms: 300,
            reason: AbortReason::Internal,
            detail: "late failure".into(),
        })
        .unwrap(),
    );
    assert_eq!(apply(&store, finish(first)), BatchOutcome::Committed);
    let terminal = get(&store, &keys::reservation("rid").unwrap());
    let backlog = get(&store, &keys::outcome_backlog());
    assert!(matches!(
        apply(&store, finish(stale)),
        BatchOutcome::PreconditionFailed { .. }
    ));
    assert_eq!(get(&store, &keys::reservation("rid").unwrap()), terminal);
    assert_eq!(get(&store, &keys::outcome_backlog()), backlog);
    assert_eq!(
        get(&store, &keys::outbox_sequence()),
        Some(codec::encode_u64(1))
    );
}

#[test]
fn malformed_fragments_and_overflow_leave_output_vectors_unchanged() {
    assert!(OutboxBuilder::new(Some(&codec::encode_u64(0)), None).is_err());
    assert!(OutboxBuilder::new(Some(&Value::new(vec![1])), None).is_err());
    assert!(OutboxBuilder::new(None, Some(&Value::new(vec![1]))).is_err());
    let mut builders = vec![];
    let mut builder = OutboxBuilder::new(None, None).unwrap();
    builder.reserve("bad id", [1; 32], None);
    builders.push(builder);
    let mut builder = OutboxBuilder::new(None, None).unwrap();
    builder.reserve("duplicate", [1; 32], None);
    builder.reserve("duplicate", [2; 32], None);
    builders.push(builder);
    let mut builder = OutboxBuilder::new(None, None).unwrap();
    builder.outcome("bad-prior", &Value::default(), expired());
    builders.push(builder);
    let mut builder = OutboxBuilder::new(Some(&codec::encode_u64(u64::MAX)), None).unwrap();
    builder.outcome("overflow", &ticketed(), expired());
    builders.push(builder);
    let mut builder = OutboxBuilder::new(
        None,
        Some(&codec::encode_backlog(&Backlog {
            rows: u64::MAX,
            bytes: u64::MAX,
        })),
    )
    .unwrap();
    builder.outcome("overflow", &ticketed(), expired());
    builders.push(builder);
    let mut builder = OutboxBuilder::new(None, None).unwrap();
    let key = keys::reservation("relay").unwrap();
    builder.relay(
        &partition(),
        vec![(key.clone(), Value::default()), (key, ticketed())],
    );
    builders.push(builder);
    let mut builder = OutboxBuilder::new(Some(&codec::encode_u64(u64::MAX)), None).unwrap();
    builder.relay(
        &partition(),
        vec![(keys::reservation("relay").unwrap(), Value::default())],
    );
    builders.push(builder);
    for builder in builders {
        let mut batch = Batch::new().require(Precondition::NotAfter(500));
        let before = batch.clone();
        assert!(
            builder
                .try_finish(&mut batch.preconditions, &mut batch.writes)
                .is_err()
        );
        assert_eq!(batch, before);
    }
}

#[test]
fn infallible_finish_invalidates_the_batch_without_applying_other_writes() {
    let store = MemoryKv::default();
    let key = keys::reservation("unrelated").unwrap();
    let mut batch = Batch::new().put(key.clone(), ticketed());
    let mut builder = OutboxBuilder::new(None, None).unwrap();
    builder.reserve("bad id", [1; 32], None);
    builder.finish(&mut batch.preconditions, &mut batch.writes);
    assert!(matches!(
        apply(&store, batch),
        BatchOutcome::PreconditionFailed { .. }
    ));
    assert_eq!(get(&store, &key), None);
}

#[test]
fn ack_rejects_missing_index_and_leaves_terminal_and_backlog_intact() {
    let store = MemoryKv::default();
    let mut builder = OutboxBuilder::new(None, None).unwrap();
    builder.outcome("rid", &ticketed(), expired());
    assert_eq!(
        apply(
            &store,
            Batch::new().put(keys::reservation("rid").unwrap(), ticketed())
        ),
        BatchOutcome::Committed
    );
    assert_eq!(apply(&store, finish(builder)), BatchOutcome::Committed);
    let value = get(&store, &keys::reservation("rid").unwrap()).unwrap();
    let oc = get(&store, &keys::outcome_backlog()).unwrap();
    let mut batch = Batch::new();
    plan_ack(
        "rid",
        &value,
        2,
        Some(&oc),
        &mut batch.preconditions,
        &mut batch.writes,
    )
    .unwrap();
    assert!(matches!(
        apply(&store, batch),
        BatchOutcome::PreconditionFailed { .. }
    ));
    assert_eq!(get(&store, &keys::reservation("rid").unwrap()), Some(value));
    assert_eq!(get(&store, &keys::outcome_backlog()), Some(oc));
    assert_eq!(
        get(&store, &keys::outcome_pending(1, "rid").unwrap()),
        Some(Value::default())
    );
}

#[test]
fn ack_rejects_invalid_ids_ticketed_rows_and_backlog_underflow_without_outputs() {
    let terminal = codec::encode_reservation(&ReservationV1::Expired {
        repository: "repo".into(),
        occurred_at_ms: 200,
    });
    let valid_oc = codec::encode_backlog(&Backlog {
        rows: 1,
        bytes: 1000,
    });
    let short_oc = codec::encode_backlog(&Backlog { rows: 1, bytes: 1 });
    for (rid, value, seq, oc) in [
        ("rid", ticketed(), 1, Some(valid_oc.clone())),
        ("bad id", terminal.clone(), 1, Some(valid_oc.clone())),
        ("rid", terminal.clone(), 0, Some(valid_oc)),
        ("rid", terminal.clone(), 1, None),
        ("rid", terminal, 1, Some(short_oc)),
    ] {
        let mut batch = Batch::new().require(Precondition::NotAfter(500));
        let before = batch.clone();
        assert!(
            plan_ack(
                rid,
                &value,
                seq,
                oc.as_ref(),
                &mut batch.preconditions,
                &mut batch.writes
            )
            .is_err()
        );
        assert_eq!(batch, before);
    }
}

#[test]
fn batched_acknowledgements_share_one_guard_and_subtract_both_exact_rows() {
    let store = MemoryKv::default();
    let mut builder = OutboxBuilder::new(None, None).unwrap();
    for rid in ["one", "two"] {
        assert_eq!(
            apply(
                &store,
                Batch::new().put(keys::reservation(rid).unwrap(), ticketed())
            ),
            BatchOutcome::Committed
        );
        builder.outcome(rid, &ticketed(), expired());
    }
    assert_eq!(apply(&store, finish(builder)), BatchOutcome::Committed);
    let oc = get(&store, &keys::outcome_backlog()).unwrap();
    let mut batch = Batch::new();
    for (seq, rid) in [(1, "one"), (2, "two")] {
        let value = get(&store, &keys::reservation(rid).unwrap()).unwrap();
        plan_ack(
            rid,
            &value,
            seq,
            Some(&oc),
            &mut batch.preconditions,
            &mut batch.writes,
        )
        .unwrap();
        let before = batch.clone();
        assert!(
            plan_ack(
                rid,
                &value,
                seq,
                Some(&oc),
                &mut batch.preconditions,
                &mut batch.writes
            )
            .is_err()
        );
        assert_eq!(batch, before);
    }
    assert_eq!(
        batch
            .preconditions
            .iter()
            .filter(|p| matches!(p, Precondition::Equals(k, _) if *k == keys::outcome_backlog()))
            .count(),
        1
    );
    assert_eq!(
        batch
            .writes
            .iter()
            .filter(|w| matches!(w, Write::Delete(k) if *k == keys::outcome_backlog()))
            .count(),
        1
    );
    assert_eq!(apply(&store, batch), BatchOutcome::Committed);
    for (seq, rid) in [(1, "one"), (2, "two")] {
        assert_eq!(get(&store, &keys::reservation(rid).unwrap()), None);
        assert_eq!(get(&store, &keys::outcome_pending(seq, rid).unwrap()), None);
    }
    assert_eq!(get(&store, &keys::outcome_backlog()), None);
}

#[test]
fn outcome_after_ack_rejects_stale_backlog_composition_without_outputs() {
    let value = codec::encode_reservation(&ReservationV1::Expired {
        repository: "repo".into(),
        occurred_at_ms: 200,
    });
    let oc = codec::encode_backlog(&Backlog {
        rows: 1,
        bytes: (keys::reservation("old").unwrap().as_bytes().len() + value.as_bytes().len()) as u64,
    });
    let os = codec::encode_u64(1);
    let mut batch = Batch::new();
    plan_ack(
        "old",
        &value,
        1,
        Some(&oc),
        &mut batch.preconditions,
        &mut batch.writes,
    )
    .unwrap();
    let before = batch.clone();
    let mut builder = OutboxBuilder::new(Some(&os), Some(&oc)).unwrap();
    builder.outcome("new", &ticketed(), expired());
    assert!(
        builder
            .try_finish(&mut batch.preconditions, &mut batch.writes)
            .is_err()
    );
    assert_eq!(batch, before);
}

#[test]
fn two_builders_cannot_allocate_the_same_sequence_in_one_batch() {
    let mut first = OutboxBuilder::new(None, None).unwrap();
    first.relay(
        &partition(),
        vec![(
            keys::membership(&crate::repo::RepoName::new("repo").unwrap(), &[1; 32]),
            Value::default(),
        )],
    );
    let mut batch = finish(first);
    let before = batch.clone();
    let mut second = OutboxBuilder::new(None, None).unwrap();
    second.relay(
        &partition(),
        vec![(
            keys::membership(&crate::repo::RepoName::new("repo").unwrap(), &[2; 32]),
            Value::default(),
        )],
    );
    assert!(
        second
            .try_finish(&mut batch.preconditions, &mut batch.writes)
            .is_err()
    );
    assert_eq!(batch, before);
}

#[test]
fn separate_reservation_fragments_reject_duplicate_ids_in_one_batch() {
    let mut first = OutboxBuilder::new(None, None).unwrap();
    first.reserve("rid", [1; 32], None);
    let mut batch = finish(first);
    let before = batch.clone();
    let mut second = OutboxBuilder::new(None, None).unwrap();
    second.reserve("rid", [2; 32], None);
    assert!(
        second
            .try_finish(&mut batch.preconditions, &mut batch.writes)
            .is_err()
    );
    assert_eq!(batch, before);
}

#[test]
fn outcome_then_ack_in_one_batch_preserves_only_the_new_backlog_row() {
    let store = MemoryKv::default();
    let old = codec::encode_reservation(&ReservationV1::Expired {
        repository: "repo".into(),
        occurred_at_ms: 200,
    });
    let row_size = |rid: &str| {
        (keys::reservation(rid).unwrap().as_bytes().len() + old.as_bytes().len()) as u64
    };
    let oc = codec::encode_backlog(&Backlog {
        rows: 1,
        bytes: row_size("old"),
    });
    let os = codec::encode_u64(1);
    let seed = Batch::new()
        .put(keys::reservation("old").unwrap(), old.clone())
        .put(keys::outcome_pending(1, "old").unwrap(), Value::default())
        .put(keys::reservation("new").unwrap(), ticketed())
        .put(keys::outbox_sequence(), os.clone())
        .put(keys::outcome_backlog(), oc.clone());
    assert_eq!(apply(&store, seed), BatchOutcome::Committed);
    let mut builder = OutboxBuilder::new(Some(&os), Some(&oc)).unwrap();
    builder.outcome("new", &ticketed(), expired());
    let mut batch = finish(builder);
    plan_ack(
        "old",
        &old,
        1,
        Some(&oc),
        &mut batch.preconditions,
        &mut batch.writes,
    )
    .unwrap();
    batch.validate(&StoreCapabilities::full()).unwrap();
    assert_eq!(apply(&store, batch), BatchOutcome::Committed);
    assert_eq!(get(&store, &keys::reservation("old").unwrap()), None);
    let remaining = get(&store, &keys::outcome_backlog()).unwrap();
    assert_eq!(
        codec::decode_backlog(&remaining).unwrap(),
        Backlog {
            rows: 1,
            bytes: row_size("new")
        }
    );
}
