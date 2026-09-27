use futures_executor::block_on;
use mkit_core::hash::{hash, to_hex};
use mkit_core::upload_parts::MIN_PART_SIZE;

use super::*;
use crate::memory::MemoryKv;
use crate::pipeline::{D34Shards, SinglePartition};
use crate::repo::NamespaceKey;
use crate::store::codec::{OutcomeRef, ReservationV1};
use crate::store::outbox::{MAX_TICKETS_PER_ADVANCE, Terminal};
use crate::store::{Batch, BatchOutcome, BlobKey, NamespaceStore, StoreCapabilities};

fn spec() -> TicketSpec {
    TicketSpec {
        repo: RepoName::new("repo").unwrap(),
        ref_name: "refs/heads/main".into(),
        signer: [1; 32],
        pack_id: [2; 32],
        bytes: 100,
        part_size: MIN_PART_SIZE,
        created_at_ms: 100,
        expires_at_ms: 1_100,
        now_ms: 100,
        reservation_id: "reservation-1".into(),
        upload_session: None,
    }
}

fn caps() -> TicketCaps {
    TicketCaps {
        per_ref: 1024,
        per_signer: 64,
    }
}

fn partition() -> Partition {
    Partition::Namespace(NamespaceKey::deployment_default())
}

fn get(store: &MemoryKv, key: &Key) -> Option<Value> {
    block_on(store.get(&partition(), key)).unwrap()
}

fn apply(store: &MemoryKv, batch: Batch) -> BatchOutcome {
    block_on(store.apply(&partition(), batch)).unwrap()
}

fn open(spec: &TicketSpec, reads: &TicketReads) -> Batch {
    let mut batch = Batch::new();
    plan_ticket_open(
        spec,
        reads,
        caps(),
        &mut batch.preconditions,
        &mut batch.writes,
    )
    .unwrap();
    batch
}

fn close(ticket: &TicketV1, count: u64, why: CloseReason) -> Batch {
    let mut batch = Batch::new();
    let id = ticket_id(&ticket.reservation_id);
    plan_ticket_close(
        &id,
        ticket,
        &codec::encode_ticket(ticket),
        Some(&codec::encode_ref_id(&id)),
        Some(&codec::encode_u64(count)),
        Some(&codec::encode_u64(count)),
        why,
        &mut batch.preconditions,
        &mut batch.writes,
    )
    .unwrap();
    batch
}

#[test]
fn new_ticket_reserves_one_outcome_and_initializes_positive_counters() {
    let spec = spec();
    let read_keys = keys(&spec);
    let batch = open(&spec, &TicketReads::default());
    batch.validate(&StoreCapabilities::full()).unwrap();
    let store = MemoryKv::default();
    assert_eq!(apply(&store, batch), BatchOutcome::Committed);
    assert_eq!(
        codec::decode_ticket(&get(&store, &read_keys.ticket).unwrap()).unwrap(),
        spec.record()
    );
    assert_eq!(
        get(&store, &read_keys.index),
        Some(codec::encode_ref_id(&ticket_id(&spec.reservation_id)))
    );
    for key in [&read_keys.per_ref, &read_keys.per_signer] {
        assert_eq!(get(&store, key), Some(codec::encode_u64(1)));
    }
    assert_eq!(
        get(
            &store,
            &layout::timer(
                spec.expires_at_ms,
                kinds::TICKET_EXPIRY.get(),
                &ticket_id(&spec.reservation_id)
            )
        ),
        Some(Value::default())
    );
    assert_eq!(
        codec::decode_reservation(&get(&store, &read_keys.reservation).unwrap()).unwrap(),
        ReservationV1::Ticketed {
            ticket_id: ticket_id(&spec.reservation_id)
        }
    );
    assert_eq!(get(&store, &layout::outbox_sequence()), None);
    assert_eq!(get(&store, &layout::outcome_backlog()), None);
}

#[test]
fn live_index_returns_existing_even_when_caps_are_full_without_changing_outputs() {
    let original = spec();
    let mut retry = original.clone();
    retry.reservation_id = "retry".into();
    let reads = TicketReads {
        index: Some(codec::encode_ref_id(&ticket_id(&original.reservation_id))),
        indexed_ticket: Some(codec::encode_ticket(&original.record())),
        per_ref: Some(codec::encode_u64(1024)),
        per_signer: Some(codec::encode_u64(64)),
        ..TicketReads::default()
    };
    let mut batch = Batch::new().require(Precondition::NotAfter(500));
    let before = batch.clone();
    let result = plan_ticket_open(
        &retry,
        &reads,
        caps(),
        &mut batch.preconditions,
        &mut batch.writes,
    );
    assert!(
        matches!(result, Err(TicketPlanError::Existing(ticket)) if ticket == original.record())
    );
    assert_eq!(batch, before);
}

#[test]
fn index_naming_proposed_id_uses_the_proposed_ticket_snapshot() {
    let spec = spec();
    let reads = TicketReads {
        index: Some(codec::encode_ref_id(&ticket_id(&spec.reservation_id))),
        ticket: Some(codec::encode_ticket(&spec.record())),
        ..TicketReads::default()
    };
    assert!(matches!(
        plan_ticket_open(&spec, &reads, caps(), &mut vec![], &mut vec![]),
        Err(TicketPlanError::Existing(_))
    ));
}

#[test]
fn expired_index_is_replaced_under_equals_and_late_close_preserves_new_index() {
    let original = spec();
    let old_id = ticket_id(&original.reservation_id);
    let index_value = codec::encode_ref_id(&old_id);
    let mut replacement = original.clone();
    replacement.reservation_id = "replacement".into();
    replacement.created_at_ms = original.expires_at_ms;
    replacement.now_ms = original.expires_at_ms;
    replacement.expires_at_ms += 1_000;
    let reads = TicketReads {
        index: Some(index_value.clone()),
        indexed_ticket: Some(codec::encode_ticket(&original.record())),
        per_ref: Some(codec::encode_u64(1)),
        per_signer: Some(codec::encode_u64(1)),
        ..TicketReads::default()
    };
    let store = MemoryKv::default();
    assert_eq!(
        apply(&store, open(&original, &TicketReads::default())),
        BatchOutcome::Committed
    );
    let batch = open(&replacement, &reads);
    assert!(batch.preconditions.contains(&Precondition::Equals(
        keys(&replacement).index.clone(),
        index_value
    )));
    assert_eq!(apply(&store, batch), BatchOutcome::Committed);
    let new_index = codec::encode_ref_id(&ticket_id(&replacement.reservation_id));
    let mut expiry = Batch::new();
    plan_ticket_close(
        &old_id,
        &original.record(),
        &codec::encode_ticket(&original.record()),
        Some(&new_index),
        Some(&codec::encode_u64(2)),
        Some(&codec::encode_u64(2)),
        CloseReason::Expired,
        &mut expiry.preconditions,
        &mut expiry.writes,
    )
    .unwrap();
    assert_eq!(apply(&store, expiry), BatchOutcome::Committed);
    assert_eq!(get(&store, &keys(&replacement).index), Some(new_index));
    assert!(get(&store, &keys(&replacement).ticket).is_some());
    assert_eq!(
        get(&store, &keys(&replacement).per_ref),
        Some(codec::encode_u64(1))
    );
}

#[test]
fn both_cap_paths_leave_existing_fragments_untouched() {
    for (per_ref, per_signer, is_ref) in [(1024, 1, true), (1, 64, false)] {
        let reads = TicketReads {
            per_ref: Some(codec::encode_u64(per_ref)),
            per_signer: Some(codec::encode_u64(per_signer)),
            ..TicketReads::default()
        };
        let mut batch = Batch::new().require(Precondition::NotAfter(500));
        let before = batch.clone();
        let result = plan_ticket_open(
            &spec(),
            &reads,
            caps(),
            &mut batch.preconditions,
            &mut batch.writes,
        );
        assert!(
            matches!(result, Err(TicketPlanError::CapExceeded { per_ref }) if per_ref == is_ref)
        );
        assert_eq!(batch, before);
    }
}

#[test]
fn close_consumed_and_expired_decrement_and_delete_counters_at_zero() {
    let spec = spec();
    let ticket = spec.record();
    let read_keys = keys(&spec);
    let timer = layout::timer(
        spec.expires_at_ms,
        kinds::TICKET_EXPIRY.get(),
        &ticket_id(&spec.reservation_id),
    );
    for why in [CloseReason::Consumed, CloseReason::Expired] {
        for count in [1, 2] {
            let store = MemoryKv::default();
            assert_eq!(
                apply(&store, open(&spec, &TicketReads::default())),
                BatchOutcome::Committed
            );
            assert_eq!(
                apply(
                    &store,
                    Batch::new()
                        .put(read_keys.per_ref.clone(), codec::encode_u64(count))
                        .put(read_keys.per_signer.clone(), codec::encode_u64(count))
                ),
                BatchOutcome::Committed
            );
            assert_eq!(
                apply(&store, close(&ticket, count, why)),
                BatchOutcome::Committed
            );
            for key in [&read_keys.ticket, &read_keys.index] {
                assert_eq!(get(&store, key), None);
            }
            let expected = (count > 1).then(|| codec::encode_u64(count - 1));
            assert_eq!(get(&store, &read_keys.per_ref), expected);
            assert_eq!(get(&store, &read_keys.per_signer), expected);
            assert_eq!(
                get(&store, &timer),
                (why == CloseReason::Consumed).then(Value::default)
            );
            assert!(get(&store, &read_keys.reservation).is_some());
        }
    }
}

#[test]
fn two_tickets_with_one_signer_coalesce_both_counter_guards_and_delete_at_zero() {
    let first = spec();
    let mut second = first.clone();
    second.reservation_id = "reservation-2".into();
    second.pack_id = [4; 32];
    let store = MemoryKv::default();
    assert_eq!(
        apply(&store, open(&first, &TicketReads::default())),
        BatchOutcome::Committed
    );
    let reads = TicketReads {
        per_ref: Some(codec::encode_u64(1)),
        per_signer: Some(codec::encode_u64(1)),
        ..TicketReads::default()
    };
    assert_eq!(
        apply(&store, open(&second, &reads)),
        BatchOutcome::Committed
    );
    let count = codec::encode_u64(2);
    let mut batch = Batch::new();
    for spec in [&first, &second] {
        let id = ticket_id(&spec.reservation_id);
        plan_ticket_close(
            &id,
            &spec.record(),
            &codec::encode_ticket(&spec.record()),
            Some(&codec::encode_ref_id(&id)),
            Some(&count),
            Some(&count),
            CloseReason::Consumed,
            &mut batch.preconditions,
            &mut batch.writes,
        )
        .unwrap();
    }
    for counter in [keys(&first).per_ref, keys(&first).per_signer] {
        assert_eq!(
            batch
                .preconditions
                .iter()
                .filter(|p| **p == Precondition::Equals(counter.clone(), count.clone()))
                .count(),
            1
        );
        assert_eq!(
            batch
                .writes
                .iter()
                .filter(|w| **w == Write::Delete(counter.clone()))
                .count(),
            1
        );
    }
    batch.validate(&StoreCapabilities::full()).unwrap();
    assert_eq!(apply(&store, batch), BatchOutcome::Committed);
    for spec in [&first, &second] {
        let read_keys = keys(spec);
        for key in [
            read_keys.ticket,
            read_keys.index,
            read_keys.per_ref,
            read_keys.per_signer,
        ] {
            assert_eq!(get(&store, &key), None);
        }
    }
}

#[test]
fn tickets_open_guard_rejects_changed_ticket_and_writes_nothing() {
    let spec = spec();
    let store = MemoryKv::default();
    assert_eq!(
        apply(&store, open(&spec, &TicketReads::default())),
        BatchOutcome::Committed
    );
    let closing = close(&spec.record(), 1, CloseReason::Consumed);
    let mut changed = spec.record();
    changed.upload_session = Some("new-session".into());
    let changed_value = codec::encode_ticket(&changed);
    assert_eq!(
        apply(
            &store,
            Batch::new().put(keys(&spec).ticket.clone(), changed_value.clone())
        ),
        BatchOutcome::Committed
    );
    assert!(
        matches!(apply(&store, closing), BatchOutcome::PreconditionFailed { index: 0, observed: Some(value) } if value == changed_value)
    );
    assert_eq!(
        get(&store, &keys(&spec).index),
        Some(codec::encode_ref_id(&ticket_id(&spec.reservation_id)))
    );
    assert_eq!(
        get(&store, &keys(&spec).per_ref),
        Some(codec::encode_u64(1))
    );
    assert_eq!(
        get(&store, &keys(&spec).per_signer),
        Some(codec::encode_u64(1))
    );
}

#[test]
fn close_planned_before_index_replacement_cannot_delete_the_replacement() {
    let spec = spec();
    let store = MemoryKv::default();
    assert_eq!(
        apply(&store, open(&spec, &TicketReads::default())),
        BatchOutcome::Committed
    );
    let closing = close(&spec.record(), 1, CloseReason::Consumed);
    let replacement = codec::encode_ref_id(&[9; 32]);
    assert_eq!(
        apply(
            &store,
            Batch::new().put(keys(&spec).index.clone(), replacement.clone())
        ),
        BatchOutcome::Committed
    );
    assert!(matches!(
        apply(&store, closing),
        BatchOutcome::PreconditionFailed { .. }
    ));
    assert_eq!(get(&store, &keys(&spec).index), Some(replacement));
    assert!(get(&store, &keys(&spec).ticket).is_some());
    assert_eq!(
        get(&store, &keys(&spec).per_ref),
        Some(codec::encode_u64(1))
    );
}

#[test]
fn duplicate_close_and_second_open_on_same_ref_leave_first_fragment_untouched() {
    let spec = spec();
    let mut batch = close(&spec.record(), 2, CloseReason::Consumed);
    let before = batch.clone();
    let id = ticket_id(&spec.reservation_id);
    assert!(
        plan_ticket_close(
            &id,
            &spec.record(),
            &codec::encode_ticket(&spec.record()),
            Some(&codec::encode_ref_id(&id)),
            Some(&codec::encode_u64(2)),
            Some(&codec::encode_u64(2)),
            CloseReason::Consumed,
            &mut batch.preconditions,
            &mut batch.writes
        )
        .is_err()
    );
    assert_eq!(batch, before);
    let mut batch = open(&spec, &TicketReads::default());
    let before = batch.clone();
    let mut second = spec.clone();
    second.reservation_id = "second".into();
    second.signer = [3; 32];
    second.pack_id = [4; 32];
    assert!(
        plan_ticket_open(
            &second,
            &TicketReads::default(),
            TicketCaps {
                per_ref: 1,
                per_signer: 64
            },
            &mut batch.preconditions,
            &mut batch.writes
        )
        .is_err()
    );
    assert_eq!(batch, before);
}

#[test]
fn membership_is_local_under_single_and_relays_identical_deduplicated_upserts_under_d34() {
    let spec = spec();
    let repo_id = RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: spec.repo.clone(),
    };
    let pack = spec.pack_id;
    for (shards, source) in [
        (&SinglePartition as &dyn ShardMap, partition()),
        (
            &D34Shards as &dyn ShardMap,
            D34Shards.ref_shard(&repo_id, &spec.ref_name),
        ),
    ] {
        let mut outbox = OutboxBuilder::new(None, None).unwrap();
        let mut batch = Batch::new();
        plan_membership(
            &spec.repo,
            &[pack, pack],
            &source,
            shards,
            &repo_id,
            &mut outbox,
            &mut batch.writes,
        );
        outbox
            .try_finish(&mut batch.preconditions, &mut batch.writes)
            .unwrap();
        let membership = (layout::membership(&spec.repo, &pack), Value::default());
        assert_eq!(
            batch
                .writes
                .iter()
                .filter(|w| **w == Write::Put(membership.0.clone(), membership.1.clone()))
                .count(),
            1
        );
        let relays: Vec<_> = batch
            .writes
            .iter()
            .filter_map(|w| match w {
                Write::Put(key, value)
                    if matches!(layout::parse(key), Some(layout::ParsedKey::Relay(_))) =>
                {
                    Some(codec::decode_relay(value).unwrap())
                }
                _ => None,
            })
            .collect();
        if source == partition() {
            assert!(relays.is_empty());
            assert!(batch.preconditions.is_empty());
            assert_eq!(batch.writes.len(), 1);
        } else {
            assert_eq!(relays.len(), 1);
            assert_eq!(
                relays[0].target,
                shards.membership(&repo_id, &BlobKey::new(pack))
            );
            assert_eq!(relays[0].puts, vec![membership]);
        }
    }
}

#[test]
fn seven_distinct_signers_and_relay_targets_fit_with_twenty_shared_operations() {
    let mut spec = spec();
    spec.repo = RepoName::new("r".repeat(255)).unwrap();
    spec.ref_name = format!("refs/heads/{}", "x".repeat(512 - "refs/heads/".len()));
    let repo_id = RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: spec.repo.clone(),
    };
    let source = D34Shards.ref_shard(&repo_id, &spec.ref_name);
    let shared_counter = codec::encode_u64(MAX_TICKETS_PER_ADVANCE as u64);
    let mut batch = Batch::new();
    let mut outbox = OutboxBuilder::new(None, None).unwrap();
    for i in 0..MAX_TICKETS_PER_ADVANCE {
        spec.reservation_id = format!("reservation-{i}");
        spec.signer = hash(spec.reservation_id.as_bytes());
        spec.pack_id = [u8::try_from(i).unwrap(); 32];
        let ticket = spec.record();
        let id = ticket_id(&spec.reservation_id);
        plan_ticket_close(
            &id,
            &ticket,
            &codec::encode_ticket(&ticket),
            Some(&codec::encode_ref_id(&id)),
            Some(&shared_counter),
            Some(&codec::encode_u64(1)),
            CloseReason::Consumed,
            &mut batch.preconditions,
            &mut batch.writes,
        )
        .unwrap();
        outbox.outcome(
            &spec.reservation_id,
            &codec::encode_reservation(&ReservationV1::Ticketed { ticket_id: id }),
            Terminal::new(ReservationV1::Committed {
                repository: "repo".into(),
                occurred_at_ms: 200,
                bytes_stored: spec.bytes,
                new_to_repo: spec.bytes,
                new_to_store: spec.bytes,
                refs: vec![OutcomeRef {
                    name: spec.ref_name.clone(),
                    new: Some([3; 32]),
                    deleted: false,
                }],
            })
            .unwrap(),
        );
        plan_membership(
            &spec.repo,
            &[spec.pack_id],
            &source,
            &D34Shards,
            &repo_id,
            &mut outbox,
            &mut batch.writes,
        );
    }
    outbox
        .try_finish(&mut batch.preconditions, &mut batch.writes)
        .unwrap();
    // Ref counter (2) and os/oc (4) already occupy six of the twenty shared ops.
    for i in 0..7 {
        let key = layout::ref_key(&spec.repo, &format!("refs/heads/shared-{i}"));
        batch.preconditions.push(Precondition::Absent(key.clone()));
        batch
            .writes
            .push(Write::Put(key, codec::encode_ref_id(&[3; 32])));
    }
    assert_eq!(batch.preconditions.len() + batch.writes.len(), 97);
    batch.validate(&StoreCapabilities::full()).unwrap();
    assert_eq!(batch.writes.iter().filter(|w| matches!(w, Write::Put(key, _) if matches!(layout::parse(key), Some(layout::ParsedKey::Relay(_))))).count(), 7);
    let tc = keys(&spec).per_ref;
    assert_eq!(
        batch
            .writes
            .iter()
            .filter(|w| matches!(w, Write::Delete(k) if *k == tc))
            .count(),
        1
    );
    let backlog = batch
        .writes
        .iter()
        .find_map(|w| match w {
            Write::Put(k, v) if *k == layout::outcome_backlog() => {
                Some(codec::decode_backlog(v).unwrap())
            }
            _ => None,
        })
        .unwrap();
    assert_eq!(backlog.rows, 7);
    assert!(backlog.bytes > 0);
}

#[test]
fn malformed_inputs_and_counter_underflow_leave_ticket_outputs_unchanged() {
    let mut invalid_specs = vec![];
    let mut invalid = spec();
    invalid.bytes = 0;
    invalid_specs.push(invalid);
    let mut invalid = spec();
    invalid.part_size = MIN_PART_SIZE + 1;
    invalid_specs.push(invalid);
    let mut invalid = spec();
    invalid.reservation_id = "invalid id".into();
    invalid_specs.push(invalid);
    let mut invalid = spec();
    invalid.now_ms = invalid.expires_at_ms;
    invalid_specs.push(invalid);
    for spec in invalid_specs {
        let mut batch = Batch::new().require(Precondition::NotAfter(500));
        let before = batch.clone();
        assert!(matches!(
            plan_ticket_open(
                &spec,
                &TicketReads::default(),
                caps(),
                &mut batch.preconditions,
                &mut batch.writes
            ),
            Err(TicketPlanError::Invalid(_))
        ));
        assert_eq!(batch, before);
    }
    for reads in [
        TicketReads {
            index: Some(Value::new(vec![0; 31])),
            ..TicketReads::default()
        },
        TicketReads {
            per_ref: Some(codec::encode_u64(0)),
            ..TicketReads::default()
        },
        TicketReads {
            per_signer: Some(Value::new(vec![1])),
            ..TicketReads::default()
        },
    ] {
        let mut batch = Batch::new().require(Precondition::NotAfter(500));
        let before = batch.clone();
        assert!(matches!(
            plan_ticket_open(
                &spec(),
                &reads,
                caps(),
                &mut batch.preconditions,
                &mut batch.writes
            ),
            Err(TicketPlanError::Corrupt(_))
        ));
        assert_eq!(batch, before);
    }
    let spec = spec();
    let mut batch = Batch::new().require(Precondition::NotAfter(500));
    let before = batch.clone();
    assert!(
        plan_ticket_close(
            &ticket_id(&spec.reservation_id),
            &spec.record(),
            &codec::encode_ticket(&spec.record()),
            None,
            None,
            Some(&codec::encode_u64(1)),
            CloseReason::Consumed,
            &mut batch.preconditions,
            &mut batch.writes
        )
        .is_err()
    );
    assert_eq!(batch, before);
}

#[test]
fn inconsistent_counter_snapshots_and_index_binding_fail_closed() {
    let spec = spec();
    let mut batch = open(&spec, &TicketReads::default());
    let before = batch.clone();
    let mut second = spec.clone();
    second.reservation_id = "second".into();
    let reads = TicketReads {
        per_ref: Some(codec::encode_u64(2)),
        ..TicketReads::default()
    };
    assert!(
        plan_ticket_open(
            &second,
            &reads,
            caps(),
            &mut batch.preconditions,
            &mut batch.writes
        )
        .is_err()
    );
    assert_eq!(batch, before);
    let mut wrong = spec.record();
    wrong.pack_id = [9; 32];
    let reads = TicketReads {
        index: Some(codec::encode_ref_id(&ticket_id(&spec.reservation_id))),
        indexed_ticket: Some(codec::encode_ticket(&wrong)),
        ..TicketReads::default()
    };
    assert!(matches!(
        plan_ticket_open(&spec, &reads, caps(), &mut vec![], &mut vec![]),
        Err(TicketPlanError::Corrupt(_))
    ));
}

#[test]
fn deterministic_ticket_id_binds_the_domain_and_reservation() {
    let id = ticket_id("reservation-1");
    assert_eq!(
        to_hex(&id),
        "366c44902f8e8cc8e4801bb5f4d4b639f83e679a7063e1b6e0034013ef5828ed"
    );
    assert_eq!(id, hash(b"mkit.ticket.v1\nreservation-1"));
    assert_ne!(id, hash(b"reservation-1"));
    assert_ne!(id, ticket_id("reservation-2"));
    assert_eq!(to_hex(&id).len(), 64);
}
