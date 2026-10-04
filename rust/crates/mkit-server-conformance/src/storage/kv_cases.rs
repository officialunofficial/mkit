//! Ticket, membership and outbox planners against every atomic metadata
//! backend. Each case owns a namespace partition and uses caller-supplied
//! timestamps, so it requires neither a clock seam nor a timer handler.

use std::collections::BTreeMap;

use mkit_core::upload_parts::MIN_PART_SIZE;
use mkit_server::pipeline::SinglePartition;
use mkit_server::store::adapter_spi::codec::{
    AbortReason, Backlog, PendingOp, ReservationV1, TicketV1,
};
use mkit_server::store::adapter_spi::outbox::{self, OutboxBuilder, Terminal};
use mkit_server::store::adapter_spi::tickets::{
    self, CloseReason, TicketCaps, TicketPlanError, TicketReads, TicketSpec,
};
use mkit_server::store::adapter_spi::{codec, keys};
use mkit_server::{
    Batch, BatchOutcome, Key, NamespaceStore, Partition, Precondition, RepoId, RepoName, Value,
    Write,
};

use super::CaseResult::Pass;
use super::{KvHarness, Outcome, commit, need_all_classes, need_atomic, outcome, part};

fn spec(rid: &str) -> Result<TicketSpec, String> {
    Ok(TicketSpec {
        authority_generation: None,
        repo: ok!(RepoName::new("conformance")),
        ref_name: "refs/heads/main".into(),
        signer: [0x11; 32],
        pack_id: [0x22; 32],
        bytes: 1_024,
        part_size: MIN_PART_SIZE,
        expires_at_ms: 2_000,
        created_at_ms: 1_000,
        now_ms: 1_000,
        reservation_id: rid.into(),
        upload_session: None,
    })
}

async fn reads<S: NamespaceStore>(
    s: &S,
    p: &Partition,
    spec: &TicketSpec,
) -> Result<TicketReads, String> {
    let keys = tickets::keys(spec);
    let index = ok!(s.get(p, &keys.index).await);
    let indexed_ticket = match &index {
        Some(value) => {
            let id = ok!(codec::decode_ref_id(value));
            ok!(s.get(p, &keys::ticket(&id)).await)
        }
        None => None,
    };
    Ok(TicketReads {
        ticket: ok!(s.get(p, &keys.ticket).await),
        indexed_ticket,
        index,
        per_ref: ok!(s.get(p, &keys.per_ref).await),
        per_signer: ok!(s.get(p, &keys.per_signer).await),
        reservation: ok!(s.get(p, &keys.reservation).await),
    })
}

fn caps() -> TicketCaps {
    TicketCaps::new(1_024, 64)
}

async fn open<S: NamespaceStore>(
    s: &S,
    p: &Partition,
    spec: &TicketSpec,
) -> Result<[u8; 32], String> {
    let reads = reads(s, p, spec).await?;
    let mut batch = Batch::new();
    let id = tickets::plan_ticket_open(
        spec,
        &reads,
        caps(),
        &mut batch.preconditions,
        &mut batch.writes,
    )
    .map_err(|e| format!("ticket open: {e:?}"))?;
    commit(s, p, batch).await?;
    Ok(id)
}

fn terminal(spec: &TicketSpec) -> Result<Terminal, String> {
    Ok(ok!(Terminal::new(ReservationV1::committed(
        spec.repo.as_str().into(),
        1_500,
        spec.bytes,
        spec.bytes,
        spec.bytes,
        vec![]
    ))))
}

/// Compose the same fragments a ticket-consuming advance composes.
async fn consume<S: NamespaceStore>(
    s: &S,
    p: &Partition,
    spec: &TicketSpec,
    id: &[u8; 32],
) -> Result<Batch, String> {
    let read = reads(s, p, spec).await?;
    let ticket_value = read.ticket.as_ref().ok_or("ticket missing")?;
    let ticket: TicketV1 = ok!(codec::decode_ticket(ticket_value));
    let mut batch = Batch::new();
    ok!(tickets::plan_ticket_close(
        id,
        &ticket,
        ticket_value,
        read.index.as_ref(),
        read.per_ref.as_ref(),
        read.per_signer.as_ref(),
        CloseReason::Consumed,
        &mut batch.preconditions,
        &mut batch.writes,
    ));
    let os = ok!(s.get(p, &keys::outbox_sequence()).await);
    let oc = ok!(s.get(p, &keys::outcome_backlog()).await);
    let mut outbox = ok!(OutboxBuilder::new(os.as_ref(), oc.as_ref()));
    let ns = match p {
        Partition::Namespace(ns) => ns.clone(),
        _ => return Err("case needs its namespace partition".into()),
    };
    let repo = RepoId {
        namespace: ns,
        name: spec.repo.clone(),
    };
    tickets::plan_membership(
        &spec.repo,
        &[spec.pack_id],
        p,
        &SinglePartition,
        &repo,
        &mut outbox,
        &mut batch.writes,
    );
    outbox.outcome(
        &spec.reservation_id,
        read.reservation.as_ref().ok_or("reservation missing")?,
        terminal(spec)?,
    );
    ok!(outbox.try_finish(&mut batch.preconditions, &mut batch.writes));
    Ok(batch)
}

/// Snapshot every key a batch can change, including counters and indexes.
async fn snapshot<S: NamespaceStore>(
    s: &S,
    p: &Partition,
    batch: &Batch,
) -> Result<BTreeMap<Key, Option<Value>>, String> {
    let mut rows = BTreeMap::new();
    for write in &batch.writes {
        let key = match write {
            Write::Put(key, _) | Write::Delete(key) => key,
        };
        rows.insert(key.clone(), ok!(s.get(p, key).await));
    }
    Ok(rows)
}

async fn unchanged<S: NamespaceStore>(
    s: &S,
    p: &Partition,
    before: &BTreeMap<Key, Option<Value>>,
) -> Result<(), String> {
    for (key, value) in before {
        ensure_eq!(ok!(s.get(p, key).await), *value);
    }
    Ok(())
}

/// Reopening the same signer/ref/pack finds the live ticket and plans no writes.
pub async fn kv_ticket_create_idempotent<H: KvHarness>(h: H) -> Outcome {
    let s = h.store();
    let p = part("kv_ticket_create_idempotent");
    gate!(need_all_classes(&s, &p).await);
    gate!(need_atomic(&s, &p).await);
    let mut spec = spec("ticket-create")?;
    let id = open(&s, &p, &spec).await?;
    let original = ok!(s.get(&p, &keys::ticket(&id)).await).ok_or("ticket missing")?;
    let original = ok!(codec::decode_ticket(&original));
    // A retry after authorization may have a fresh candidate reservation id.
    spec.reservation_id = "ticket-create-retry".into();
    let reads = reads(&s, &p, &spec).await?;
    let mut batch = Batch::new();
    match tickets::plan_ticket_open(
        &spec,
        &reads,
        caps(),
        &mut batch.preconditions,
        &mut batch.writes,
    ) {
        Err(TicketPlanError::Existing(ticket)) => ensure_eq!(ticket, original),
        other => return Err(format!("expected Existing, got {other:?}")),
    }
    ensure!(
        batch.preconditions.is_empty() && batch.writes.is_empty(),
        "idempotent retry planned effects"
    );
    ensure_eq!(
        ok!(s.get(&p, &tickets::keys(&spec).reservation).await),
        None
    );
    ensure_eq!(
        ok!(codec::decode_u64(
            reads.per_ref.as_ref().ok_or("ref counter missing")?
        )),
        1
    );
    ensure_eq!(
        ok!(codec::decode_u64(
            reads.per_signer.as_ref().ok_or("signer counter missing")?
        )),
        1
    );
    Ok(Pass)
}

/// Ref CAS, ticket consumption, membership and the terminal outcome commit
/// together; a conflicting ref CAS leaves every planned row untouched.
pub async fn kv_refs_membership_outcome_atomic<H: KvHarness>(h: H) -> Outcome {
    let s = h.store();
    let p = part("kv_refs_membership_outcome_atomic");
    gate!(need_all_classes(&s, &p).await);
    gate!(need_atomic(&s, &p).await);
    let spec = spec("atomic-advance")?;
    let id = open(&s, &p, &spec).await?;
    let head = keys::ref_key(&spec.repo, &spec.ref_name);
    let packmap = keys::ref_key(&spec.repo, "refs/mkit/packmap/main");
    let old = codec::encode_ref_id(&[1; 32]);
    let new = codec::encode_ref_id(&[2; 32]);
    commit(&s, &p, Batch::new().put(head.clone(), old.clone())).await?;
    let mut batch = consume(&s, &p, &spec, &id).await?;
    batch.preconditions.push(Precondition::Equals(
        head.clone(),
        codec::encode_ref_id(&[9; 32]),
    ));
    batch
        .preconditions
        .push(Precondition::Absent(packmap.clone()));
    batch.writes.push(Write::Put(head.clone(), new.clone()));
    batch.writes.push(Write::Put(packmap.clone(), new.clone()));
    let before = snapshot(&s, &p, &batch).await?;
    ensure!(
        matches!(
            outcome(&s, &p, batch.clone()).await?,
            BatchOutcome::PreconditionFailed { .. }
        ),
        "conflicting advance committed"
    );
    unchanged(&s, &p, &before).await?;
    let guard = batch
        .preconditions
        .iter_mut()
        .find(|pre| matches!(pre, Precondition::Equals(key, _) if *key == head))
        .ok_or("head guard missing")?;
    *guard = Precondition::Equals(head.clone(), old);
    commit(&s, &p, batch).await?;
    ensure_eq!(ok!(s.get(&p, &head).await), Some(new.clone()));
    ensure_eq!(ok!(s.get(&p, &packmap).await), Some(new));
    ensure_eq!(ok!(s.get(&p, &keys::ticket(&id)).await), None);
    let read_keys = tickets::keys(&spec);
    for key in [&read_keys.index, &read_keys.per_ref, &read_keys.per_signer] {
        ensure_eq!(ok!(s.get(&p, key).await), None);
    }
    ensure_eq!(
        ok!(s
            .get(&p, &keys::membership(&spec.repo, &spec.pack_id))
            .await),
        Some(Value::default())
    );
    let row = ok!(s.get(&p, &read_keys.reservation).await).ok_or("outcome missing")?;
    ensure!(
        matches!(
            ok!(codec::decode_reservation(&row)),
            ReservationV1::Committed { .. }
        ),
        "reservation not committed"
    );
    ensure_eq!(
        ok!(s
            .get(&p, &ok!(keys::outcome_pending(1, &spec.reservation_id)))
            .await),
        Some(Value::default())
    );
    Ok(Pass)
}

/// The `tickets_open` guard catches replacement between planning and apply,
/// with no partial consumption, membership or outcome effects.
pub async fn kv_ticket_changed_precondition_writes_nothing<H: KvHarness>(h: H) -> Outcome {
    let s = h.store();
    let p = part("kv_ticket_changed_precondition_writes_nothing");
    gate!(need_all_classes(&s, &p).await);
    gate!(need_atomic(&s, &p).await);
    let spec = spec("changed-ticket")?;
    let id = open(&s, &p, &spec).await?;
    let batch = consume(&s, &p, &spec, &id).await?;
    let key = keys::ticket(&id);
    let old = ok!(s.get(&p, &key).await).ok_or("ticket missing")?;
    let mut ticket = ok!(codec::decode_ticket(&old));
    ticket.upload_session = Some("replacement-session".into());
    let replacement = codec::encode_ticket(&ticket);
    commit(&s, &p, Batch::new().put(key.clone(), replacement.clone())).await?;
    let before = snapshot(&s, &p, &batch).await?;
    let result = outcome(&s, &p, batch).await?;
    ensure!(
        matches!(result, BatchOutcome::PreconditionFailed { observed: Some(ref value), .. } if *value == replacement),
        "changed ticket did not fail with observed replacement: {result:?}"
    );
    unchanged(&s, &p, &before).await?;
    Ok(Pass)
}

/// Ack removes only its terminal row and queue index. Backlog bytes are
/// the exact key/value lengths and survive other outstanding outcomes.
pub async fn kv_outcome_ack_exact_backlog<H: KvHarness>(h: H) -> Outcome {
    let s = h.store();
    let p = part("kv_outcome_ack_exact_backlog");
    gate!(need_all_classes(&s, &p).await);
    gate!(need_atomic(&s, &p).await);
    let ids = ["ack-one", "ack-two"];
    let prior = codec::encode_reservation(&ReservationV1::Ticketed {
        ticket_id: [0x33; 32],
    });
    for rid in ids {
        commit(
            &s,
            &p,
            Batch::new().put(ok!(keys::reservation(rid)), prior.clone()),
        )
        .await?;
    }
    let spec = spec("ack-one")?;
    let mut batch = Batch::new();
    let mut outbox = ok!(OutboxBuilder::new(None, None));
    for rid in ids {
        outbox.outcome(rid, &prior, terminal(&spec)?);
    }
    ok!(outbox.try_finish(&mut batch.preconditions, &mut batch.writes));
    commit(&s, &p, batch).await?;
    let mut total = 0;
    for rid in ids {
        let key = ok!(keys::reservation(rid));
        let value = ok!(s.get(&p, &key).await).ok_or("outcome missing")?;
        total += (key.as_bytes().len() + value.as_bytes().len()) as u64;
    }
    let backlog_key = keys::outcome_backlog();
    let oc = ok!(s.get(&p, &backlog_key).await).ok_or("backlog missing")?;
    ensure_eq!(
        ok!(codec::decode_backlog(&oc)),
        Backlog {
            rows: 2,
            bytes: total
        }
    );
    for (i, rid) in ids.into_iter().enumerate() {
        let key = ok!(keys::reservation(rid));
        let value = ok!(s.get(&p, &key).await).ok_or("outcome missing")?;
        let oc = ok!(s.get(&p, &backlog_key).await);
        let mut ack = Batch::new();
        let seq = i as u64 + 1;
        ok!(outbox::plan_ack(
            rid,
            &value,
            seq,
            oc.as_ref(),
            &mut ack.preconditions,
            &mut ack.writes
        ));
        commit(&s, &p, ack).await?;
        total -= (key.as_bytes().len() + value.as_bytes().len()) as u64;
        ensure_eq!(ok!(s.get(&p, &key).await), None);
        ensure_eq!(
            ok!(s.get(&p, &ok!(keys::outcome_pending(seq, rid))).await),
            None
        );
        let actual = match ok!(s.get(&p, &backlog_key).await) {
            Some(value) => ok!(codec::decode_backlog(&value)),
            None => Backlog { rows: 0, bytes: 0 },
        };
        ensure_eq!(
            actual,
            Backlog {
                rows: 1 - i as u64,
                bytes: total
            }
        );
        ensure_eq!(
            ok!(codec::decode_u64(
                &ok!(s.get(&p, &keys::outbox_sequence()).await).ok_or("sequence missing")?
            )),
            2
        );
    }
    Ok(Pass)
}

/// Pending and reconcile contenders use the same stored value as their arbiter.
/// A losing batch leaves its terminal value, queue and backlog unchanged.
pub async fn kv_pending_terminal_arbitration<H: KvHarness>(h: H) -> Outcome {
    let s = h.store();
    let p = part("kv_pending_terminal_arbitration");
    gate!(need_all_classes(&s, &p).await);
    gate!(need_atomic(&s, &p).await);
    for (rid, op) in [("write", PendingOp::Write), ("read", PendingOp::Read)] {
        let pending = ReservationV1::pending("conformance".into(), 100, 200, op);
        let prior = codec::encode_reservation(&pending);
        let mut builder = ok!(OutboxBuilder::new(None, None));
        builder.pending(rid, None, &pending);
        let mut batch = Batch::new();
        ok!(builder.try_finish(&mut batch.preconditions, &mut batch.writes));
        commit(&s, &p, batch).await?;
        ensure_eq!(
            ok!(s.get(&p, &ok!(keys::reservation(rid))).await),
            Some(prior.clone())
        );
        ensure!(
            ok!(s.get(&p, &keys::timer(200, 9, rid.as_bytes())).await).is_some(),
            "missing reconcile timer"
        );

        let committed = match op {
            PendingOp::Write => {
                ReservationV1::committed("conformance".into(), 150, 0, 0, 0, vec![])
            }
            PendingOp::Read => ReservationV1::read_served("conformance".into(), 150, [9; 32], 7),
        };
        let abandoned = ReservationV1::aborted(
            "conformance".into(),
            201,
            AbortReason::Abandoned,
            String::new(),
        );
        let os = ok!(s.get(&p, &keys::outbox_sequence()).await);
        let oc = ok!(s.get(&p, &keys::outcome_backlog()).await);
        let mut winner = ok!(OutboxBuilder::new(os.as_ref(), oc.as_ref()));
        winner.outcome(rid, &prior, ok!(Terminal::new(committed.clone())));
        let mut winner_batch = Batch::new();
        ok!(winner.try_finish(&mut winner_batch.preconditions, &mut winner_batch.writes));
        let mut loser = ok!(OutboxBuilder::new(os.as_ref(), oc.as_ref()));
        loser.outcome(rid, &prior, ok!(Terminal::new(abandoned)));
        let mut loser_batch = Batch::new();
        ok!(loser.try_finish(&mut loser_batch.preconditions, &mut loser_batch.writes));
        commit(&s, &p, winner_batch).await?;
        ensure!(
            matches!(
                ok!(s.apply(&p, loser_batch).await),
                BatchOutcome::PreconditionFailed { .. }
            ),
            "reconcile overwrote terminal outcome"
        );
        ensure_eq!(
            ok!(s.get(&p, &ok!(keys::reservation(rid))).await),
            Some(codec::encode_reservation(&committed))
        );
    }
    ensure_eq!(
        ok!(codec::decode_backlog(
            &ok!(s.get(&p, &keys::outcome_backlog()).await).ok_or("backlog missing")?
        ))
        .rows,
        2
    );
    Ok(Pass)
}
