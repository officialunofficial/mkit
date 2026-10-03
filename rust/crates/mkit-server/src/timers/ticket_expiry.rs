//! Close due upload tickets and queue one terminal `Expired` outcome.

use std::sync::atomic::{AtomicU64, Ordering};

use mkit_core::hash::Hash;
use mkit_core::repo_identity::RepositoryIdentity;

use super::{DueTimer, Fired, TimerCtx, TimerHandler, TimerKind, registry::kinds};
use crate::repo::NamespaceKey;
use crate::rt::BoxFuture;
use crate::store::codec::{self, ReservationV1, TicketV1};
use crate::store::outbox::{OutboxBuilder, Terminal};
use crate::store::tickets::{self, CloseReason};
use crate::store::{
    Batch, BlobKey, MultipartBlobStore, NamespaceStore, Partition, Precondition, StoreError, Write,
    keys,
};

static ABORT_FAILURES: AtomicU64 = AtomicU64::new(0);

/// Best-effort session abort failures observed by this process.
#[must_use]
pub fn abort_failures() -> u64 {
    ABORT_FAILURES.load(Ordering::Relaxed)
}

/// Kind-2 expiry handler. The per-kind cap bounds each native and Worker tick.
#[derive(Debug)]
pub struct TicketExpiry<B> {
    /// The blob store backing the tickets on this server.
    pub blobs: B,
}

fn repository(partition: &Partition, ticket: &TicketV1) -> Result<String, StoreError> {
    let ns = match partition {
        Partition::Namespace(ns) => ns,
        Partition::Ref {
            ns,
            repo,
            shard_ref,
        } if repo == &ticket.repo && shard_ref == &ticket.ref_name => ns,
        _ => return Err(StoreError::Corrupt("ticket in wrong partition".into())),
    };
    let name = if ns == &NamespaceKey::deployment_default() {
        ticket.repo.as_str().to_owned()
    } else {
        format!("{}/{}", ns.as_str(), ticket.repo.as_str())
    };
    RepositoryIdentity::parse_bare_allowed(&name)
        .map_err(|_| StoreError::Corrupt("invalid ticket repository".into()))?;
    Ok(name)
}

/// An unconsumed pack's verification state goes with its ticket (R-148); a
/// scheduled job's rows go with it too, by the job's own timer, which this
/// kicks (WP-4.8). A member pack keeps `vs`: GC removes it with `m`.
async fn verification_cleanup<S: NamespaceStore>(
    ctx: &TimerCtx<'_, S>,
    ticket: &TicketV1,
    batch: &mut Batch,
) -> Result<(), StoreError> {
    let vs_key = keys::verification(&ticket.repo, &ticket.pack_id);
    let rows = ctx
        .store
        .get_many(
            ctx.partition,
            &[
                keys::membership(&ticket.repo, &ticket.pack_id),
                vs_key.clone(),
                keys::verify_job(&ticket.repo, &ticket.pack_id),
            ],
        )
        .await?;
    let [member, state, job] = rows.as_slice() else {
        return Err(StoreError::Corrupt(
            "short verification cleanup read".into(),
        ));
    };
    if let (None, Some(raw)) = (member, state) {
        batch
            .preconditions
            .push(Precondition::Equals(vs_key.clone(), raw.clone()));
        batch
            .preconditions
            .push(Precondition::Absent(keys::membership(
                &ticket.repo,
                &ticket.pack_id,
            )));
        batch.writes.push(Write::Delete(vs_key));
    }
    if job.is_some() {
        batch.writes.push(Write::Put(
            keys::timer(
                ctx.now_ms,
                kinds::VERIFY.get(),
                &crate::indexed::checkpoint::timer_reference(&ticket.repo, &ticket.pack_id),
            ),
            crate::store::Value::default(),
        ));
    }
    Ok(())
}

impl<S: NamespaceStore, B: MultipartBlobStore> TimerHandler<S> for TicketExpiry<B> {
    fn kind(&self) -> TimerKind {
        kinds::TICKET_EXPIRY
    }

    fn max_per_tick(&self) -> Option<u32> {
        Some(8)
    }

    fn fire<'a>(
        &'a self,
        ctx: &'a TimerCtx<'a, S>,
        timer: &'a DueTimer,
    ) -> BoxFuture<'a, Result<Fired, StoreError>> {
        Self::fire_with(&self.blobs, ctx, timer)
    }
}

impl<B: MultipartBlobStore> TicketExpiry<B> {
    fn fire_with<'a, S: NamespaceStore>(
        blobs: &'a B,
        ctx: &'a TimerCtx<'a, S>,
        timer: &'a DueTimer,
    ) -> BoxFuture<'a, Result<Fired, StoreError>> {
        Box::pin(async move {
            let fire = async {
                let id: Hash = timer.reference.as_ref().try_into().map_err(|_| {
                    StoreError::Corrupt("ticket expiry reference is not a ticket id".into())
                })?;
                let key = keys::ticket(&id);
                let Some(raw) = ctx.store.get(ctx.partition, &key).await? else {
                    return Ok(Fired::Done(Batch::new()));
                };
                let ticket = codec::decode_ticket(&raw)?;
                if ticket.expires_at_ms > ctx.now_ms {
                    return Ok(Fired::Reschedule {
                        due_at_ms: ticket.expires_at_ms,
                        value: timer.value.clone(),
                        batch: Batch::new(),
                    });
                }

                let rid = &ticket.reservation_id;
                let reservation = ctx
                    .store
                    .get(ctx.partition, &keys::reservation(rid)?)
                    .await?
                    .ok_or_else(|| StoreError::Corrupt("ticket has no reservation".into()))?;
                if !matches!(
                    codec::decode_reservation(&reservation)?,
                    ReservationV1::Ticketed { ticket_id } if ticket_id == id
                ) {
                    return Err(StoreError::Corrupt("ticket reservation mismatch".into()));
                }
                let index = keys::ticket_index(
                    &ticket.repo,
                    &ticket.ref_name,
                    &ticket.pack_id,
                    &ticket.signer,
                )?;
                let tc = keys::tickets_per_ref(&ticket.repo, &ticket.ref_name)?;
                let tu = keys::tickets_per_signer(&ticket.repo, &ticket.ref_name, &ticket.signer)?;
                let (index_value, ref_count, signer_count, os, oc) = (
                    ctx.store.get(ctx.partition, &index).await?,
                    ctx.store.get(ctx.partition, &tc).await?,
                    ctx.store.get(ctx.partition, &tu).await?,
                    ctx.store
                        .get(ctx.partition, &keys::outbox_sequence())
                        .await?,
                    ctx.store
                        .get(ctx.partition, &keys::outcome_backlog())
                        .await?,
                );
                let mut batch = Batch::new();
                tickets::plan_ticket_close(
                    &id,
                    &ticket,
                    &raw,
                    index_value.as_ref(),
                    ref_count.as_ref(),
                    signer_count.as_ref(),
                    CloseReason::ExpiryTimerFired,
                    &mut batch.preconditions,
                    &mut batch.writes,
                )?;
                let mut outbox = OutboxBuilder::new(os.as_ref(), oc.as_ref())?;
                outbox.outcome(
                    rid,
                    &reservation,
                    Terminal::new(ReservationV1::Expired {
                        repository: repository(ctx.partition, &ticket)?,
                        occurred_at_ms: ctx.now_ms,
                    })?,
                );
                outbox.try_finish(&mut batch.preconditions, &mut batch.writes)?;

                verification_cleanup(ctx, &ticket, &mut batch).await?;

                if let Some(session) = &ticket.upload_session
                    && let Err(error) = blobs.abort(BlobKey::pack(ticket.pack_id), session).await
                {
                    ABORT_FAILURES.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(error = %error, ticket_id = %mkit_core::hash::to_hex(&id), "ticket expiry session abort failed");
                }
                Ok(Fired::Done(batch))
            };
            match fire.await {
                Err(error @ StoreError::Corrupt(_)) => {
                    tracing::warn!(%error, "corrupt ticket expiry row deferred for repair");
                    Ok(Fired::Reschedule {
                        due_at_ms: ctx.now_ms.saturating_add(60_000),
                        value: timer.value.clone(),
                        batch: Batch::new(),
                    })
                }
                other => other,
            }
        })
    }
}

/// Borrow the pipeline's store for the test-only manual timer tick.
#[cfg(feature = "__test-faults")]
#[derive(Debug)]
pub(crate) struct BorrowedTicketExpiry<'a, B> {
    pub(crate) blobs: &'a B,
}

#[cfg(feature = "__test-faults")]
impl<S: NamespaceStore, B: MultipartBlobStore> TimerHandler<S> for BorrowedTicketExpiry<'_, B> {
    fn kind(&self) -> TimerKind {
        kinds::TICKET_EXPIRY
    }

    fn max_per_tick(&self) -> Option<u32> {
        Some(8)
    }

    fn fire<'a>(
        &'a self,
        ctx: &'a TimerCtx<'a, S>,
        timer: &'a DueTimer,
    ) -> BoxFuture<'a, Result<Fired, StoreError>> {
        TicketExpiry::fire_with(self.blobs, ctx, timer)
    }
}

#[cfg(all(test, feature = "memory"))]
#[allow(clippy::unwrap_used)] // Unwraps assert fixed test fixtures.
mod tests {
    use super::*;
    use crate::repo::RepoName;
    use crate::store::{
        BatchOutcome, BlobBody, BlobMeta, BlobStore, ByteRange, UnsupportedPartSink, Value,
    };
    use crate::timers::{TickBudget, TimerRegistry, run_due};
    use crate::{ManualClock, MemoryBlobStore, MemoryKv};

    fn partition() -> Partition {
        Partition::Namespace(NamespaceKey::deployment_default())
    }

    fn ticket(n: usize, expiry: u64, session: Option<Vec<u8>>) -> TicketV1 {
        TicketV1 {
            authority_generation: None,
            repo: RepoName::new("repo").unwrap(),
            ref_name: format!("refs/heads/branch-{n}"),
            signer: [1; 32],
            pack_id: [2; 32],
            bytes: 8 * 1024 * 1024 + 1,
            part_size: 8 * 1024 * 1024,
            expires_at_ms: expiry,
            created_at_ms: 1,
            reservation_id: format!("s:{n:064x}"),
            upload_session: session,
        }
    }

    async fn plant(store: &MemoryKv, t: &TicketV1, due: u64) -> Hash {
        let id = tickets::ticket_id(&t.reservation_id);
        let batch = Batch::new()
            .put(keys::ticket(&id), codec::encode_ticket(t))
            .put(
                keys::reservation(&t.reservation_id).unwrap(),
                codec::encode_reservation(&ReservationV1::Ticketed { ticket_id: id }),
            )
            .put(
                keys::ticket_index(&t.repo, &t.ref_name, &t.pack_id, &t.signer).unwrap(),
                codec::encode_ref_id(&id),
            )
            .put(
                keys::tickets_per_ref(&t.repo, &t.ref_name).unwrap(),
                codec::encode_u64(1),
            )
            .put(
                keys::tickets_per_signer(&t.repo, &t.ref_name, &t.signer).unwrap(),
                codec::encode_u64(1),
            )
            .put(
                keys::timer(due, kinds::TICKET_EXPIRY.get(), &id),
                Value::default(),
            );
        assert_eq!(
            store.apply(&partition(), batch).await.unwrap(),
            BatchOutcome::Committed
        );
        id
    }

    async fn tick(store: &MemoryKv, blobs: MemoryBlobStore, now: u64) -> crate::timers::RunReport {
        let clock = ManualClock::new(i64::try_from(now).expect("test time fits i64"));
        run_due(
            store,
            &partition(),
            &TimerRegistry::new().register(TicketExpiry { blobs }),
            &clock,
            now,
            &TickBudget::default(),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn expired_ticket_closes_once_and_aborts_session() {
        let store = MemoryKv::default();
        let blobs = MemoryBlobStore::default();
        let t = ticket(1, 100, None);
        let id = tickets::ticket_id(&t.reservation_id);
        let session = blobs
            .begin_multipart_for_ticket(BlobKey::pack(t.pack_id), t.bytes, t.part_size, id)
            .await
            .unwrap();
        let t = TicketV1 {
            upload_session: Some(session),
            ..t
        };
        plant(&store, &t, 100).await;
        assert_eq!(blobs.multipart_session_count(), 1);
        let report = tick(&store, blobs.clone(), 100).await;
        assert_eq!(report.fired, 1);
        assert_eq!(blobs.multipart_session_count(), 0);
        for key in [
            keys::ticket(&id),
            keys::ticket_index(&t.repo, &t.ref_name, &t.pack_id, &t.signer).unwrap(),
            keys::tickets_per_ref(&t.repo, &t.ref_name).unwrap(),
            keys::tickets_per_signer(&t.repo, &t.ref_name, &t.signer).unwrap(),
            keys::timer(100, kinds::TICKET_EXPIRY.get(), &id),
        ] {
            assert!(store.get(&partition(), &key).await.unwrap().is_none());
        }
        let outcome = store
            .get(&partition(), &keys::reservation(&t.reservation_id).unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            codec::decode_reservation(&outcome).unwrap(),
            ReservationV1::Expired {
                repository: "repo".into(),
                occurred_at_ms: 100,
            }
        );
        assert_eq!(tick(&store, blobs, 100).await.fired, 0);
        assert_eq!(
            codec::decode_backlog(
                &store
                    .get(&partition(), &keys::outcome_backlog())
                    .await
                    .unwrap()
                    .unwrap()
            )
            .unwrap()
            .rows,
            1
        );
    }

    #[tokio::test]
    async fn expiry_clears_an_unconsumed_packs_verification_and_kicks_its_job() {
        use crate::indexed::state::{VerificationV1, encode};
        for member in [false, true] {
            let store = MemoryKv::default();
            let t = ticket(4, 100, None);
            plant(&store, &t, 100).await;
            let vs = keys::verification(&t.repo, &t.pack_id);
            let job = keys::verify_job(&t.repo, &t.pack_id);
            let mut rows = Batch::new()
                .put(
                    vs.clone(),
                    encode(&VerificationV1::Verified {
                        pack_len: 1,
                        verified_at_ms: 1,
                        publication: None,
                    }),
                )
                .put(job.clone(), Value::default());
            if member {
                rows = rows.put(keys::membership(&t.repo, &t.pack_id), Value::default());
            }
            store.apply(&partition(), rows).await.unwrap();
            assert_eq!(tick(&store, MemoryBlobStore::default(), 100).await.fired, 1);
            // A member pack keeps `vs` (GC removes it with `m`); an unconsumed
            // one loses it. Either way a scheduled job's timer is kicked to
            // delete the job's rows.
            assert_eq!(
                store.get(&partition(), &vs).await.unwrap().is_some(),
                member
            );
            let kick = keys::timer(
                100,
                kinds::VERIFY.get(),
                &crate::indexed::checkpoint::timer_reference(&t.repo, &t.pack_id),
            );
            assert!(store.get(&partition(), &kick).await.unwrap().is_some());
        }
        // No verification rows: nothing extra is written.
        let store = MemoryKv::default();
        let t = ticket(5, 100, None);
        plant(&store, &t, 100).await;
        assert_eq!(tick(&store, MemoryBlobStore::default(), 100).await.fired, 1);
        let (start, end) = keys::class_range(keys::TAG_TIMER);
        let timers = store
            .scan(&partition(), &start, &end, None, 10)
            .await
            .unwrap()
            .entries;
        assert!(!timers.iter().any(|(key, _)| matches!(
            keys::parse(key),
            Some(keys::ParsedKey::Timer { kind, .. }) if kind == kinds::VERIFY.get()
        )));
    }

    #[tokio::test]
    async fn early_timer_reschedules_and_consumed_ticket_is_done() {
        let store = MemoryKv::default();
        let blobs = MemoryBlobStore::default();
        let t = ticket(2, 200, None);
        let id = plant(&store, &t, 100).await;
        assert_eq!(tick(&store, blobs.clone(), 100).await.fired, 1);
        assert!(
            store
                .get(
                    &partition(),
                    &keys::timer(200, kinds::TICKET_EXPIRY.get(), &id)
                )
                .await
                .unwrap()
                .is_some()
        );
        store
            .apply(&partition(), Batch::new().delete(keys::ticket(&id)))
            .await
            .unwrap();
        assert_eq!(tick(&store, blobs, 200).await.fired, 1);
        assert!(
            store
                .get(&partition(), &keys::reservation(&t.reservation_id).unwrap())
                .await
                .unwrap()
                .is_some_and(|v| matches!(
                    codec::decode_reservation(&v),
                    Ok(ReservationV1::Ticketed { .. })
                ))
        );
    }

    #[tokio::test]
    async fn consumption_race_rejects_stale_expiry_batch() {
        let store = MemoryKv::default();
        let t = ticket(3, 100, None);
        let id = plant(&store, &t, 100).await;
        let timer = DueTimer {
            due_at_ms: 100,
            kind: kinds::TICKET_EXPIRY,
            reference: bytes::Bytes::copy_from_slice(&id),
            value: Value::default(),
        };
        let ctx = TimerCtx {
            store: &store,
            partition: &partition(),
            now_ms: 100,
        };
        let Fired::Done(stale) = (TicketExpiry {
            blobs: MemoryBlobStore::default(),
        })
        .fire(&ctx, &timer)
        .await
        .unwrap() else {
            panic!("due ticket must close");
        };
        let committed = codec::encode_reservation(&ReservationV1::Expired {
            repository: "repo".into(),
            occurred_at_ms: 99,
        });
        store
            .apply(
                &partition(),
                Batch::new().delete(keys::ticket(&id)).put(
                    keys::reservation(&t.reservation_id).unwrap(),
                    committed.clone(),
                ),
            )
            .await
            .unwrap();
        assert!(matches!(
            store.apply(&partition(), stale).await.unwrap(),
            BatchOutcome::PreconditionFailed { .. }
        ));
        assert_eq!(tick(&store, MemoryBlobStore::default(), 100).await.fired, 1);
        assert_eq!(
            store
                .get(&partition(), &keys::reservation(&t.reservation_id).unwrap())
                .await
                .unwrap(),
            Some(committed)
        );
    }

    #[tokio::test]
    async fn only_eight_tickets_fire_per_tick() {
        let store = MemoryKv::default();
        for n in 0..10 {
            plant(&store, &ticket(n, 100, None), 100).await;
        }
        let report = tick(&store, MemoryBlobStore::default(), 100).await;
        assert_eq!(report.fired, 8);
        assert_eq!(report.deferred, 2);
    }

    struct FailingAbort(MemoryBlobStore);

    impl BlobStore for FailingAbort {
        type Sink = <MemoryBlobStore as BlobStore>::Sink;

        async fn begin(&self, key: BlobKey, len: u64) -> Result<Self::Sink, StoreError> {
            self.0.begin(key, len).await
        }

        async fn get(
            &self,
            key: &BlobKey,
            range: Option<ByteRange>,
        ) -> Result<Option<BlobBody>, StoreError> {
            self.0.get(key, range).await
        }

        async fn head(&self, key: &BlobKey) -> Result<Option<BlobMeta>, StoreError> {
            self.0.head(key).await
        }

        async fn probe(&self) -> Result<(), StoreError> {
            self.0.probe().await
        }

        async fn delete(&self, key: &BlobKey) -> Result<bool, StoreError> {
            self.0.delete(key).await
        }
    }

    impl MultipartBlobStore for FailingAbort {
        type PartSink = UnsupportedPartSink;
        const MAX_PARTS: u32 = 1;

        async fn abort(&self, _key: BlobKey, _session: &[u8]) -> Result<(), StoreError> {
            Err(StoreError::Unavailable("injected abort failure".into()))
        }
    }

    #[tokio::test]
    async fn abort_failure_is_counted_and_does_not_block_expiry() {
        let store = MemoryKv::default();
        let t = ticket(11, 100, Some(vec![7; 32]));
        plant(&store, &t, 100).await;
        let before = abort_failures();
        let clock = ManualClock::new(100);
        let report = run_due(
            &store,
            &partition(),
            &TimerRegistry::new().register(TicketExpiry {
                blobs: FailingAbort(MemoryBlobStore::default()),
            }),
            &clock,
            100,
            &TickBudget::default(),
        )
        .await
        .unwrap();
        assert_eq!(report.fired, 1);
        assert!(abort_failures() > before);
        assert!(matches!(
            codec::decode_reservation(
                &store
                    .get(&partition(), &keys::reservation(&t.reservation_id).unwrap())
                    .await
                    .unwrap()
                    .unwrap()
            ),
            Ok(ReservationV1::Expired { .. })
        ));
    }

    #[tokio::test]
    // The corrupt row takes one slot on its first tick, then backs off 60 s,
    // so it cannot starve healthy tickets on later ticks.
    async fn corrupt_expiry_backs_off_without_starving_healthy_tickets() {
        let store = MemoryKv::default();
        let bad = [0_u8; 32];
        store
            .apply(
                &partition(),
                Batch::new()
                    .put(keys::ticket(&bad), Value::new(&b"bad ticket"[..]))
                    .put(
                        keys::timer(99, kinds::TICKET_EXPIRY.get(), &bad),
                        Value::default(),
                    ),
            )
            .await
            .unwrap();
        let mut tickets = Vec::new();
        for n in 20..29 {
            let t = ticket(n, 100, None);
            plant(&store, &t, 100).await;
            tickets.push(t);
        }
        let report = tick(&store, MemoryBlobStore::default(), 100).await;
        assert_eq!(report.failed, 0);
        assert_eq!(report.fired, 8);
        assert_eq!(report.deferred, 2);
        assert_eq!(tick(&store, MemoryBlobStore::default(), 100).await.fired, 2);
        let closed = futures::future::join_all(tickets.iter().map(|t| async {
            let value = store
                .get(&partition(), &keys::reservation(&t.reservation_id).unwrap())
                .await
                .unwrap()
                .unwrap();
            matches!(
                codec::decode_reservation(&value),
                Ok(ReservationV1::Expired { .. })
            )
        }))
        .await;
        assert_eq!(closed.into_iter().filter(|yes| *yes).count(), 9);
    }
}
