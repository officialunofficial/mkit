//! Best-effort relay wakeups using existing guarded timer rows.
use super::checkpoint::{Phase, decode_job, parse_reference};
use crate::store::{Batch, NamespaceStore, Precondition, StoreError, keys};
use crate::timers::{TimerCtx, registry::kinds};

/// Best effort only: polling recovers an unavailable or contended nudge.
pub(crate) async fn after_relay<S: NamespaceStore>(
    ctx: &TimerCtx<'_, S>,
    allocated: u64,
    metrics: &dyn crate::Metrics,
) -> Batch {
    try_after_relay(ctx, allocated, metrics)
        .await
        .unwrap_or_else(|error| {
            tracing::warn!(%error, "verification relay nudge skipped");
            Batch::new()
        })
}

/// Target watermarks and source cleanup committed before this observation.
async fn try_after_relay<S: NamespaceStore>(
    ctx: &TimerCtx<'_, S>,
    allocated: u64,
    metrics: &dyn crate::Metrics,
) -> Result<Batch, StoreError> {
    let (start, end) = keys::class_range(keys::TAG_RELAY);
    let remaining = ctx.store.scan(ctx.partition, &start, &end, None, 1).await?;
    let through = match remaining.entries.first().map(|(key, _)| keys::parse(key)) {
        Some(Some(keys::ParsedKey::Relay(first))) => allocated.min(first.saturating_sub(1)),
        None => allocated,
        _ => return Err(StoreError::Corrupt("invalid relay head".into())),
    };
    metrics.incr(
        crate::telemetry::METRIC_VERIFICATION_PROGRESS,
        &[("stage", "relay_delivered")],
        1,
    );
    tracing::info!(event = "verification_relay_delivered", now_ms = ctx.now_ms,
        source = ?ctx.partition, delivered_through = through);
    after_delivery(ctx, through).await
}

/// At most sixteen timer/job reads and eight moves. Anything not observed
/// keeps its recovery poll. No verification runs in the relay handler.
pub(crate) async fn after_delivery<S: NamespaceStore>(
    ctx: &TimerCtx<'_, S>,
    delivered_through: u64,
) -> Result<Batch, StoreError> {
    let start = keys::timer(ctx.now_ms.saturating_add(1), 0, b"");
    let (_, end) = keys::class_range(keys::TAG_TIMER);
    let page = ctx
        .store
        .scan(ctx.partition, &start, &end, None, 16)
        .await?;
    let mut batch = Batch::new();
    let mut moved = std::collections::BTreeSet::new();
    for (key, value) in page.entries {
        let Some(keys::ParsedKey::Timer {
            kind, reference, ..
        }) = keys::parse(&key)
        else {
            continue;
        };
        if kind != kinds::VERIFY.get()
            || keys::timer_retry_state(&key).is_none_or(|(_, attempt)| attempt != 0)
        {
            continue;
        }
        let Some((repo, pack)) = parse_reference(&reference) else {
            continue;
        };
        let job_key = keys::verify_job(&repo, &pack);
        let Some(raw) = ctx.store.get(ctx.partition, &job_key).await? else {
            continue;
        };
        let job = decode_job(&raw)?;
        if job.gone
            || job.phase != Phase::AwaitDelivery
            || job.last_relay_seq.is_none_or(|seq| seq > delivered_through)
        {
            continue;
        }
        if !moved.insert(reference.clone()) {
            continue;
        }
        let next = keys::timer(ctx.now_ms, kind, &reference);
        batch = batch
            .require(Precondition::Equals(job_key, raw))
            .require(Precondition::Equals(key.clone(), value.clone()))
            .require(Precondition::Absent(next.clone()))
            .delete(key)
            .put(next, value);
        if moved.len() == 8 {
            break;
        }
    }
    Ok(batch)
}

/// Inspect the already-built checkpoint; observation never adds storage work.
pub(crate) fn committed_progress(
    batch: &Batch,
) -> Option<(
    mkit_core::hash::Hash,
    super::checkpoint::VerifyJobV1,
    Phase,
    bool,
)> {
    batch.writes.iter().find_map(|write| {
        let crate::store::Write::Put(key, value) = write else {
            return None;
        };
        let Some(keys::ParsedKey::VerifyCursor {
            pack_id,
            sub: keys::VC_JOB,
            ..
        }) = keys::parse(key)
        else {
            return None;
        };
        let job = decode_job(value).ok()?;
        let old = batch.preconditions.iter().find_map(|guard| match guard {
            Precondition::Equals(k, raw) if k == key => decode_job(raw).ok().map(|job| job.phase),
            _ => None,
        })?;
        let verified = batch.preconditions.iter().any(|guard| matches!(guard,
            Precondition::Equals(k, raw) if matches!(keys::parse(k), Some(keys::ParsedKey::Verification { pack_id: p, .. }) if p == pack_id)
                && matches!(super::state::decode(raw), Ok(super::state::VerificationV1::Verified { pack_len, .. }) if pack_len == job.pack_len)));
        Some((pack_id, job, old, verified))
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::indexed::checkpoint::{VerifyJobV1, encode_job, timer_reference};
    use crate::store::BatchOutcome;
    use crate::{ManualClock, MemoryKv, NamespaceKey, Partition, RepoName, Value};
    use std::sync::Arc;

    #[test]
    fn nudge_accepts_polls_created_after_the_tick_snapshot() {
        futures_executor::block_on(async {
            let store = MemoryKv::with_clock(Arc::new(ManualClock::new(500)));
            let source = Partition::Namespace(NamespaceKey::deployment_default());
            let repo = RepoName::new("latency").unwrap();
            let pack = [1; 32];
            let mut job = VerifyJobV1::new(pack, 100, 320, 64);
            job.phase = Phase::AwaitDelivery;
            job.last_relay_seq = Some(7);
            let reference = timer_reference(&repo, &pack);
            let poll = keys::timer(2_500, kinds::VERIFY.get(), &reference);
            store
                .apply(
                    &source,
                    Batch::new()
                        .put(keys::verify_job(&repo, &pack), encode_job(&job))
                        .put(poll.clone(), Value::default()),
                )
                .await
                .unwrap();
            let ctx = TimerCtx {
                store: &store,
                partition: &source,
                now_ms: 100,
            };
            let batch = after_delivery(&ctx, 7).await.unwrap();
            assert_eq!(batch.writes.len(), 2);
            assert_eq!(
                store.apply(&source, batch).await.unwrap(),
                BatchOutcome::Committed
            );
            assert!(store.get(&source, &poll).await.unwrap().is_none());
            assert!(
                store
                    .get(&source, &keys::timer(100, kinds::VERIFY.get(), &reference))
                    .await
                    .unwrap()
                    .is_some()
            );
        });
    }

    #[test]
    fn nudge_is_bounded_deduplicated_guarded_and_preserves_failure_backoff() {
        futures_executor::block_on(async {
            let store = MemoryKv::with_clock(Arc::new(ManualClock::new(100)));
            let source = Partition::Namespace(NamespaceKey::deployment_default());
            let repo = RepoName::new("latency").unwrap();
            let mut jobs = Vec::new();
            for n in 1..=10 {
                let pack = [n; 32];
                let mut job = VerifyJobV1::new([n; 32], 100, 320, 64);
                job.phase = Phase::AwaitDelivery;
                job.last_relay_seq = Some(7);
                let reference = timer_reference(&repo, &pack);
                let timer = keys::timer(2_100, kinds::VERIFY.get(), &reference);
                let job_key = keys::verify_job(&repo, &pack);
                assert_eq!(
                    store
                        .apply(
                            &source,
                            Batch::new()
                                .put(job_key.clone(), encode_job(&job))
                                .put(timer.clone(), Value::default())
                        )
                        .await
                        .unwrap(),
                    BatchOutcome::Committed
                );
                jobs.push((job_key, job, timer));
            }
            // A duplicate timer must not add a second destination Put.
            let reference = timer_reference(&repo, &[1; 32]);
            store
                .apply(
                    &source,
                    Batch::new().put(
                        keys::timer(2_099, kinds::VERIFY.get(), &reference),
                        Value::default(),
                    ),
                )
                .await
                .unwrap();
            let ctx = TimerCtx {
                store: &store,
                partition: &source,
                now_ms: 100,
            };
            assert!(after_delivery(&ctx, 6).await.unwrap().writes.is_empty());
            let batch = after_delivery(&ctx, 7).await.unwrap();
            assert_eq!(batch.writes.len(), 16, "eight moves, despite duplicate");
            batch.validate(&store.capabilities()).unwrap();
            // A concurrent checkpoint defeats the whole nudge; recovery timers survive.
            jobs[0].1.generation += 1;
            store
                .apply(
                    &source,
                    Batch::new().put(jobs[0].0.clone(), encode_job(&jobs[0].1)),
                )
                .await
                .unwrap();
            assert!(matches!(
                store.apply(&source, batch).await.unwrap(),
                BatchOutcome::PreconditionFailed { .. }
            ));
            assert!(store.get(&source, &jobs[0].2).await.unwrap().is_some());
            let batch = after_delivery(&ctx, 7).await.unwrap();
            assert_eq!(
                store.apply(&source, batch).await.unwrap(),
                BatchOutcome::Committed
            );
            assert!(
                store
                    .get(&source, &keys::timer(100, kinds::VERIFY.get(), &reference))
                    .await
                    .unwrap()
                    .is_some()
            );
            // A timer already in infrastructure backoff must retain that delay.
            let reference = timer_reference(&repo, &[10; 32]);
            let retry = keys::timer_retry(2_100, kinds::VERIFY.get(), &reference, 1, 1);
            store
                .apply(
                    &source,
                    Batch::new()
                        .delete(jobs[9].2.clone())
                        .put(retry.clone(), Value::default()),
                )
                .await
                .unwrap();
            let batch = after_delivery(&ctx, 7).await.unwrap();
            assert!(
                !batch
                    .writes
                    .iter()
                    .any(|write| matches!(write, crate::store::Write::Delete(k) if k == &retry))
            );
        });
    }
}
