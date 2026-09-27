//! Expired epoch-lease table cleanup, confined to the coordinator partition.

use bytes::Bytes;

use super::{DueTimer, Fired, TimerCtx, TimerHandler, TimerKind, registry::kinds};
use crate::repo::RepoName;
use crate::rt::BoxFuture;
use crate::store::{Batch, NamespaceStore, Partition, Precondition, StoreError, codec, keys};

/// Reference shared by the lease grant's timer and its sweep handler.
#[must_use]
pub fn lease_reference(repo: &RepoName, shard_ref: &str) -> Bytes {
    Bytes::from([repo.as_str().as_bytes(), b"\0", shard_ref.as_bytes()].concat())
}

/// Deletes a coordinator lease-table row only once its actual expiry passes.
#[derive(Debug)]
pub struct LeaseSweep;

impl<S: NamespaceStore> TimerHandler<S> for LeaseSweep {
    fn kind(&self) -> TimerKind {
        kinds::LEASE_SWEEP
    }

    fn fire<'a>(
        &'a self,
        ctx: &'a TimerCtx<'a, S>,
        timer: &'a DueTimer,
    ) -> BoxFuture<'a, Result<Fired, StoreError>> {
        Box::pin(async move {
            if !matches!(ctx.partition, Partition::Coordinator(_)) {
                return Ok(Fired::Retry);
            }
            let Some(sep) = timer.reference.iter().position(|&byte| byte == 0) else {
                return Ok(Fired::Retry);
            };
            let (Ok(repo), Ok(shard_ref)) = (
                core::str::from_utf8(&timer.reference[..sep]),
                core::str::from_utf8(&timer.reference[sep + 1..]),
            ) else {
                return Ok(Fired::Retry);
            };
            let Ok(repo) = RepoName::new(repo) else {
                return Ok(Fired::Retry);
            };
            if !crate::refs::validate_ref_name(shard_ref) {
                return Ok(Fired::Retry);
            }
            let key = keys::leased_shard(&repo, shard_ref);
            let Some(value) = ctx.store.get(ctx.partition, &key).await? else {
                return Ok(Fired::Done(Batch::new()));
            };
            let lease = codec::decode_leased_shard(&value)?;
            let batch = Batch::new().require(Precondition::Equals(key.clone(), value));
            if ctx.now_ms >= lease.expires_at_ms {
                Ok(Fired::Done(batch.delete(key)))
            } else {
                Ok(Fired::Reschedule {
                    due_at_ms: lease.expires_at_ms,
                    value: timer.value.clone(),
                    batch,
                })
            }
        })
    }
}

#[cfg(all(test, feature = "memory"))]
mod tests {
    use super::*;
    use crate::store::{BatchOutcome, Value};
    use crate::timers::{TickBudget, TimerRegistry, run_due};
    use crate::{ManualClock, MemoryKv, NamespaceKey};
    use std::sync::Arc;

    fn partition() -> Partition {
        Partition::Coordinator(NamespaceKey::deployment_default())
    }

    fn repo() -> RepoName {
        RepoName::new("room").expect("valid test repository")
    }

    fn lease_key() -> crate::store::Key {
        keys::leased_shard(&repo(), "refs/heads/main")
    }

    fn timer_key(due: u64) -> crate::store::Key {
        keys::timer(
            due,
            kinds::LEASE_SWEEP.get(),
            &lease_reference(&repo(), "refs/heads/main"),
        )
    }

    fn lease(expires_at_ms: u64) -> codec::LeasedShard {
        codec::LeasedShard {
            epoch: 3,
            expires_at_ms,
            acked_epoch: 2,
        }
    }

    #[tokio::test]
    async fn expiry_deletes_row_and_timer_atomically() {
        let clock = Arc::new(ManualClock::new(100));
        let store = MemoryKv::with_clock(clock.clone());
        store
            .apply(
                &partition(),
                Batch::new()
                    .put(lease_key(), codec::encode_leased_shard(&lease(100)))
                    .put(timer_key(100), Value::default()),
            )
            .await
            .unwrap();
        let registry = TimerRegistry::new().register(LeaseSweep);
        let report = run_due(
            &store,
            &partition(),
            &registry,
            clock.as_ref(),
            100,
            &TickBudget::default(),
        )
        .await
        .unwrap();
        assert_eq!(report.fired, 1);
        assert!(
            store
                .get(&partition(), &lease_key())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .get(&partition(), &timer_key(100))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn renewal_race_prevents_deletion_and_early_timer_moves_to_expiry() {
        let store = MemoryKv::default();
        let old_value = codec::encode_leased_shard(&lease(100));
        store
            .apply(&partition(), Batch::new().put(lease_key(), old_value))
            .await
            .unwrap();
        let timer = DueTimer {
            due_at_ms: 100,
            kind: kinds::LEASE_SWEEP,
            reference: lease_reference(&repo(), "refs/heads/main"),
            value: Value::default(),
        };
        let ctx = TimerCtx {
            store: &store,
            partition: &partition(),
            now_ms: 100,
        };
        let Fired::Done(batch) = LeaseSweep.fire(&ctx, &timer).await.unwrap() else {
            panic!("expired lease must produce a deletion");
        };
        let new_value = codec::encode_leased_shard(&lease(200));
        store
            .apply(
                &partition(),
                Batch::new().put(lease_key(), new_value.clone()),
            )
            .await
            .unwrap();
        assert!(matches!(
            store.apply(&partition(), batch).await.unwrap(),
            BatchOutcome::PreconditionFailed { .. }
        ));
        let Fired::Reschedule { due_at_ms, .. } = LeaseSweep.fire(&ctx, &timer).await.unwrap()
        else {
            panic!("renewed lease must reschedule");
        };
        assert_eq!(due_at_ms, 200);
        assert_eq!(
            store.get(&partition(), &lease_key()).await.unwrap(),
            Some(new_value)
        );
    }
}
