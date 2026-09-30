//! One guarded legacy publication backfill page per alarm.
use crate::RepoName;
use crate::rt::BoxFuture;
use crate::store::{Key, NamespaceStore, StoreError, migration};
use crate::timers::{DueTimer, Fired, TimerCtx, TimerHandler, TimerKind, registry::kinds};

/// Initialization is separate from blocked-advance dependency rechecks.
#[derive(Debug, Default)]
pub struct PublicationMigration;
impl<S: NamespaceStore> TimerHandler<S> for PublicationMigration {
    fn kind(&self) -> TimerKind {
        kinds::PUBLICATION_MIGRATION
    }
    fn max_per_tick(&self) -> Option<u32> {
        Some(1)
    }
    fn fire<'a>(
        &'a self,
        ctx: &'a TimerCtx<'a, S>,
        timer: &'a DueTimer,
    ) -> BoxFuture<'a, Result<Fired, StoreError>> {
        Box::pin(async move {
            let reference = timer
                .reference
                .strip_prefix(b"pv\0")
                .and_then(|name| std::str::from_utf8(name).ok())
                .ok_or_else(|| StoreError::Corrupt("invalid publication migration timer".into()))?;
            let repo = RepoName::new(reference)
                .map_err(|_| StoreError::Corrupt("invalid migration repository".into()))?;
            let key = Key::new(timer.reference.clone());
            if key != migration::key(&repo) {
                return Err(StoreError::Corrupt("invalid migration timer key".into()));
            }
            let raw =
                ctx.store.get(ctx.partition, &key).await?.ok_or_else(|| {
                    StoreError::Corrupt("missing durable migration progress".into())
                })?;
            let (batch, done) =
                migration::page(ctx.store, ctx.partition, &repo, &raw, ctx.now_ms).await?;
            if done {
                Ok(Fired::Done(batch))
            } else {
                Ok(Fired::Reschedule {
                    due_at_ms: ctx.now_ms.saturating_add(1),
                    value: timer.value.clone(),
                    batch,
                })
            }
        })
    }
}
