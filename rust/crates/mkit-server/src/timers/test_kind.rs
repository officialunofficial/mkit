//! Ref-deleting test timer; absent from release builds.
use super::{DueTimer, Fired, TimerCtx, TimerHandler, TimerKind, registry::kinds};
use crate::pipeline::{D34Shards, ShardMap};
use crate::repo::RepoId;
use crate::store::{Partition, keys, outbox::OutboxBuilder};
use crate::{Batch, BoxFuture, NamespaceStore, RepoName, StoreError};

/// Deletes the ref named by `<repo> 00 <refname>`.
#[derive(Debug)]
pub struct TestTimer;
impl<S: NamespaceStore> TimerHandler<S> for TestTimer {
    fn kind(&self) -> TimerKind {
        kinds::TEST
    }
    fn fire<'a>(
        &'a self,
        ctx: &'a TimerCtx<'a, S>,
        timer: &'a DueTimer,
    ) -> BoxFuture<'a, Result<Fired, StoreError>> {
        Box::pin(async move {
            let reference = &timer.reference;
            let Some(sep) = reference.iter().position(|&b| b == 0) else {
                return Ok(Fired::Retry);
            };
            let (Ok(repo), Ok(name)) = (
                core::str::from_utf8(&reference[..sep]),
                core::str::from_utf8(&reference[sep + 1..]),
            ) else {
                return Ok(Fired::Retry);
            };
            let Ok(repo) = RepoName::new(repo) else {
                return Ok(Fired::Retry);
            };
            if !crate::refs::validate_ref_name(name) {
                return Ok(Fired::Retry);
            }
            let mut batch = Batch::new().delete(keys::ref_key(&repo, name));
            if let Partition::Ref { ns, .. } = ctx.partition {
                let id = RepoId {
                    namespace: ns.clone(),
                    name: repo.clone(),
                };
                let target = D34Shards.ref_index(&id, name);
                let os = ctx
                    .store
                    .get(ctx.partition, &keys::outbox_sequence())
                    .await?;
                let mut outbox = OutboxBuilder::new(os.as_ref(), None)?;
                outbox.relay_delete(&target, vec![keys::ref_index_key(&repo, name)]);
                outbox.relay_at(ctx.now_ms);
                // Test-only exemption from R-127: this timer is absent from
                // release builds and can fire after the source lease expires.
                outbox.try_finish(&mut batch.preconditions, &mut batch.writes)?;
            }
            Ok(Fired::Done(batch))
        })
    }
}
