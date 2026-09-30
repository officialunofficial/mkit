//! Ref-deleting test timer; absent from release builds.
use super::{DueTimer, Fired, TimerCtx, TimerHandler, TimerKind, registry::kinds};
use crate::pipeline::{D34Shards, ShardMap, SinglePartition, clearance};
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
            let (namespace, shards): (_, &dyn ShardMap) = match ctx.partition {
                Partition::Ref { ns, .. } => (ns.clone(), &D34Shards),
                Partition::Namespace(ns) => (ns.clone(), &SinglePartition),
                _ => return Ok(Fired::Retry),
            };
            let id = RepoId {
                namespace,
                name: repo.clone(),
            };
            let canonical = crate::store::publication::sequence_ref(name);
            let wanted = [
                keys::publication(&repo, &canonical),
                keys::outbox_sequence(),
                keys::outcome_backlog(),
            ];
            let rows = ctx.store.get_many(ctx.partition, &wanted).await?;
            if rows.len() != wanted.len() {
                return Err(StoreError::Corrupt("short test deletion read".into()));
            }
            let mut batch = Batch::new().require(crate::Precondition::NotAfter(
                ctx.now_ms.saturating_add(10_000),
            ));
            let mut outbox = OutboxBuilder::new(rows[1].as_ref(), rows[2].as_ref())?;
            for name in std::iter::once(canonical.clone())
                .chain(mkit_attest::grant::head_packmap(&canonical))
            {
                batch
                    .writes
                    .push(crate::Write::Delete(keys::ref_key(&repo, &name)));
                let target = shards.ref_index(&id, &name);
                if target != *ctx.partition {
                    outbox.relay_delete(&target, vec![keys::ref_index_key(&repo, &name)]);
                }
            }
            crate::store::publication::append(
                &id,
                &canonical,
                ctx.partition,
                shards,
                rows[0].as_ref(),
                clearance::immediate(crate::store::publication::Pair::default(), [0; 32], vec![]),
                true,
                &mut batch.preconditions,
                &mut batch.writes,
                &mut outbox,
            )?;
            outbox.relay_at(ctx.now_ms);
            // Test-only exemption from the source lease: this seam never ships.
            outbox.try_finish(&mut batch.preconditions, &mut batch.writes)?;
            Ok(Fired::Done(batch))
        })
    }
}
