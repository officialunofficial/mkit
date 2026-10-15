//! Consecutive slices with durable checkpoints and one shared call allowance.

use super::{
    Batch, BatchOutcome, BlobStore, DueTimer, ENTRY_RESERVE, Fired, Kind, NamespaceStore,
    PackWindows, Precondition, Run, SliceExtension, StoreError, keys, now_ms,
};

use super::checkpoint::{TINY_ENTRIES, TINY_PACK_BYTES, TINY_PACKLIST_BYTES, VerifyJobV1};

const MAX_SLICES: u32 = 8;
const MAX_ELAPSED_MS: u64 = 2_000;
const NEXT_SLICE_CALLS: u32 = 2 * ENTRY_RESERVE;

impl<S, R, B, W, X> Run<'_, S, R, B, W, X>
where
    S: NamespaceStore,
    R: NamespaceStore,
    B: BlobStore,
    W: PackWindows,
    X: SliceExtension,
{
    fn elapsed_cutoff(&self, started: u64) -> bool {
        let now = self.h.clock.now_ms();
        u64::try_from(now).unwrap_or(0).saturating_sub(started) >= MAX_ELAPSED_MS
            || self
                .continuation_deadline_ms
                .is_some_and(|deadline| now >= deadline)
    }

    // Selection callbacks reuse the tiny-pack driver's timer fencing and
    // checkpoint protocol. Their independent ceiling cannot increase the
    // original tiny-pack ceiling, and neither path refreshes the call budget.
    pub(super) async fn tiny_slices(&self, timer: &DueTimer) -> Result<Fired, StoreError> {
        let started = now_ms(self.h.clock.as_ref());
        let tiny_ceiling = self.h.limits.tiny_chain_slices.clamp(1, MAX_SLICES);
        let selection_ceiling = self.h.limits.extract_chain_slices.clamp(1, MAX_SLICES);
        let ceiling = tiny_ceiling.max(selection_ceiling);
        let key = keys::timer(timer.due_at_ms, timer.kind.get(), &timer.reference);
        let mut selection_only = false;
        for slice in 1..=ceiling {
            let mut local_closure = false;
            let mut local_selection = false;
            // Later durable boundaries refresh phase time while retaining the
            // same call allowance and physical deadline.
            let resumed = (slice > 1).then(|| Run {
                repo: self.repo.clone(),
                now: now_ms(self.h.clock.as_ref()).max(self.now),
                ..*self
            });
            let run = resumed.as_ref().unwrap_or(self);
            let fired = run
                .slice(
                    timer,
                    &mut local_closure,
                    &mut local_selection,
                    selection_only,
                )
                .await?;
            if slice == ceiling {
                return Ok(fired);
            }
            let Fired::Reschedule {
                due_at_ms, batch, ..
            } = &fired
            else {
                return Ok(fired);
            };
            let Some((_, job, _, _)) = super::super::wake::committed_progress(batch) else {
                return Ok(fired);
            };
            let required_calls = if job.phase == super::Phase::ClosureResolve && !local_closure {
                self.closure_lookup_reserve().max(NEXT_SLICE_CALLS)
            } else {
                NEXT_SLICE_CALLS
            };
            let now = now_ms(self.h.clock.as_ref()).max(self.now);
            let selection = local_selection
                && !job.tiny()
                && job.phase == super::Phase::Extract
                && job
                    .extraction
                    .as_ref()
                    .is_some_and(|x| super::extraction::chains(x.stage))
                && slice < selection_ceiling;
            let tiny = slice < tiny_ceiling && tiny_continuation(&job, &self.pack);
            if (!selection && !tiny)
                || job.usable()
                || *due_at_ms > now.saturating_add(1)
                || self.budget.remaining() < required_calls
                || self.elapsed_cutoff(started)
            {
                return Ok(fired);
            }
            selection_only = selection && !tiny;
            // Infrastructure retry keys retain an earlier logical due time.
            // Only the original timer row can fence intermediate checkpoints.
            if self.local.get(self.source, &key).await?.as_ref() != Some(&timer.value) {
                return Ok(fired);
            }
            if self.elapsed_cutoff(started) {
                return Ok(fired);
            }
            let put_due = crate::timers::earliest_timer_put(batch);
            let progress = super::super::wake::committed_progress(batch);
            let Fired::Reschedule { batch, .. } = fired else {
                unreachable!();
            };
            let batch = batch.require(Precondition::Equals(key.clone(), timer.value.clone()));
            // Keep the original timer until the final slice. A crash or lost
            // apply reply resumes the latest job under that durable timer.
            match self.local.apply(self.source, batch).await? {
                BatchOutcome::Committed => {
                    if let Some(progress) = progress {
                        crate::timers::observe_checkpoint(
                            progress,
                            put_due,
                            self.source,
                            self.h.clock.as_ref(),
                            self.h.metrics.as_ref(),
                            self.now,
                        );
                    }
                }
                BatchOutcome::PreconditionFailed { .. } | BatchOutcome::DeadlinePassed { .. } => {
                    return Ok(Fired::Retry);
                }
            }
            // The checkpoint itself can cross the elapsed cutoff during I/O.
            // Move the retained timer without starting another slice then.
            if self.elapsed_cutoff(started) {
                return Ok(self.reschedule(timer, 0, Batch::new()));
            }
        }
        unreachable!()
    }
}

fn tiny_continuation(job: &VerifyJobV1, pack: &super::Hash) -> bool {
    job.tiny()
        && !job.extract_needed
        && job.owed <= TINY_ENTRIES
        && job.extraction_group.len() <= 2
        && job
            .extraction_group
            .iter()
            .all(|member| member.bytes <= TINY_PACK_BYTES)
        && (job.kind == Kind::Packlist
            || job
                .extraction_group
                .iter()
                .all(|member| member.pack == *pack || member.bytes <= TINY_PACKLIST_BYTES))
}
