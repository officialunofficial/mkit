//! Bounded raw-Blob lookahead; other objects and deltas are ordering barriers.
use super::{
    ComputeConfig, ComputeDisposition, ComputeJob, ComputeOperation, ComputeOutput, ComputePermits,
    ComputeRequest, CoreStep, Failure, FrameInfo, PackEntry, Phase, Request, Stage, Step,
    VerifyDriver, invalid, resource,
};
use mkit_core::pack::window::{WindowBoundary, WindowCursor};
use std::{borrow::Cow, collections::VecDeque, mem::size_of};

// A Blob has no edges. Only three fixed-record indexes can change: Objects,
// Occurrences and Ordinals. Each has at most 33 levels, 16 records per page,
// records <=179 bytes, and pages <4 KiB. Three complete descents and three
// maximally splitting rewrites, including all authentication/emission passes,
// use <8 MiB even allowing eight passes per fetched page and four per
// emitted page. The remaining 8 MiB covers canonical work and bookkeeping.
// This escrow controls optional admission, never content validity or charging.
const BLOB_WORK_ESCROW: u64 = 16 << 20;
const JOB_OVERHEAD: u64 = 64 << 10;
// Two bounded subtree frontiers plus fixed metadata; this allowance also covers
// the temporary cursor clone when the boundary is materialized for a snapshot.
const BOUNDARY_BYTES: u64 = 8192;

#[derive(Debug)]
pub(super) enum Deferred {
    Entry(PackEntry<'static>, FrameInfo),
    Window(u64, u64),
    Done(u32, u32),
    Failed(Failure),
}

#[derive(Debug)]
struct Slot {
    descriptor: ComputeRequest,
    job: Option<ComputeJob>,
    output: Option<ComputeOutput>,
    merged: bool,
    overlap: u64,
    boundary: WindowBoundary,
}

#[derive(Debug)]
pub(super) struct Scheduler {
    config: ComputeConfig,
    slots: VecDeque<Slot>,
    deferred: Option<Deferred>,
    sealed: bool,
    retired: Option<u64>,
    control_charged: bool,
    committed_boundary: Option<WindowBoundary>,
}

impl VerifyDriver {
    /// Enables caller-owned pure compute execution on a fresh or resumed driver.
    ///
    /// `new` keeps its serial execution path. Raw Blob entries may overlap;
    /// other objects and deltas drain their predecessors before dispatch.
    /// Dispatch, completion, and retention do not authorize publication.
    /// Retire outstanding jobs before replacing a driver's resource envelope.
    /// Checkpoints contain no jobs and resume serially unless enabled again.
    ///
    /// # Examples
    /// ```
    /// use mkit_primitives::{evidence::{PackSource, SourceBinding, RepositoryId},
    ///     limits::{IndexedProfile, VerifyLimits},
    ///     pack_verify::verify::{VerifyDriver, ComputeConfig}};
    /// let source = PackSource { id: [1; 32], len: 128, binding: SourceBinding([2; 32]) };
    /// let profile = IndexedProfile { pack_bytes: 4 << 30, decoded_bytes: 4 << 30, delta_depth: 50 };
    /// let driver = VerifyDriver::new(source, RepositoryId([3; 32]), profile,
    ///     VerifyLimits::indexed(), 1)?.with_compute(ComputeConfig { max_jobs: 3 })?;
    /// # let _ = driver;
    /// # Ok::<(), mkit_primitives::error::Failure>(())
    /// ```
    ///
    /// # Errors
    /// Refuses a repeated configuration, active entry/request/retention, an
    /// ended run, a capacity outside 1..=16, or insufficient control memory.
    pub fn with_compute(mut self, config: ComputeConfig) -> Result<Self, Failure> {
        if self.scheduler.is_some()
            || !matches!(self.phase, Phase::Roots | Phase::Entries)
            || self.work.is_some()
            || self.pending.is_some()
            || self.retained.is_some()
        {
            return Err(invalid());
        }
        if !(1..=16).contains(&config.max_jobs) {
            return Err(resource());
        }
        let capacity = usize::from(config.max_jobs);
        let bytes = size_of::<Scheduler>() + capacity * size_of::<Slot>();
        // The existing decoder reservation already includes 64 KiB of fixed
        // control workspace. Keep this queue, driver and reader inside it;
        // temporarily charge that allowance separately before decoding starts.
        if bytes + size_of::<super::Work>() + size_of::<super::WindowReader>() + size_of::<Self>()
            > 64 << 10
        {
            return Err(resource());
        }
        let control_charged = self.phase == Phase::Roots;
        if control_charged {
            self.resources.reserve(JOB_OVERHEAD)?;
        }
        let mut slots = VecDeque::new();
        slots.try_reserve_exact(capacity).map_err(|_| resource())?;
        self.scheduler = Some(Box::new(Scheduler {
            config,
            slots,
            deferred: None,
            sealed: false,
            retired: None,
            control_charged,
            committed_boundary: None,
        }));
        Ok(self)
    }

    /// Transfers the exact requested job once to a caller-owned worker.
    /// Execute `job.run()` and return its opaque result with `supply_compute`.
    ///
    /// # Errors
    /// Unissued, mismatched, repeated, or terminal requests are `InvalidResponse`.
    /// A refusal preserves all outstanding jobs.
    pub fn take_compute(&mut self, request: ComputeRequest) -> Result<ComputeJob, Failure> {
        if self.phase != Phase::Entries {
            return Err(invalid());
        }
        let scheduler = self.scheduler.as_mut().ok_or_else(invalid)?;
        if !scheduler.sealed {
            return Err(invalid());
        }
        scheduler
            .slots
            .iter_mut()
            .find(|slot| slot.descriptor == request)
            .and_then(|slot| slot.job.take())
            .ok_or_else(invalid)
    }

    /// Records a library-created completion without merging later ordinals early.
    /// Stale generations and retired or duplicate results change no counters.
    ///
    /// # Errors
    /// An unknown current-run identity, input, operation, or permit binding is
    /// `InvalidResponse` and preserves outstanding work.
    pub fn supply_compute(&mut self, output: ComputeOutput) -> Result<ComputeDisposition, Failure> {
        let descriptor = output.descriptor;
        if descriptor.request.generation != self.generation
            || matches!(self.phase, Phase::Failed | Phase::Complete | Phase::Drain)
        {
            return Ok(ComputeDisposition::Stale);
        }
        let scheduler = self.scheduler.as_mut().ok_or_else(invalid)?;
        let Some(slot) = scheduler
            .slots
            .iter_mut()
            .find(|slot| slot.descriptor == descriptor)
        else {
            if scheduler
                .retired
                .is_some_and(|sequence| descriptor.request.sequence <= sequence)
            {
                return Ok(ComputeDisposition::Stale);
            }
            return Err(invalid());
        };
        if slot.job.is_some() {
            return Err(invalid());
        }
        if slot.merged || slot.output.is_some() {
            return Ok(ComputeDisposition::Stale);
        }
        slot.output = Some(output);
        Ok(ComputeDisposition::Accepted)
    }

    // Outstanding caller-owned jobs remain provisional and become stale.
    // Their reservations stay charged until the driver is dropped: a worker
    // may still own its input even after an earlier entry has failed.
    pub(super) fn discard_compute(&mut self) {
        if let Some(scheduler) = &mut self.scheduler {
            scheduler.deferred = None;
            scheduler.sealed = true;
        }
    }

    pub(super) fn loan_compute_control(&mut self) -> Result<(), Failure> {
        if let Some(scheduler) = &mut self.scheduler
            && scheduler.control_charged
        {
            self.resources.release(JOB_OVERHEAD)?;
            scheduler.control_charged = false;
        }
        Ok(())
    }

    pub(super) fn reclaim_compute_control(&mut self) -> Result<(), Failure> {
        if let Some(scheduler) = &mut self.scheduler {
            if scheduler.committed_boundary.take().is_some() {
                self.resources.release(BOUNDARY_BYTES)?;
            }
            if !scheduler.control_charged {
                self.resources.reserve(JOB_OVERHEAD)?;
                scheduler.control_charged = true;
            }
        }
        Ok(())
    }

    pub(super) fn compute_request(&self) -> Option<Step<'static>> {
        let scheduler = self.scheduler.as_ref()?;
        if !scheduler.sealed {
            return None;
        }
        scheduler
            .slots
            .iter()
            .find(|slot| slot.job.is_some())
            .map(|slot| {
                Step::Request(Request::Compute {
                    job: slot.descriptor,
                })
            })
    }

    pub(super) fn compute_checkpointable(&self) -> bool {
        self.phase == Phase::Drain
            || self.scheduler.as_ref().is_none_or(|scheduler| {
                scheduler.committed_boundary.is_some()
                    || (scheduler.slots.is_empty() && scheduler.deferred.is_none())
            })
    }

    pub(super) fn checkpoint_cursor_work(&self) -> u64 {
        let Some(reader) = &self.reader else {
            return 0;
        };
        if self.phase != Phase::Drain
            && let Some(boundary) = self
                .scheduler
                .as_ref()
                .and_then(|s| s.committed_boundary.as_ref())
        {
            return reader.exact_checkpoint_work_at(boundary);
        }
        reader.exact_checkpoint_work()
    }

    pub(super) fn checkpoint_cursor(&self) -> Option<WindowCursor> {
        let reader = self.reader.as_ref()?;
        if self.phase != Phase::Drain
            && let Some(boundary) = self
                .scheduler
                .as_ref()
                .and_then(|s| s.committed_boundary.as_ref())
        {
            return reader.checkpoint_exact_at(boundary);
        }
        reader.checkpoint_exact()
    }

    fn read_scheduled(&mut self) -> Result<Deferred, Failure> {
        Ok(match self.read_entry_step() {
            Ok(CoreStep::Entry(entry)) => Deferred::Entry(
                entry,
                self.reader
                    .as_ref()
                    .and_then(super::WindowReader::last_frame)
                    .ok_or_else(invalid)?,
            ),
            Ok(CoreStep::NeedWindow(range)) => Deferred::Window(range.offset, range.len),
            Ok(CoreStep::Done(summary)) => Deferred::Done(summary.version, summary.entry_count),
            Err(error) => Deferred::Failed(error),
            _ => return Err(invalid()),
        })
    }

    // Protect the entire predecessor commit path. Timing cannot turn optional
    // overlap into a resource refusal. No acquisition occurs during lookahead;
    // WindowReader's current input/decoder workspace is already charged.
    fn can_look_ahead(&self) -> bool {
        let Some(scheduler) = &self.scheduler else {
            return false;
        };
        let count = scheduler.slots.len() as u64 + 1;
        let usage = self.resources.usage();
        // Optional overlap keeps a complete decoder envelope available. The
        // serial reader may use its smaller frame-sensitive reservation, but
        // batching does not depend on that optimization for admission.
        let decoder = self
            .limits
            .acquisition_bytes
            .saturating_mul(2)
            .saturating_add(super::FRAME_BYTES)
            .saturating_add(super::DELTA_BYTES + 32)
            .saturating_add(super::CANONICAL_BYTES)
            .saturating_add(super::DECODER_SCRATCH)
            .saturating_add(JOB_OVERHEAD);
        let resident = usage
            .resident_bytes
            .saturating_add(decoder.saturating_sub(self.decoder_reservation));
        let headroom = self
            .limits
            .page_bytes
            .saturating_mul(4)
            .saturating_add(256 << 10);
        scheduler.config.max_jobs > 1
            && count <= u64::from(scheduler.config.max_jobs)
            && count.saturating_mul(BLOB_WORK_ESCROW) <= self.resources.remaining_work()
            && resident
                .saturating_add(headroom)
                .saturating_add(JOB_OVERHEAD)
                .saturating_add(BOUNDARY_BYTES)
                <= self.limits.resident_bytes
    }

    fn queue_job(
        &mut self,
        entry: PackEntry<'static>,
        info: FrameInfo,
        ordinal: u64,
        base: Option<super::Hash>,
        base_bytes: Option<Vec<u8>>,
        overlap: u64,
        work: u64,
    ) -> Result<(), Failure> {
        let scheduler = self.scheduler.as_mut().ok_or_else(invalid)?;
        if scheduler.slots.is_empty() && scheduler.committed_boundary.take().is_some() {
            self.resources.release(BOUNDARY_BYTES)?;
        }
        self.resources.reserve(BOUNDARY_BYTES)?;
        let boundary = self
            .reader
            .as_ref()
            .and_then(super::WindowReader::checkpoint_boundary)
            .ok_or_else(invalid)?;
        let descriptor = ComputeRequest {
            request: self.request_id()?,
            source: self.source,
            repository: self.repository,
            ordinal,
            info,
            base,
            operation: ComputeOperation::VerifyEntry,
            permits: ComputePermits {
                resident_bytes: if overlap == 0 {
                    self.decoder_reservation
                        .saturating_add(base_bytes.as_ref().map_or(0, |b| b.len() as u64))
                } else {
                    overlap
                },
                work,
            },
        };
        let job = ComputeJob::new(descriptor, entry, base, base_bytes);
        self.scheduler
            .as_mut()
            .ok_or_else(invalid)?
            .slots
            .push_back(Slot {
                descriptor,
                job: Some(job),
                output: None,
                merged: false,
                overlap,
                boundary,
            });
        Ok(())
    }

    pub(super) fn advance_scheduled(&mut self) -> Result<Step<'static>, Failure> {
        let scheduler = self.scheduler.as_ref().ok_or_else(invalid)?;
        if scheduler.sealed && !scheduler.slots.is_empty() {
            let slot = scheduler.slots.front().ok_or_else(invalid)?;
            let info = slot.descriptor.info;
            if slot.descriptor.ordinal != self.ordinal {
                return Err(invalid());
            }
            return self.start_entry(
                PackEntry::Raw {
                    bytes: Cow::Owned(Vec::new()),
                },
                info,
            );
        }
        if let Some(deferred) = self.scheduler.as_mut().ok_or_else(invalid)?.deferred.take() {
            return self.apply_deferred(deferred);
        }
        let batch = self.can_look_ahead();
        let nonempty = !self
            .scheduler
            .as_ref()
            .ok_or_else(invalid)?
            .slots
            .is_empty();
        if nonempty
            && (!batch
                || !self
                    .reader
                    .as_ref()
                    .ok_or_else(invalid)?
                    .next_entry_fits_window())
        {
            self.scheduler.as_mut().ok_or_else(invalid)?.sealed = true;
            return Ok(Step::Progress);
        }
        let next = self.read_scheduled()?;
        if batch && let Deferred::Entry(PackEntry::Raw { ref bytes }, _) = next {
            // Checking the discriminant is admission only. Core still
            // validates every prologue/length/canonicality rule in the job.
            if bytes.first() == Some(&(super::ObjectType::Blob as u8))
                && bytes.len() as u64 <= super::CANONICAL_BYTES
            {
                let overlap = (bytes.len() as u64)
                    .saturating_mul(8)
                    .saturating_add(JOB_OVERHEAD);
                let usage = self.resources.usage();
                let headroom = self
                    .limits
                    .page_bytes
                    .saturating_mul(4)
                    .saturating_add(256 << 10);
                if usage
                    .resident_bytes
                    .saturating_add(overlap)
                    .saturating_add(BOUNDARY_BYTES)
                    .saturating_add(headroom)
                    <= self.limits.resident_bytes
                {
                    let ordinal = self.ordinal
                        + self.scheduler.as_ref().ok_or_else(invalid)?.slots.len() as u64;
                    let Deferred::Entry(entry, info) = next else {
                        return Err(invalid());
                    };
                    self.resources.reserve(overlap)?;
                    self.queue_job(entry, info, ordinal, None, None, overlap, BLOB_WORK_ESCROW)?;
                    return Ok(Step::Progress);
                }
            }
        }
        if nonempty {
            let scheduler = self.scheduler.as_mut().ok_or_else(invalid)?;
            scheduler.deferred = Some(next);
            scheduler.sealed = true;
            Ok(Step::Progress)
        } else {
            self.apply_deferred(next)
        }
    }

    fn apply_deferred(&mut self, deferred: Deferred) -> Result<Step<'static>, Failure> {
        match deferred {
            Deferred::Entry(entry, info) => self.start_entry(entry, info),
            Deferred::Window(offset, len) => self.request_input(offset, len),
            Deferred::Done(version, count) => self.entries_done(version, count),
            Deferred::Failed(error) => Err(error),
        }
    }

    pub(super) fn dispatch_entry(&mut self) -> Result<Step<'static>, Failure> {
        let work = self.work.as_mut().ok_or_else(invalid)?;
        let ordinal = work.ordinal;
        let queued = self
            .scheduler
            .as_ref()
            .and_then(|s| s.slots.front())
            .is_some_and(|slot| slot.descriptor.ordinal == ordinal);
        if queued {
            work.entry = None;
            work.stage = Stage::Compute;
            // Its reservation remains live through evidence commit. A future
            // barrier frame may still occupy the reader's own frame workspace.
        } else {
            let entry = work.entry.take().ok_or_else(invalid)?;
            let info = work.info;
            let base = work.base;
            let base_bytes = work.base_bytes.take();
            work.stage = Stage::Compute;
            self.queue_job(
                entry,
                info,
                ordinal,
                base,
                base_bytes,
                0,
                super::CANONICAL_BYTES,
            )?;
            self.scheduler.as_mut().ok_or_else(invalid)?.sealed = true;
        }
        Ok(Step::Progress)
    }

    pub(super) fn finish_compute(&mut self) -> Result<Step<'static>, Failure> {
        let slot = self
            .scheduler
            .as_mut()
            .and_then(|s| s.slots.front_mut())
            .ok_or_else(invalid)?;
        let Some(output) = slot.output.take() else {
            return Ok(Step::Progress);
        };
        slot.merged = true;
        let decoded = output.outcome?;
        let base_len = std::mem::take(&mut self.work.as_mut().ok_or_else(invalid)?.base_len);
        self.resources.release(base_len)?;
        self.finish_canonical(
            decoded.id,
            decoded.bytes,
            decoded.object,
            Some(decoded.signature),
        )
    }

    pub(super) fn retire_compute(&mut self) -> Result<(), Failure> {
        let Some(scheduler) = &mut self.scheduler else {
            return Ok(());
        };
        let slot = scheduler.slots.pop_front().ok_or_else(invalid)?;
        if !slot.merged {
            return Err(invalid());
        }
        self.resources.release(slot.overlap)?;
        if scheduler
            .committed_boundary
            .replace(slot.boundary)
            .is_some()
        {
            self.resources.release(BOUNDARY_BYTES)?;
        }
        scheduler.retired = Some(slot.descriptor.request.sequence);
        if scheduler.slots.is_empty() {
            scheduler.sealed = false;
        }
        Ok(())
    }
}
