//! Bounded consumed-set selection and two-pass extraction. Only the current
//! eight-MiB part is spooled locally; CVs, offsets and receipts are small rows.
use super::super::checkpoint::{ExtractionSource, ExtractionV1};
use super::super::selection::Projection;
use super::{
    Batch, BatchOutcome, BlobStore, Cursor, FrameRow, Hash, Key, NamespaceStore, Object, Outcome,
    PackWindows, Partition, Phase, Precondition, Run, SliceExtension, SliceState, Stop, StoreError,
    Value, VerificationV1, VerifyJobV1, Write, checkpoint, codec, decode_frame, hash, keys, now_ms,
    relay_delivered_through, renew_for_relay, resolve, state, unavailable,
};
use crate::store::{
    BlobKey, BorrowedStore, ContentIndex, HoldOutcome, Holder, PackSink, PartRef, PendingHolderV1,
    content_shard,
};
use bytes::Bytes;
use mkit_core::object::ObjectType;
use mkit_core::upload_parts::{MIN_PART_SIZE, PartPlan, merge_to_root, part_subtree_cv};

mod member;

const FRAGMENT: u64 = 128 << 10;
const PART: u64 = MIN_PART_SIZE;
const SCAN: u8 = 0;
const SELECT: u8 = 1;
const CHOOSE: u8 = 2;
const PREFLIGHT: u8 = 3;
const START: u8 = 4;
const UPLOAD: u8 = 5;
const COMPLETE: u8 = 6;
const OFFSETS: u8 = 7;
const ENQUEUE: u8 = 8;
const DELIVERY: u8 = 9;
const CLOSURE: u8 = 10;
const DEPENDENCIES: u8 = 11;
const MEMBERS: u8 = 12;
const HEAD: u8 = 13;

fn unfrozen(x: &ExtractionV1) -> bool {
    matches!(
        x.stage,
        SCAN | SELECT | CLOSURE | DEPENDENCIES | MEMBERS | HEAD
    )
}

fn corrupt() -> Stop {
    Stop::Store(StoreError::Corrupt("bad extraction checkpoint".into()))
}
fn check(valid: bool) -> Result<(), Stop> {
    valid.then_some(()).ok_or_else(corrupt)
}
fn number(value: &Value) -> Result<u64, Stop> {
    Ok(codec::decode_u64(value)?)
}
fn n32(value: u64) -> Result<u32, Stop> {
    u32::try_from(value).map_err(|_| corrupt())
}
fn size(value: u64) -> Result<usize, Stop> {
    usize::try_from(value).map_err(|_| corrupt())
}
fn hash_row(label: &[u8], group: &Hash, object: &Hash, index: u32) -> Hash {
    let mut h = mkit_core::hash::Hasher::new();
    h.update(b"mkit-extraction-row:v1");
    h.update(label);
    h.update(group);
    h.update(object);
    h.update(&index.to_be_bytes());
    h.finalize()
}
fn plan(length: u64) -> Result<PartPlan, Stop> {
    PartPlan::new(length, PART, 10_000).map_err(|_| Stop::Outcome(Outcome::DecodeBudget))
}

fn advance_member(x: &mut ExtractionV1, next: Option<Cursor>) {
    if let Some(next) = next {
        x.scan = next.into_bytes().to_vec();
    } else {
        x.member += 1;
        x.scan.clear();
    }
}

impl<S: NamespaceStore, R: NamespaceStore, B: BlobStore, W: PackWindows, X: SliceExtension>
    Run<'_, S, R, B, W, X>
{
    async fn get(&self, key: &Key) -> Result<Option<Value>, Stop> {
        Ok(self.local.get(self.source, key).await?)
    }
    async fn has(&self, key: &Key) -> Result<bool, Stop> {
        Ok(self.local.has(self.source, key).await?)
    }
    async fn require(&self, key: &Key) -> Result<Value, Stop> {
        self.get(key).await?.ok_or_else(corrupt)
    }
    fn source_row(&self, pack: &Hash, kind: u8, object: &Hash) -> Key {
        keys::verify_row(&self.repo.name, pack, kind, Some(object))
    }
    fn aux(&self, x: &ExtractionV1, label: &[u8], object: &Hash, index: u32) -> Key {
        self.row(
            keys::VC_CANDIDATE,
            &hash_row(label, &x.group, object, index),
        )
    }
    fn shared(&self, x: &ExtractionV1) -> Result<Key, Stop> {
        let first = x.sources.first().ok_or_else(corrupt)?;
        Ok(self.source_row(
            &first.member.pack,
            keys::VC_CANDIDATE,
            &hash_row(b"charged", &x.group, &[0; 32], 0),
        ))
    }
    async fn put_aux(&self, st: &SliceState, key: Key, value: Value) -> Result<(), Stop> {
        self.auxiliary(st, vec![Write::Put(key, value)]).await
    }
    /// Auxiliary writes are deterministic, guarded by this exact job. A crash
    /// before the final cursor replays them; it cannot advance an accounting row.
    async fn auxiliary(&self, st: &SliceState, writes: Vec<Write>) -> Result<(), Stop> {
        let preconditions = vec![
            Precondition::Equals(self.job_key(), st.job_guard.clone().ok_or_else(corrupt)?),
            Precondition::NotAfter(self.deadline()),
        ];
        let mut batches = Vec::new();
        let mut batch = Batch {
            preconditions: preconditions.clone(),
            writes: Vec::new(),
        };
        for write in writes {
            let mut candidate = batch.clone();
            candidate.writes.push(write.clone());
            if candidate.validate(&self.local.capabilities()).is_err() {
                if batch.writes.is_empty() {
                    candidate.validate(&self.local.capabilities())?;
                }
                batches.push(batch);
                batch = Batch {
                    preconditions: preconditions.clone(),
                    writes: vec![write],
                };
                batch.validate(&self.local.capabilities())?;
            } else {
                batch = candidate;
            }
        }
        if !batch.writes.is_empty() {
            batches.push(batch);
        }
        for batch in batches {
            if !matches!(
                self.local.apply(self.source, batch).await?,
                BatchOutcome::Committed
            ) {
                return Err(unavailable("extraction cursor changed"));
            }
        }
        Ok(())
    }
    async fn capture_sources(&self, job: &VerifyJobV1) -> Result<ExtractionV1, Stop> {
        if job.extraction_group.is_empty() {
            return Err(Stop::Outcome(Outcome::ExtractionUnavailable));
        }
        let mut x = ExtractionV1::default();
        for member in &job.extraction_group {
            let key = keys::verify_job(&self.repo.name, &member.pack);
            let raw = self.get(&key).await?.ok_or(Stop::Wait(1_000))?;
            let source = checkpoint::decode_job(&raw)?;
            if source.gone || source.bad_signature {
                return Err(Stop::Wait(1_000));
            }
            if source.outcome.is_some() && !source.closure_retry() {
                return Err(Stop::Outcome(source.outcome.ok_or_else(corrupt)?));
            }
            if matches!(
                source.phase,
                Phase::Decode | Phase::ClosureResolve | Phase::EmitIndex | Phase::AwaitDelivery
            ) {
                return Err(Stop::Wait(1_000));
            }
            if source.pack_len != member.bytes
                || (!member.already_verified && source.ticket_id != member.ticket)
            {
                return Err(unavailable("extraction group source replaced"));
            }
            x.sources.push(ExtractionSource {
                member: member.clone(),
                etag: source.etag,
                version: source.version,
                entries: source.entries,
                decoded: source.in_pack_bytes,
                member_body_id: source.member_body_id,
            });
        }
        let mut identity = x.sources.clone();
        for source in &mut identity {
            source.member_body_id = None;
        }
        x.group = hash(&serde_json::to_vec(&identity).map_err(|_| corrupt())?);
        Ok(x)
    }
    /// Exact source headers guard checkpoints, selection freeze and charges.
    async fn source_guards(&self, x: &ExtractionV1, st: &mut SliceState) -> Result<bool, Stop> {
        for source in &x.sources {
            let key = keys::verify_job(&self.repo.name, &source.member.pack);
            let raw = self
                .get(&key)
                .await?
                .ok_or_else(|| unavailable("extraction source disappeared"))?;
            let current = checkpoint::decode_job(&raw)?;
            if current.gone {
                return Err(unavailable("frozen extraction source disappeared"));
            }
            // A recheck may add a satisfying member. Before freeze, restart
            // against its new immutable body; afterward the validated body
            // and frame facts remain pinned by this extraction group.
            if unfrozen(x) && current.member_body_id != source.member_body_id {
                return Ok(false);
            }
            let state_key = keys::verification(&self.repo.name, &source.member.pack);
            let state_raw = self.get(&state_key).await?;
            let verification = state_raw.as_ref().map(state::decode).transpose()?;
            if current.bad_signature
                || matches!(verification, Some(VerificationV1::Rejected { .. }))
            {
                return Err(Stop::Wait(1_000));
            }
            if let Some(outcome) = current.outcome
                && !current.closure_retry()
            {
                return Err(Stop::Outcome(outcome));
            }
            if source.member.pack != self.pack {
                // A canceled first owner cannot satisfy another pack's selected
                // objects. Its own started object may still drain under gp.
                if !source.member.already_verified
                    && !matches!(verification, Some(VerificationV1::Verified { .. }))
                {
                    let ticket = keys::ticket(&source.member.ticket);
                    let raw = self.get(&ticket).await?.ok_or(Stop::Wait(1_000))?;
                    st.guards.push(Precondition::Equals(ticket, raw));
                }
                st.guards.push(match state_raw {
                    Some(raw) => Precondition::Equals(state_key, raw),
                    None => Precondition::Absent(state_key),
                });
            }
            if current.etag != source.etag
                || current.version != source.version
                || current.entries != source.entries
                || current.in_pack_bytes != source.decoded
                || current.pack_len != source.member.bytes
                || (!source.member.already_verified && current.ticket_id != source.member.ticket)
                || matches!(current.phase, Phase::Decode | Phase::ClosureResolve)
            {
                return Err(unavailable("frozen extraction source changed"));
            }
            if key != self.job_key() {
                st.guards.push(Precondition::Equals(key, raw));
            }
        }
        Ok(true)
    }
    async fn next_frame(
        &self,
        x: &ExtractionV1,
        pack: &Hash,
    ) -> Result<Option<(Hash, FrameRow, Option<Cursor>)>, Stop> {
        let (a, b) = keys::verify_range(&self.repo.name, pack, Some(keys::VC_FRAME));
        let cursor = (!x.scan.is_empty()).then(|| Cursor::new(x.scan.clone()));
        let page = self
            .local
            .scan(self.source, &a, &b, cursor.as_ref(), 1)
            .await?;
        let Some((key, raw)) = page.entries.first() else {
            return Ok(None);
        };
        let Some(keys::ParsedKey::VerifyCursor { id: Some(id), .. }) = keys::parse(key) else {
            return Err(corrupt());
        };
        Ok(Some((id, decode_frame(&id, raw)?, page.next)))
    }
    async fn projection(
        &self,
        source: &ExtractionSource,
        id: Hash,
        frame: &FrameRow,
        marking: Option<(&SliceState, &ExtractionV1)>,
    ) -> Result<Projection, Stop> {
        let key = self.source_row(&source.member.pack, keys::VC_CANDIDATE, &id);
        let raw = self.require(&key).await?;
        let p = Projection::decode(&id, &raw)?;
        p.validate_frame(frame, source.member.bytes, source.decoded)?;
        let mut digest = Projection::reference_hasher(&id, p.kind);
        for start in (0..p.pages()).step_by(8) {
            let end = (start + 8).min(p.pages());
            let keys: Vec<_> = (start..end)
                .map(|i| self.source_row(&source.member.pack, keys::VC_CANDIDATE, &p.page_id(i)))
                .collect();
            let values = self.local.get_many(self.source, &keys).await?;
            check(values.len() == keys.len())?;
            for (i, raw) in (start..end).zip(values) {
                let mut writes = Vec::new();
                for id in p.decode_page(i, &raw.ok_or_else(corrupt)?)? {
                    digest.update(&id);
                    if let Some((_, x)) = marking {
                        let label = if p.kind == 1 {
                            b"chunk".as_slice()
                        } else {
                            b"file".as_slice()
                        };
                        writes.push(Write::Put(self.aux(x, label, &id, 0), Value::default()));
                    }
                }
                if let Some((st, _)) = marking {
                    self.auxiliary(st, writes).await?;
                }
            }
        }
        check(digest.finalize() == p.digest)?;
        Ok(p)
    }
    async fn scan_group(&self, st: &mut SliceState, x: &mut ExtractionV1) -> Result<(), Stop> {
        if x.member >= x.sources.len() {
            x.member = 0;
            x.scan.clear();
            x.stage = CLOSURE;
            return Ok(());
        }
        let source = x.sources[x.member].clone();
        let Some((id, frame, next)) = self.next_frame(x, &source.member.pack).await? else {
            advance_member(x, None);
            return Ok(());
        };
        self.projection(&source, id, &frame, Some((st, x))).await?;
        let owner = self.aux(x, b"owner", &id, 0);
        let first = self.get(&owner).await?;
        let mut writes = Vec::new();
        if first
            .as_ref()
            .map(number)
            .transpose()?
            .is_none_or(|owner| owner == x.member as u64)
        {
            // Ahead-of-checkpoint owner rows replay this step's count and charge.
            x.staged_objects = x.staged_objects.checked_add(1).ok_or_else(corrupt)?;
            x.staged_bytes = x
                .staged_bytes
                .checked_add(frame.value.decoded_size)
                .ok_or_else(corrupt)?;
            if first.is_none() {
                writes.push(Write::Put(owner, codec::encode_u64(x.member as u64)));
            }
        }
        self.auxiliary(st, writes).await?;
        advance_member(x, next);
        if x.staged_bytes > self.h.cfg.decode_budget {
            return Err(Stop::Outcome(Outcome::DecodeBudget));
        }
        Ok(())
    }
    fn missing_closure(&self, created: u64, outcome: Outcome) -> Stop {
        if resolve::lagged(self.now, created, self.h.cfg.relay_lag_bound_ms) {
            Stop::Wait(1_000)
        } else {
            Stop::Outcome(outcome)
        }
    }
    /// Validate all owed children against the staged union, then recheck the
    /// member packs that satisfied children or delta bases during decode.
    /// Neither this pass nor the union scan performs extraction effects.
    async fn closure_rows(&self, st: &mut SliceState, x: &mut ExtractionV1) -> Result<(), Stop> {
        if x.member == x.sources.len() {
            x.member = 0;
            x.scan.clear();
            x.stage = if x.stage == CLOSURE {
                DEPENDENCIES
            } else {
                MEMBERS
            };
            return Ok(());
        }
        let source = &x.sources[x.member];
        let section = if x.stage == CLOSURE {
            keys::VC_CHILD
        } else {
            keys::VC_DEPENDENCY
        };
        let (start, end) = keys::verify_range(&self.repo.name, &source.member.pack, Some(section));
        let cursor = (!x.scan.is_empty()).then(|| Cursor::new(x.scan.clone()));
        let page = self
            .local
            .scan(self.source, &start, &end, cursor.as_ref(), 1)
            .await?;
        if let Some((key, _)) = page.entries.first() {
            let Some(keys::ParsedKey::VerifyCursor { id: Some(id), .. }) = keys::parse(key) else {
                return Err(corrupt());
            };
            let missing = if x.stage == DEPENDENCIES {
                let found = crate::store::read::members_many(
                    self.remote,
                    self.h.shards.as_ref(),
                    &self.repo,
                    self.source,
                    &[id],
                )
                .await?;
                check(found.len() == 1)?;
                !found[0]
            } else if self
                .local
                .has(self.source, &self.aux(x, b"owner", &id, 0))
                .await?
            {
                false
            } else {
                let found =
                    self.member_lookup(st, x, (id, id), None, 0)
                        .await
                        .map_err(|e| match e {
                            Stop::Outcome(Outcome::BaseCapped) => {
                                Stop::Outcome(Outcome::ClosureCapped)
                            }
                            other => other,
                        })?;
                let Some(found) = found else {
                    return Ok(());
                };
                found.is_none()
            };
            if missing {
                return Err(self.missing_closure(
                    source.member.created_at_ms,
                    if x.stage == CLOSURE {
                        Outcome::ClosureMissing
                    } else {
                        // The owner's lag elapsed: this existing outcome is
                        // permanent regardless of the extracting ticket's age.
                        Outcome::BaseCapped
                    },
                ));
            }
        }
        advance_member(x, page.next);
        Ok(())
    }
    async fn closure_members(&self, x: &mut ExtractionV1) -> Result<(), Stop> {
        if x.member == x.sources.len() {
            x.member = 0;
            x.chunk = 0;
            x.stage = HEAD;
            return Ok(());
        }
        let source = &x.sources[x.member];
        let raw = self
            .get(&keys::verify_job(&self.repo.name, &source.member.pack))
            .await?
            .ok_or_else(corrupt)?;
        let mut job = checkpoint::decode_job(&raw)?;
        if job.gone || job.member_body_id != source.member_body_id {
            return Err(Stop::Wait(1_000));
        }
        checkpoint::hydrate_job(
            self.local,
            self.source,
            &self.repo.name,
            &source.member.pack,
            &mut job,
        )
        .await?;
        let at = x.chunk as usize;
        if at == job.satisfying.len() + job.packlist.len() {
            x.member += 1;
            x.chunk = 0;
            return Ok(());
        }
        let (pack, listing) = if at < job.satisfying.len() {
            (job.satisfying[at], false)
        } else {
            (
                *job.packlist
                    .get(at - job.satisfying.len())
                    .ok_or_else(corrupt)?,
                true,
            )
        };
        if !listing || !x.sources.iter().any(|s| s.member.pack == pack) {
            let found = crate::store::read::members_many(
                self.remote,
                self.h.shards.as_ref(),
                &self.repo,
                self.source,
                &[pack],
            )
            .await?;
            check(found.len() == 1)?;
            if !found[0] {
                return Err(self.missing_closure(
                    source.member.created_at_ms,
                    if listing {
                        Outcome::PacklistMissing
                    } else {
                        Outcome::ClosureMissing
                    },
                ));
            }
        }
        x.chunk = x.chunk.checked_add(1).ok_or_else(corrupt)?;
        Ok(())
    }
    async fn closure_head(
        &self,
        st: &mut SliceState,
        x: &mut ExtractionV1,
        job: &mut VerifyJobV1,
    ) -> Result<(), Stop> {
        let head = job
            .extraction_head
            .ok_or(Stop::Outcome(Outcome::ExtractionUnavailable))?;
        let mut kind = None;
        for source in &x.sources {
            let key = self.source_row(&source.member.pack, keys::VC_FRAME, &head);
            if let Some(raw) = self.get(&key).await? {
                kind = Some(decode_frame(&head, &raw)?.object_type);
                break;
            }
        }
        if kind.is_none() {
            let (object, bytes) = self
                .incremental_member(st, x, head)
                .await?
                .ok_or(Stop::Yield(0))?;
            if x.staged_bytes.saturating_add(bytes) > self.h.cfg.decode_budget {
                return Err(Stop::Outcome(Outcome::DecodeBudget));
            }
            kind = Some(object.object_type() as u8);
        }
        if !kind.is_some_and(|kind| {
            [ObjectType::Commit, ObjectType::Remix, ObjectType::Tag]
                .iter()
                .any(|allowed| kind == *allowed as u8)
        }) {
            return Err(Stop::Outcome(Outcome::OpenClosure));
        }
        job.outcome = None;
        x.stage = SELECT;
        Ok(())
    }
    async fn select_group(&self, st: &mut SliceState, x: &mut ExtractionV1) -> Result<(), Stop> {
        if x.member >= x.sources.len() {
            x.member = 0;
            x.scan.clear();
            x.stage = CHOOSE;
            return Ok(());
        }
        let source = x.sources[x.member].clone();
        let Some((id, frame, next)) = self.next_frame(x, &source.member.pack).await? else {
            advance_member(x, None);
            return Ok(());
        };
        let owner = self
            .get(&self.aux(x, b"owner", &id, 0))
            .await?
            .ok_or_else(corrupt)?;
        if number(&owner)? == x.member as u64 {
            let p = self.projection(&source, id, &frame, None).await?;
            let selected = p.kind == 1
                || (p.kind == 0
                    && p.size >= self.h.cfg.extract_min_bytes
                    && (!self.has(&self.aux(x, b"chunk", &id, 0)).await?
                        || self.has(&self.aux(x, b"file", &id, 0)).await?));
            if selected {
                x.selected_bytes = x.selected_bytes.checked_add(p.size).ok_or_else(corrupt)?;
                if !source.member.already_verified && source.member.pack == self.pack {
                    self.put_aux(
                        st,
                        self.aux(x, b"selected", &id, 0),
                        codec::encode_u64(p.size),
                    )
                    .await?;
                }
            }
        }
        if x.selected_bytes > self.h.cfg.effective_max_extract_bytes() {
            return Err(Stop::Outcome(Outcome::DecodeBudget));
        }
        advance_member(x, next);
        Ok(())
    }
    async fn choose_object(&self, x: &mut ExtractionV1, job: &mut VerifyJobV1) -> Result<(), Stop> {
        let Some((id, _, next)) = self.next_frame(x, &self.pack).await? else {
            job.phase = Phase::Verify;
            return Ok(());
        };
        if let Some(value) = self.get(&self.aux(x, b"selected", &id, 0)).await? {
            x.object = Some(id);
            x.length = number(&value)?;
            x.chunk = 0;
            x.chunk_offset = 0;
            x.written = 0;
            x.cvs = 0;
            x.uploaded = 0;
            x.root = None;
            x.session.clear();
            x.relay = None;
            x.stage = PREFLIGHT;
        }
        // Keep the last examined key even when it was the final frame: after
        // this object, the next scan must not start over.
        x.scan = next.map_or_else(
            || {
                self.source_row(&self.pack, keys::VC_FRAME, &id)
                    .into_bytes()
                    .to_vec()
            },
            |c| c.into_bytes().to_vec(),
        );
        Ok(())
    }
    fn identity(&self, job: &VerifyJobV1, x: &ExtractionV1) -> Result<PendingHolderV1, Stop> {
        let id = x.object.ok_or_else(corrupt)?;
        let hold = super::super::extract::hold_id(&self.repo, &job.ticket_id, &id);
        Ok(PendingHolderV1::new(
            Holder::new(self.repo.namespace.clone(), self.repo.name.clone()),
            self.source.clone(),
            job.ticket_id,
            id,
            hold,
            hash_row(b"operation", &x.group, &id, 0),
        )?)
    }
    async fn extraction_lease(&self) -> Result<Option<Value>, Stop> {
        Ok(if matches!(self.source, Partition::Ref { .. }) {
            Some(
                renew_for_relay(
                    self.local,
                    self.remote,
                    self.h.shards.as_ref(),
                    self.h.clock.as_ref(),
                    self.h.metrics.as_ref(),
                    &self.repo,
                    self.source,
                    &self.h.lease,
                )
                .await
                .map_err(|_| unavailable("extraction lease lost"))?,
            )
        } else {
            None
        })
    }
    async fn protect(&self, job: &VerifyJobV1, x: &ExtractionV1) -> Result<(), Stop> {
        if x.stage != DELIVERY {
            self.extraction_lease().await?;
        }
        let identity = self.identity(job, x)?;
        let index = ContentIndex::new(BorrowedStore(self.remote));
        let now = now_ms(self.h.clock.as_ref());
        let ttl = super::super::extract::hold_ttl_ms(self.h.cfg.relay_lag_bound_ms);
        // gp remains durable across lapsed TTLs and ticket disappearance. Re-adding
        // the ordinary hold is safe under gp and rechecks block/deleting state.
        match index
            .add_hold(
                &identity.object,
                &identity.hold_id,
                now.saturating_add(ttl),
                now,
            )
            .await?
        {
            HoldOutcome::Held => {}
            _ if x.stage == DELIVERY => return Ok(()),
            _ => return Err(Stop::Outcome(Outcome::ObjectBlocked)),
        }
        if x.stage != DELIVERY {
            match index
                .protect_pending_holder(&identity.object, &identity.hold_id, &identity, now)
                .await?
            {
                HoldOutcome::Held => {}
                _ => return Err(Stop::Outcome(Outcome::ObjectBlocked)),
            }
        }
        Ok(())
    }
    async fn selected_projection(
        &self,
        x: &ExtractionV1,
        id: Hash,
    ) -> Result<(Hash, Projection), Stop> {
        let owner = number(&self.require(&self.aux(x, b"owner", &id, 0)).await?)?;
        let pack = x.sources.get(size(owner)?).ok_or_else(corrupt)?.member.pack;
        let key = self.source_row(&pack, keys::VC_CANDIDATE, &id);
        let p = Projection::decode(&id, &self.require(&key).await?)?;
        check(matches!(p.kind, 0 | 1) && p.size == x.length)?;
        Ok((pack, p))
    }

    async fn charge_sources(
        &self,
        st: &mut SliceState,
        x: &ExtractionV1,
        bytes: u64,
    ) -> Result<(), Stop> {
        if bytes == 0 {
            return Ok(());
        }
        let key = self.shared(x)?;
        let raw = self.get(&key).await?;
        let prior = raw.as_ref().map(number).transpose()?.unwrap_or(0);
        let next = prior.checked_add(bytes).ok_or_else(corrupt)?;
        let limit = self
            .h
            .cfg
            .effective_max_extract_bytes()
            .min(self.h.cfg.decode_budget.saturating_sub(x.staged_bytes));
        if next > limit {
            return Err(Stop::Outcome(Outcome::DecodeBudget));
        }
        st.guards.push(match raw {
            Some(raw) => Precondition::Equals(key.clone(), raw),
            None => Precondition::Absent(key.clone()),
        });
        st.settled.push(Write::Put(key, codec::encode_u64(next)));
        Ok(())
    }
    async fn fragment_bytes(
        &self,
        x: &ExtractionV1,
        id: Hash,
        label: &[u8],
        len: u64,
    ) -> Result<Vec<u8>, Stop> {
        check(len <= PART)?;
        let mut bytes = Vec::with_capacity(size(len)?);
        let count = len.div_ceil(FRAGMENT);
        for start in (0..count).step_by(8) {
            let keys = (start..(start + 8).min(count))
                .map(|i| Ok(self.aux(x, label, &id, n32(i)?)))
                .collect::<Result<Vec<_>, Stop>>()?;
            let rows = self.local.get_many(self.source, &keys).await?;
            check(rows.len() == keys.len())?;
            for row in rows {
                let raw = row.ok_or_else(corrupt)?;
                check(raw.as_bytes().len() == size(FRAGMENT.min(len - bytes.len() as u64))?)?;
                bytes.extend_from_slice(raw.as_bytes());
            }
        }
        Ok(bytes)
    }
    async fn append_fragment(
        &self,
        st: &SliceState,
        x: &ExtractionV1,
        id: Hash,
        label: &[u8],
        start: u64,
        data: &[u8],
    ) -> Result<(), Stop> {
        let mut at = start;
        let mut rest = data;
        let mut writes = Vec::new();
        while !rest.is_empty() {
            let slot = n32(at / FRAGMENT)?;
            let offset = (at % FRAGMENT) as usize;
            let key = self.aux(x, label, &id, slot);
            let mut bytes = if offset == 0 {
                Vec::new()
            } else {
                self.require(&key)
                    .await?
                    .as_bytes()
                    .get(..offset)
                    .ok_or_else(corrupt)?
                    .to_vec()
            };
            let take = (size(FRAGMENT)? - offset).min(rest.len());
            bytes.extend_from_slice(&rest[..take]);
            rest = &rest[take..];
            at += take as u64;
            writes.push(Write::Put(key, Value::new(bytes)));
        }
        self.auxiliary(st, writes).await
    }
    async fn bulk(
        &self,
        x: &ExtractionV1,
        id: Hash,
        label: &[u8],
        count: u32,
    ) -> Result<Vec<Value>, Stop> {
        let mut out = Vec::with_capacity(count as usize);
        for start in (0..count).step_by(8) {
            let keys: Vec<_> = (start..(start + 8).min(count))
                .map(|i| self.aux(x, label, &id, i))
                .collect();
            let rows = self.local.get_many(self.source, &keys).await?;
            check(rows.len() == keys.len())?;
            for row in rows {
                let raw = row.ok_or_else(corrupt)?;
                check(raw.as_bytes().len() <= if label == b"receipt" { 1089 } else { 32 })?;
                out.push(raw);
            }
        }
        Ok(out)
    }
    async fn cv_list(&self, x: &ExtractionV1, id: Hash) -> Result<Vec<Hash>, Stop> {
        check(x.cvs == plan(x.length)?.count())?;
        self.bulk(x, id, b"cv", x.cvs)
            .await?
            .into_iter()
            .map(|v| v.as_bytes().try_into().map_err(|_| corrupt()))
            .collect()
    }
    async fn walk_source(
        &self,
        st: &mut SliceState,
        job: &VerifyJobV1,
        x: &mut ExtractionV1,
    ) -> Result<(), Stop> {
        let id = x.object.ok_or_else(corrupt)?;
        self.protect(job, x).await?;
        let (pack, p) = self.selected_projection(x, id).await?;
        let count = if p.kind == 0 { 1 } else { p.references };
        check(x.chunk <= count)?;
        if x.chunk == count {
            if x.written != x.length {
                return Err(Stop::Reject("object hash mismatch"));
            }
            if x.length <= PART {
                let bytes = self.fragment_bytes(x, id, b"payload", x.length).await?;
                x.root = Some(hash(&bytes));
            } else {
                x.root = Some(
                    merge_to_root(&plan(x.length)?, &self.cv_list(x, id).await?)
                        .map_err(|_| corrupt())?,
                );
            }
            x.stage = if x.stage == PREFLIGHT {
                START
            } else {
                COMPLETE
            };
            return Ok(());
        }
        let chunk_id = if p.kind == 0 {
            id
        } else {
            let page = x.chunk / 128;
            let key = self.source_row(&pack, keys::VC_CANDIDATE, &p.page_id(page));
            let raw = self.require(&key).await?;
            p.decode_page(page, &raw)?
                .nth((x.chunk % 128) as usize)
                .ok_or_else(corrupt)?
        };
        let (chunk, charged) = self
            .incremental_member(st, x, chunk_id)
            .await?
            .ok_or(Stop::Yield(0))?;
        let Object::Blob(blob) = chunk else {
            return Err(Stop::Reject("object hash mismatch"));
        };
        check(x.chunk_offset <= blob.data.len() as u64)?;
        let remaining = PART - x.written % PART;
        let available = &blob.data[size(x.chunk_offset)?..];
        let take = size(remaining.min(available.len() as u64))?;
        if x.written
            .checked_add(take as u64)
            .is_none_or(|n| n > x.length)
        {
            return Err(Stop::Reject("object hash mismatch"));
        }
        self.append_fragment(st, x, id, b"payload", x.written % PART, &available[..take])
            .await?;
        if x.stage == PREFLIGHT && x.chunk_offset == 0 {
            self.charge_sources(st, x, charged).await?;
        }
        x.written += take as u64;
        x.chunk_offset += take as u64;
        if x.chunk_offset == blob.data.len() as u64 {
            if x.stage == PREFLIGHT {
                self.put_aux(
                    st,
                    self.aux(x, b"offset", &id, x.chunk),
                    codec::encode_u64(x.written),
                )
                .await?;
            }
            x.chunk += 1;
            x.chunk_offset = 0;
        }
        if take > 0 && x.length > PART && (x.written.is_multiple_of(PART) || x.written == x.length)
        {
            self.finish_part(st, x, id).await?;
        }
        Ok(())
    }
    async fn finish_part(
        &self,
        st: &SliceState,
        x: &mut ExtractionV1,
        id: Hash,
    ) -> Result<(), Stop> {
        let index = n32((x.written - 1) / PART)?;
        let len = plan(x.length)?.expected_len(index).map_err(|_| corrupt())?;
        let bytes = self.fragment_bytes(x, id, b"payload", len).await?;
        let cv = part_subtree_cv(&plan(x.length)?, index, &bytes).map_err(|_| corrupt())?;
        if x.stage == PREFLIGHT {
            self.put_aux(st, self.aux(x, b"cv", &id, index), Value::new(cv.to_vec()))
                .await?;
            x.cvs = index + 1;
        } else {
            let expected = self.require(&self.aux(x, b"cv", &id, index)).await?;
            check(expected.as_bytes() == cv)?;
            self.extraction_lease().await?;
            let tag = self
                .h
                .extension
                .put_object_part(
                    BlobKey::object(id),
                    &x.session,
                    &plan(x.length)?,
                    index,
                    cv,
                    bytes,
                    self.budget,
                )
                .await?
                .ok_or_else(|| unavailable("extraction callback unavailable"))?;
            check(tag.len() <= 1089)?;
            self.put_aux(st, self.aux(x, b"receipt", &id, index), Value::new(tag))
                .await?;
            x.uploaded = index + 1;
        }
        Ok(())
    }
    async fn start_object(&self, job: &VerifyJobV1, x: &mut ExtractionV1) -> Result<(), Stop> {
        self.protect(job, x).await?;
        let id = x.object.ok_or_else(corrupt)?;
        if x.length > PART {
            let cvs = self.cv_list(x, id).await?;
            x.session = self
                .h
                .extension
                .begin_object(
                    BlobKey::object(id),
                    &plan(x.length)?,
                    x.root.ok_or_else(corrupt)?,
                    &cvs,
                    self.identity(job, x)?.operation,
                    self.budget,
                )
                .await?
                .ok_or_else(|| unavailable("extraction callback unavailable"))?;
            check(x.session.len() <= 1024)?;
            x.chunk = 0;
            x.chunk_offset = 0;
            x.written = 0;
            x.stage = UPLOAD;
        } else {
            x.stage = COMPLETE;
        }
        Ok(())
    }
    async fn put_small(&self, key: BlobKey, bytes: Vec<u8>, root: Hash) -> Result<(), Stop> {
        // One PUT plus root-binding reads/conditional write/re-read, reserved
        // before beginning the upload. Offsets need just the PUT.
        for _ in 0..6 {
            self.budget.charge()?;
        }
        let mut sink = self.h.blobs.begin(key, bytes.len() as u64).await?;
        for chunk in bytes.chunks(crate::store::MAX_BLOB_PIECE_BYTES) {
            if let Err(error) = sink.write(Bytes::copy_from_slice(chunk)).await {
                sink.abort().await;
                return Err(error.into());
            }
        }
        self.extraction_lease().await?;
        sink.commit_with_root(root).await?;
        Ok(())
    }
    async fn complete_object(&self, job: &VerifyJobV1, x: &mut ExtractionV1) -> Result<(), Stop> {
        self.protect(job, x).await?;
        let id = x.object.ok_or_else(corrupt)?;
        if x.length <= PART {
            let bytes = self.fragment_bytes(x, id, b"payload", x.length).await?;
            self.put_small(BlobKey::object(id), bytes, x.root.ok_or_else(corrupt)?)
                .await?;
        } else {
            let p = plan(x.length)?;
            check(x.uploaded == p.count())?;
            let parts = self
                .bulk(x, id, b"receipt", x.uploaded)
                .await?
                .into_iter()
                .enumerate()
                .map(|(i, tag)| {
                    Ok(PartRef {
                        index: n32(i as u64)?,
                        len: p.expected_len(n32(i as u64)?).map_err(|_| corrupt())?,
                        tag: tag.into_bytes().to_vec(),
                    })
                })
                .collect::<Result<Vec<_>, Stop>>()?;
            self.h
                .extension
                .complete_object(
                    BlobKey::object(id),
                    &x.session,
                    &p,
                    parts,
                    x.root.ok_or_else(corrupt)?,
                    self.budget,
                )
                .await?
                .ok_or_else(|| unavailable("extraction callback unavailable"))?;
        }
        x.stage = OFFSETS;
        Ok(())
    }
    async fn offsets(&self, job: &VerifyJobV1, x: &mut ExtractionV1) -> Result<(), Stop> {
        self.protect(job, x).await?;
        let id = x.object.ok_or_else(corrupt)?;
        let (_, p) = self.selected_projection(x, id).await?;
        if p.kind == 1 {
            let mut offsets = Vec::with_capacity(p.references as usize + 1);
            offsets.push(0);
            for value in self.bulk(x, id, b"offset", p.references).await? {
                offsets.push(number(&value)?);
            }
            check(offsets.last() == Some(&p.size) && offsets.windows(2).all(|w| w[0] <= w[1]))?;
            let bytes = super::super::extract::encode_offsets(&offsets);
            let root = hash(&bytes);
            self.put_small(BlobKey::object_offsets(id), bytes, root)
                .await?;
        }
        x.stage = ENQUEUE;
        Ok(())
    }
    async fn enqueue_holder(
        &self,
        st: &mut SliceState,
        job: &VerifyJobV1,
        x: &mut ExtractionV1,
    ) -> Result<(), Stop> {
        self.protect(job, x).await?;
        let identity = self.identity(job, x)?;
        let lease = self.extraction_lease().await?;
        let sequence = self.get(&keys::outbox_sequence()).await?;
        let row = codec::RelayV1 {
            at_ms: self.now,
            target: content_shard(&identity.object),
            puts: vec![(
                keys::pending_holder(&identity.object, &identity.hold_id),
                identity.encode()?,
            )],
            deletes: Vec::new(),
        };
        let snapshot = crate::relay::RelayEnqueueSnapshot {
            sequence: sequence.clone(),
            source_lease: lease,
            deadline_ms: self.deadline(),
        };
        let mut batches =
            crate::relay::enqueue_relay_rows(&snapshot, self.source, &[row], self.now)?;
        let batch = batches.pop().ok_or_else(corrupt)?;
        st.guards.extend(batch.preconditions);
        st.settled.extend(batch.writes);
        x.relay = Some(
            sequence
                .as_ref()
                .map(codec::decode_u64)
                .transpose()?
                .unwrap_or(0)
                .checked_add(1)
                .ok_or_else(corrupt)?,
        );
        x.stage = DELIVERY;
        Ok(())
    }
    async fn delivery(
        &self,
        st: &SliceState,
        job: &VerifyJobV1,
        x: &mut ExtractionV1,
    ) -> Result<(), Stop> {
        if !relay_delivered_through(self.local, self.source, x.relay.ok_or_else(corrupt)?).await? {
            self.protect(job, x).await?;
            return Err(Stop::Wait(1_000));
        }
        let id = x.object.ok_or_else(corrupt)?;
        self.auxiliary(
            st,
            (0_u32..64)
                .map(|i| Write::Delete(self.aux(x, b"payload", &id, i)))
                .collect(),
        )
        .await?;
        x.object = None;
        x.stage = CHOOSE;
        Ok(())
    }
    pub(super) async fn extraction(
        &self,
        st: &mut SliceState,
        job: &mut VerifyJobV1,
    ) -> Result<u64, Stop> {
        let mut x = match job.extraction.clone() {
            Some(x) => x,
            None => self.capture_sources(job).await?,
        };
        if x.stage != DELIVERY {
            let guards = st.guards.len();
            if !self.source_guards(&x, st).await? {
                st.guards.truncate(guards);
                job.extraction = Some(self.capture_sources(job).await?);
                return Ok(1_000);
            }
        }
        let result = match x.stage {
            SCAN => self.scan_group(st, &mut x).await,
            CLOSURE | DEPENDENCIES => self.closure_rows(st, &mut x).await,
            MEMBERS => self.closure_members(&mut x).await,
            HEAD => self.closure_head(st, &mut x, job).await,
            SELECT => self.select_group(st, &mut x).await,
            CHOOSE => self.choose_object(&mut x, job).await,
            PREFLIGHT | UPLOAD => self.walk_source(st, job, &mut x).await,
            START => self.start_object(job, &mut x).await,
            COMPLETE => self.complete_object(job, &mut x).await,
            OFFSETS => self.offsets(job, &mut x).await,
            ENQUEUE => self.enqueue_holder(st, job, &mut x).await,
            DELIVERY => self.delivery(st, job, &mut x).await,
            _ => return Err(corrupt()),
        };
        job.extraction = Some(x);
        result?;
        Ok(0)
    }
}
