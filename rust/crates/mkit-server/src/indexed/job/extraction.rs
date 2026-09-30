//! Bounded consumed-set selection and two-pass extraction. Only the current
//! eight-MiB part is spooled locally; CVs, offsets and receipts are small rows.
use super::super::checkpoint::{ExtractionSource, ExtractionV1};
use super::super::selection::Projection;
use super::{
    BTreeSet, Batch, BatchOutcome, BlobStore, Cursor, FrameRow, Hash, Key, MemberCache,
    NamespaceStore, Object, Outcome, PackWindows, Partition, Phase, Precondition, Run,
    SliceExtension, SliceState, Stop, StoreError, Value, VerificationV1, VerifyJobV1, Write,
    checkpoint, codec, decode_frame, hash, keys, now_ms, relay_delivered_through, renew_for_relay,
    resolve, state, unavailable,
};
use crate::store::{
    BlobKey, BorrowedStore, ContentIndex, HoldOutcome, Holder, PackSink, PartRef, PendingHolderV1,
    content_shard,
};
use bytes::Bytes;
use mkit_core::upload_parts::{MIN_PART_SIZE, PartPlan, merge_to_root, part_subtree_cv};

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

fn corrupt() -> Stop {
    Stop::Store(StoreError::Corrupt("bad extraction checkpoint".into()))
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

impl<S: NamespaceStore, R: NamespaceStore, B: BlobStore, W: PackWindows, X: SliceExtension>
    Run<'_, S, R, B, W, X>
{
    fn aux(&self, x: &ExtractionV1, label: &[u8], object: &Hash, index: u32) -> Key {
        self.row(
            keys::VC_CANDIDATE,
            &hash_row(label, &x.group, object, index),
        )
    }
    fn shared(&self, x: &ExtractionV1) -> Result<Key, Stop> {
        let first = x.sources.first().ok_or_else(corrupt)?;
        Ok(keys::verify_row(
            &self.repo.name,
            &first.member.pack,
            keys::VC_CANDIDATE,
            Some(&hash_row(b"charged", &x.group, &[0; 32], 0)),
        ))
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
            let raw = self
                .local
                .get(self.source, &key)
                .await?
                .ok_or(Stop::Wait(1_000))?;
            let source = checkpoint::decode_job(&raw)?;
            if source.bad_signature {
                return Err(Stop::Wait(1_000));
            }
            if source.outcome.is_some() {
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
            });
        }
        x.group = hash(&serde_json::to_vec(&x.sources).map_err(|_| corrupt())?);
        Ok(x)
    }
    /// Progress may change, identity may not. Exact guards accompany every
    /// source-dependent checkpoint, including selection freeze and charging.
    async fn source_guards(&self, x: &ExtractionV1, st: &mut SliceState) -> Result<(), Stop> {
        for source in &x.sources {
            let key = keys::verify_job(&self.repo.name, &source.member.pack);
            let raw = self
                .local
                .get(self.source, &key)
                .await?
                .ok_or_else(|| unavailable("extraction source disappeared"))?;
            let current = checkpoint::decode_job(&raw)?;
            let state_key = keys::verification(&self.repo.name, &source.member.pack);
            let state_raw = self.local.get(self.source, &state_key).await?;
            let verification = state_raw.as_ref().map(state::decode).transpose()?;
            if current.bad_signature
                || matches!(verification, Some(VerificationV1::Rejected { .. }))
            {
                return Err(Stop::Wait(1_000));
            }
            if source.member.pack != self.pack {
                // A canceled first owner cannot satisfy another pack's selected
                // objects. Its own started object may still drain under gp.
                if !source.member.already_verified
                    && !matches!(verification, Some(VerificationV1::Verified { .. }))
                {
                    let ticket = keys::ticket(&source.member.ticket);
                    let raw = self
                        .local
                        .get(self.source, &ticket)
                        .await?
                        .ok_or(Stop::Wait(1_000))?;
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
        Ok(())
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
        let key = keys::verify_row(
            &self.repo.name,
            &source.member.pack,
            keys::VC_CANDIDATE,
            Some(&id),
        );
        let raw = self
            .local
            .get(self.source, &key)
            .await?
            .ok_or_else(corrupt)?;
        let p = Projection::decode(&id, &raw)?;
        p.validate_frame(frame, source.member.bytes, source.decoded)?;
        let mut digest = Projection::reference_hasher(&id, p.kind);
        for start in (0..p.pages()).step_by(90) {
            let end = (start + 90).min(p.pages());
            let keys: Vec<_> = (start..end)
                .map(|i| {
                    keys::verify_row(
                        &self.repo.name,
                        &source.member.pack,
                        keys::VC_CANDIDATE,
                        Some(&p.page_id(i)),
                    )
                })
                .collect();
            let values = self.local.get_many(self.source, &keys).await?;
            if values.len() != keys.len() {
                return Err(corrupt());
            }
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
        if digest.finalize() != p.digest {
            return Err(corrupt());
        }
        Ok(p)
    }
    async fn scan_group(&self, st: &mut SliceState, x: &mut ExtractionV1) -> Result<(), Stop> {
        if x.member >= x.sources.len() {
            x.member = 0;
            x.scan.clear();
            x.stage = SELECT;
            return Ok(());
        }
        let source = x.sources[x.member].clone();
        let Some((id, frame, next)) = self.next_frame(x, &source.member.pack).await? else {
            x.member += 1;
            x.scan.clear();
            return Ok(());
        };
        self.projection(&source, id, &frame, Some((st, x))).await?;
        let owner = self.aux(x, b"owner", &id, 0);
        let first = self.local.get(self.source, &owner).await?;
        let mut writes = Vec::new();
        if first.is_none() {
            x.staged_bytes = x
                .staged_bytes
                .checked_add(frame.value.decoded_size)
                .ok_or_else(corrupt)?;
            writes.push(Write::Put(owner, codec::encode_u64(x.member as u64)));
        } else if number(first.as_ref().ok_or_else(corrupt)?)? == x.member as u64 {
            // Pure ahead-of-checkpoint rows replay, but do not erase this step's charge.
            x.staged_bytes = x
                .staged_bytes
                .checked_add(frame.value.decoded_size)
                .ok_or_else(corrupt)?;
        }
        self.auxiliary(st, writes).await?;
        if let Some(next) = next {
            x.scan = next.into_bytes().to_vec();
        } else {
            x.member += 1;
            x.scan.clear();
        }
        if x.staged_bytes > self.h.cfg.decode_budget {
            return Err(Stop::Outcome(Outcome::DecodeBudget));
        }
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
            x.member += 1;
            x.scan.clear();
            return Ok(());
        };
        let owner = self
            .local
            .get(self.source, &self.aux(x, b"owner", &id, 0))
            .await?
            .ok_or_else(corrupt)?;
        if number(&owner)? == x.member as u64 {
            let p = self.projection(&source, id, &frame, None).await?;
            let selected = p.kind == 1
                || (p.kind == 0
                    && p.size >= self.h.cfg.extract_min_bytes
                    && (!self
                        .local
                        .has(self.source, &self.aux(x, b"chunk", &id, 0))
                        .await?
                        || self
                            .local
                            .has(self.source, &self.aux(x, b"file", &id, 0))
                            .await?));
            if selected {
                x.selected_bytes = x.selected_bytes.checked_add(p.size).ok_or_else(corrupt)?;
                if !source.member.already_verified && source.member.pack == self.pack {
                    self.auxiliary(
                        st,
                        vec![Write::Put(
                            self.aux(x, b"selected", &id, 0),
                            codec::encode_u64(p.size),
                        )],
                    )
                    .await?;
                }
            }
        }
        if x.selected_bytes > self.h.cfg.effective_max_extract_bytes() {
            return Err(Stop::Outcome(Outcome::DecodeBudget));
        }
        if let Some(next) = next {
            x.scan = next.into_bytes().to_vec();
        } else {
            x.member += 1;
            x.scan.clear();
        }
        Ok(())
    }
    async fn choose_object(&self, x: &mut ExtractionV1, job: &mut VerifyJobV1) -> Result<(), Stop> {
        let Some((id, _, next)) = self.next_frame(x, &self.pack).await? else {
            job.phase = Phase::Verify;
            return Ok(());
        };
        if let Some(value) = self
            .local
            .get(self.source, &self.aux(x, b"selected", &id, 0))
            .await?
        {
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
                keys::verify_row(&self.repo.name, &self.pack, keys::VC_FRAME, Some(&id))
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
    async fn protect(&self, job: &VerifyJobV1, x: &ExtractionV1) -> Result<(), Stop> {
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
    /// Reconstruct canonical staged sources from the frozen local frames. The
    /// disposable decoding state never writes or charges the source job again.
    async fn source_object(&self, x: &ExtractionV1, id: Hash) -> Result<(Object, u64), Stop> {
        for source in &x.sources {
            let key = keys::verify_row(
                &self.repo.name,
                &source.member.pack,
                keys::VC_FRAME,
                Some(&id),
            );
            if self.local.has(self.source, &key).await? {
                let raw = self
                    .local
                    .get(
                        self.source,
                        &keys::verify_job(&self.repo.name, &source.member.pack),
                    )
                    .await?
                    .ok_or_else(corrupt)?;
                let mut job = checkpoint::decode_job(&raw)?;
                job.in_pack_bytes = 0;
                job.external_bytes = 0;
                let run = Run {
                    h: self.h,
                    local: self.local,
                    source: self.source,
                    repo: self.repo.clone(),
                    pack: source.member.pack,
                    budget: self.budget,
                    remote: self.remote,
                    blobs: self.blobs,
                    now: self.now,
                };
                let mut st = SliceState {
                    entry_idx: u64::MAX,
                    ..SliceState::default()
                };
                run.ensure_base(&mut st, &mut job, id, u64::MAX).await?;
                let bytes = st.cache.map.get(&id).ok_or_else(corrupt)?;
                let object = mkit_core::serialize::deserialize(bytes).map_err(|_| corrupt())?;
                if object.id().map_err(|_| corrupt())? != id {
                    return Err(corrupt());
                }
                return Ok((object, 0));
            }
        }
        let found = resolve::locate_split(
            self.remote,
            self.h.shards.as_ref(),
            &self.repo,
            &[id],
            self.h.metrics.as_ref(),
        )
        .await
        .map_err(|_| unavailable("extraction source lookup failed"))?;
        let location = match found.get(&id) {
            Some(Ok(Some(found))) => *found,
            Some(Err(_)) => return Err(Stop::Outcome(Outcome::BaseCapped)),
            _ => return Err(Stop::Wait(1_000)),
        };
        let mut cache = MemberCache::default();
        let (bytes, _) = resolve::member_object(
            self.blobs,
            self.remote,
            self.h.shards.as_ref(),
            &self.repo,
            id,
            location,
            self.h.cfg.max_delta_chain_depth,
            self.decode_limits().max_decoded_bytes,
            &mut cache,
            &mut BTreeSet::new(),
            self.h.metrics.as_ref(),
        )
        .await
        .map_err(|_| unavailable("extraction member unavailable"))?;
        let object = mkit_core::serialize::deserialize(&bytes).map_err(|_| corrupt())?;
        if object.id().map_err(|_| corrupt())? != id {
            return Err(corrupt());
        }
        Ok((object, cache.retained_bytes()))
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
        let raw = self.local.get(self.source, &key).await?;
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
        at: u64,
        len: u64,
    ) -> Result<Vec<u8>, Stop> {
        let mut bytes = Vec::with_capacity(usize::try_from(len).map_err(|_| corrupt())?);
        let first = at / FRAGMENT;
        let last = (at + len).div_ceil(FRAGMENT);
        let keys: Vec<_> = (first..last)
            .map(|i| Ok(self.aux(x, b"payload", &id, n32(i)?)))
            .collect::<Result<_, Stop>>()?;
        let rows = self.local.get_many(self.source, &keys).await?;
        if rows.len() != keys.len() {
            return Err(corrupt());
        }
        for (i, row) in (first..last).zip(rows) {
            let raw = row.ok_or_else(corrupt)?;
            let start = if i == first {
                (at % FRAGMENT) as usize
            } else {
                0
            };
            let take =
                size(len - bytes.len() as u64)?.min(raw.as_bytes().len().saturating_sub(start));
            bytes.extend_from_slice(
                raw.as_bytes()
                    .get(start..start + take)
                    .ok_or_else(corrupt)?,
            );
        }
        if bytes.len() as u64 != len {
            return Err(corrupt());
        }
        Ok(bytes)
    }
    async fn append_fragment(
        &self,
        st: &SliceState,
        x: &ExtractionV1,
        id: Hash,
        data: &[u8],
    ) -> Result<(), Stop> {
        let start = x.written % PART;
        let mut at = start;
        let mut rest = data;
        let mut writes = Vec::new();
        while !rest.is_empty() {
            let slot = n32(at / FRAGMENT)?;
            let offset = (at % FRAGMENT) as usize;
            let key = self.aux(x, b"payload", &id, slot);
            let mut bytes = if offset == 0 {
                Vec::new()
            } else {
                self.local
                    .get(self.source, &key)
                    .await?
                    .ok_or_else(corrupt)?
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
        for start in (0..count).step_by(90) {
            let keys: Vec<_> = (start..(start + 90).min(count))
                .map(|i| self.aux(x, label, &id, i))
                .collect();
            let rows = self.local.get_many(self.source, &keys).await?;
            if rows.len() != keys.len() {
                return Err(corrupt());
            }
            for row in rows {
                out.push(row.ok_or_else(corrupt)?);
            }
        }
        Ok(out)
    }
    async fn cv_list(&self, x: &ExtractionV1, id: Hash) -> Result<Vec<Hash>, Stop> {
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
        let (object, _) = self.source_object(x, id).await?;
        let (chunk_id, count) = match &object {
            Object::Blob(_) => (id, 1),
            Object::ChunkedBlob(cb) => (
                cb.chunks.get(x.chunk as usize).copied().unwrap_or(id),
                n32(cb.chunks.len() as u64)?,
            ),
            _ => return Err(corrupt()),
        };
        if x.chunk == count {
            if x.written != x.length {
                return Err(Stop::Reject("object hash mismatch"));
            }
            if x.length <= PART {
                let bytes = self.fragment_bytes(x, id, 0, x.length).await?;
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
        let (chunk, charged) = if chunk_id == id {
            (object, 0)
        } else {
            // The manifest's reference vector is no longer needed while the
            // member decoder uses its reserved scratch regions.
            drop(object);
            self.source_object(x, chunk_id).await?
        };
        let Object::Blob(blob) = chunk else {
            return Err(Stop::Reject("object hash mismatch"));
        };
        if x.chunk_offset > blob.data.len() as u64 {
            return Err(corrupt());
        }
        let remaining = PART - x.written % PART;
        let available = &blob.data[size(x.chunk_offset)?..];
        let take = size(remaining.min(available.len() as u64))?;
        if x.written
            .checked_add(take as u64)
            .is_none_or(|n| n > x.length)
        {
            return Err(Stop::Reject("object hash mismatch"));
        }
        self.append_fragment(st, x, id, &available[..take]).await?;
        if x.stage == PREFLIGHT && x.chunk_offset == 0 {
            self.charge_sources(st, x, charged).await?;
        }
        x.written += take as u64;
        x.chunk_offset += take as u64;
        if x.chunk_offset == blob.data.len() as u64 {
            if x.stage == PREFLIGHT {
                self.auxiliary(
                    st,
                    vec![Write::Put(
                        self.aux(x, b"offset", &id, x.chunk),
                        codec::encode_u64(x.written),
                    )],
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
        let bytes = self.fragment_bytes(x, id, 0, len).await?;
        let cv = part_subtree_cv(&plan(x.length)?, index, &bytes).map_err(|_| corrupt())?;
        if x.stage == PREFLIGHT {
            self.auxiliary(
                st,
                vec![Write::Put(
                    self.aux(x, b"cv", &id, index),
                    Value::new(cv.to_vec()),
                )],
            )
            .await?;
            x.cvs = index + 1;
        } else {
            let expected = self
                .local
                .get(self.source, &self.aux(x, b"cv", &id, index))
                .await?
                .ok_or_else(corrupt)?;
            if expected.as_bytes() != cv {
                return Err(corrupt());
            }
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
            if tag.len() > 1089 {
                return Err(corrupt());
            }
            self.auxiliary(
                st,
                vec![Write::Put(
                    self.aux(x, b"receipt", &id, index),
                    Value::new(tag),
                )],
            )
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
            if x.session.len() > 1024 {
                return Err(corrupt());
            }
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
        sink.commit_with_root(root).await?;
        Ok(())
    }
    async fn complete_object(&self, job: &VerifyJobV1, x: &mut ExtractionV1) -> Result<(), Stop> {
        self.protect(job, x).await?;
        let id = x.object.ok_or_else(corrupt)?;
        if x.length <= PART {
            let bytes = self.fragment_bytes(x, id, 0, x.length).await?;
            self.put_small(BlobKey::object(id), bytes, x.root.ok_or_else(corrupt)?)
                .await?;
        } else {
            let p = plan(x.length)?;
            if x.uploaded != p.count() {
                return Err(corrupt());
            }
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
        if let (Object::ChunkedBlob(cb), _) = self.source_object(x, id).await? {
            let mut offsets = Vec::with_capacity(cb.chunks.len() + 1);
            offsets.push(0);
            for value in self
                .bulk(x, id, b"offset", n32(cb.chunks.len() as u64)?)
                .await?
            {
                offsets.push(number(&value)?);
            }
            if offsets.last() != Some(&cb.total_size) || offsets.windows(2).any(|w| w[0] > w[1]) {
                return Err(corrupt());
            }
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
        let lease = if matches!(self.source, Partition::Ref { .. }) {
            Some(
                renew_for_relay(
                    self.local,
                    self.remote,
                    self.h.shards.as_ref(),
                    self.h.clock.as_ref(),
                    &self.repo,
                    self.source,
                    &self.h.lease,
                )
                .await
                .map_err(|_| unavailable("extraction lease lost"))?,
            )
        } else {
            None
        };
        let sequence = self
            .local
            .get(self.source, &keys::outbox_sequence())
            .await?;
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
            return Ok(());
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
        let mut x = match job.extraction.take() {
            Some(x) => x,
            None => self.capture_sources(job).await?,
        };
        if x.stage != DELIVERY {
            self.source_guards(&x, st).await?;
        }
        match x.stage {
            SCAN => self.scan_group(st, &mut x).await?,
            SELECT => self.select_group(st, &mut x).await?,
            CHOOSE => self.choose_object(&mut x, job).await?,
            PREFLIGHT | UPLOAD => self.walk_source(st, job, &mut x).await?,
            START => self.start_object(job, &mut x).await?,
            COMPLETE => self.complete_object(job, &mut x).await?,
            OFFSETS => self.offsets(job, &mut x).await?,
            ENQUEUE => self.enqueue_holder(st, job, &mut x).await?,
            DELIVERY => self.delivery(st, job, &mut x).await?,
            _ => return Err(corrupt()),
        }
        job.extraction = Some(x);
        Ok(1_000)
    }
}
