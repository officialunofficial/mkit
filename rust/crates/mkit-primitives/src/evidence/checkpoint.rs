//! Strict versioned framing checkpoints. Checksums detect corruption, not forgery.
//!
//! Decoding establishes envelope syntax and bounds only. The framing driver
//! checks the expected source, repository, ruleset, budgets, and embedded cursor
//! metadata before resuming. Checkpoints never establish verified-pack evidence.
use super::{
    PackSource, PageCommitment, PageKind, ProfileId, RepositoryId, RulesetBinding, RulesetId,
    SourceBinding,
};
use crate::{
    codec::{Budget, Cursor, failure},
    error::{Failure, FailureCode},
    limits::{IndexedProfile, VerifyLimits},
    pack_verify::ResourceUsage,
};
use mkit_core::{
    hash::{Hash, domain_digest},
    pack::{MAX_ENTRIES, MAX_TOTAL_PAYLOAD, window::WindowCursor},
};

const DOMAIN: &[u8] = b"mkit-checkpoint-checksum:v1";
const MAGIC: &[u8; 4] = b"MKCP";
const VERSION: u16 = 1;
const SUBTREE: u64 = 8 << 20;
const MAX_CVS: usize = 518;
const MAX_PACK: u64 = MAX_TOTAL_PAYLOAD + MAX_ENTRIES as u64 * 5 + 44;
const CURSOR_CAP: u64 = 4096;

fn invalid() -> Failure {
    failure(FailureCode::InvalidCheckpoint)
}
fn resource() -> Failure {
    failure(FailureCode::ResourceLimit)
}

/// Opaque, syntactically validated checkpoint envelope.
///
/// Caller-provided bytes remain untrusted resume input even after decoding.
#[derive(Debug)]
#[must_use]
pub struct Checkpoint {
    bytes: Vec<u8>,
    meta: CheckpointMeta,
}
impl Checkpoint {
    /// Canonical versioned bytes, including the corruption-detection checksum.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Copies a strictly decoded checkpoint under explicit finite budgets.
    ///
    /// This validates syntax and local bounds; it does not authorize resumption
    /// or authenticate the caller's source and retained-page store.
    ///
    /// # Errors
    /// Refuses unsupported versions, malformed fields, corruption, truncation,
    /// trailing data, impossible phase state, and exhausted execution budgets.
    pub fn from_bytes(bytes: &[u8], limits: VerifyLimits) -> Result<Self, Failure> {
        let mut budget = codec_budget(bytes.len(), limits)?;
        let state = parse(bytes, &mut budget)?;
        let meta = state.meta;
        drop(state);
        budget.charge(bytes.len() as u64, bytes.len() as u64)?;
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(bytes.len())
            .map_err(|_| resource())?;
        owned.extend_from_slice(bytes);
        Ok(Self { bytes: owned, meta })
    }

    pub(crate) const fn meta(&self) -> CheckpointMeta {
        self.meta
    }

    pub(crate) fn decode(&self, limits: VerifyLimits) -> Result<CheckpointState, Failure> {
        let mut budget = codec_budget(self.bytes.len(), limits)?;
        parse(&self.bytes, &mut budget)
    }
}

/// Envelope fields common to every phase. Current residency is always zero:
/// reconstruction must charge newly allocated buffers again.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CheckpointMeta {
    pub source: PackSource,
    pub repository: RepositoryId,
    pub ruleset: RulesetBinding,
    pub limits: VerifyLimits,
    pub profile: IndexedProfile,
    pub generation: u64,
    pub sequence: u64,
    pub phase: CheckpointPhase,
    pub header: Option<(u32, u32)>,
    pub ordinal: u64,
    pub payload: u64,
    pub trailer: Hash,
    pub retention_count: u64,
    pub last_retained: Option<PageCommitment>,
    pub usage: ResourceUsage,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum CheckpointPhase {
    Header = 0,
    Integrity = 1,
    Decode = 2,
    Complete = 3,
}
#[derive(Debug, Clone, Copy)]
pub(crate) struct IntegrityView<'a> {
    pub offset: u64,
    pub whole_cvs: &'a [Hash],
    pub trailer_cvs: &'a [Hash],
    pub whole_root: Option<Hash>,
    pub trailer_root: Option<Hash>,
    pub trailer: Hash,
    pub trailer_used: u8,
}
#[derive(Debug)]
pub(crate) struct IntegrityState {
    pub offset: u64,
    pub whole_cvs: Vec<Hash>,
    pub trailer_cvs: Vec<Hash>,
    pub whole_root: Option<Hash>,
    pub trailer_root: Option<Hash>,
    pub trailer: Hash,
    pub trailer_used: u8,
}
impl IntegrityState {
    fn view(&self) -> IntegrityView<'_> {
        IntegrityView {
            offset: self.offset,
            whole_cvs: &self.whole_cvs,
            trailer_cvs: &self.trailer_cvs,
            whole_root: self.whole_root,
            trailer_root: self.trailer_root,
            trailer: self.trailer,
            trailer_used: self.trailer_used,
        }
    }
}
#[derive(Debug)]
pub(crate) struct CheckpointState {
    pub meta: CheckpointMeta,
    pub integrity: Option<IntegrityState>,
    pub cursor: Vec<u8>,
}
#[derive(Debug, Clone, Copy)]
pub(crate) struct CheckpointView<'a> {
    pub meta: CheckpointMeta,
    pub integrity: Option<IntegrityView<'a>>,
    pub cursor: &'a [u8],
}

fn validate_limits(l: VerifyLimits) -> Result<(), Failure> {
    if !(64 << 10..=64 << 20).contains(&l.acquisition_bytes)
        || !l.acquisition_bytes.is_power_of_two()
        || l.page_bytes == 0
        || l.resident_pages == 0
        || l.checkpoint_bytes == 0
        || l.work == 0
        || l.evidence_pages == 0
        || l.evidence_bytes < l.page_bytes
        || l.page_bytes
            .checked_mul(u64::from(l.resident_pages))
            .is_none_or(|n| n > l.resident_bytes)
    {
        return Err(invalid());
    }
    Ok(())
}
fn codec_budget(len: usize, limits: VerifyLimits) -> Result<Budget, Failure> {
    validate_limits(limits)?;
    let len = u64::try_from(len).map_err(|_| resource())?;
    if len > limits.checkpoint_bytes || len > limits.resident_bytes {
        return Err(resource());
    }
    Ok(Budget::new(limits.work, limits.resident_bytes))
}
fn validate_meta(m: &CheckpointMeta) -> Result<(), Failure> {
    validate_limits(m.limits)?;
    if m.ruleset.ruleset != RulesetId(1)
        || m.ruleset.profile != ProfileId::Indexed
        || !(44..=MAX_PACK).contains(&m.source.len)
        || m.source.len > m.profile.pack_bytes
        || m.ordinal > u64::from(MAX_ENTRIES)
        || m.payload > MAX_TOTAL_PAYLOAD
        || m.usage.resident_bytes != 0
        || m.usage.peak_resident_bytes > m.limits.resident_bytes
        || m.usage.evidence_bytes > m.limits.evidence_bytes
        || m.usage.evidence_pages > m.limits.evidence_pages
        || m.usage.work > m.limits.work
        || m.retention_count != m.ordinal
        || m.usage.evidence_pages != m.retention_count
        || m.last_retained.is_some() != (m.retention_count != 0)
    {
        return Err(invalid());
    }
    if let Some(page) = m.last_retained
        && (page.kind != PageKind::Occurrences
            || page.len == 0
            || page.len > m.limits.page_bytes
            || page.items != 1
            || page.len > m.usage.evidence_bytes)
    {
        return Err(invalid());
    }
    if let Some((version, count)) = m.header {
        if !matches!(version, 1 | 2) || m.ordinal > u64::from(count) {
            return Err(invalid());
        }
        // The first pass records the header before the normative count check.
        if matches!(m.phase, CheckpointPhase::Decode | CheckpointPhase::Complete)
            && count > MAX_ENTRIES
        {
            return Err(invalid());
        }
    }
    match m.phase {
        CheckpointPhase::Header => {
            if m.header.is_some() || m.ordinal != 0 || m.payload != 0 || m.trailer != [0; 32] {
                return Err(invalid());
            }
        }
        CheckpointPhase::Integrity => {
            if m.header.is_none() || m.ordinal != 0 || m.payload != 0 || m.trailer != [0; 32] {
                return Err(invalid());
            }
        }
        CheckpointPhase::Decode | CheckpointPhase::Complete => {
            let (_, count) = m.header.ok_or_else(invalid)?;
            let position = m
                .ordinal
                .checked_mul(5)
                .and_then(|v| v.checked_add(12))
                .and_then(|v| v.checked_add(m.payload))
                .ok_or_else(invalid)?;
            if position > m.source.len - 32
                || (m.ordinal == 0 && m.payload != 0)
                || (m.phase == CheckpointPhase::Complete
                    && (m.ordinal != u64::from(count) || position != m.source.len - 32))
            {
                return Err(invalid());
            }
        }
    }
    Ok(())
}
fn validate_frontier(
    total: u64,
    seen: u64,
    cvs: &[Hash],
    root: Option<Hash>,
) -> Result<(), Failure> {
    let expected = if total <= SUBTREE {
        0
    } else if seen == total {
        total.div_ceil(SUBTREE)
    } else {
        seen / SUBTREE
    };
    if seen > total
        || (seen != total && !seen.is_multiple_of(SUBTREE))
        || cvs.len() > MAX_CVS
        || cvs.len() as u64 != expected
        || root.is_some() != (seen == total)
    {
        return Err(invalid());
    }
    Ok(())
}
fn validate_view(v: &CheckpointView<'_>) -> Result<(), Failure> {
    validate_meta(&v.meta)?;
    match v.meta.phase {
        CheckpointPhase::Header | CheckpointPhase::Complete => {
            if v.integrity.is_some() || !v.cursor.is_empty() {
                return Err(invalid());
            }
        }
        CheckpointPhase::Integrity => {
            let f = v.integrity.ok_or_else(invalid)?;
            if !v.cursor.is_empty()
                || f.offset > v.meta.source.len
                || f.trailer_used > 32
                || u64::from(f.trailer_used) != f.offset.saturating_sub(v.meta.source.len - 32)
                || f.trailer[usize::from(f.trailer_used)..]
                    .iter()
                    .any(|b| *b != 0)
            {
                return Err(invalid());
            }
            validate_frontier(v.meta.source.len, f.offset, f.whole_cvs, f.whole_root)?;
            validate_frontier(
                v.meta.source.len - 32,
                f.offset.min(v.meta.source.len - 32),
                f.trailer_cvs,
                f.trailer_root,
            )?;
        }
        CheckpointPhase::Decode => {
            if v.integrity.is_some() || v.cursor.is_empty() || v.cursor.len() as u64 > CURSOR_CAP {
                return Err(invalid());
            }
        }
    }
    Ok(())
}

fn optional_hash(c: &mut Cursor<'_, '_>) -> Result<Option<Hash>, Failure> {
    match c.byte()? {
        0 => Ok(None),
        1 => Ok(Some(c.array()?)),
        _ => Err(invalid()),
    }
}
fn hashes(c: &mut Cursor<'_, '_>) -> Result<Vec<Hash>, Failure> {
    let count = usize::from(c.u16()?);
    if count > MAX_CVS {
        return Err(invalid());
    }
    c.charge(count as u64 * 32, count as u64 * 32)?;
    let mut out = Vec::new();
    out.try_reserve_exact(count).map_err(|_| resource())?;
    for _ in 0..count {
        out.push(c.array()?);
    }
    Ok(out)
}
fn read_limits(c: &mut Cursor<'_, '_>) -> Result<VerifyLimits, Failure> {
    Ok(VerifyLimits {
        acquisition_bytes: c.u64()?,
        resident_bytes: c.u64()?,
        page_bytes: c.u64()?,
        resident_pages: c.u32()?,
        checkpoint_bytes: c.u64()?,
        evidence_bytes: c.u64()?,
        evidence_pages: c.u64()?,
        decoded_bytes: c.u64()?,
        dependency_edges: c.u64()?,
        external_lookups: c.u64()?,
        work: c.u64()?,
    })
}
fn read_meta(c: &mut Cursor<'_, '_>) -> Result<CheckpointMeta, Failure> {
    let source = PackSource {
        id: c.array()?,
        len: c.u64()?,
        binding: SourceBinding(c.array()?),
    };
    let repository = RepositoryId(c.array()?);
    let ruleset = RulesetBinding {
        ruleset: RulesetId(c.u32()?),
        profile: match c.byte()? {
            1 => ProfileId::Indexed,
            _ => return Err(invalid()),
        },
    };
    let limits = read_limits(c)?;
    let profile = IndexedProfile {
        pack_bytes: c.u64()?,
        decoded_bytes: c.u64()?,
        delta_depth: c.u32()?,
    };
    let generation = c.u64()?;
    let sequence = c.u64()?;
    let phase = match c.byte()? {
        0 => CheckpointPhase::Header,
        1 => CheckpointPhase::Integrity,
        2 => CheckpointPhase::Decode,
        3 => CheckpointPhase::Complete,
        _ => return Err(invalid()),
    };
    let header = match c.byte()? {
        0 => None,
        1 => Some((c.u32()?, c.u32()?)),
        _ => return Err(invalid()),
    };
    let ordinal = c.u64()?;
    let payload = c.u64()?;
    let trailer = c.array()?;
    let retention_count = c.u64()?;
    let last_retained = match c.byte()? {
        0 => None,
        1 => Some(PageCommitment {
            digest: c.array()?,
            kind: match c.byte()? {
                1 => PageKind::Occurrences,
                _ => return Err(invalid()),
            },
            len: c.u64()?,
            items: c.u64()?,
        }),
        _ => return Err(invalid()),
    };
    let usage = ResourceUsage {
        resident_bytes: c.u64()?,
        peak_resident_bytes: c.u64()?,
        evidence_bytes: c.u64()?,
        evidence_pages: c.u64()?,
        work: c.u64()?,
    };
    Ok(CheckpointMeta {
        source,
        repository,
        ruleset,
        limits,
        profile,
        generation,
        sequence,
        phase,
        header,
        ordinal,
        payload,
        trailer,
        retention_count,
        last_retained,
        usage,
    })
}
fn parse(bytes: &[u8], budget: &mut Budget) -> Result<CheckpointState, Failure> {
    let split = bytes.len().checked_sub(32).ok_or_else(invalid)?;
    let (body, checksum) = bytes.split_at(split);
    budget.charge(body.len() as u64, 0)?;
    if domain_digest(DOMAIN, body).as_slice() != checksum {
        return Err(invalid());
    }
    let mut c = Cursor::new(body, budget);
    if c.array::<4>()? != *MAGIC || c.u16()? != VERSION {
        return Err(invalid());
    }
    let meta = read_meta(&mut c)?;
    validate_meta(&meta)?;
    if bytes.len() as u64 > meta.limits.checkpoint_bytes {
        return Err(invalid());
    }
    let integrity = match c.byte()? {
        0 => None,
        1 => Some(IntegrityState {
            offset: c.u64()?,
            whole_cvs: hashes(&mut c)?,
            trailer_cvs: hashes(&mut c)?,
            whole_root: optional_hash(&mut c)?,
            trailer_root: optional_hash(&mut c)?,
            trailer: c.array()?,
            trailer_used: c.byte()?,
        }),
        _ => return Err(invalid()),
    };
    let cursor_len = u64::from(c.u16()?);
    let cursor = c.owned(cursor_len, CURSOR_CAP)?;
    c.finish()?;
    validate_cursor(&cursor, budget)?;
    let state = CheckpointState {
        meta,
        integrity,
        cursor,
    };
    validate_view(&CheckpointView {
        meta: state.meta,
        integrity: state.integrity.as_ref().map(IntegrityState::view),
        cursor: &state.cursor,
    })?;
    Ok(state)
}

fn validate_cursor(bytes: &[u8], budget: &mut Budget) -> Result<(), Failure> {
    if !bytes.is_empty() {
        // Core bounds each of two frontier vectors to 64 hashes. Charge their
        // worst-case heap size before its independently bounded decoder runs.
        budget.charge(bytes.len() as u64, 4096)?;
        WindowCursor::from_bytes(bytes).map_err(|_| invalid())?;
    }
    Ok(())
}

/// Fallible bounded writer; callers lend frontiers rather than cloning them.
struct Output {
    bytes: Vec<u8>,
    cap: u64,
    budget: Budget,
}
impl Output {
    fn append(&mut self, bytes: &[u8]) -> Result<(), Failure> {
        let len = bytes.len() as u64;
        if (self.bytes.len() as u64)
            .checked_add(len)
            .is_none_or(|n| n > self.cap)
        {
            return Err(resource());
        }
        self.budget.charge(len, 0)?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
    fn byte(&mut self, value: u8) -> Result<(), Failure> {
        self.append(&[value])
    }
    fn u32(&mut self, value: u32) -> Result<(), Failure> {
        self.append(&value.to_le_bytes())
    }
    fn u64(&mut self, value: u64) -> Result<(), Failure> {
        self.append(&value.to_le_bytes())
    }
    fn hash(&mut self, value: Option<Hash>) -> Result<(), Failure> {
        self.byte(u8::from(value.is_some()))?;
        if let Some(hash) = value {
            self.append(&hash)?;
        }
        Ok(())
    }
    fn hashes(&mut self, values: &[Hash]) -> Result<(), Failure> {
        let count = u16::try_from(values.len()).map_err(|_| invalid())?;
        self.append(&count.to_le_bytes())?;
        for value in values {
            self.append(value)?;
        }
        Ok(())
    }
}
fn write_binding(out: &mut Output, m: &CheckpointMeta) -> Result<(), Failure> {
    out.append(MAGIC)?;
    out.append(&VERSION.to_le_bytes())?;
    out.append(&m.source.id)?;
    out.u64(m.source.len)?;
    out.append(&m.source.binding.0)?;
    out.append(&m.repository.0)?;
    out.u32(m.ruleset.ruleset.0)?;
    out.byte(1)?;
    for n in [
        m.limits.acquisition_bytes,
        m.limits.resident_bytes,
        m.limits.page_bytes,
    ] {
        out.u64(n)?;
    }
    out.u32(m.limits.resident_pages)?;
    for n in [
        m.limits.checkpoint_bytes,
        m.limits.evidence_bytes,
        m.limits.evidence_pages,
        m.limits.decoded_bytes,
        m.limits.dependency_edges,
        m.limits.external_lookups,
        m.limits.work,
    ] {
        out.u64(n)?;
    }
    out.u64(m.profile.pack_bytes)?;
    out.u64(m.profile.decoded_bytes)?;
    out.u32(m.profile.delta_depth)?;
    Ok(())
}
fn write_progress(out: &mut Output, m: &CheckpointMeta) -> Result<(), Failure> {
    out.u64(m.generation)?;
    out.u64(m.sequence)?;
    out.byte(m.phase as u8)?;
    out.byte(u8::from(m.header.is_some()))?;
    if let Some((version, count)) = m.header {
        out.u32(version)?;
        out.u32(count)?;
    }
    out.u64(m.ordinal)?;
    out.u64(m.payload)?;
    out.append(&m.trailer)?;
    out.u64(m.retention_count)?;
    out.byte(u8::from(m.last_retained.is_some()))?;
    if let Some(page) = m.last_retained {
        out.append(&page.digest)?;
        out.byte(1)?;
        out.u64(page.len)?;
        out.u64(page.items)?;
    }
    for n in [
        m.usage.resident_bytes,
        m.usage.peak_resident_bytes,
        m.usage.evidence_bytes,
        m.usage.evidence_pages,
        m.usage.work,
    ] {
        out.u64(n)?;
    }
    Ok(())
}
fn write_integrity(out: &mut Output, integrity: Option<IntegrityView<'_>>) -> Result<(), Failure> {
    out.byte(u8::from(integrity.is_some()))?;
    if let Some(f) = integrity {
        out.u64(f.offset)?;
        out.hashes(f.whole_cvs)?;
        out.hashes(f.trailer_cvs)?;
        out.hash(f.whole_root)?;
        out.hash(f.trailer_root)?;
        out.append(&f.trailer)?;
        out.byte(f.trailer_used)?;
    }
    Ok(())
}
pub(crate) fn encode(
    view: &CheckpointView<'_>,
    limits: VerifyLimits,
) -> Result<Checkpoint, Failure> {
    validate_view(view)?;
    // Compute and reserve once: incremental exact reallocations would copy
    // already written frontiers repeatedly and obscure simultaneous residency.
    let frontier_bytes = view.integrity.map_or(0, |f| {
        47 + (f.whole_cvs.len() + f.trailer_cvs.len()) as u64 * 32
            + u64::from(f.whole_root.is_some()) * 32
            + u64::from(f.trailer_root.is_some()) * 32
    });
    let encoded_len = 369_u64
        .checked_add(u64::from(view.meta.header.is_some()) * 8)
        .and_then(|n| n.checked_add(u64::from(view.meta.last_retained.is_some()) * 49))
        .and_then(|n| n.checked_add(frontier_bytes))
        .and_then(|n| n.checked_add(view.cursor.len() as u64))
        .ok_or_else(resource)?;
    if encoded_len > view.meta.limits.checkpoint_bytes {
        return Err(invalid());
    }
    let mut budget = codec_budget(
        usize::try_from(encoded_len).map_err(|_| resource())?,
        limits,
    )?;
    budget.charge(0, encoded_len)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(usize::try_from(encoded_len).map_err(|_| resource())?)
        .map_err(|_| resource())?;
    let mut out = Output {
        bytes,
        cap: encoded_len,
        budget,
    };
    validate_cursor(view.cursor, &mut out.budget)?;
    write_binding(&mut out, &view.meta)?;
    write_progress(&mut out, &view.meta)?;
    write_integrity(&mut out, view.integrity)?;
    out.append(
        &u16::try_from(view.cursor.len())
            .map_err(|_| invalid())?
            .to_le_bytes(),
    )?;
    out.append(view.cursor)?;
    out.budget.charge(out.bytes.len() as u64, 0)?;
    let checksum = domain_digest(DOMAIN, &out.bytes);
    out.append(&checksum)?;
    if out.bytes.len() as u64 > view.meta.limits.checkpoint_bytes {
        return Err(invalid());
    }
    Ok(Checkpoint {
        bytes: out.bytes,
        meta: view.meta,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn view() -> CheckpointView<'static> {
        CheckpointView {
            meta: CheckpointMeta {
                source: PackSource {
                    id: [1; 32],
                    len: 44,
                    binding: SourceBinding([2; 32]),
                },
                repository: RepositoryId([3; 32]),
                ruleset: RulesetBinding {
                    ruleset: RulesetId(1),
                    profile: ProfileId::Indexed,
                },
                limits: VerifyLimits::indexed(),
                profile: IndexedProfile {
                    pack_bytes: MAX_PACK,
                    decoded_bytes: 4 << 30,
                    delta_depth: 32,
                },
                generation: 9,
                sequence: 0,
                phase: CheckpointPhase::Header,
                header: None,
                ordinal: 0,
                payload: 0,
                trailer: [0; 32],
                retention_count: 0,
                last_retained: None,
                usage: ResourceUsage::default(),
            },
            integrity: None,
            cursor: &[],
        }
    }
    fn resign(bytes: &mut [u8]) {
        let end = bytes.len() - 32;
        let checksum = domain_digest(DOMAIN, &bytes[..end]);
        bytes[end..].copy_from_slice(&checksum);
    }
    #[test]
    fn pinned_header_fixture_reencodes_without_changing_any_bytes() {
        let bytes = include_bytes!("../../fixtures/evidence/checkpoint-header.bin");
        let limits = VerifyLimits::indexed();
        let checkpoint = Checkpoint::from_bytes(bytes, limits).unwrap();
        let state = checkpoint.decode(limits).unwrap();
        let reencoded = encode(
            &CheckpointView {
                meta: state.meta,
                integrity: state.integrity.as_ref().map(IntegrityState::view),
                cursor: &state.cursor,
            },
            limits,
        )
        .unwrap();
        assert_eq!(reencoded.bytes(), bytes);
    }
    #[test]
    fn strict_version_checksum_truncation_trailing_and_caps() {
        let limits = VerifyLimits::indexed();
        let cp = encode(&view(), limits).unwrap();
        let decoded = Checkpoint::from_bytes(cp.bytes(), limits).unwrap();
        assert_eq!(decoded.decode(limits).unwrap().meta.generation, 9);
        for len in 0..cp.bytes().len() {
            assert!(Checkpoint::from_bytes(&cp.bytes()[..len], limits).is_err());
        }
        let mut wrong = cp.bytes().to_vec();
        wrong[4] = 2;
        resign(&mut wrong);
        assert_eq!(
            Checkpoint::from_bytes(&wrong, limits).unwrap_err().code,
            FailureCode::InvalidCheckpoint
        );
        let mut trailing = cp.bytes().to_vec();
        trailing.insert(trailing.len() - 32, 0);
        resign(&mut trailing);
        assert_eq!(
            Checkpoint::from_bytes(&trailing, limits).unwrap_err().code,
            FailureCode::TrailingData
        );
        assert_eq!(
            Checkpoint::from_bytes(
                cp.bytes(),
                VerifyLimits {
                    checkpoint_bytes: cp.bytes().len() as u64 - 1,
                    ..limits
                }
            )
            .unwrap_err()
            .code,
            FailureCode::ResourceLimit
        );
    }
    #[test]
    fn integrity_and_complete_optional_fields_roundtrip() {
        let limits = VerifyLimits::indexed();
        let mut v = view();
        v.meta.phase = CheckpointPhase::Integrity;
        v.meta.header = Some((1, 0));
        v.integrity = Some(IntegrityView {
            offset: 44,
            whole_cvs: &[],
            trailer_cvs: &[],
            whole_root: Some([1; 32]),
            trailer_root: Some([5; 32]),
            trailer: [5; 32],
            trailer_used: 32,
        });
        let cp = encode(&v, limits).unwrap();
        assert_eq!(cp.bytes().len(), 488);
        let restored = Checkpoint::from_bytes(cp.bytes(), limits)
            .unwrap()
            .decode(limits)
            .unwrap();
        assert_eq!(restored.integrity.unwrap().trailer_used, 32);
        v.meta.phase = CheckpointPhase::Complete;
        v.integrity = None;
        assert_eq!(
            Checkpoint::from_bytes(encode(&v, limits).unwrap().bytes(), limits)
                .unwrap()
                .decode(limits)
                .unwrap()
                .meta
                .phase,
            CheckpointPhase::Complete
        );
    }
    #[test]
    fn recomputed_checksum_does_not_excuse_inconsistent_counts() {
        let limits = VerifyLimits::indexed();
        let mut cp = encode(&view(), limits).unwrap();
        // Fixed prefix through limits/profile/generation/sequence/phase/header.
        let ordinal_offset = 4 + 2 + 32 + 8 + 32 + 32 + 4 + 1 + 84 + 20 + 16 + 1 + 1;
        cp.bytes[ordinal_offset] = 1;
        resign(&mut cp.bytes);
        assert!(Checkpoint::from_bytes(cp.bytes(), limits).is_err());
        let mut impossible = view();
        impossible.meta.phase = CheckpointPhase::Integrity;
        impossible.meta.header = Some((1, 0));
        impossible.integrity = Some(IntegrityView {
            offset: 0,
            whole_cvs: &[[1; 32]],
            trailer_cvs: &[],
            whole_root: None,
            trailer_root: None,
            trailer: [0; 32],
            trailer_used: 0,
        });
        assert!(encode(&impossible, limits).is_err());
    }
}
