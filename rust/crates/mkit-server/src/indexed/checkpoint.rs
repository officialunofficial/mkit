//! Job and checkpoint rows of scheduled verification (`vc`, WP-4.8).
//!
//! One job per (repository, pack) lives in the consuming ref shard. Every row
//! of a job sits under one prefix, so cleanup is a single range. Frame, child
//! and base rows are written idempotently ahead of the guarded job row that
//! commits a slice. Settled children are deleted with that checkpoint, so a
//! crash cannot discard the satisfying-pack dependency.

use super::state::VerificationV1;
use crate::repo::RepoName;
use crate::store::{
    codec::CODEC_V1,
    index::{IndexEntry, IndexValue},
    keys,
};
use crate::{Batch, NamespaceStore, Partition, StoreError, Value};
use mkit_core::hash::Hash;
use serde::{Deserialize, Serialize};

/// New progress per slice: one window, plus the current window on resume.
pub const WINDOW_BYTES: u64 = 16 << 20;
/// Entries one slice decodes before its next checkpoint, at most.
pub const DEFAULT_ENTRY_CAP: u32 = 4096;

/// Cursor bytes are hex strings; hashes use strict fixed-size JSON arrays.
mod hex {
    pub(super) mod bytes {
        use serde::{Deserialize, Deserializer, Serialize, Serializer};
        pub(in super::super) fn serialize<S: Serializer>(
            bytes: &[u8],
            s: S,
        ) -> Result<S::Ok, S::Error> {
            mkit_core::hash::to_hex_bytes(bytes).serialize(s)
        }
        pub(in super::super) fn deserialize<'de, D: Deserializer<'de>>(
            d: D,
        ) -> Result<Vec<u8>, D::Error> {
            let text = String::deserialize(d)?;
            if text.len() % 2 != 0 || !text.is_ascii() {
                return Err(serde::de::Error::custom("malformed hex"));
            }
            (0..text.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(serde::de::Error::custom))
                .collect()
        }
    }
}

/// Where a job is. `Recheck` and `Watch` follow `Verified`: the pack is
/// usable by an advance from `Recheck` on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// Window-by-window decode, hashing, signatures and frame rows.
    #[default]
    Decode,
    /// Owed closure children looked up in the repository's members.
    ClosureResolve,
    /// Index rows relayed to their shards, only after the pack decoded to `Done`.
    EmitIndex,
    /// Wait until every emitted relay row has been delivered (R-130).
    AwaitDelivery,
    /// Extraction slot: WP-4.10b fills it; this WP fails closed (R-163).
    Extract,
    /// Guarded `Pending` to `Verified` transition of `vs`.
    Verify,
    /// Final closure recheck once the membership lag window has passed.
    Recheck,
    /// Finished: waits for the ticket to close, then cleans its rows.
    Watch,
}

/// What kind of upload a job verifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// The first window is not read yet.
    #[default]
    Unknown,
    /// An MKIT pack.
    Pack,
    /// An MKPL packlist node.
    Packlist,
}

/// A terminal result that is never persisted as `Rejected`: its cause is the
/// repository's membership or the platform, not the pack (R-148).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// An external base was not a member after the lag window.
    BaseMissing,
    /// A fresh global denial: permission failure, distinct from unavailable storage.
    Blocked,
    /// An external base lookup hit an index cap.
    BaseCapped,
    /// A closure lookup hit an index cap.
    ClosureCapped,
    /// Whole-group closure was still open after the membership lag window.
    ClosureMissing,
    /// A named pack was still not a member after the membership lag window.
    PacklistMissing,
    /// The claimed head has a type that cannot be a history tip.
    OpenClosure,
    /// In-pack plus external chain depth passed the cap.
    ExternalTooDeep,
    /// The decode budget, or one object past the Worker's resident cap.
    DecodeBudget,
    /// The pack needs extraction, which the Worker cannot do yet (WP-4.10b).
    ExtractionUnavailable,
    /// A selected object became blocked before a holder could be queued.
    ObjectBlocked,
}

/// One immutable member of the Advance that claimed an extraction group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtractionGroupMember {
    /// Immutable source pack identity.
    pub pack: Hash,
    /// Ticket identity selected by the Advance.
    pub ticket: Hash,
    /// Declared pack length.
    pub bytes: u64,
    /// Source age for repository-local resolution failures.
    pub created_at_ms: u64,
    /// Native still stages this member's selection facts, but does not extract
    /// objects whose first owner was already verified.
    pub already_verified: bool,
}

/// The persisted state of one job, guarded by `vc` sub-class 0.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)] // Independent pack facts, lifetime and hydration markers.
pub struct VerifyJobV1 {
    /// Monotone across every mutation and retained Gone header.
    pub generation: u64,
    /// Cleanup retained this header after deleting its facts and bodies.
    pub gone: bool,
    /// Immutable satisfying-member and packlist body in this pack's vc4 range.
    pub member_body_id: Option<Hash>,
    /// Only hydrated jobs may replace the member lists.
    #[serde(skip)]
    pub members_loaded: bool,
    /// First consuming Advance's immutable head, checked before effects.
    pub extraction_head: Option<Hash>,
    /// Bounded extraction cursors; bulk parts, receipts and offsets stay in vc4.
    #[serde(default)]
    pub extraction: Option<ExtractionV1>,
    /// Ordered, atomically claimed first-Advance extraction context. Standalone
    /// jobs await a consuming Advance before an extraction group is claimed.
    #[serde(default)]
    pub extraction_group: Vec<ExtractionGroupMember>,
    /// The ticket this job serves; the job lives while that ticket does.
    pub ticket_id: Hash,
    /// That ticket's creation time: the start of the membership lag window.
    pub created_at_ms: u64,
    /// Declared pack length.
    pub pack_len: u64,
    /// Current phase.
    pub phase: Phase,
    /// Upload type, known after the first window.
    pub kind: Kind,
    /// Pack format version, known after the first window.
    pub version: u32,
    /// `WindowCursor` bytes at the last checkpoint; empty before the first.
    #[serde(with = "hex::bytes")]
    pub cursor: Vec<u8>,
    /// Object-store etag every window read is bound to (SPEC-PACKFILE §11).
    pub etag: Option<String>,
    /// Entries decoded up to `cursor`.
    pub entries: u64,
    /// Sum of first-occurrence decoded sizes.
    pub in_pack_bytes: u64,
    /// Sum of distinct external base and chain-intermediate sizes.
    pub external_bytes: u64,
    /// Windows read so far, for `Retry-After`.
    pub windows_done: u32,
    /// Slices started on the current cursor.
    pub attempts: u32,
    /// Entries one slice may decode; halved after repeated failures.
    pub entry_cap: u32,
    /// Closure ids per slice; repeated interrupted passes shrink this to one.
    pub closure_cap: u32,
    /// Times a source change restarted the job.
    pub restarts: u8,
    /// A bad signature was seen; reported only if the pack decodes to `Done`.
    pub bad_signature: bool,
    /// An entry needs extraction (see [`Outcome::ExtractionUnavailable`]).
    pub extract_needed: bool,
    /// Last examined closure id (or emit page); advances with guarded deletions.
    #[serde(with = "hex::bytes")]
    pub scan: Vec<u8>,
    /// Owed closure children seen in the current pass.
    pub owed: u64,
    /// Whether the current closure pass is the final recheck.
    pub final_pass: bool,
    /// Distinct member packs that satisfied a child.
    #[serde(skip)]
    pub satisfying: Vec<Hash>,
    /// The last relay sequence this job enqueued.
    pub last_relay_seq: Option<u64>,
    /// When the final closure recheck finished.
    pub closure_final_at_ms: Option<u64>,
    /// The packs a packlist names.
    #[serde(skip)]
    pub packlist: Vec<Hash>,
    /// Verified MKPL predecessor, checkpointed with its decoded header.
    #[serde(default)]
    pub packlist_prev: Option<Hash>,
    /// A terminal non-persisted result.
    pub outcome: Option<Outcome>,
}

/// Resumable driver progress. Every bulk row is keyed by the frozen group digest.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtractionV1 {
    /// Immutable decoded member descriptors captured before effects.
    pub sources: Vec<ExtractionSource>,
    /// Domain separated group identity.
    pub group: Hash,
    /// Scan, selection, source verification, upload, offsets, enqueue or delivery.
    pub stage: u8,
    /// Group scan's member cursor.
    pub member: usize,
    /// Frame scan cursor.
    #[serde(with = "hex::bytes")]
    pub scan: Vec<u8>,
    /// Distinct canonical objects in the frozen group.
    pub staged_objects: u64,
    /// Union canonical bytes.
    pub staged_bytes: u64,
    /// Union selected content bytes.
    pub selected_bytes: u64,
    /// Current selected object.
    pub object: Option<Hash>,
    /// Declared current object length.
    pub length: u64,
    /// Next chunk to resolve.
    pub chunk: u32,
    /// Bytes already consumed from the current canonical chunk.
    pub chunk_offset: u64,
    /// Verified content bytes stored in bounded local fragments.
    pub written: u64,
    /// Parts whose CV was computed.
    pub cvs: u32,
    /// Content root computed before any publication.
    pub root: Option<Hash>,
    /// Root pinned opaque backend session.
    #[serde(with = "hex::bytes")]
    pub session: Vec<u8>,
    /// Parts committed to the backend.
    pub uploaded: u32,
    /// Atomic holder outbox sequence.
    pub relay: Option<u64>,
    /// Resumable member reconstruction; ancestry and bytes remain in vc4.
    pub reconstruction: Option<MemberCursor>,
}

/// One member resolution; only its immediate canonical parent remains live.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberCursor {
    /// Immutable source being resolved.
    pub target: Hash,
    /// Current descent frontier.
    pub next: Hash,
    /// Previous pack and offset for same-pack preference.
    pub preferred: Option<(Hash, u64)>,
    /// Stack row cursor.
    pub level: u32,
    /// Whether the current descent still follows a staged pack.
    pub local: bool,
    /// Decode the stored chain toward its requested source.
    pub ascending: bool,
    /// Immediate canonical parent (id, length, total depth, source pack).
    pub canonical: Option<(Hash, u64, u32, Hash)>,
    /// Native canonical byte cost, including discarded ancestors.
    pub bytes: u64,
}

/// Identity of one verified source's selection facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtractionSource {
    /// Ordered immutable group member.
    pub member: ExtractionGroupMember,
    /// Bounded content addressed `ETag` token.
    pub etag: Option<String>,
    /// Canonical source pack version.
    pub version: u32,
    /// Completed frame count.
    pub entries: u64,
    /// Canonical bytes this source decoded.
    pub decoded: u64,
    /// Immutable member lists validated by the frozen closure barrier.
    pub member_body_id: Option<Hash>,
}

impl VerifyJobV1 {
    pub(super) fn closure_retry(&self) -> bool {
        matches!(
            self.outcome,
            Some(Outcome::ClosureMissing | Outcome::PacklistMissing | Outcome::BaseCapped)
        ) && self
            .extraction
            .as_ref()
            .is_some_and(|x| x.object.is_none() && (x.stage <= 2 || (10..=13).contains(&x.stage)))
    }

    /// A job for `ticket`, at the start of `Decode`.
    #[must_use]
    pub fn new(ticket_id: Hash, created_at_ms: u64, pack_len: u64, entry_cap: u32) -> Self {
        Self {
            ticket_id,
            created_at_ms,
            pack_len,
            entry_cap,
            closure_cap: 4,
            members_loaded: true,
            ..Self::default()
        }
    }

    /// The job's progress reset for a fresh run: a source changed.
    pub fn restart(&mut self) {
        let fresh = Self::new(
            self.ticket_id,
            self.created_at_ms,
            self.pack_len,
            self.entry_cap,
        );
        *self = Self {
            restarts: self.restarts.saturating_add(1),
            extraction_group: self.extraction_group.clone(),
            extraction_head: self.extraction_head,
            ..fresh
        };
    }

    /// Whether an advance may rely on the pack: verified, extracted, indexed.
    #[must_use]
    pub fn usable(&self) -> bool {
        !self.gone && self.outcome.is_none() && matches!(self.phase, Phase::Recheck | Phase::Watch)
    }
}

/// Encode a job with the metadata codec version byte.
///
/// # Panics
/// Serializing this fixed DTO into a `Vec` cannot fail.
#[must_use]
pub fn encode_job(job: &VerifyJobV1) -> Value {
    let mut bytes = vec![CODEC_V1];
    serde_json::to_writer(&mut bytes, job).expect("job DTO serializes");
    Value::new(bytes)
}

/// Decode a job, failing closed on corrupt or future values.
pub fn decode_job(value: &Value) -> Result<VerifyJobV1, StoreError> {
    let Some((&CODEC_V1, body)) = value.as_bytes().split_first() else {
        return Err(StoreError::Corrupt("bad verification job version".into()));
    };
    let mut job: VerifyJobV1 = serde_json::from_slice(body)
        .map_err(|_| StoreError::Corrupt("bad verification job".into()))?;
    validate_header(&job, value)?;
    if job.kind == Kind::Packlist && job.phase == Phase::Verify && !job.gone {
        // Legacy jobs already decoded the list, but did not checkpoint its
        // predecessor. Re-read the bounded MKPL window before sealing facts;
        // absence must not be interpreted as a verified null predecessor.
        #[derive(Deserialize)]
        struct Presence {
            #[serde(default, deserialize_with = "present")]
            packlist_prev: bool,
        }
        fn present<'de, D: serde::Deserializer<'de>>(d: D) -> Result<bool, D::Error> {
            Option::<Hash>::deserialize(d).map(|_| true)
        }
        let presence: Presence = serde_json::from_slice(body)
            .map_err(|_| StoreError::Corrupt("bad verification job".into()))?;
        if !presence.packlist_prev {
            job.phase = Phase::Decode;
            job.scan.clear();
        }
    }
    Ok(job)
}

/// Every guarded header is small even with seven source snapshots. Window
/// cursors are at most 4KiB; extraction starts only after that cursor clears.
pub const MAX_JOB_HEADER_BYTES: usize = 16 << 10;

fn validate_header(job: &VerifyJobV1, raw: &Value) -> Result<(), StoreError> {
    let bounded = raw.as_bytes().len() <= MAX_JOB_HEADER_BYTES
        && job.cursor.len() <= 4096
        && job.scan.len() <= 324
        && job.etag.as_ref().is_none_or(|e| e.len() <= 64)
        && job.extraction_group.len() <= crate::store::outbox::MAX_TICKETS_PER_ADVANCE
        && job.extraction.as_ref().is_none_or(|x| {
            job.cursor.is_empty()
                && x.scan.len() <= 324
                && x.session.len() <= 1024
                && x.cvs <= 10_000
                && x.uploaded <= 10_000
                && x.reconstruction
                    .as_ref()
                    .is_none_or(|r| r.canonical.is_none_or(|(_, n, _, _)| n <= 8 << 20))
                && x.stage <= 13
                && x.member <= x.sources.len()
                && x.sources.len() <= crate::store::outbox::MAX_TICKETS_PER_ADVANCE
                && x.sources
                    .iter()
                    .all(|s| s.etag.as_ref().is_none_or(|e| e.len() <= 64))
        });
    if bounded {
        Ok(())
    } else {
        Err(StoreError::Corrupt("oversized job header".into()))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MemberLists {
    satisfying: Vec<Hash>,
    packlist: Vec<Hash>,
}

fn member_id(bytes: &[u8]) -> Hash {
    let mut h = mkit_core::hash::Hasher::new();
    h.update(b"mkit-job-members:v1");
    h.update(bytes);
    h.finalize()
}
fn member_key(repo: &RepoName, pack: &Hash, id: &Hash) -> crate::Key {
    keys::verify_row(repo, pack, keys::VC_CANDIDATE, Some(id))
}

/// Append a generation-bumped header and, only when changed, its immutable
/// lists. The caller must guard the exact prior header and its deadline.
pub fn write_job(
    mut batch: Batch,
    job: &mut VerifyJobV1,
    prior: Option<&Value>,
    repo: &RepoName,
    pack: &Hash,
) -> Result<Batch, StoreError> {
    let old = prior.map(decode_job).transpose()?;
    job.generation = old
        .as_ref()
        .map_or(0, |j| j.generation)
        .checked_add(1)
        .ok_or_else(|| StoreError::Corrupt("job generation overflow".into()))?;
    let old_body = old.as_ref().and_then(|j| j.member_body_id);
    if job.members_loaded {
        if job.satisfying.len() > crate::store::index::MAX_LOOKUP_IDS
            || job.packlist.len()
                > crate::store::index::MAX_LOOKUP_IDS
                    + crate::store::outbox::MAX_TICKETS_PER_ADVANCE
        {
            return Err(StoreError::Corrupt("oversized job member lists".into()));
        }
        job.member_body_id = if job.satisfying.is_empty() && job.packlist.is_empty() {
            None
        } else {
            let mut bytes = vec![CODEC_V1];
            serde_json::to_writer(
                &mut bytes,
                &MemberLists {
                    satisfying: job.satisfying.clone(),
                    packlist: job.packlist.clone(),
                },
            )
            .map_err(StoreError::unavailable)?;
            let id = member_id(&bytes);
            if Some(id) != old_body {
                batch = batch.put(member_key(repo, pack, &id), Value::new(bytes));
            }
            Some(id)
        };
    } else if job.member_body_id != old_body {
        return Err(StoreError::Corrupt(
            "unloaded job member lists changed".into(),
        ));
    }
    let header = encode_job(job);
    validate_header(job, &header)?;
    Ok(batch.put(keys::verify_job(repo, pack), header))
}

/// Hydrate a header without expanding any peer's guarded value. Bodies are
/// content addressed and remain immutable until the job's guarded cleanup.
pub async fn hydrate_job<S: NamespaceStore>(
    store: &S,
    source: &Partition,
    repo: &RepoName,
    pack: &Hash,
    job: &mut VerifyJobV1,
) -> Result<(), StoreError> {
    if !job.gone
        && let Some(id) = job.member_body_id
    {
        let raw = store
            .get(source, &member_key(repo, pack, &id))
            .await?
            .ok_or_else(|| StoreError::Unavailable("job member body disappeared".into()))?;
        let Some((&CODEC_V1, bytes)) = raw.as_bytes().split_first() else {
            return Err(StoreError::Corrupt("bad job member body version".into()));
        };
        if member_id(raw.as_bytes()) != id {
            return Err(StoreError::Corrupt("bad job member body digest".into()));
        }
        let lists: MemberLists = serde_json::from_slice(bytes)
            .map_err(|_| StoreError::Corrupt("bad job member body".into()))?;
        if lists.satisfying.len() > crate::store::index::MAX_LOOKUP_IDS
            || lists.packlist.len()
                > crate::store::index::MAX_LOOKUP_IDS
                    + crate::store::outbox::MAX_TICKETS_PER_ADVANCE
        {
            return Err(StoreError::Corrupt("oversized job member body".into()));
        }
        job.satisfying = lists.satisfying;
        job.packlist = lists.packlist;
    }
    job.members_loaded = true;
    Ok(())
}

/// A pack entry as the job recorded it. First occurrence wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameRow {
    /// Location, sizes and in-pack depth, as the index row will carry them.
    pub value: IndexValue,
    /// Object type tag, for the head check.
    pub object_type: u8,
    /// The external base this entry's delta chain ends at, if any.
    pub external: Option<Hash>,
}

/// Encode a frame row: type, optional external base, then the index value.
pub fn encode_frame(id: &Hash, row: &FrameRow) -> Result<Value, StoreError> {
    let index = crate::store::codec::encode_object_index(id, &row.value)?;
    let mut bytes = vec![row.object_type, u8::from(row.external.is_some())];
    if let Some(base) = &row.external {
        bytes.extend_from_slice(base);
    }
    bytes.extend_from_slice(index.as_bytes());
    Ok(Value::new(bytes))
}

/// Decode a frame row for object `id`.
pub fn decode_frame(id: &Hash, value: &Value) -> Result<FrameRow, StoreError> {
    let corrupt = || StoreError::Corrupt("bad verification frame row".into());
    let bytes = value.as_bytes();
    let (&object_type, rest) = bytes.split_first().ok_or_else(corrupt)?;
    let (external, rest) = match rest.split_first() {
        Some((0, rest)) => (None, rest),
        Some((1, rest)) => {
            let (base, rest) = rest.split_first_chunk::<32>().ok_or_else(corrupt)?;
            (Some(*base), rest)
        }
        _ => return Err(corrupt()),
    };
    Ok(FrameRow {
        value: crate::store::codec::decode_object_index(id, &Value::new(rest.to_vec()))?,
        object_type,
        external,
    })
}

/// An external base row: location-keyed rows charge size once using the first
/// entry marker; object-keyed zero-size rows retain the base's chain depth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BaseRow {
    /// Decoded size of the base object.
    pub size: u64,
    /// Total delta depth of the base in its member pack.
    pub depth: u32,
    /// Index of the first entry that needed it.
    pub entry: u64,
}

/// Encode a base row.
#[must_use]
pub fn encode_base(row: &BaseRow) -> Value {
    let mut bytes = row.size.to_be_bytes().to_vec();
    bytes.extend_from_slice(&row.depth.to_be_bytes());
    bytes.extend_from_slice(&row.entry.to_be_bytes());
    Value::new(bytes)
}

/// Decode a base row.
pub fn decode_base(value: &Value) -> Result<BaseRow, StoreError> {
    let bytes: &[u8; 20] = value
        .as_bytes()
        .try_into()
        .map_err(|_| StoreError::Corrupt("bad verification base row".into()))?;
    Ok(BaseRow {
        size: u64::from_be_bytes(bytes[..8].try_into().unwrap_or_default()),
        depth: u32::from_be_bytes(bytes[8..12].try_into().unwrap_or_default()),
        entry: u64::from_be_bytes(bytes[12..].try_into().unwrap_or_default()),
    })
}

/// The index entry a frame row stands for.
#[must_use]
pub fn index_entry(id: Hash, row: &FrameRow) -> IndexEntry {
    IndexEntry {
        object: id,
        value: row.value,
    }
}

/// The reference of a job's timer: `repo 00 pack`.
#[must_use]
pub fn timer_reference(repo: &RepoName, pack: &Hash) -> Vec<u8> {
    let mut reference = repo.as_str().as_bytes().to_vec();
    reference.push(0);
    reference.extend_from_slice(pack);
    reference
}

/// Split a timer reference back into its repository and pack.
#[must_use]
pub fn parse_reference(reference: &[u8]) -> Option<(RepoName, Hash)> {
    let sep = reference.iter().position(|&b| b == 0)?;
    let pack: Hash = reference[sep + 1..].try_into().ok()?;
    let repo = RepoName::new(String::from_utf8(reference[..sep].to_vec()).ok()?).ok()?;
    Some((repo, pack))
}

type Stored<T> = Option<(T, Value)>;

/// The job row and `vs` in one read.
pub async fn read_job<S: NamespaceStore>(
    store: &S,
    source: &Partition,
    repo: &RepoName,
    pack: &Hash,
) -> Result<(Stored<VerifyJobV1>, Stored<VerificationV1>), StoreError> {
    let rows = store
        .get_many(
            source,
            &[keys::verify_job(repo, pack), keys::verification(repo, pack)],
        )
        .await?;
    let [job, state] = <[_; 2]>::try_from(rows)
        .map_err(|_| StoreError::Corrupt("short verification read".into()))?;
    let job = if let Some(raw) = job {
        let mut job = decode_job(&raw)?;
        hydrate_job(store, source, repo, pack, &mut job).await?;
        Some((job, raw))
    } else {
        None
    };
    Ok((
        job,
        state
            .map(|raw| super::state::decode(&raw).map(|state| (state, raw)))
            .transpose()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_frame_and_base_codecs_round_trip() {
        let mut job = VerifyJobV1::new([1; 32], 5, 99, 4096);
        job.cursor = vec![0xab, 0x01];
        job.satisfying = vec![[2; 32]];
        job.outcome = Some(Outcome::BaseMissing);
        let header = decode_job(&encode_job(&job)).unwrap();
        assert!(header.satisfying.is_empty());
        assert!(!header.members_loaded);
        assert_eq!(header.outcome, job.outcome);
        assert!(decode_job(&Value::new(b"\x02{}".to_vec())).is_err());
        let frame = FrameRow {
            value: IndexValue {
                frame_offset: 12,
                frame_length: 40,
                wire_type: 0x02,
                decoded_size: 7,
                chain_depth: 2,
                delta_base: Some([3; 32]),
            },
            object_type: 3,
            external: Some([4; 32]),
        };
        let id = [9; 32];
        assert_eq!(
            decode_frame(&id, &encode_frame(&id, &frame).unwrap()).unwrap(),
            frame
        );
        let base = BaseRow {
            size: 1,
            depth: 2,
            entry: 3,
        };
        assert_eq!(decode_base(&encode_base(&base)).unwrap(), base);
        let name = RepoName::new("a").unwrap();
        assert_eq!(
            parse_reference(&timer_reference(&name, &[7; 32])),
            Some((name, [7; 32]))
        );
        job.restart();
        assert_eq!(
            (job.restarts, job.phase, job.cursor.len()),
            (1, Phase::Decode, 0)
        );
    }
}

#[cfg(test)]
mod legacy_tests {
    use super::*;
    // Exact version-one JSON fields at 8948ae34; not generated by today's DTO.
    const LEGACY_JOB: &[u8] = b"\x01{\"generation\":1,\"gone\":false,\"member_body_id\":null,\"extraction_head\":null,\"extraction\":null,\"extraction_group\":[],\"ticket_id\":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],\"created_at_ms\":0,\"pack_len\":100,\"phase\":\"watch\",\"kind\":\"packlist\",\"version\":1,\"cursor\":\"\",\"etag\":null,\"entries\":0,\"in_pack_bytes\":0,\"external_bytes\":0,\"windows_done\":1,\"attempts\":1,\"entry_cap\":4096,\"closure_cap\":4,\"restarts\":0,\"bad_signature\":false,\"extract_needed\":false,\"scan\":\"\",\"owed\":0,\"final_pass\":false,\"last_relay_seq\":null,\"closure_final_at_ms\":null,\"outcome\":null}";
    #[test]
    fn legacy_in_progress_packlist_redecodes_instead_of_assuming_null_predecessor() {
        let json = String::from_utf8(LEGACY_JOB[1..].to_vec())
            .unwrap()
            .replace("\"phase\":\"watch\"", "\"phase\":\"verify\"");
        let job = decode_job(&Value::new([vec![CODEC_V1], json.into_bytes()].concat())).unwrap();
        assert_eq!(job.phase, Phase::Decode);
        assert_eq!(job.generation, 1);
        let current = VerifyJobV1 {
            phase: Phase::Verify,
            ..job
        };
        assert_eq!(
            decode_job(&encode_job(&current)).unwrap().phase,
            Phase::Verify
        );
    }

    #[test]
    fn legacy_packlist_checkpoint_decodes_without_predecessor_field() {
        let job = decode_job(&Value::new(LEGACY_JOB.to_vec())).unwrap();
        assert_eq!(job.packlist_prev, None);
        assert_eq!(job.kind, Kind::Packlist);
        assert_eq!(job.phase, Phase::Watch);
        assert_eq!(decode_job(&encode_job(&job)).unwrap(), job);
    }
}
