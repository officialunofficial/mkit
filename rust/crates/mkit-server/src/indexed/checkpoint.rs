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
use crate::{NamespaceStore, Partition, StoreError, Value};
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
    /// An external base lookup hit an index cap.
    BaseCapped,
    /// A closure lookup hit an index cap.
    ClosureCapped,
    /// In-pack plus external chain depth passed the cap.
    ExternalTooDeep,
    /// The decode budget, or one object past the Worker's resident cap.
    DecodeBudget,
    /// The pack needs extraction, which the Worker cannot do yet (WP-4.10b).
    ExtractionUnavailable,
}

/// The persisted state of one job, guarded by `vc` sub-class 0.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyJobV1 {
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
    pub satisfying: Vec<Hash>,
    /// The last relay sequence this job enqueued.
    pub last_relay_seq: Option<u64>,
    /// When the final closure recheck finished.
    pub closure_final_at_ms: Option<u64>,
    /// The packs a packlist names.
    pub packlist: Vec<Hash>,
    /// A terminal non-persisted result.
    pub outcome: Option<Outcome>,
}

impl VerifyJobV1 {
    /// A job for `ticket`, at the start of `Decode`.
    #[must_use]
    pub fn new(ticket_id: Hash, created_at_ms: u64, pack_len: u64, entry_cap: u32) -> Self {
        Self {
            ticket_id,
            created_at_ms,
            pack_len,
            entry_cap,
            closure_cap: 4,
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
            ..fresh
        };
    }

    /// Whether an advance may rely on the pack: verified, extracted, indexed.
    #[must_use]
    pub fn usable(&self) -> bool {
        self.outcome.is_none() && matches!(self.phase, Phase::Recheck | Phase::Watch)
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
    serde_json::from_slice(body).map_err(|_| StoreError::Corrupt("bad verification job".into()))
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
    Ok((
        job.map(|raw| decode_job(&raw).map(|job| (job, raw)))
            .transpose()?,
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
        assert_eq!(decode_job(&encode_job(&job)).unwrap(), job);
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
