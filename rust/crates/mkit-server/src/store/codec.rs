//! Value codecs. Structured values are `serde_json` behind a leading
//! version byte ([`CODEC_V1`]); refs are the raw 32-byte id and integers
//! are raw big-endian. Decoding an unknown version, a wrong length or a
//! value that fails validation is [`StoreError::Corrupt`].

use mkit_core::hash::{Hash, from_hex, to_hex, to_hex_bytes};
use mkit_core::protocol::AdvanceOutcome;
use serde::{Deserialize, Serialize};

use super::content_index::{BlockEntry, HolderRecord, ObjectState};
use super::error::StoreError;
use super::index::IndexValue;
use super::keys::validate_reservation_id;
use super::kv::{Key, MAX_KEY_BYTES, MAX_VALUE_BYTES, Value};
use super::partition::Partition;
use crate::error::Code;
use crate::quota::{NamespaceUsage, NamespaceView, QuotaState};
use crate::refs::is_served_ref_name;
use crate::replay::{
    BeginUploadResult, ReplayRecord, ReplayState, StoredRejection, StoredResult, UpdateRefResult,
};
use crate::repo::RepoName;
use mkit_core::repo_identity::RepositoryIdentity;
use mkit_core::upload_parts::MIN_PART_SIZE;
use mkit_core::write_auth::is_hex;

/// The namespace coordinator record. The first configuration version is 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceRecord {
    /// Creation time, Unix milliseconds from the business clock.
    pub created_at_ms: u64,
    /// Namespace configuration version, starting at 1.
    pub config_version: u64,
}

/// The repository coordinator record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepoRecord {
    /// Creation time, Unix milliseconds from the business clock.
    pub created_at_ms: u64,
}

/// A repository's stored visibility (SPEC-WRITE-GRANTS §9.1). A missing
/// `rv` row inherits the deployment default; the row may exist before `rr` does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepoVisibilityV1 {
    /// The repository's visibility.
    pub visibility: StoredVisibility,
    /// The newer of the last accepted statement's `created` and the last
    /// envelope write's time; 0 before any write.
    pub last_created_ms: u64,
    /// The last accepted statement's id, 64 lowercase hex. The key is
    /// always present in a stored row (`null` when none): a row missing it
    /// is corrupt.
    #[serde(deserialize_with = "present_option")]
    pub last_statement_id: Option<String>,
    /// The server clock when the row last changed visibility (envelope or
    /// statement), Unix milliseconds. URL tokens issued at or before it are
    /// refused (SPEC-WRITE-GRANTS §9.4). Absent in a row stored before the
    /// field existed; read it through [`Self::visibility_changed_ms`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed_ms: Option<u64>,
}

impl RepoVisibilityV1 {
    /// The time of the last visibility change. A legacy row has none, so
    /// its `last_created_ms` stands in: the envelope path stored server
    /// time there and the statement path the accepted `created`, never
    /// earlier than the change, so the fallback fails closed.
    #[must_use]
    pub fn visibility_changed_ms(&self) -> u64 {
        self.changed_ms.unwrap_or(self.last_created_ms)
    }
}

/// Deserialize an `Option` whose key must be present (serde would default
/// a missing `Option` field to `None`).
fn present_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

/// The visibility values a `rv` row stores.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StoredVisibility {
    /// Readable by every caller, anonymous or signed.
    Public,
    /// Readable only by a signed, authorized caller (§9.3).
    Private,
}

/// The ref shard's durable copy of its coordinator epoch lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpochLease {
    /// Initial generation-zero activation barrier completed before this grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_ready: Option<bool>,
    /// Epoch against which the shard can authorize writes.
    pub epoch: u64,
    /// Lease expiry, Unix milliseconds from the pipeline clock.
    pub expires_at_ms: u64,
    /// Namespace configuration version at grant, starting at 1.
    pub config_version: u64,
    /// Independent authority generation; absent in legacy unfenced codecs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_generation: Option<u64>,
}

/// The coordinator's durable lease grant and installation acknowledgement.
///
/// `acked_epoch = n` means the shard durably holds epoch at least `n`, or
/// every older-epoch write is already past its deadline. A live row's
/// acknowledgement is preserved by renewal and raised only after a
/// committed shard push. An absent or expired row may acknowledge its grant
/// immediately because older writes are past their commit deadlines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeasedShard {
    /// Epoch granted by the most recent renewal.
    pub epoch: u64,
    /// Granted expiry; identical to the shard copy at grant.
    pub expires_at_ms: u64,
    /// Epoch whose installation in the shard has been acknowledged.
    pub acked_epoch: u64,
    /// Authority generation granted alongside the epoch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_generation: Option<u64>,
    /// Raised only after a committed push, or expiry of every older lease.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acked_authority_generation: Option<u64>,
    /// Greatest source relay lower bound observed for this shard.
    pub relay_watermark_ms: u64,
    /// Due time of the one sweep timer owned by this row.
    pub sweep_due_ms: u64,
}

/// Declared coordinator recovery, retained until a later recovery overwrites it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseRecovery {
    /// Durable namespace authority mode, independent of business creation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_fence: Option<bool>,
    /// Initial barrier is complete; fenced grants can now be installed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_ready: Option<bool>,
    /// This row carries activation state without declaring a real recovery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation_only: Option<bool>,
    /// Recovery time, Unix milliseconds from the pipeline clock.
    pub resumed_at_ms: u64,
}

impl LeaseRecovery {
    /// Actual recovery time; a pure activation marker creates no holdoff.
    #[must_use]
    pub fn recovery_time(self) -> Option<u64> {
        (self.activation_only != Some(true)).then_some(self.resumed_at_ms)
    }
}

/// The last consistent Worker snapshot of one partition. A zero export time
/// and empty key mark a timer that has been seeded but has not fired yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupStateV1 {
    /// Export time encoded in the last uploaded snapshot, Unix milliseconds.
    pub last_export_ms: u64,
    /// BLAKE3 of the last uploaded portable export.
    pub digest: Hash,
    /// R2 object key of the last upload.
    pub r2_key: String,
    /// Time of the last successful upload, Unix milliseconds.
    pub last_upload_ms: u64,
}

/// An open upload ticket. Its audience is bound by the shard's deployment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TicketV1 {
    /// Authority generation authorized when this ticket was created.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_generation: Option<u64>,
    /// Repository name within the partition's namespace.
    #[serde(with = "repo_json")]
    pub repo: RepoName,
    /// Ref authorized to consume the ticket.
    pub ref_name: String,
    /// Authorized signer.
    #[serde(with = "hash_json")]
    pub signer: Hash,
    /// Expected pack id.
    #[serde(with = "hash_json")]
    pub pack_id: Hash,
    /// Declared nonzero pack size.
    pub bytes: u64,
    /// Power-of-two part size, at least the protocol minimum.
    pub part_size: u64,
    /// Expiry, Unix milliseconds.
    pub expires_at_ms: u64,
    /// Creation, Unix milliseconds.
    pub created_at_ms: u64,
    /// One durable outcome id, including synthetic ids for default admission.
    pub reservation_id: String,
    /// Backend multipart upload session, when allocated.
    #[serde(with = "optional_bytes_hex_json")]
    pub upload_session: Option<Vec<u8>>,
}

/// The hooks protocol's terminal abort reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AbortReason {
    /// A policy or pre-apply refusal without a more specific reason.
    Unspecified,
    /// A guarded ref update failed.
    RefConflict,
    /// An epoch changed.
    EpochMismatch,
    /// A required pack is missing.
    PackMissing,
    /// A concurrent request won the replay race.
    ReplayRace,
    /// An internal failure prevented the apply.
    Internal,
    /// Reconcile found an abandoned pending reservation.
    Abandoned,
}

/// The operation a pending reservation will settle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingOp {
    /// A directly admitted write or `BeginUpload`.
    Write,
    /// An admitted HTTP read.
    Read,
}

/// A ref changed by a committed reservation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomeRef {
    /// Full ref name.
    pub name: String,
    /// New ref target; absent on deletion.
    #[serde(with = "optional_hash_json")]
    pub new: Option<Hash>,
    /// Whether this ref was deleted.
    pub deleted: bool,
}

/// The one durable reservation arbiter, replaced under an Equals guard.
///
/// Unknown state tags fail decoding, so older readers fail closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReservationV1 {
    /// Admission's durable pre-apply arbiter.
    Pending {
        /// Full wire repository identity (or bare single-deployment name).
        repository: String,
        /// Creation time, Unix milliseconds.
        created_at_ms: u64,
        /// Earliest safe reconciliation time, Unix milliseconds.
        reconcile_at_ms: u64,
        /// Write or read semantics.
        op: PendingOp,
    },
    /// Successful `BeginUpload`, awaiting ticket consumption or expiry.
    Ticketed {
        /// Bound ticket id.
        #[serde(with = "hash_json")]
        ticket_id: Hash,
    },
    /// A committed apply, including its byte accounting and ref changes.
    Committed {
        /// Full wire repository identity (or a bare single-deployment name).
        repository: String,
        /// Outcome time, Unix milliseconds.
        occurred_at_ms: u64,
        /// Stored bytes.
        bytes_stored: u64,
        /// Bytes new to the repository.
        new_to_repo: u64,
        /// Bytes new to the store.
        new_to_store: u64,
        /// Ref changes included in this apply.
        refs: Vec<OutcomeRef>,
    },
    /// Failed apply or abandoned pending reservation.
    Aborted {
        /// Full wire repository identity (or a bare single-deployment name).
        repository: String,
        /// Outcome time, Unix milliseconds.
        occurred_at_ms: u64,
        /// Stable hooks reason.
        reason: AbortReason,
        /// Safe diagnostic detail, bounded to 512 UTF-8 bytes.
        detail: String,
    },
    /// An unconsumed ticket expired.
    Expired {
        /// Full wire repository identity (or a bare single-deployment name).
        repository: String,
        /// Outcome time, Unix milliseconds.
        occurred_at_ms: u64,
    },
    /// An admitted HTTP read, including partial delivery.
    ReadServed {
        /// Full wire repository identity (or bare single-deployment name).
        repository: String,
        /// Completion time, Unix milliseconds.
        occurred_at_ms: u64,
        /// Object identifier served.
        #[serde(with = "hash_json")]
        object: Hash,
        /// Actual body bytes sent; zero for HEAD.
        bytes_served: u64,
    },
}

/// An idempotent relay of upserts and deletes to one partition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayV1 {
    /// Writer plan-time lower bound on commit time. V1 changed in place before deployment.
    pub at_ms: u64,
    /// Destination partition.
    pub target: Partition,
    /// Idempotent key/value upserts.
    pub puts: Vec<(Key, Value)>,
    /// Keys removed after this row's upserts.
    pub deletes: Vec<Key>,
}

/// Maximum retained targets in a persistent relay scan cycle.
pub const MAX_BLOCKED_TARGETS: usize = 32;

/// Source-local scan progress. Every retained row at or below `cursor`
/// belongs to a blocked target; new rows beyond `cycle_end` wait for the
/// next cycle. The relay checkpoints this row under a guard on its prior value,
/// atomically deleting delivered queue rows. Timer rescheduling is separate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayScanV1 {
    /// Source `os` observed when the scan cycle started.
    pub cycle_end: u64,
    /// Last inspected relay sequence, or zero before the first row.
    pub cursor: u64,
    /// Sorted, unique retained targets in [`Partition`] order.
    pub blocked: Vec<Partition>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayScanDtoV1 {
    cycle_end: u64,
    cursor: u64,
    blocked: Vec<String>,
}

/// Terminal outcome backlog. Relay rows are excluded.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Backlog {
    /// Number of terminal outcome rows.
    pub rows: u64,
    /// Sum of terminal outcome key lengths plus encoded value lengths.
    pub bytes: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayDtoV1 {
    at_ms: u64,
    target: String,
    puts: Vec<(String, String)>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    deletes: Vec<String>,
}

mod hash_json {
    use super::{Deserialize, Hash, from_hex, to_hex};
    pub(super) fn serialize<S: serde::Serializer>(
        hash: &Hash,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&to_hex(hash))
    }
    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Hash, D::Error> {
        let s = String::deserialize(deserializer)?;
        from_hex(&s).map_err(serde::de::Error::custom)
    }
}

mod optional_hash_json {
    use super::{Deserialize, Hash, Serialize, from_hex, to_hex};
    // serde with-module serialization requires a reference to the field.
    #[allow(clippy::ref_option)]
    pub(super) fn serialize<S: serde::Serializer>(
        hash: &Option<Hash>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        hash.as_ref().map(to_hex).serialize(serializer)
    }
    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Hash>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .as_deref()
            .map(from_hex)
            .transpose()
            .map_err(serde::de::Error::custom)
    }
}

mod optional_bytes_hex_json {
    use super::{Deserialize, Serialize, hex_nibble, to_hex_bytes};

    #[allow(clippy::ref_option)]
    pub(super) fn serialize<S: serde::Serializer>(
        bytes: &Option<Vec<u8>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        bytes
            .as_ref()
            .map(|value| to_hex_bytes(value))
            .serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Vec<u8>>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .map(|s| {
                if s.len() % 2 != 0 {
                    return Err(serde::de::Error::custom("odd-length upload session hex"));
                }
                s.as_bytes()
                    .chunks_exact(2)
                    .map(|pair| {
                        let high = hex_nibble(pair[0]).ok_or_else(|| {
                            serde::de::Error::custom("invalid upload session hex")
                        })?;
                        let low = hex_nibble(pair[1]).ok_or_else(|| {
                            serde::de::Error::custom("invalid upload session hex")
                        })?;
                        Ok((high << 4) | low)
                    })
                    .collect()
            })
            .transpose()
    }
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

mod repo_json {
    use super::{Deserialize, RepoName};
    pub(super) fn serialize<S: serde::Serializer>(
        repo: &RepoName,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(repo.as_str())
    }
    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<RepoName, D::Error> {
        RepoName::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Version byte of every structured value this binary writes.
pub const CODEC_V1: u8 = 0x01;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordV1 {
    fingerprint: String,
    expires_at_ms: i64,
    state: StateV1,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum StateV1 {
    InFlight { resumable: bool },
    Committed { result: ResultV1 },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ResultV1 {
    UpdateRefCommitted,
    UpdateRefConflict {
        current: Option<String>,
    },
    AdvanceCommitted,
    AdvanceHeadConflict,
    AdvancePackmapConflict,
    UploadPack,
    RepoVisibility,
    BeginUploadAlreadyPresent,
    BeginUploadTicket {
        id: String,
        part_size: u64,
        expires_at_ms: u64,
        token_hex: String,
    },
    Rejected {
        code: String,
        message: String,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct QuotaV1 {
    window_start: i64,
    ops: u32,
    bytes: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HoldV1 {
    expires_at_ms: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HolderV1 {
    seq: u64,
    #[serde(with = "hash_json")]
    op_id: Hash,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BlockV1 {
    reason: String,
    blocked_at_ms: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObjectStateV1 {
    seq: u64,
    changed_at_ms: u64,
    holders: u64,
    deleting: bool,
}

/// Every [`Code`], to invert [`Code::as_str`].
const CODES: [Code; 16] = [
    Code::Canceled,
    Code::Unknown,
    Code::InvalidArgument,
    Code::DeadlineExceeded,
    Code::NotFound,
    Code::AlreadyExists,
    Code::PermissionDenied,
    Code::ResourceExhausted,
    Code::FailedPrecondition,
    Code::Aborted,
    Code::OutOfRange,
    Code::Unimplemented,
    Code::Internal,
    Code::Unavailable,
    Code::DataLoss,
    Code::Unauthenticated,
];

fn corrupt(what: &'static str) -> StoreError {
    StoreError::Corrupt(what.into())
}

fn encode_json<T: Serialize>(value: &T) -> Value {
    let mut out = vec![CODEC_V1];
    serde_json::to_writer(&mut out, value).expect("codec DTOs always serialize");
    Value::new(out)
}

fn decode_json<'a, T: Deserialize<'a>>(
    value: &'a Value,
    what: &'static str,
) -> Result<T, StoreError> {
    match value.as_bytes().split_first() {
        Some((&CODEC_V1, body)) => serde_json::from_slice(body).map_err(|_| corrupt(what)),
        _ => Err(corrupt("unknown codec version")),
    }
}

fn hash_from(hex: &str) -> Result<Hash, StoreError> {
    from_hex(hex).map_err(|_| corrupt("bad hash"))
}

/// Encode a namespace coordinator record.
#[must_use]
pub fn encode_namespace_record(record: &NamespaceRecord) -> Value {
    encode_json(record)
}

/// Decode a namespace coordinator record. Configuration version zero is
/// invalid: the namespace's first version is 1.
pub fn decode_namespace_record(value: &Value) -> Result<NamespaceRecord, StoreError> {
    let record: NamespaceRecord = decode_json(value, "bad namespace record")?;
    if record.config_version == 0 {
        return Err(corrupt("namespace configuration version is zero"));
    }
    Ok(record)
}

/// Encode a repository coordinator record.
#[must_use]
pub fn encode_repo_record(record: &RepoRecord) -> Value {
    encode_json(record)
}

/// Decode a repository coordinator record.
pub fn decode_repo_record(value: &Value) -> Result<RepoRecord, StoreError> {
    decode_json(value, "bad repo record")
}

/// Encode a repository visibility row.
#[must_use]
pub fn encode_repo_visibility(row: &RepoVisibilityV1) -> Value {
    encode_json(row)
}

/// Decode a repository visibility row. The statement id is canonical: 64
/// lowercase hexadecimal digits.
pub fn decode_repo_visibility(value: &Value) -> Result<RepoVisibilityV1, StoreError> {
    let row: RepoVisibilityV1 = decode_json(value, "bad repo visibility")?;
    if let Some(id) = &row.last_statement_id
        && !is_hex(id, 32)
    {
        return Err(corrupt("bad statement id"));
    }
    Ok(row)
}

/// Encode a ref shard epoch lease.
#[must_use]
pub fn encode_epoch_lease(lease: &EpochLease) -> Value {
    encode_json(lease)
}

/// Decode an epoch lease; namespace configuration versions start at 1.
pub fn decode_epoch_lease(value: &Value) -> Result<EpochLease, StoreError> {
    let lease: EpochLease = decode_json(value, "bad epoch lease")?;
    if lease.authority_ready.is_some() && lease.authority_generation.is_none() {
        return Err(corrupt("authority ready lease missing generation"));
    }
    if lease.config_version == 0 {
        return Err(corrupt("lease configuration version is zero"));
    }
    Ok(lease)
}

/// Encode a coordinator lease-table row.
#[must_use]
pub fn encode_leased_shard(lease: &LeasedShard) -> Value {
    encode_json(lease)
}

/// Decode a coordinator lease-table row.
pub fn decode_leased_shard(value: &Value) -> Result<LeasedShard, StoreError> {
    decode_json(value, "bad leased shard")
}

/// Encode a declared lease-table recovery marker.
#[must_use]
pub fn encode_lease_recovery(recovery: &LeaseRecovery) -> Value {
    encode_json(recovery)
}

/// Decode a declared lease-table recovery marker.
pub fn decode_lease_recovery(value: &Value) -> Result<LeaseRecovery, StoreError> {
    let mode: LeaseRecovery = decode_json(value, "bad lease recovery")?;
    if mode.authority_fence == Some(false)
        || mode.activation_only == Some(false)
        || ((mode.authority_ready.is_some() || mode.activation_only == Some(true))
            && mode.authority_fence != Some(true))
    {
        return Err(corrupt("invalid authority activation marker"));
    }
    Ok(mode)
}

/// Encode a per-partition Worker backup state.
#[must_use]
pub fn encode_backup_state(state: &BackupStateV1) -> Value {
    encode_json(state)
}

/// Decode a per-partition Worker backup state.
pub fn decode_backup_state(value: &Value) -> Result<BackupStateV1, StoreError> {
    decode_json(value, "bad backup state")
}

/// Validate ticket semantics before opening or after decoding a row.
pub fn validate_ticket(ticket: &TicketV1) -> Result<(), StoreError> {
    let ttl = ticket.expires_at_ms.checked_sub(ticket.created_at_ms);
    if !is_served_ref_name(&ticket.ref_name)
        || !validate_reservation_id(&ticket.reservation_id)
        || ticket.bytes == 0
        || ticket.part_size < MIN_PART_SIZE
        || !ticket.part_size.is_power_of_two()
        || !matches!(ttl, Some(1..604_800_000))
    {
        return Err(corrupt("invalid ticket"));
    }
    Ok(())
}

/// Encode an upload ticket.
#[must_use]
pub fn encode_ticket(ticket: &TicketV1) -> Value {
    encode_json(ticket)
}

/// Decode an upload ticket, validating ref, reservation, geometry and lifetime.
pub fn decode_ticket(value: &Value) -> Result<TicketV1, StoreError> {
    check_value_limit(value)?;
    let ticket = decode_json(value, "bad ticket")?;
    validate_ticket(&ticket)?;
    Ok(ticket)
}

/// Encode a pending, ticket-backed, or terminal reservation.
#[must_use]
pub fn encode_reservation(reservation: &ReservationV1) -> Value {
    encode_json(reservation)
}

/// Decode a reservation; unknown states, identities and malformed outcomes fail closed.
pub fn decode_reservation(value: &Value) -> Result<ReservationV1, StoreError> {
    check_value_limit(value)?;
    let reservation = decode_json(value, "bad reservation")?;
    let repository = match &reservation {
        ReservationV1::Ticketed { .. } => return Ok(reservation),
        ReservationV1::Pending {
            repository,
            created_at_ms,
            reconcile_at_ms,
            ..
        } => {
            if reconcile_at_ms < created_at_ms {
                return Err(corrupt("invalid pending deadline"));
            }
            repository
        }
        ReservationV1::Committed {
            repository, refs, ..
        } => {
            for r in refs {
                if !is_served_ref_name(&r.name) || r.deleted != r.new.is_none() {
                    return Err(corrupt("invalid outcome ref"));
                }
            }
            repository
        }
        ReservationV1::Aborted {
            repository, detail, ..
        } => {
            if detail.len() > 512 {
                return Err(corrupt("outcome detail exceeds 512 bytes"));
            }
            repository
        }
        ReservationV1::Expired { repository, .. }
        | ReservationV1::ReadServed { repository, .. } => repository,
    };
    RepositoryIdentity::parse_bare_allowed(repository)
        .map_err(|_| corrupt("bad outcome repository"))?;
    Ok(reservation)
}

fn check_value_limit(value: &Value) -> Result<(), StoreError> {
    if value.as_bytes().len() > MAX_VALUE_BYTES {
        return Err(corrupt("value exceeds MAX_VALUE_BYTES"));
    }
    Ok(())
}

fn hex_bytes(hex: &str) -> Result<Vec<u8>, StoreError> {
    if !hex.len().is_multiple_of(2) {
        return Err(corrupt("bad hex bytes"));
    }
    let digit = |b| match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    };
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            Ok(digit(pair[0]).ok_or_else(|| corrupt("bad hex bytes"))? * 16
                + digit(pair[1]).ok_or_else(|| corrupt("bad hex bytes"))?)
        })
        .collect()
}

/// Encode idempotent relay operations. A malformed target returns Invalid.
pub fn encode_relay(relay: &RelayV1) -> Result<Value, StoreError> {
    let put_keys: std::collections::BTreeSet<_> = relay.puts.iter().map(|(key, _)| key).collect();
    let mut delete_keys = std::collections::BTreeSet::new();
    for key in &relay.deletes {
        if key.as_bytes().len() > MAX_KEY_BYTES
            || put_keys.contains(key)
            || !delete_keys.insert(key)
        {
            return Err(StoreError::Invalid("invalid relay delete key".into()));
        }
    }
    let value = encode_json(&RelayDtoV1 {
        at_ms: relay.at_ms,
        target: to_hex_bytes(&relay.target.encode()?),
        puts: relay
            .puts
            .iter()
            .map(|(key, value)| (to_hex_bytes(key.as_bytes()), to_hex_bytes(value.as_bytes())))
            .collect(),
        deletes: relay
            .deletes
            .iter()
            .map(|key| to_hex_bytes(key.as_bytes()))
            .collect(),
    });
    if value.as_bytes().len() > MAX_VALUE_BYTES {
        return Err(StoreError::Invalid("relay exceeds MAX_VALUE_BYTES".into()));
    }
    for (key, value) in &relay.puts {
        if key.as_bytes().len() > MAX_KEY_BYTES || value.as_bytes().len() > MAX_VALUE_BYTES {
            return Err(StoreError::Invalid("invalid relay upsert size".into()));
        }
    }
    Ok(value)
}

/// Decode a relay target and its bounded idempotent operations.
pub fn decode_relay(value: &Value) -> Result<RelayV1, StoreError> {
    check_value_limit(value)?;
    let dto: RelayDtoV1 = decode_json(value, "bad relay")?;
    let target = Partition::decode(&hex_bytes(&dto.target)?)?;
    let puts: Vec<(Key, Value)> = dto
        .puts
        .into_iter()
        .map(|(key, value)| {
            let key = hex_bytes(&key)?;
            let value = hex_bytes(&value)?;
            if key.len() > MAX_KEY_BYTES || value.len() > MAX_VALUE_BYTES {
                return Err(corrupt("invalid relay upsert size"));
            }
            Ok((Key::new(key), Value::new(value)))
        })
        .collect::<Result<_, StoreError>>()?;
    let put_keys: std::collections::BTreeSet<_> = puts.iter().map(|(key, _)| key).collect();
    let mut delete_keys = std::collections::BTreeSet::new();
    let mut deletes = Vec::with_capacity(dto.deletes.len());
    for encoded in dto.deletes {
        let key = Key::new(hex_bytes(&encoded)?);
        if key.as_bytes().len() > MAX_KEY_BYTES
            || put_keys.contains(&key)
            || !delete_keys.insert(key.clone())
        {
            return Err(corrupt("invalid relay delete key"));
        }
        deletes.push(key);
    }
    Ok(RelayV1 {
        at_ms: dto.at_ms,
        target,
        puts,
        deletes,
    })
}

/// Encode a repository object-index value. All integers are big-endian.
/// Layout: version, frame offset/length (u64 each), wire type (u8),
/// decoded size (u64), chain depth (u32), base-present (u8), optional base id.
pub fn encode_object_index(object: &Hash, row: &IndexValue) -> Result<Value, StoreError> {
    row.validate(object)?;
    let mut bytes = Vec::with_capacity(63);
    bytes.push(CODEC_V1);
    bytes.extend_from_slice(&row.frame_offset.to_be_bytes());
    bytes.extend_from_slice(&row.frame_length.to_be_bytes());
    bytes.push(row.wire_type);
    bytes.extend_from_slice(&row.decoded_size.to_be_bytes());
    bytes.extend_from_slice(&row.chain_depth.to_be_bytes());
    match row.delta_base {
        Some(base) => {
            bytes.push(1);
            bytes.extend_from_slice(&base);
        }
        None => bytes.push(0),
    }
    Ok(Value::new(bytes))
}

/// Decode and validate a repository object-index value.
pub fn decode_object_index(object: &Hash, value: &Value) -> Result<IndexValue, StoreError> {
    let bytes = value.as_bytes();
    if !matches!(bytes.len(), 31 | 63) || bytes[0] != CODEC_V1 {
        return Err(StoreError::Corrupt("bad object index value".into()));
    }
    let base = match (bytes[30], bytes.len()) {
        (0, 31) => None,
        (1, 63) => Some(
            bytes[31..63]
                .try_into()
                .map_err(|_| StoreError::Corrupt("bad object index base".into()))?,
        ),
        _ => return Err(StoreError::Corrupt("bad object index base flag".into())),
    };
    let row = IndexValue {
        frame_offset: u64::from_be_bytes(
            bytes[1..9]
                .try_into()
                .map_err(|_| StoreError::Corrupt("bad object index offset".into()))?,
        ),
        frame_length: u64::from_be_bytes(
            bytes[9..17]
                .try_into()
                .map_err(|_| StoreError::Corrupt("bad object index length".into()))?,
        ),
        wire_type: bytes[17],
        decoded_size: u64::from_be_bytes(
            bytes[18..26]
                .try_into()
                .map_err(|_| StoreError::Corrupt("bad object index size".into()))?,
        ),
        chain_depth: u32::from_be_bytes(
            bytes[26..30]
                .try_into()
                .map_err(|_| StoreError::Corrupt("bad object index depth".into()))?,
        ),
        delta_base: base,
    };
    row.validate(object)
        .map_err(|_| StoreError::Corrupt("invalid object index value".into()))?;
    Ok(row)
}

fn relay_scan_invalid(scan: &RelayScanV1) -> Option<&'static str> {
    if scan.cursor > scan.cycle_end {
        Some("relay scan cursor exceeds cycle end")
    } else if scan.blocked.len() > MAX_BLOCKED_TARGETS {
        Some("relay scan exceeds MAX_BLOCKED_TARGETS")
    } else if scan.blocked.windows(2).any(|pair| pair[0] >= pair[1]) {
        Some("relay scan targets are not sorted and unique")
    } else {
        None
    }
}

/// Encode bounded, canonical source relay scan progress.
pub fn encode_relay_scan(scan: &RelayScanV1) -> Result<Value, StoreError> {
    if let Some(message) = relay_scan_invalid(scan) {
        return Err(StoreError::Invalid(message.into()));
    }
    let blocked = scan
        .blocked
        .iter()
        .map(|target| Ok(to_hex_bytes(&target.encode()?)))
        .collect::<Result<_, StoreError>>()?;
    let value = encode_json(&RelayScanDtoV1 {
        cycle_end: scan.cycle_end,
        cursor: scan.cursor,
        blocked,
    });
    if value.as_bytes().len() > MAX_VALUE_BYTES {
        return Err(StoreError::Invalid(
            "relay scan exceeds MAX_VALUE_BYTES".into(),
        ));
    }
    Ok(value)
}

/// Decode source relay scan progress, rejecting malformed or unbounded state.
pub fn decode_relay_scan(value: &Value) -> Result<RelayScanV1, StoreError> {
    check_value_limit(value)?;
    let dto: RelayScanDtoV1 = decode_json(value, "bad relay scan")?;
    if dto.blocked.len() > MAX_BLOCKED_TARGETS {
        return Err(corrupt("relay scan exceeds MAX_BLOCKED_TARGETS"));
    }
    let blocked = dto
        .blocked
        .into_iter()
        .map(|target| Partition::decode(&hex_bytes(&target)?))
        .collect::<Result<_, _>>()?;
    let scan = RelayScanV1 {
        cycle_end: dto.cycle_end,
        cursor: dto.cursor,
        blocked,
    };
    if let Some(message) = relay_scan_invalid(&scan) {
        return Err(corrupt(message));
    }
    Ok(scan)
}

/// Encode the terminal outcome backlog.
#[must_use]
pub fn encode_backlog(backlog: &Backlog) -> Value {
    encode_json(backlog)
}

/// Decode the terminal outcome backlog.
pub fn decode_backlog(value: &Value) -> Result<Backlog, StoreError> {
    check_value_limit(value)?;
    let backlog: Backlog = decode_json(value, "bad outcome backlog")?;
    if (backlog.rows == 0) != (backlog.bytes == 0) {
        return Err(corrupt("inconsistent outcome backlog"));
    }
    Ok(backlog)
}

/// Encode a replay record.
#[must_use]
pub fn encode_replay_record(record: &ReplayRecord) -> Value {
    let state = match &record.state {
        ReplayState::InFlight { resumable } => StateV1::InFlight {
            resumable: *resumable,
        },
        ReplayState::Committed(result) => StateV1::Committed {
            result: match result {
                StoredResult::UpdateRef(UpdateRefResult::Committed) => ResultV1::UpdateRefCommitted,
                StoredResult::UpdateRef(UpdateRefResult::Conflict { current }) => {
                    ResultV1::UpdateRefConflict {
                        current: current.as_ref().map(to_hex),
                    }
                }
                StoredResult::AdvanceRefs(AdvanceOutcome::Committed) => ResultV1::AdvanceCommitted,
                StoredResult::AdvanceRefs(AdvanceOutcome::HeadConflict) => {
                    ResultV1::AdvanceHeadConflict
                }
                StoredResult::AdvanceRefs(AdvanceOutcome::PackmapConflict) => {
                    ResultV1::AdvancePackmapConflict
                }
                StoredResult::BeginUpload(BeginUploadResult::AlreadyPresent) => {
                    ResultV1::BeginUploadAlreadyPresent
                }
                StoredResult::BeginUpload(BeginUploadResult::Ticket {
                    id,
                    part_size,
                    expires_at_ms,
                    token,
                }) => ResultV1::BeginUploadTicket {
                    id: to_hex(id),
                    part_size: *part_size,
                    expires_at_ms: *expires_at_ms,
                    token_hex: to_hex_bytes(token),
                },
                StoredResult::UploadPack => ResultV1::UploadPack,
                StoredResult::RepoVisibility => ResultV1::RepoVisibility,
                StoredResult::Rejected(r) => ResultV1::Rejected {
                    code: r.code().as_str().to_owned(),
                    message: r.message().to_owned(),
                },
            },
        },
    };
    encode_json(&RecordV1 {
        fingerprint: to_hex(&record.fingerprint),
        expires_at_ms: record.expires_at_ms,
        state,
    })
}

/// Decode a replay record.
pub fn decode_replay_record(value: &Value) -> Result<ReplayRecord, StoreError> {
    let dto: RecordV1 = decode_json(value, "bad replay record")?;
    let state = match dto.state {
        StateV1::InFlight { resumable } => ReplayState::InFlight { resumable },
        StateV1::Committed { result } => ReplayState::Committed(match result {
            ResultV1::UpdateRefCommitted => StoredResult::UpdateRef(UpdateRefResult::Committed),
            ResultV1::UpdateRefConflict { current } => {
                StoredResult::UpdateRef(UpdateRefResult::Conflict {
                    current: current.as_deref().map(hash_from).transpose()?,
                })
            }
            ResultV1::AdvanceCommitted => StoredResult::AdvanceRefs(AdvanceOutcome::Committed),
            ResultV1::AdvanceHeadConflict => {
                StoredResult::AdvanceRefs(AdvanceOutcome::HeadConflict)
            }
            ResultV1::AdvancePackmapConflict => {
                StoredResult::AdvanceRefs(AdvanceOutcome::PackmapConflict)
            }
            ResultV1::BeginUploadAlreadyPresent => {
                StoredResult::BeginUpload(BeginUploadResult::AlreadyPresent)
            }
            ResultV1::BeginUploadTicket {
                id,
                part_size,
                expires_at_ms,
                token_hex,
            } => {
                if part_size < mkit_core::upload_parts::MIN_PART_SIZE
                    || !part_size.is_power_of_two()
                    || token_hex.is_empty()
                {
                    return Err(corrupt("invalid stored ticket result"));
                }
                StoredResult::BeginUpload(BeginUploadResult::Ticket {
                    id: hash_from(&id)?,
                    part_size,
                    expires_at_ms,
                    token: hex_bytes(&token_hex)?,
                })
            }
            ResultV1::UploadPack => StoredResult::UploadPack,
            ResultV1::RepoVisibility => StoredResult::RepoVisibility,
            ResultV1::Rejected { code, message } => {
                let code = CODES
                    .into_iter()
                    .find(|c| c.as_str() == code)
                    .ok_or_else(|| corrupt("unknown code"))?;
                StoredResult::Rejected(
                    StoredRejection::new(code, message)
                        .ok_or_else(|| corrupt("stored rejection code is not final"))?,
                )
            }
        }),
    };
    Ok(ReplayRecord {
        fingerprint: hash_from(&dto.fingerprint)?,
        expires_at_ms: dto.expires_at_ms,
        state,
    })
}

/// Encode a quota window's usage.
#[must_use]
pub fn encode_quota_state(state: &QuotaState) -> Value {
    encode_json(&QuotaV1 {
        window_start: state.window_start,
        ops: state.ops,
        bytes: state.bytes,
    })
}

/// Decode a quota window's usage.
pub fn decode_quota_state(value: &Value) -> Result<QuotaState, StoreError> {
    let dto: QuotaV1 = decode_json(value, "bad quota state")?;
    Ok(QuotaState {
        window_start: dto.window_start,
        ops: dto.ops,
        bytes: dto.bytes,
    })
}

/// Two big-endian u64 counters, ops then bytes. Used by qs, qc and qt.
#[must_use]
pub fn encode_namespace_usage(usage: NamespaceUsage) -> Value {
    Value::new([usage.ops.to_be_bytes(), usage.bytes.to_be_bytes()].concat())
}

/// Decode a fixed-width namespace counter, rejecting malformed rows.
pub fn decode_namespace_usage(value: &Value) -> Result<NamespaceUsage, StoreError> {
    let (ops, bytes) = value
        .as_bytes()
        .split_first_chunk::<8>()
        .ok_or_else(|| corrupt("bad namespace usage"))?;
    let bytes: [u8; 8] = bytes
        .try_into()
        .map_err(|_| corrupt("bad namespace usage"))?;
    Ok(NamespaceUsage {
        ops: u64::from_be_bytes(*ops),
        bytes: u64::from_be_bytes(bytes),
    })
}

/// Three usage fields and a read timestamp, each big-endian u64.
#[must_use]
pub fn encode_namespace_view(view: NamespaceView) -> Value {
    Value::new(
        [
            view.total.ops.to_be_bytes(),
            view.total.bytes.to_be_bytes(),
            view.pushed.ops.to_be_bytes(),
            view.pushed.bytes.to_be_bytes(),
            view.observed_at_ms.to_be_bytes(),
        ]
        .concat(),
    )
}

/// Decode a view and reject a contribution larger than the aggregate.
pub fn decode_namespace_view(value: &Value) -> Result<NamespaceView, StoreError> {
    let bytes: [u8; 40] = value
        .as_bytes()
        .try_into()
        .map_err(|_| corrupt("bad namespace view"))?;
    let word = |i| -> Result<u64, StoreError> {
        let chunk: [u8; 8] = bytes
            .get(i..i + 8)
            .ok_or_else(|| corrupt("bad namespace view"))?
            .try_into()
            .map_err(|_| corrupt("bad namespace view"))?;
        Ok(u64::from_be_bytes(chunk))
    };
    let view = NamespaceView {
        total: NamespaceUsage {
            ops: word(0)?,
            bytes: word(8)?,
        },
        pushed: NamespaceUsage {
            ops: word(16)?,
            bytes: word(24)?,
        },
        observed_at_ms: word(32)?,
    };
    if view.total.delta_from(view.pushed).is_none() {
        return Err(corrupt("namespace view exceeds total"));
    }
    Ok(view)
}

/// Encode a `ContentIndex` GC hold: its expiry, Unix ms.
#[must_use]
pub fn encode_hold(expires_at_ms: u64) -> Value {
    encode_json(&HoldV1 { expires_at_ms })
}

/// Decode a `ContentIndex` GC hold's expiry.
pub fn decode_hold(value: &Value) -> Result<u64, StoreError> {
    let dto: HoldV1 = decode_json(value, "bad hold")?;
    Ok(dto.expires_at_ms)
}

/// Encode a `ContentIndex` holder row (R-131).
#[must_use]
pub fn encode_holder(record: &HolderRecord) -> Value {
    encode_json(&HolderV1 {
        seq: record.seq,
        op_id: record.op_id,
    })
}

/// Decode a `ContentIndex` holder row.
pub fn decode_holder(value: &Value) -> Result<HolderRecord, StoreError> {
    let dto: HolderV1 = decode_json(value, "bad holder")?;
    Ok(HolderRecord::new(dto.seq, dto.op_id))
}

/// Encode a blocklist entry.
#[must_use]
pub fn encode_block_entry(entry: &BlockEntry) -> Value {
    encode_json(&BlockV1 {
        reason: entry.reason.clone(),
        blocked_at_ms: entry.blocked_at_ms,
    })
}

/// Decode a blocklist entry.
pub fn decode_block_entry(value: &Value) -> Result<BlockEntry, StoreError> {
    let dto: BlockV1 = decode_json(value, "bad blocklist entry")?;
    Ok(BlockEntry {
        reason: dto.reason,
        blocked_at_ms: dto.blocked_at_ms,
    })
}

/// Encode a `ContentIndex` object state.
#[must_use]
pub fn encode_object_state(state: &ObjectState) -> Value {
    encode_json(&ObjectStateV1 {
        seq: state.seq,
        changed_at_ms: state.changed_at_ms,
        holders: state.holders,
        deleting: state.deleting,
    })
}

/// Decode a `ContentIndex` object state.
pub fn decode_object_state(value: &Value) -> Result<ObjectState, StoreError> {
    let dto: ObjectStateV1 = decode_json(value, "bad object state")?;
    Ok(ObjectState {
        seq: dto.seq,
        changed_at_ms: dto.changed_at_ms,
        holders: dto.holders,
        deleting: dto.deleting,
    })
}

/// A ref value: the raw 32-byte id.
#[must_use]
pub fn encode_ref_id(id: &Hash) -> Value {
    Value::new(id.to_vec())
}

/// Decode a ref value.
pub fn decode_ref_id(value: &Value) -> Result<Hash, StoreError> {
    Hash::try_from(value.as_bytes()).map_err(|_| corrupt("ref value is not 32 bytes"))
}

/// A be64 integer (the grant epoch).
#[must_use]
pub fn encode_u64(n: u64) -> Value {
    Value::new(n.to_be_bytes().to_vec())
}

/// Decode a be64 integer.
pub fn decode_u64(value: &Value) -> Result<u64, StoreError> {
    <[u8; 8]>::try_from(value.as_bytes())
        .map(u64::from_be_bytes)
        .map_err(|_| corrupt("integer is not 8 bytes"))
}

/// A be32 integer (the layout version).
#[must_use]
pub fn encode_u32(n: u32) -> Value {
    Value::new(n.to_be_bytes().to_vec())
}

/// Decode a be32 integer.
pub fn decode_u32(value: &Value) -> Result<u32, StoreError> {
    <[u8; 4]>::try_from(value.as_bytes())
        .map(u32::from_be_bytes)
        .map_err(|_| corrupt("integer is not 4 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ticket_fixture() -> TicketV1 {
        TicketV1 {
            authority_generation: None,
            repo: RepoName::new("a").unwrap(),
            ref_name: "refs/heads/main".into(),
            signer: [0x11; 32],
            pack_id: [0x22; 32],
            bytes: 9,
            part_size: MIN_PART_SIZE,
            expires_at_ms: 24,
            created_at_ms: 1,
            reservation_id: "R-1:ok".into(),
            upload_session: None,
        }
    }

    fn json_value(json: &serde_json::Value) -> Value {
        let mut bytes = vec![CODEC_V1];
        bytes.extend(serde_json::to_vec(json).unwrap());
        Value::new(bytes)
    }

    #[test]
    fn ticket_codec_golden_roundtrip_and_rejections() {
        let ticket = ticket_fixture();
        let golden = format!(
            r#"{{"repo":"a","ref_name":"refs/heads/main","signer":"{}","pack_id":"{}","bytes":9,"part_size":8388608,"expires_at_ms":24,"created_at_ms":1,"reservation_id":"R-1:ok","upload_session":null}}"#,
            "11".repeat(32),
            "22".repeat(32)
        );
        assert_eq!(
            encode_ticket(&ticket).as_bytes(),
            [&[CODEC_V1][..], golden.as_bytes()].concat()
        );
        assert_eq!(decode_ticket(&encode_ticket(&ticket)).unwrap(), ticket);
        let mut session = ticket.clone();
        session.upload_session = Some(b"backend-session".to_vec());
        let encoded = encode_ticket(&session);
        let expected = golden.replace(
            "\"upload_session\":null",
            "\"upload_session\":\"6261636b656e642d73657373696f6e\"",
        );
        assert_eq!(
            encoded.as_bytes(),
            [&[CODEC_V1][..], expected.as_bytes()].concat()
        );
        assert_eq!(decode_ticket(&encode_ticket(&session)).unwrap(), session);
        let base = serde_json::to_value(&ticket).unwrap();
        for (field, bad) in [
            ("signer", serde_json::json!("bad hex")),
            ("pack_id", serde_json::json!("00")),
            ("bytes", serde_json::json!(0)),
            ("part_size", serde_json::json!(8_388_609)),
            ("part_size", serde_json::json!(1)),
            ("unknown", serde_json::json!(1)),
            ("upload_session", serde_json::json!("+0")),
            ("upload_session", serde_json::json!("0+")),
            ("upload_session", serde_json::json!("é0")),
            ("reservation_id", serde_json::json!("bad/id")),
            ("reservation_id", serde_json::json!("")),
            ("reservation_id", serde_json::json!("a".repeat(129))),
            ("repo", serde_json::json!("bad name")),
            ("ref_name", serde_json::json!("refs/heads/../b")),
            ("expires_at_ms", serde_json::json!(1)),
            ("expires_at_ms", serde_json::json!(604_800_001)),
            ("created_at_ms", serde_json::json!(25)),
            ("bytes", serde_json::json!(-1)),
        ] {
            let mut bad_json = base.clone();
            bad_json[field] = bad;
            assert!(
                matches!(
                    decode_ticket(&json_value(&bad_json)),
                    Err(StoreError::Corrupt(_))
                ),
                "{field}"
            );
        }
        let mut boundary = ticket;
        boundary.expires_at_ms = boundary.created_at_ms + 604_799_999;
        assert!(decode_ticket(&encode_ticket(&boundary)).is_ok());
        for bad in [
            Value::new(vec![]),
            Value::new(b"\x02{}".to_vec()),
            Value::new(b"\x01{".to_vec()),
            Value::new(vec![0; MAX_VALUE_BYTES + 1]),
        ] {
            assert!(decode_ticket(&bad).is_err());
        }
    }

    #[test]
    fn reservation_codec_all_variants_golden_and_roundtrip() {
        let cases = vec![
            (ReservationV1::Pending { repository: "a".into(), created_at_ms: 1, reconcile_at_ms: 300_001, op: PendingOp::Write }, r#"{"state":"pending","repository":"a","created_at_ms":1,"reconcile_at_ms":300001,"op":"write"}"#.into()),
            (ReservationV1::Pending { repository: "a".into(), created_at_ms: 1, reconcile_at_ms: 60_001, op: PendingOp::Read }, r#"{"state":"pending","repository":"a","created_at_ms":1,"reconcile_at_ms":60001,"op":"read"}"#.into()),
            (ReservationV1::Ticketed { ticket_id: [0x11; 32] }, format!(r#"{{"state":"ticketed","ticket_id":"{}"}}"#, "11".repeat(32))),
            (ReservationV1::Committed { repository: "a".into(), occurred_at_ms: 7, bytes_stored: 9, new_to_repo: 8, new_to_store: 6, refs: vec![OutcomeRef { name: "refs/heads/main".into(), new: Some([0x22; 32]), deleted: false }, OutcomeRef { name: "refs/tags/v1".into(), new: None, deleted: true }] }, format!(r#"{{"state":"committed","repository":"a","occurred_at_ms":7,"bytes_stored":9,"new_to_repo":8,"new_to_store":6,"refs":[{{"name":"refs/heads/main","new":"{}","deleted":false}},{{"name":"refs/tags/v1","new":null,"deleted":true}}]}}"#, "22".repeat(32))),
            (ReservationV1::Aborted { repository: "a".into(), occurred_at_ms: 7, reason: AbortReason::Abandoned, detail: "gone".into() }, r#"{"state":"aborted","repository":"a","occurred_at_ms":7,"reason":"ABANDONED","detail":"gone"}"#.into()),
            (ReservationV1::Expired { repository: "a".into(), occurred_at_ms: 7 }, r#"{"state":"expired","repository":"a","occurred_at_ms":7}"#.into()),
            (ReservationV1::ReadServed { repository: "a".into(), occurred_at_ms: 7, object: [0x33; 32], bytes_served: 9 }, format!(r#"{{"state":"read_served","repository":"a","occurred_at_ms":7,"object":"{}","bytes_served":9}}"#, "33".repeat(32))),
        ];
        for (row, golden) in cases {
            let value = encode_reservation(&row);
            assert_eq!(
                value.as_bytes(),
                [&[CODEC_V1][..], golden.as_bytes()].concat()
            );
            assert_eq!(decode_reservation(&value).unwrap(), row);
            let mut json = serde_json::to_value(&row).unwrap();
            json["extra"] = serde_json::json!(1);
            assert!(decode_reservation(&json_value(&json)).is_err());
        }
        for (reason, name) in [
            (AbortReason::Unspecified, "UNSPECIFIED"),
            (AbortReason::RefConflict, "REF_CONFLICT"),
            (AbortReason::EpochMismatch, "EPOCH_MISMATCH"),
            (AbortReason::PackMissing, "PACK_MISSING"),
            (AbortReason::ReplayRace, "REPLAY_RACE"),
            (AbortReason::Internal, "INTERNAL"),
            (AbortReason::Abandoned, "ABANDONED"),
        ] {
            let row = ReservationV1::Aborted {
                repository: "a".into(),
                occurred_at_ms: 7,
                reason,
                detail: String::new(),
            };
            let value = encode_reservation(&row);
            assert_eq!(value.as_bytes(), format!("\x01{{\"state\":\"aborted\",\"repository\":\"a\",\"occurred_at_ms\":7,\"reason\":\"{name}\",\"detail\":\"\"}}").as_bytes());
            assert_eq!(decode_reservation(&value).unwrap(), row);
        }
        let full_repo = format!(
            "ed25519-{}/{}",
            "ab".repeat(32),
            "r".repeat(mkit_core::repo_identity::MAX_NAME_LEN)
        );
        let row = ReservationV1::Expired {
            repository: full_repo,
            occurred_at_ms: 7,
        };
        assert_eq!(decode_reservation(&encode_reservation(&row)).unwrap(), row);
    }

    #[test]
    fn reservation_codec_rejects_malformed_states_and_outcomes() {
        for json in [
            serde_json::json!({"state":"unknown"}),
            serde_json::json!({"state":"pending"}),
            serde_json::json!({"state":"ticketed","ticket_id":"nope"}),
            serde_json::json!({"state":"expired","repository":"bad name","occurred_at_ms":7}),
            serde_json::json!({"state":"aborted","repository":"a","occurred_at_ms":7,"reason":"UNKNOWN","detail":""}),
            serde_json::json!({"state":"aborted","repository":"a","occurred_at_ms":7,"reason":"INTERNAL","detail":"x".repeat(513)}),
            serde_json::json!({"state":"aborted","repository":"a","occurred_at_ms":7,"reason":"INTERNAL","detail":"é".repeat(257)}),
            serde_json::json!({"state":"committed","repository":"a","occurred_at_ms":7,"bytes_stored":1,"new_to_repo":1,"new_to_store":0,"refs":[{"name":"bad","new":null,"deleted":true}]}),
            serde_json::json!({"state":"committed","repository":"a","occurred_at_ms":7,"bytes_stored":1,"new_to_repo":1,"new_to_store":0,"refs":[{"name":"refs/heads/a","new":null,"deleted":false}]}),
            serde_json::json!({"state":"committed","repository":"a","occurred_at_ms":7,"bytes_stored":1,"new_to_repo":1,"new_to_store":0,"refs":[{"name":"refs/heads/a","new":"bad","deleted":false}]}),
            serde_json::json!({"state":"committed","repository":"a","occurred_at_ms":7,"bytes_stored":1,"new_to_repo":1,"new_to_store":0,"refs":[{"name":"refs/heads/a","new":null,"deleted":true,"extra":1}]}),
        ] {
            assert!(matches!(
                decode_reservation(&json_value(&json)),
                Err(StoreError::Corrupt(_))
            ));
        }
        let boundary = ReservationV1::Aborted {
            repository: "a".into(),
            occurred_at_ms: 7,
            reason: AbortReason::Internal,
            detail: "é".repeat(256),
        };
        assert_eq!(
            decode_reservation(&encode_reservation(&boundary)).unwrap(),
            boundary
        );
        for value in [
            Value::new(vec![]),
            Value::new(b"\x02{}".to_vec()),
            Value::new(b"\x01{".to_vec()),
        ] {
            assert!(decode_reservation(&value).is_err());
        }
    }

    #[test]
    fn relay_and_backlog_codec_golden_roundtrip_and_rejections() {
        let relay = RelayV1 {
            at_ms: 123,
            target: Partition::Namespace(crate::repo::NamespaceKey::deployment_default()),
            puts: vec![(Key::new(b"m\0a\0".to_vec()), Value::new(vec![]))],
            deletes: Vec::new(),
        };
        let encoded = encode_relay(&relay).unwrap();
        assert_eq!(
            encoded.as_bytes(),
            b"\x01{\"at_ms\":123,\"target\":\"6e726f6f7400\",\"puts\":[[\"6d006100\",\"\"]]}"
        );
        assert_eq!(decode_relay(&encoded).unwrap(), relay);
        let backlog = Backlog { rows: 3, bytes: 72 };
        let encoded = encode_backlog(&backlog);
        assert_eq!(encoded.as_bytes(), b"\x01{\"rows\":3,\"bytes\":72}");
        assert_eq!(decode_backlog(&encoded).unwrap(), backlog);
        assert_eq!(
            decode_backlog(&encode_backlog(&Backlog::default())).unwrap(),
            Backlog::default()
        );
        for json in [
            serde_json::json!({"target":"6e726f6f7400","puts":[]}),
            serde_json::json!({"at_ms":-1,"target":"6e726f6f7400","puts":[]}),
            serde_json::json!({"at_ms":123,"target":"bad","puts":[]}),
            serde_json::json!({"at_ms":123,"target":"zz","puts":[]}),
            serde_json::json!({"at_ms":123,"target":"00","puts":[]}),
            serde_json::json!({"at_ms":123,"target":"6e726f6f7400","puts":[["gg",""]]}),
            serde_json::json!({"at_ms":123,"target":"6e726f6f7400","puts":[],"extra":1}),
            serde_json::json!({"at_ms":123,"target":"6e726f6f7400","puts":[["00".repeat(MAX_KEY_BYTES + 1),""]]}),
        ] {
            assert!(decode_relay(&json_value(&json)).is_err());
        }
        for json in [
            serde_json::json!({"rows":-1,"bytes":1}),
            serde_json::json!({"rows":1,"bytes":0}),
            serde_json::json!({"rows":0,"bytes":1}),
            serde_json::json!({"rows":1,"bytes":1,"extra":1}),
        ] {
            assert!(decode_backlog(&json_value(&json)).is_err());
        }
        for value in [
            Value::new(vec![]),
            Value::new(b"\x02{}".to_vec()),
            Value::new(b"\x01{".to_vec()),
            Value::new(vec![0; MAX_VALUE_BYTES + 1]),
        ] {
            assert!(decode_backlog(&value).is_err());
            assert!(decode_relay(&value).is_err());
        }
        let oversized = RelayV1 {
            at_ms: 123,
            target: relay.target.clone(),
            puts: vec![(Key::new(vec![0; MAX_KEY_BYTES + 1]), Value::new(vec![]))],
            deletes: Vec::new(),
        };
        assert!(encode_relay(&oversized).is_err());
        let key = Key::new(b"x\0a\0refs/heads/main".as_slice());
        let mut deleted = relay.clone();
        deleted.deletes.push(key.clone());
        assert_eq!(
            decode_relay(&encode_relay(&deleted).unwrap()).unwrap(),
            deleted
        );
        deleted.puts.push((key.clone(), Value::default()));
        assert!(encode_relay(&deleted).is_err());
        deleted.puts.pop();
        deleted.deletes.push(key.clone());
        assert!(encode_relay(&deleted).is_err());
        deleted.deletes = vec![Key::new(vec![b'x'; MAX_KEY_BYTES + 1])];
        assert!(encode_relay(&deleted).is_err());
        for json in [
            serde_json::json!({"at_ms":123,"target":"6e726f6f7400","puts":[["780061",""]],"deletes":["780061"]}),
            serde_json::json!({"at_ms":123,"target":"6e726f6f7400","puts":[],"deletes":["78","78"]}),
            serde_json::json!({"at_ms":123,"target":"6e726f6f7400","puts":[],"deletes":["78"],"extra":1}),
            serde_json::json!({"at_ms":123,"target":"6e726f6f7400","puts":[],"deletes":["78".repeat(MAX_KEY_BYTES + 1)]}),
        ] {
            assert!(decode_relay(&json_value(&json)).is_err());
        }
    }

    #[test]
    fn relay_scan_codec_golden_and_roundtrip() {
        let scan = RelayScanV1 {
            cycle_end: 17,
            cursor: 3,
            blocked: vec![
                Partition::Namespace(crate::repo::NamespaceKey::deployment_default()),
                Partition::ContentShard(7),
            ],
        };
        let encoded = encode_relay_scan(&scan).unwrap();
        assert_eq!(
            encoded.as_bytes(),
            b"\x01{\"cycle_end\":17,\"cursor\":3,\"blocked\":[\"6e726f6f7400\",\"733700\"]}"
        );
        assert_eq!(decode_relay_scan(&encoded).unwrap(), scan);
        for (cycle_end, cursor) in [(0, 0), (17, 0), (17, 17), (u64::MAX, u64::MAX)] {
            let scan = RelayScanV1 {
                cycle_end,
                cursor,
                blocked: vec![],
            };
            assert_eq!(
                decode_relay_scan(&encode_relay_scan(&scan).unwrap()).unwrap(),
                scan
            );
        }
    }

    #[test]
    fn relay_scan_codec_rejects_invalid_progress_and_blocked_targets() {
        let scans = [
            RelayScanV1 {
                cycle_end: 1,
                cursor: 2,
                blocked: vec![],
            },
            RelayScanV1 {
                cycle_end: 1,
                cursor: 0,
                blocked: vec![Partition::ContentShard(2), Partition::ContentShard(1)],
            },
            RelayScanV1 {
                cycle_end: 1,
                cursor: 0,
                blocked: vec![Partition::ContentShard(1), Partition::ContentShard(1)],
            },
            RelayScanV1 {
                cycle_end: 1,
                cursor: 0,
                blocked: (0..=32u16).map(Partition::ContentShard).collect(),
            },
            RelayScanV1 {
                cycle_end: 1,
                cursor: 0,
                blocked: vec![Partition::Namespace(
                    crate::repo::NamespaceKey::from_stored("bad\0ns".into()),
                )],
            },
        ];
        for scan in scans {
            assert!(matches!(
                encode_relay_scan(&scan),
                Err(StoreError::Invalid(_))
            ));
        }
        for json in [
            serde_json::json!({"cycle_end":1,"cursor":2,"blocked":[]}),
            serde_json::json!({"cycle_end":1,"cursor":0,"blocked":["733200","733100"]}),
            serde_json::json!({"cycle_end":1,"cursor":0,"blocked":["733100","733100"]}),
            serde_json::json!({"cycle_end":1,"cursor":0,"blocked":(0..=32u16).map(|n| to_hex_bytes(&Partition::ContentShard(n).encode().unwrap())).collect::<Vec<_>>()}),
            serde_json::json!({"cycle_end":1,"cursor":0,"blocked":["gg"]}),
            serde_json::json!({"cycle_end":1,"cursor":0,"blocked":["0"]}),
            serde_json::json!({"cycle_end":1,"cursor":0,"blocked":["00"]}),
            serde_json::json!({"cycle_end":-1,"cursor":0,"blocked":[]}),
            serde_json::json!({"cycle_end":1,"cursor":0}),
            serde_json::json!({"cycle_end":1,"cursor":0,"blocked":[],"extra":1}),
        ] {
            assert!(matches!(
                decode_relay_scan(&json_value(&json)),
                Err(StoreError::Corrupt(_))
            ));
        }
        for value in [
            Value::new(vec![]),
            Value::new(b"\x02{}".to_vec()),
            Value::new(b"\x01{".to_vec()),
            Value::new(vec![0; MAX_VALUE_BYTES + 1]),
        ] {
            assert!(matches!(
                decode_relay_scan(&value),
                Err(StoreError::Corrupt(_))
            ));
        }
    }

    #[test]
    fn relay_scan_32_maximum_partitions_fit_the_value_limit() {
        use crate::refs::MAX_REF_NAME_BYTES;
        use crate::repo::{MAX_REPO_NAME_BYTES, NamespaceKey};

        assert_eq!(MAX_BLOCKED_TARGETS, 32);
        let namespace = NamespaceKey::from_stored(format!("ed25519-{}", "a".repeat(64)));
        let repo = RepoName::new("r".repeat(MAX_REPO_NAME_BYTES)).unwrap();
        let base = format!(
            "refs/heads/{}",
            "a".repeat(MAX_REF_NAME_BYTES - "refs/heads/".len() - 2)
        );
        let blocked = (0..32)
            .map(|n| {
                let shard_ref = format!("{base}{n:02}");
                assert_eq!(shard_ref.len(), MAX_REF_NAME_BYTES);
                assert!(crate::refs::validate_ref_name(&shard_ref));
                Partition::Ref {
                    ns: namespace.clone(),
                    repo: repo.clone(),
                    shard_ref,
                }
            })
            .collect();
        let scan = RelayScanV1 {
            cycle_end: u64::MAX,
            cursor: u64::MAX,
            blocked,
        };
        let encoded = encode_relay_scan(&scan).unwrap();
        assert!(encoded.as_bytes().len() < MAX_VALUE_BYTES);
        assert_eq!(decode_relay_scan(&encoded).unwrap(), scan);

        let oversized = RelayScanV1 {
            cycle_end: 1,
            cursor: 0,
            blocked: vec![Partition::Namespace(NamespaceKey::from_stored(
                "a".repeat(MAX_VALUE_BYTES),
            ))],
        };
        assert!(matches!(
            encode_relay_scan(&oversized),
            Err(StoreError::Invalid(_))
        ));
    }

    fn records() -> Vec<ReplayRecord> {
        let results = [
            StoredResult::UpdateRef(UpdateRefResult::Committed),
            StoredResult::UpdateRef(UpdateRefResult::Conflict { current: None }),
            StoredResult::UpdateRef(UpdateRefResult::Conflict {
                current: Some([3; 32]),
            }),
            StoredResult::AdvanceRefs(AdvanceOutcome::Committed),
            StoredResult::AdvanceRefs(AdvanceOutcome::HeadConflict),
            StoredResult::AdvanceRefs(AdvanceOutcome::PackmapConflict),
            StoredResult::UploadPack,
            StoredResult::RepoVisibility,
            StoredResult::Rejected(StoredRejection::new(Code::PermissionDenied, "no").unwrap()),
        ];
        let mut states: Vec<_> = results.into_iter().map(ReplayState::Committed).collect();
        states.push(ReplayState::InFlight { resumable: true });
        states.push(ReplayState::InFlight { resumable: false });
        states
            .into_iter()
            .map(|state| ReplayRecord {
                fingerprint: [9; 32],
                expires_at_ms: -5,
                state,
            })
            .collect()
    }

    #[test]
    fn codec_roundtrip_every_value_type() {
        for record in records() {
            let value = encode_replay_record(&record);
            assert_eq!(value.as_bytes()[0], CODEC_V1);
            assert_eq!(decode_replay_record(&value).unwrap(), record);
        }
        let quota = QuotaState {
            window_start: 1_700_000_000_000,
            ops: 3,
            bytes: u64::MAX,
        };
        assert_eq!(
            decode_quota_state(&encode_quota_state(&quota)).unwrap(),
            quota
        );
        assert_eq!(decode_ref_id(&encode_ref_id(&[4; 32])).unwrap(), [4; 32]);
        assert_eq!(decode_u64(&encode_u64(u64::MAX - 1)).unwrap(), u64::MAX - 1);
        assert_eq!(
            decode_u32(&encode_u32(1)).unwrap().to_be_bytes(),
            [0, 0, 0, 1]
        );
        for code in CODES {
            assert_eq!(
                CODES.iter().filter(|c| c.as_str() == code.as_str()).count(),
                1
            );
        }
    }

    #[test]
    fn codec_golden_bytes() {
        let head = format!(
            "\x01{{\"fingerprint\":\"{}\",\"expires_at_ms\":-5,\"state\":",
            "09".repeat(32)
        );
        let committed = |result: &str| format!("{{\"state\":\"committed\",\"result\":{result}}}");
        let states = [
            committed(r#"{"kind":"update_ref_committed"}"#),
            committed(r#"{"kind":"update_ref_conflict","current":null}"#),
            committed(&format!(
                r#"{{"kind":"update_ref_conflict","current":"{}"}}"#,
                "03".repeat(32)
            )),
            committed(r#"{"kind":"advance_committed"}"#),
            committed(r#"{"kind":"advance_head_conflict"}"#),
            committed(r#"{"kind":"advance_packmap_conflict"}"#),
            committed(r#"{"kind":"upload_pack"}"#),
            committed(r#"{"kind":"repo_visibility"}"#),
            committed(r#"{"kind":"rejected","code":"permission_denied","message":"no"}"#),
            r#"{"state":"in_flight","resumable":true}"#.to_owned(),
            r#"{"state":"in_flight","resumable":false}"#.to_owned(),
        ];
        for (record, state) in records().iter().zip(states) {
            let golden = format!("{head}{state}}}");
            assert_eq!(encode_replay_record(record).as_bytes(), golden.as_bytes());
        }
        let quota = QuotaState {
            window_start: 1_700_000_000_000,
            ops: 3,
            bytes: u64::MAX,
        };
        let golden =
            b"\x01{\"window_start\":1700000000000,\"ops\":3,\"bytes\":18446744073709551615}";
        assert_eq!(encode_quota_state(&quota).as_bytes(), golden);
        assert_eq!(encode_ref_id(&[4; 32]).as_bytes(), [4; 32]);
        assert_eq!(
            encode_u64(u64::MAX - 1).as_bytes(),
            [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe]
        );
        assert_eq!(encode_u64(1).as_bytes(), [0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(encode_u32(1).as_bytes(), [0, 0, 0, 1]);
    }

    #[test]
    fn coordinator_codecs_roundtrip_and_golden_bytes() {
        let namespace = NamespaceRecord {
            created_at_ms: 1_700_000_000_000,
            config_version: 1,
        };
        let repo = RepoRecord {
            created_at_ms: u64::MAX,
        };
        let namespace_value = encode_namespace_record(&namespace);
        let repo_value = encode_repo_record(&repo);
        assert_eq!(
            namespace_value.as_bytes(),
            b"\x01{\"created_at_ms\":1700000000000,\"config_version\":1}"
        );
        assert_eq!(
            repo_value.as_bytes(),
            b"\x01{\"created_at_ms\":18446744073709551615}"
        );
        assert_eq!(
            decode_namespace_record(&namespace_value).unwrap(),
            namespace
        );
        assert_eq!(decode_repo_record(&repo_value).unwrap(), repo);
        let public = RepoVisibilityV1 {
            visibility: StoredVisibility::Public,
            last_created_ms: 0,
            last_statement_id: None,
            changed_ms: None,
        };
        let private = RepoVisibilityV1 {
            visibility: StoredVisibility::Private,
            last_created_ms: 1_700_000_000_000,
            last_statement_id: Some("ab".repeat(32)),
            changed_ms: Some(1_700_000_000_001),
        };
        let public_value = encode_repo_visibility(&public);
        let private_value = encode_repo_visibility(&private);
        assert_eq!(
            public_value.as_bytes(),
            b"\x01{\"visibility\":\"public\",\"last_created_ms\":0,\"last_statement_id\":null}"
        );
        assert_eq!(
            private_value.as_bytes(),
            format!(
                "\x01{{\"visibility\":\"private\",\"last_created_ms\":1700000000000,\"last_statement_id\":\"{}\",\"changed_ms\":1700000000001}}",
                "ab".repeat(32)
            )
            .as_bytes()
        );
        assert_eq!(decode_repo_visibility(&public_value).unwrap(), public);
        assert_eq!(decode_repo_visibility(&private_value).unwrap(), private);
        // A legacy 3-key row has no change time and falls back to its
        // last accepted creation time.
        let legacy = decode_repo_visibility(&Value::new(
            b"\x01{\"visibility\":\"private\",\"last_created_ms\":7,\"last_statement_id\":null}"
                .to_vec(),
        ))
        .unwrap();
        assert_eq!(legacy.changed_ms, None);
        assert_eq!(legacy.visibility_changed_ms(), 7);
        assert_eq!(private.visibility_changed_ms(), 1_700_000_000_001);
        for bytes in [
            &b""[..],
            b"\x02{\"visibility\":\"public\",\"last_created_ms\":0,\"last_statement_id\":null}",
            b"\x01{\"visibility\":\"internal\",\"last_created_ms\":0,\"last_statement_id\":null}",
            b"\x01{\"visibility\":\"public\"}",
            b"\x01{\"visibility\":\"public\",\"last_created_ms\":0,\"last_statement_id\":\"AB\",\"changed_ms\":0}",
            b"\x01{\"visibility\":\"public\",\"last_created_ms\":0}",
            b"\x01{\"visibility\":\"public\",\"last_created_ms\":0,\"last_statement_id\":\"ab\",\"changed_ms\":0,\"extra\":1}",
        ] {
            assert!(matches!(
                decode_repo_visibility(&Value::new(bytes.to_vec())),
                Err(StoreError::Corrupt(_))
            ));
        }
        for bytes in [
            &b""[..],
            b"\x02{\"created_at_ms\":0,\"config_version\":1}",
            b"\x01{\"created_at_ms\":-1,\"config_version\":1}",
            b"\x01{\"created_at_ms\":0,\"config_version\":0}",
            b"\x01{\"created_at_ms\":0,\"config_version\":1,\"extra\":1}",
            b"\x01{\"created_at_ms\":0}",
        ] {
            assert!(matches!(
                decode_namespace_record(&Value::new(bytes.to_vec())),
                Err(StoreError::Corrupt(_))
            ));
        }
        for bytes in [
            &b""[..],
            b"\x02{\"created_at_ms\":0}",
            b"\x01{\"created_at_ms\":-1}",
            b"\x01{\"created_at_ms\":0,\"extra\":1}",
            b"\x01{}",
        ] {
            assert!(matches!(
                decode_repo_record(&Value::new(bytes.to_vec())),
                Err(StoreError::Corrupt(_))
            ));
        }
    }

    #[test]
    fn lease_codecs_roundtrip_and_golden_bytes() {
        let epoch = EpochLease {
            authority_ready: None,
            authority_generation: None,
            epoch: 7,
            expires_at_ms: 30000,
            config_version: 2,
        };
        let shard = LeasedShard {
            authority_generation: None,
            acked_authority_generation: None,
            epoch: 7,
            expires_at_ms: 30000,
            acked_epoch: 6,
            relay_watermark_ms: 123,
            sweep_due_ms: 30000,
        };
        let recovery = LeaseRecovery {
            authority_fence: None,
            authority_ready: None,
            activation_only: None,
            resumed_at_ms: 100_000,
        };
        let epoch_value = encode_epoch_lease(&epoch);
        let shard_value = encode_leased_shard(&shard);
        let recovery_value = encode_lease_recovery(&recovery);
        assert_eq!(
            epoch_value.as_bytes(),
            b"\x01{\"epoch\":7,\"expires_at_ms\":30000,\"config_version\":2}"
        );
        assert_eq!(
            shard_value.as_bytes(),
            b"\x01{\"epoch\":7,\"expires_at_ms\":30000,\"acked_epoch\":6,\"relay_watermark_ms\":123,\"sweep_due_ms\":30000}"
        );
        assert_eq!(recovery_value.as_bytes(), b"\x01{\"resumed_at_ms\":100000}");
        assert_eq!(decode_epoch_lease(&epoch_value).unwrap(), epoch);
        assert_eq!(decode_leased_shard(&shard_value).unwrap(), shard);
        assert_eq!(decode_lease_recovery(&recovery_value).unwrap(), recovery);
        for version in [0, 2, 255] {
            for value in [&epoch_value, &shard_value, &recovery_value] {
                let mut bytes = value.as_bytes().to_vec();
                bytes[0] = version;
                let bad = Value::new(bytes);
                assert!(decode_epoch_lease(&bad).is_err());
                assert!(decode_leased_shard(&bad).is_err());
                assert!(decode_lease_recovery(&bad).is_err());
            }
        }
        for body in [
            "{\"epoch\":7,\"expires_at_ms\":30000,\"config_version\":2,\"extra\":0}",
            "{\"epoch\":7,\"expires_at_ms\":30000,\"config_version\":0}",
            "{\"epoch\":7,\"expires_at_ms\":30000}",
        ] {
            assert!(
                decode_epoch_lease(&Value::new([&[CODEC_V1][..], body.as_bytes()].concat()))
                    .is_err()
            );
        }
        for body in [
            "{\"epoch\":7,\"expires_at_ms\":30000,\"acked_epoch\":6,\"extra\":0}",
            "{\"epoch\":7,\"expires_at_ms\":30000}",
        ] {
            assert!(
                decode_leased_shard(&Value::new([&[CODEC_V1][..], body.as_bytes()].concat()))
                    .is_err()
            );
        }
        assert!(
            decode_lease_recovery(&Value::new(
                b"\x01{\"resumed_at_ms\":100000,\"extra\":0}".to_vec()
            ))
            .is_err()
        );
        assert!(
            decode_lease_recovery(&Value::new(b"\x02{\"resumed_at_ms\":100000}".to_vec())).is_err()
        );
        assert!(
            decode_leased_shard(&Value::new(
                b"\x02{\"epoch\":7,\"expires_at_ms\":30000,\"acked_epoch\":6}".to_vec()
            ))
            .is_err()
        );
    }

    #[test]
    fn content_index_codecs_golden_bytes() {
        let block = BlockEntry {
            reason: "dmca".into(),
            blocked_at_ms: 7,
        };
        let state = ObjectState {
            seq: u64::MAX,
            changed_at_ms: 1_700_000_000_000,
            holders: 2,
            deleting: true,
        };
        let holder = HolderRecord::new(5, [0xab; 32]);
        let holder_golden = format!("\x01{{\"seq\":5,\"op_id\":\"{}\"}}", "ab".repeat(32));
        assert_eq!(encode_holder(&holder).as_bytes(), holder_golden.as_bytes());
        assert_eq!(decode_holder(&encode_holder(&holder)).unwrap(), holder);
        for bad in [
            &b"\x01{\"seq\":5}"[..],
            b"\x01{\"seq\":5,\"op_id\":\"zz\"}",
            b"\x02{}",
            b"",
        ] {
            let bad = Value::new(bad.to_vec());
            assert!(matches!(decode_holder(&bad), Err(StoreError::Corrupt(_))));
        }
        let cases: [(Value, &[u8]); 3] = [
            (encode_hold(9), b"\x01{\"expires_at_ms\":9}"),
            (
                encode_block_entry(&block),
                b"\x01{\"reason\":\"dmca\",\"blocked_at_ms\":7}",
            ),
            (
                encode_object_state(&state),
                b"\x01{\"seq\":18446744073709551615,\"changed_at_ms\":1700000000000,\"holders\":2,\"deleting\":true}",
            ),
        ];
        for (value, golden) in &cases {
            assert_eq!(value.as_bytes(), *golden);
        }
        assert_eq!(decode_hold(&cases[0].0).unwrap(), 9);
        assert_eq!(decode_block_entry(&cases[1].0).unwrap(), block);
        assert_eq!(decode_object_state(&cases[2].0).unwrap(), state);
        for bad in [
            &b"\x02{\"expires_at_ms\":9}"[..],
            b"\x01{\"expires_at_ms\":-1}",
            b"\x01{\"seq\":0,\"changed_at_ms\":0}",
        ] {
            let v = Value::new(bad.to_vec());
            assert!(matches!(decode_hold(&v), Err(StoreError::Corrupt(_))));
            assert!(matches!(
                decode_block_entry(&v),
                Err(StoreError::Corrupt(_))
            ));
            assert!(matches!(
                decode_object_state(&v),
                Err(StoreError::Corrupt(_))
            ));
        }
    }

    #[test]
    fn unknown_version_byte_is_corrupt() {
        let mut bytes = encode_replay_record(&records()[0]).as_bytes().to_vec();
        bytes[0] = 0x02;
        let bumped = Value::new(bytes);
        assert!(matches!(
            decode_replay_record(&bumped),
            Err(StoreError::Corrupt(_))
        ));
        assert!(matches!(
            decode_quota_state(&bumped),
            Err(StoreError::Corrupt(_))
        ));
        for bad in [
            &b""[..],
            b"\x01{",
            b"\x01{\"window_start\":0,\"ops\":0,\"bytes\":0,\"extra\":1}",
            b"\x01{\"fingerprint\":\"00\",\"expires_at_ms\":0,\"state\":{\"state\":\"in_flight\",\"resumable\":true}}",
        ] {
            let v = Value::new(bad.to_vec());
            assert!(matches!(decode_replay_record(&v), Err(StoreError::Corrupt(_))));
            assert!(matches!(decode_quota_state(&v), Err(StoreError::Corrupt(_))));
        }
        let retryable = format!(
            "\x01{{\"fingerprint\":\"{}\",\"expires_at_ms\":0,\"state\":{{\"state\":\"committed\",\"result\":{{\"kind\":\"rejected\",\"code\":\"unavailable\",\"message\":\"m\"}}}}}}",
            "00".repeat(32)
        );
        assert!(matches!(
            decode_replay_record(&Value::new(retryable.into_bytes())),
            Err(StoreError::Corrupt(_))
        ));
        assert!(matches!(
            decode_ref_id(&Value::new(vec![0; 31])),
            Err(StoreError::Corrupt(_))
        ));
        assert!(matches!(
            decode_u64(&Value::new(vec![0; 4])),
            Err(StoreError::Corrupt(_))
        ));
    }

    #[test]
    fn namespace_quota_binary_goldens_and_corruption() {
        let usage = NamespaceUsage { ops: 2, bytes: 258 };
        assert_eq!(
            encode_namespace_usage(usage).as_bytes(),
            b"\0\0\0\0\0\0\0\x02\0\0\0\0\0\0\x01\x02"
        );
        assert_eq!(
            decode_namespace_usage(&encode_namespace_usage(usage)).unwrap(),
            usage
        );
        let view = NamespaceView {
            total: usage,
            pushed: NamespaceUsage { ops: 1, bytes: 1 },
            observed_at_ms: 60_000,
        };
        assert_eq!(encode_namespace_view(view).as_bytes().len(), 40);
        assert_eq!(
            decode_namespace_view(&encode_namespace_view(view)).unwrap(),
            view
        );
        assert!(matches!(
            decode_namespace_usage(&Value::new(vec![0; 15])),
            Err(StoreError::Corrupt(_))
        ));
        assert!(matches!(
            decode_namespace_view(&Value::new(vec![0; 39])),
            Err(StoreError::Corrupt(_))
        ));
        let invalid = NamespaceView {
            pushed: NamespaceUsage { ops: 3, bytes: 1 },
            ..view
        };
        assert!(matches!(
            decode_namespace_view(&encode_namespace_view(invalid)),
            Err(StoreError::Corrupt(_))
        ));
    }
}

#[cfg(test)]
#[path = "codec_v050_tests.rs"]
mod stored_v050_tests;
