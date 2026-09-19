//! Bounded v1 durable-state envelopes for scoped workspaces.
//!
//! Every envelope is `[magic:4][version:1][payload][checksum:32]` where
//! `checksum = BLAKE3(magic ‖ version ‖ payload)`. Fixed-width integers are
//! big-endian, counts and byte strings use minimal unsigned LEB128, fixed
//! arrays carry no length, option tags are exactly `0`/`1`, and decoding
//! rejects unknown versions, unknown tags, trailing bytes, and any complete
//! envelope over [`MAX_ENVELOPE_BYTES`]. The checksum detects corruption and
//! torn writes; it is not a signature and confers no authority.

use crate::hash::{self, Hash};
use crate::object::EntryMode;

use super::state::{
    AcceptedStateV1, PartialStateError, PendingOperationV1, PendingStateV1, PendingStatusV1,
    RemotePublicationTargetV1, StageEntryV1, StageStateV1, WorkspaceSelectionV1, WorkspaceStateV1,
};
use super::{PartialLimits, PartialPath, validate_paths};

const VERSION: u8 = 1;
const ENVELOPE_OVERHEAD: usize = 4 + 1 + 32;

/// Maximum byte length of a complete envelope, checksum included.
pub(crate) const MAX_ENVELOPE_BYTES: usize = 1024 * 1024;

pub(crate) const MAGIC_WORKSPACE: [u8; 4] = *b"MKWS";
pub(crate) const MAGIC_STAGE: [u8; 4] = *b"MKST";
pub(crate) const MAGIC_PENDING: [u8; 4] = *b"MKPN";
pub(crate) const MAGIC_ACCEPTED: [u8; 4] = *b"MKAC";
pub(crate) const MAGIC_MANIFEST: [u8; 4] = *b"MKGM";
pub(crate) const MAGIC_CURRENT: [u8; 4] = *b"MKCR";

/// Flat BLAKE3 of a complete envelope — the digest member names and the
/// generation directory name are derived from.
pub(crate) fn envelope_digest(bytes: &[u8]) -> Hash {
    hash::hash(bytes)
}

fn seal(magic: [u8; 4], payload: &[u8]) -> Result<Vec<u8>, PartialStateError> {
    let total = ENVELOPE_OVERHEAD
        .checked_add(payload.len())
        .ok_or(PartialStateError::EnvelopeTooLarge)?;
    if total > MAX_ENVELOPE_BYTES {
        return Err(PartialStateError::EnvelopeTooLarge);
    }
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&magic);
    out.push(VERSION);
    out.extend_from_slice(payload);
    let checksum = hash::hash(&out);
    out.extend_from_slice(&checksum);
    Ok(out)
}

fn open(magic: [u8; 4], bytes: &[u8]) -> Result<&[u8], PartialStateError> {
    if bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(PartialStateError::EnvelopeTooLarge);
    }
    if bytes.len() < ENVELOPE_OVERHEAD {
        return Err(PartialStateError::NonCanonical("short envelope"));
    }
    if bytes[..4] != magic {
        return Err(PartialStateError::NonCanonical("magic"));
    }
    if bytes[4] != VERSION {
        return Err(PartialStateError::UnsupportedVersion(bytes[4]));
    }
    let (body, checksum) = bytes.split_at(bytes.len() - 32);
    if hash::hash(body)
        != *<&Hash>::try_from(checksum)
            .map_err(|_| PartialStateError::NonCanonical("checksum length"))?
    {
        return Err(PartialStateError::ChecksumMismatch);
    }
    Ok(&body[5..])
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], PartialStateError> {
        let end = self
            .pos
            .checked_add(count)
            .ok_or(PartialStateError::NonCanonical("length"))?;
        if end > self.bytes.len() {
            return Err(PartialStateError::NonCanonical("truncated"));
        }
        let out = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, PartialStateError> {
        Ok(self.take(1)?[0])
    }

    fn u64(&mut self) -> Result<u64, PartialStateError> {
        Ok(u64::from_be_bytes(
            <[u8; 8]>::try_from(self.take(8)?)
                .map_err(|_| PartialStateError::NonCanonical("u64"))?,
        ))
    }

    fn fixed32(&mut self) -> Result<Hash, PartialStateError> {
        <Hash>::try_from(self.take(32)?).map_err(|_| PartialStateError::NonCanonical("fixed32"))
    }

    /// Minimal unsigned LEB128, at most the bits of a `u64`.
    fn varint(&mut self) -> Result<u64, PartialStateError> {
        let mut value = 0u64;
        let mut shift = 0u32;
        loop {
            let byte = self.u8()?;
            let part = u64::from(byte & 0x7F);
            if shift == 63 && part > 1 {
                return Err(PartialStateError::NonCanonical("varint overflow"));
            }
            value |= part << shift;
            if byte & 0x80 == 0 {
                if shift != 0 && part == 0 {
                    return Err(PartialStateError::NonCanonical("non-minimal varint"));
                }
                return Ok(value);
            }
            shift = shift
                .checked_add(7)
                .filter(|next| *next < 64)
                .ok_or(PartialStateError::NonCanonical("varint overflow"))?;
            if shift == 63 && self.pos >= self.bytes.len() {
                return Err(PartialStateError::NonCanonical("truncated"));
            }
        }
    }

    fn varint_bounded(&mut self, max: usize) -> Result<usize, PartialStateError> {
        let value = self.varint()?;
        let value = usize::try_from(value)
            .map_err(|_| PartialStateError::NonCanonical("count overflow"))?;
        if value > max {
            return Err(PartialStateError::NonCanonical("count bound"));
        }
        Ok(value)
    }

    fn byte_string(&mut self, max: usize) -> Result<&'a [u8], PartialStateError> {
        let len = self.varint_bounded(max)?;
        self.take(len)
    }

    fn path(&mut self) -> Result<PartialPath, PartialStateError> {
        let count = self.varint_bounded(PartialLimits::V1.max_path_depth)?;
        if count == 0 {
            return Err(PartialStateError::NonCanonical("empty path"));
        }
        let mut components = Vec::with_capacity(count);
        for _ in 0..count {
            components.push(
                self.byte_string(PartialLimits::V1.max_component_bytes)?
                    .to_vec(),
            );
        }
        Ok(components)
    }

    fn finish(self) -> Result<(), PartialStateError> {
        if self.pos != self.bytes.len() {
            return Err(PartialStateError::NonCanonical("trailing bytes"));
        }
        Ok(())
    }
}

struct Writer {
    out: Vec<u8>,
}

impl Writer {
    fn new() -> Self {
        Self { out: Vec::new() }
    }

    fn u8(&mut self, value: u8) {
        self.out.push(value);
    }

    fn u64(&mut self, value: u64) {
        self.out.extend_from_slice(&value.to_be_bytes());
    }

    fn fixed32(&mut self, value: &Hash) {
        self.out.extend_from_slice(value);
    }

    fn varint(&mut self, value: usize) -> Result<(), PartialStateError> {
        let mut value =
            u64::try_from(value).map_err(|_| PartialStateError::NonCanonical("count"))?;
        loop {
            let mut byte = (value & 0x7F) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            self.out.push(byte);
            if value == 0 {
                return Ok(());
            }
        }
    }

    fn byte_string(&mut self, bytes: &[u8]) -> Result<(), PartialStateError> {
        self.varint(bytes.len())?;
        self.out.extend_from_slice(bytes);
        Ok(())
    }

    fn path(&mut self, path: &PartialPath) -> Result<(), PartialStateError> {
        self.varint(path.len())?;
        for component in path {
            self.byte_string(component)?;
        }
        Ok(())
    }
}

const LIMIT_FIELDS: usize = 20;

fn write_limits(writer: &mut Writer, limits: &PartialLimits) -> Result<(), PartialStateError> {
    let field = |value: usize| -> Result<u64, PartialStateError> {
        u64::try_from(value).map_err(|_| PartialStateError::NonCanonical("limits"))
    };
    let fields: [u64; LIMIT_FIELDS] = [
        field(limits.max_selected_paths)?,
        field(limits.max_path_depth)?,
        field(limits.max_component_bytes)?,
        field(limits.max_path_bytes)?,
        field(limits.max_total_path_bytes)?,
        field(limits.max_selected_file_bytes)?,
        field(limits.max_total_selected_bytes)?,
        field(limits.max_base_object_bytes)?,
        field(limits.max_tree_object_bytes)?,
        field(limits.max_tree_entries)?,
        field(limits.max_witness_bytes)?,
        field(limits.max_tree_visits)?,
        field(limits.max_bundle_bytes)?,
        field(limits.max_objects)?,
        field(limits.max_object_bytes)?,
        field(limits.max_update_bytes)?,
        field(limits.max_raw_pack_bytes)?,
        field(limits.max_update_objects)?,
        field(limits.max_commit_message_bytes)?,
        field(limits.max_changed_paths)?,
    ];
    for field in fields {
        writer.u64(field);
    }
    Ok(())
}

fn read_limits(reader: &mut Reader) -> Result<PartialLimits, PartialStateError> {
    let mut fields = [0u64; LIMIT_FIELDS];
    for field in &mut fields {
        *field = reader.u64()?;
    }
    let to_usize =
        |value: u64| usize::try_from(value).map_err(|_| PartialStateError::NonCanonical("limits"));
    let limits = PartialLimits {
        max_selected_paths: to_usize(fields[0])?,
        max_path_depth: to_usize(fields[1])?,
        max_component_bytes: to_usize(fields[2])?,
        max_path_bytes: to_usize(fields[3])?,
        max_total_path_bytes: to_usize(fields[4])?,
        max_selected_file_bytes: to_usize(fields[5])?,
        max_total_selected_bytes: to_usize(fields[6])?,
        max_base_object_bytes: to_usize(fields[7])?,
        max_tree_object_bytes: to_usize(fields[8])?,
        max_tree_entries: to_usize(fields[9])?,
        max_witness_bytes: to_usize(fields[10])?,
        max_tree_visits: to_usize(fields[11])?,
        max_bundle_bytes: to_usize(fields[12])?,
        max_objects: to_usize(fields[13])?,
        max_object_bytes: to_usize(fields[14])?,
        max_update_bytes: to_usize(fields[15])?,
        max_raw_pack_bytes: to_usize(fields[16])?,
        max_update_objects: to_usize(fields[17])?,
        max_commit_message_bytes: to_usize(fields[18])?,
        max_changed_paths: to_usize(fields[19])?,
    };
    if !limits.is_v1_subset() {
        return Err(PartialStateError::LimitsUnsupported);
    }
    Ok(limits)
}

fn read_mode(reader: &mut Reader) -> Result<EntryMode, PartialStateError> {
    match reader.u8()? {
        0x01 => Ok(EntryMode::Blob),
        0x04 => Ok(EntryMode::Executable),
        _ => Err(PartialStateError::NonCanonical("mode")),
    }
}

fn write_mode(writer: &mut Writer, mode: EntryMode) -> Result<(), PartialStateError> {
    match mode {
        EntryMode::Blob | EntryMode::Executable => {
            writer.u8(mode as u8);
            Ok(())
        }
        _ => Err(PartialStateError::NonCanonical("mode")),
    }
}

fn read_tag(reader: &mut Reader) -> Result<bool, PartialStateError> {
    match reader.u8()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(PartialStateError::NonCanonical("option tag")),
    }
}

fn read_operation(reader: &mut Reader) -> Result<Option<PendingOperationV1>, PartialStateError> {
    if read_tag(reader)? {
        let operation_id = reader.fixed32()?;
        let request_fingerprint = reader.fixed32()?;
        Ok(Some(PendingOperationV1 {
            operation_id,
            request_fingerprint,
        }))
    } else {
        Ok(None)
    }
}

fn write_operation(writer: &mut Writer, operation: Option<&PendingOperationV1>) {
    match operation {
        Some(operation) => {
            writer.u8(1);
            writer.fixed32(&operation.operation_id);
            writer.fixed32(&operation.request_fingerprint);
        }
        None => writer.u8(0),
    }
}

fn read_text(
    reader: &mut Reader,
    max: usize,
    field: &'static str,
) -> Result<String, PartialStateError> {
    let bytes = reader.byte_string(max)?;
    String::from_utf8(bytes.to_vec()).map_err(|_| PartialStateError::NonCanonical(field))
}

impl WorkspaceStateV1 {
    /// Encode as the `MKWS` envelope.
    pub fn encode(&self) -> Result<Vec<u8>, PartialStateError> {
        let mut writer = Writer::new();
        writer.fixed32(&self.workspace_id);
        writer.u64(self.transaction_generation);
        writer.u64(self.base_revision);
        writer.fixed32(&self.base_id);
        writer.fixed32(&self.base_bundle_digest);
        writer.varint(self.selection.len())?;
        for entry in &self.selection {
            writer.path(&entry.path)?;
            write_mode(&mut writer, entry.mode)?;
            writer.fixed32(&entry.base_file_id);
        }
        write_limits(&mut writer, &self.limits)?;
        match &self.target {
            Some(target) => {
                writer.u8(1);
                writer.byte_string(target.endpoint.as_bytes())?;
                writer.byte_string(target.repository.as_bytes())?;
                writer.byte_string(target.exact_ref.as_bytes())?;
            }
            None => writer.u8(0),
        }
        seal(MAGIC_WORKSPACE, &writer.out)
    }

    /// Decode and strictly validate a `MKWS` envelope.
    pub fn decode(bytes: &[u8]) -> Result<Self, PartialStateError> {
        let mut reader = Reader::new(open(MAGIC_WORKSPACE, bytes)?);
        let workspace_id = reader.fixed32()?;
        let transaction_generation = reader.u64()?;
        let base_revision = reader.u64()?;
        let base_id = reader.fixed32()?;
        let base_bundle_digest = reader.fixed32()?;
        let count = reader.varint_bounded(PartialLimits::V1.max_selected_paths)?;
        let mut selection = Vec::with_capacity(count);
        for _ in 0..count {
            let path = reader.path()?;
            let mode = read_mode(&mut reader)?;
            let base_file_id = reader.fixed32()?;
            selection.push(WorkspaceSelectionV1 {
                path,
                mode,
                base_file_id,
            });
        }
        let limits = read_limits(&mut reader)?;
        let target = if read_tag(&mut reader)? {
            let endpoint = read_text(
                &mut reader,
                RemotePublicationTargetV1::MAX_ENDPOINT_BYTES,
                "endpoint",
            )?;
            let repository = read_text(
                &mut reader,
                RemotePublicationTargetV1::MAX_REPOSITORY_BYTES,
                "repository",
            )?;
            let exact_ref = read_text(
                &mut reader,
                RemotePublicationTargetV1::MAX_REF_BYTES,
                "exact_ref",
            )?;
            Some(RemotePublicationTargetV1::new(
                &endpoint,
                &repository,
                &exact_ref,
            )?)
        } else {
            None
        };
        reader.finish()?;
        validate_paths(
            &selection
                .iter()
                .map(|entry| entry.path.clone())
                .collect::<Vec<_>>(),
            &limits,
        )
        .map_err(PartialStateError::from)?;
        Ok(Self {
            workspace_id,
            transaction_generation,
            base_revision,
            base_id,
            base_bundle_digest,
            selection,
            limits,
            target,
        })
    }
}

impl StageStateV1 {
    /// Encode as the `MKST` envelope.
    pub fn encode(&self) -> Result<Vec<u8>, PartialStateError> {
        let mut writer = Writer::new();
        writer.fixed32(&self.workspace_id);
        writer.fixed32(&self.base_id);
        writer.u64(self.base_revision);
        writer.varint(self.entries.len())?;
        for entry in &self.entries {
            writer.path(&entry.path)?;
            write_mode(&mut writer, entry.mode)?;
            writer.fixed32(&entry.staged_id);
        }
        writer.varint(self.required_object_ids.len())?;
        for id in &self.required_object_ids {
            writer.fixed32(id);
        }
        seal(MAGIC_STAGE, &writer.out)
    }

    /// Decode and strictly validate a `MKST` envelope.
    pub fn decode(bytes: &[u8]) -> Result<Self, PartialStateError> {
        let mut reader = Reader::new(open(MAGIC_STAGE, bytes)?);
        let workspace_id = reader.fixed32()?;
        let base_id = reader.fixed32()?;
        let base_revision = reader.u64()?;
        let count = reader.varint_bounded(PartialLimits::V1.max_selected_paths)?;
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            let path = reader.path()?;
            let mode = read_mode(&mut reader)?;
            let staged_id = reader.fixed32()?;
            entries.push(StageEntryV1 {
                path,
                mode,
                staged_id,
            });
        }
        let object_count = reader.varint_bounded(PartialLimits::V1.max_objects)?;
        let mut required_object_ids = Vec::with_capacity(object_count);
        for _ in 0..object_count {
            let id = reader.fixed32()?;
            if required_object_ids.last().is_some_and(|prior| *prior >= id) {
                return Err(PartialStateError::NonCanonical("object id order"));
            }
            required_object_ids.push(id);
        }
        reader.finish()?;
        validate_paths(
            &entries
                .iter()
                .map(|entry| entry.path.clone())
                .collect::<Vec<_>>(),
            &PartialLimits::V1,
        )
        .map_err(PartialStateError::from)?;
        Ok(Self {
            workspace_id,
            base_id,
            base_revision,
            entries,
            required_object_ids,
        })
    }
}

impl PendingStateV1 {
    /// Encode as the `MKPN` envelope.
    pub fn encode(&self) -> Result<Vec<u8>, PartialStateError> {
        let mut writer = Writer::new();
        writer.fixed32(&self.workspace_id);
        writer.fixed32(&self.base_id);
        writer.u64(self.base_revision);
        writer.u64(self.created_generation);
        writer.fixed32(&self.candidate_id);
        writer.fixed32(&self.update_digest);
        writer.u64(self.update_length);
        writer.u8(match self.status {
            PendingStatusV1::Prepared => 0,
            PendingStatusV1::Exported => 1,
            PendingStatusV1::Conflict => 2,
            PendingStatusV1::Unknown => 3,
        });
        write_operation(&mut writer, self.operation.as_ref());
        seal(MAGIC_PENDING, &writer.out)
    }

    /// Decode and strictly validate a `MKPN` envelope.
    pub fn decode(bytes: &[u8]) -> Result<Self, PartialStateError> {
        let mut reader = Reader::new(open(MAGIC_PENDING, bytes)?);
        let workspace_id = reader.fixed32()?;
        let base_id = reader.fixed32()?;
        let base_revision = reader.u64()?;
        let created_generation = reader.u64()?;
        let candidate_id = reader.fixed32()?;
        let update_digest = reader.fixed32()?;
        let update_length = reader.u64()?;
        let status = match reader.u8()? {
            0 => PendingStatusV1::Prepared,
            1 => PendingStatusV1::Exported,
            2 => PendingStatusV1::Conflict,
            3 => PendingStatusV1::Unknown,
            _ => return Err(PartialStateError::NonCanonical("status")),
        };
        let operation = read_operation(&mut reader)?;
        reader.finish()?;
        Ok(Self {
            workspace_id,
            base_id,
            base_revision,
            created_generation,
            candidate_id,
            update_digest,
            update_length,
            status,
            operation,
        })
    }
}

impl AcceptedStateV1 {
    /// Encode as the `MKAC` envelope.
    pub fn encode(&self) -> Result<Vec<u8>, PartialStateError> {
        let mut writer = Writer::new();
        writer.fixed32(&self.workspace_id);
        writer.fixed32(&self.prior_base_id);
        writer.u64(self.accepted_base_revision);
        writer.fixed32(&self.candidate_id);
        writer.fixed32(&self.update_digest);
        write_operation(&mut writer, self.operation.as_ref());
        seal(MAGIC_ACCEPTED, &writer.out)
    }

    /// Decode and strictly validate a `MKAC` envelope.
    pub fn decode(bytes: &[u8]) -> Result<Self, PartialStateError> {
        let mut reader = Reader::new(open(MAGIC_ACCEPTED, bytes)?);
        let workspace_id = reader.fixed32()?;
        let prior_base_id = reader.fixed32()?;
        let accepted_base_revision = reader.u64()?;
        let candidate_id = reader.fixed32()?;
        let update_digest = reader.fixed32()?;
        let operation = read_operation(&mut reader)?;
        reader.finish()?;
        Ok(Self {
            workspace_id,
            prior_base_id,
            accepted_base_revision,
            candidate_id,
            update_digest,
            operation,
        })
    }
}

/// The `MKGM` generation manifest: one transaction generation plus the flat
/// BLAKE3 digest of each member envelope selected by fixed file name.
#[derive(Debug, Clone)]
pub(crate) struct GenerationManifestV1 {
    pub(crate) transaction_generation: u64,
    pub(crate) workspace_digest: Hash,
    pub(crate) stage_digest: Hash,
    pub(crate) pending_digest: Option<Hash>,
    pub(crate) accepted_digest: Option<Hash>,
}

impl GenerationManifestV1 {
    pub(crate) fn encode(&self) -> Result<Vec<u8>, PartialStateError> {
        let mut writer = Writer::new();
        writer.u64(self.transaction_generation);
        writer.fixed32(&self.workspace_digest);
        writer.fixed32(&self.stage_digest);
        match self.pending_digest {
            Some(digest) => {
                writer.u8(1);
                writer.fixed32(&digest);
            }
            None => writer.u8(0),
        }
        match self.accepted_digest {
            Some(digest) => {
                writer.u8(1);
                writer.fixed32(&digest);
            }
            None => writer.u8(0),
        }
        seal(MAGIC_MANIFEST, &writer.out)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, PartialStateError> {
        let mut reader = Reader::new(open(MAGIC_MANIFEST, bytes)?);
        let transaction_generation = reader.u64()?;
        let workspace_digest = reader.fixed32()?;
        let stage_digest = reader.fixed32()?;
        let pending_digest = if read_tag(&mut reader)? {
            Some(reader.fixed32()?)
        } else {
            None
        };
        let accepted_digest = if read_tag(&mut reader)? {
            Some(reader.fixed32()?)
        } else {
            None
        };
        reader.finish()?;
        Ok(Self {
            transaction_generation,
            workspace_digest,
            stage_digest,
            pending_digest,
            accepted_digest,
        })
    }
}

/// The `MKCR` CURRENT pointer: the single visibility point selecting one
/// committed generation.
#[derive(Debug, Clone)]
pub(crate) struct CurrentPointerV1 {
    pub(crate) transaction_generation: u64,
    pub(crate) manifest_digest: Hash,
}

impl CurrentPointerV1 {
    pub(crate) fn encode(&self) -> Result<Vec<u8>, PartialStateError> {
        let mut writer = Writer::new();
        writer.u64(self.transaction_generation);
        writer.fixed32(&self.manifest_digest);
        seal(MAGIC_CURRENT, &writer.out)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, PartialStateError> {
        let mut reader = Reader::new(open(MAGIC_CURRENT, bytes)?);
        let transaction_generation = reader.u64()?;
        let manifest_digest = reader.fixed32()?;
        reader.finish()?;
        Ok(Self {
            transaction_generation,
            manifest_digest,
        })
    }
}
