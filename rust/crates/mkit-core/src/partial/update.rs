//! `MKWU` v1 explicit raw-object partial update carrier.

#[cfg(test)]
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};

use crate::hash::Hash;
use crate::object::{Commit, EntryMode, Object, ObjectType, id_from_object};
use crate::pack::{PackEntries, PackEntry, PackWriter, pack_key};
use crate::serialize::{deserialize, serialize};
use crate::sign::verify_commit;

use super::overlay::{PreparedChange, PreparedPartialEdit, validate_prepared_output};
use super::verify::{
    add_chunk_len, preflight_file, preflight_tree, validate_chunk_occurrence,
    validate_manifest_size,
};
use super::{PartialError, PartialLimits, PartialPath, VerifiedPartialSnapshot, validate_paths};

const MAGIC: &[u8; 4] = b"MKWU";
const VERSION: u8 = 1;
const FIXED_WITHOUT_CHANGES_OR_PACK: usize = 5 + 32 + 32 + 32 + 8;

#[cfg(test)]
thread_local! {
    static PACK_BUILDS: Cell<usize> = const { Cell::new(0) };
    static DECODE_CHUNK_OCCURRENCES: Cell<usize> = const { Cell::new(0) };
}

/// Portable explicit raw-object update. It is a carrier, not an mkit object,
/// a closure claim, or publication authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialUpdate {
    base_id: Hash,
    candidate_id: Hash,
    pub(super) changes: Vec<UpdateChange>,
    pack_hash: Hash,
    pack_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct UpdateChange {
    pub(super) path: PartialPath,
    pub(super) old_mode: EntryMode,
    pub(super) old_id: Hash,
    pub(super) new_id: Hash,
}

struct DecodedInventory {
    ids: BTreeSet<Hash>,
    objects: BTreeMap<Hash, Object>,
    candidate: Commit,
}

impl PartialUpdate {
    #[must_use]
    pub fn base_id(&self) -> &Hash {
        &self.base_id
    }

    #[must_use]
    pub fn candidate_id(&self) -> &Hash {
        &self.candidate_id
    }

    #[must_use]
    pub fn changed_paths(&self) -> impl ExactSizeIterator<Item = &PartialPath> {
        self.changes.iter().map(|change| &change.path)
    }

    #[must_use]
    pub fn pack_hash(&self) -> &Hash {
        &self.pack_hash
    }

    #[must_use]
    pub fn pack_bytes(&self) -> &[u8] {
        &self.pack_bytes
    }

    pub fn encode(&self, limits: &PartialLimits) -> Result<Vec<u8>, PartialError> {
        validate_update_shape(self, limits)?;
        let encoded_len = encoded_len(&self.changes, self.pack_bytes.len())?;
        if encoded_len > limits.max_update_bytes {
            return Err(PartialError::SubmissionTooLarge);
        }
        let mut out = Vec::with_capacity(encoded_len);
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&self.base_id);
        out.extend_from_slice(&self.candidate_id);
        write_varint(&mut out, self.changes.len());
        for change in &self.changes {
            write_varint(&mut out, change.path.len());
            for component in &change.path {
                write_varint(&mut out, component.len());
                out.extend_from_slice(component);
            }
            out.push(change.old_mode as u8);
            out.extend_from_slice(&change.old_id);
            out.extend_from_slice(&change.new_id);
        }
        out.extend_from_slice(&self.pack_hash);
        out.extend_from_slice(&(self.pack_bytes.len() as u64).to_be_bytes());
        write_varint(&mut out, self.pack_bytes.len());
        out.extend_from_slice(&self.pack_bytes);
        Ok(out)
    }

    /// Decode and structurally validate an untrusted v1 update, including
    /// raw-only pack framing, canonical object ids, duplicate inventory,
    /// candidate signature, and base parent binding. Complete-base semantic
    /// admission remains the later recipient layer.
    pub fn decode(bytes: &[u8], limits: &PartialLimits) -> Result<Self, PartialError> {
        if !limits.is_v1_subset() {
            return Err(PartialError::ValidationBudgetExceeded);
        }
        if bytes.len() > limits.max_update_bytes {
            return Err(PartialError::SubmissionTooLarge);
        }
        let mut cursor = Cursor::new(bytes);
        if cursor.take(4)? != MAGIC {
            return Err(PartialError::NonCanonical);
        }
        let version = cursor.byte()?;
        if version != VERSION {
            return Err(PartialError::UnsupportedVersion(version));
        }
        let base_id = cursor.hash()?;
        let candidate_id = cursor.hash()?;
        let count = cursor.varint()?;
        if count == 0 || count > limits.max_changed_paths {
            return Err(PartialError::ValidationBudgetExceeded);
        }
        let mut changes = Vec::with_capacity(count);
        for _ in 0..count {
            let component_count = cursor.varint()?;
            if component_count == 0 || component_count > limits.max_path_depth {
                return Err(PartialError::InvalidPath);
            }
            let mut path = Vec::with_capacity(component_count);
            for _ in 0..component_count {
                let len = cursor.varint()?;
                if len == 0 || len > limits.max_component_bytes {
                    return Err(PartialError::InvalidPath);
                }
                path.push(cursor.take(len)?.to_vec());
            }
            let old_mode = match cursor.byte()? {
                0x01 => EntryMode::Blob,
                0x04 => EntryMode::Executable,
                _ => return Err(PartialError::UnsupportedPartialOperation),
            };
            let old_id = cursor.hash()?;
            let new_id = cursor.hash()?;
            if old_id == new_id {
                return Err(PartialError::NonCanonical);
            }
            changes.push(UpdateChange {
                path,
                old_mode,
                old_id,
                new_id,
            });
        }
        validate_paths(
            &changes
                .iter()
                .map(|change| change.path.clone())
                .collect::<Vec<_>>(),
            limits,
        )?;
        let declared_pack_hash = cursor.hash()?;
        let declared_pack_len =
            usize::try_from(cursor.u64()?).map_err(|_| PartialError::SubmissionTooLarge)?;
        let encoded_pack_len = cursor.varint()?;
        if declared_pack_len > limits.max_raw_pack_bytes
            || encoded_pack_len > limits.max_raw_pack_bytes
            || declared_pack_len != encoded_pack_len
            || encoded_pack_len != cursor.remaining()
        {
            return Err(PartialError::SubmissionTooLarge);
        }
        let pack_bytes = cursor.take(encoded_pack_len)?.to_vec();
        if cursor.remaining() != 0 || pack_key(&pack_bytes) != declared_pack_hash {
            return Err(PartialError::InvalidUpdatePack);
        }
        inspect_inventory(&pack_bytes, base_id, candidate_id, &changes, limits)?;
        let update = Self {
            base_id,
            candidate_id,
            changes,
            pack_hash: declared_pack_hash,
            pack_bytes,
        };
        validate_update_shape(&update, limits)?;
        Ok(update)
    }
}

/// Bind a strict signed Commit to the exact prepared unsigned fields and
/// export the deterministic explicit raw-object inventory.
pub fn export_partial_update(
    verified: &VerifiedPartialSnapshot,
    prepared: &PreparedPartialEdit,
    expected_unsigned: &Commit,
    signed: &Commit,
    limits: &PartialLimits,
) -> Result<PartialUpdate, PartialError> {
    if !limits.is_v1_subset() {
        return Err(PartialError::ValidationBudgetExceeded);
    }
    validate_prepared_output(verified, prepared, limits)?;
    if prepared.base_id != *verified.base_id()
        || expected_unsigned.tree_hash != prepared.root_id
        || expected_unsigned.parents != [*verified.base_id()]
        || expected_unsigned.message.len() > limits.max_commit_message_bytes
        || expected_unsigned.message_hash != [0; 32]
        || expected_unsigned.content_digest != [0; 32]
        || expected_unsigned.signature != [0; 64]
    {
        return Err(PartialError::CommitMismatch);
    }
    let mut signed_unsigned = signed.clone();
    signed_unsigned.signature = [0; 64];
    if signed_unsigned != *expected_unsigned || verify_commit(signed).is_err() {
        return Err(PartialError::CommitMismatch);
    }

    let candidate_bytes =
        serialize(&Object::Commit(signed.clone())).map_err(|_| PartialError::NonCanonical)?;
    if candidate_bytes.len() > limits.max_object_bytes {
        return Err(PartialError::SubmissionTooLarge);
    }
    preflight_candidate(&candidate_bytes, limits)?;
    let candidate_id = id_from_object(&Object::Commit(signed.clone()), &candidate_bytes);
    let changes = prepared
        .changes
        .iter()
        .map(update_change)
        .collect::<Vec<_>>();
    let mut predicted_pack_len = 12usize + 32;
    let mut inventory = BTreeMap::new();
    for (id, bytes) in &prepared.produced {
        insert_borrowed(&mut inventory, *id, bytes, &mut predicted_pack_len, limits)?;
    }
    for id in &prepared.dependency_ids {
        let bytes = verified
            .object_bytes(id)
            .ok_or(PartialError::InsufficientWitness)?;
        insert_borrowed(&mut inventory, *id, bytes, &mut predicted_pack_len, limits)?;
    }
    insert_borrowed(
        &mut inventory,
        candidate_id,
        &candidate_bytes,
        &mut predicted_pack_len,
        limits,
    )?;
    if encoded_len(&changes, predicted_pack_len)? > limits.max_update_bytes {
        return Err(PartialError::SubmissionTooLarge);
    }

    let pack_bytes = write_pack(&inventory)?;
    if pack_bytes.len() != predicted_pack_len {
        return Err(PartialError::InvalidUpdatePack);
    }
    let update = PartialUpdate {
        base_id: *verified.base_id(),
        candidate_id,
        changes,
        pack_hash: pack_key(&pack_bytes),
        pack_bytes,
    };
    // Encoding is the final exact framing check; no oversized output escapes.
    update.encode(limits)?;
    Ok(update)
}

fn write_pack(inventory: &BTreeMap<Hash, &[u8]>) -> Result<Vec<u8>, PartialError> {
    #[cfg(test)]
    PACK_BUILDS.with(|builds| builds.set(builds.get() + 1));
    let mut writer = PackWriter::new_raw_only();
    for (id, bytes) in inventory {
        writer
            .push_raw(*id, bytes)
            .map_err(|_| PartialError::InvalidUpdatePack)?;
    }
    writer.finish().map_err(|_| PartialError::InvalidUpdatePack)
}

#[cfg(test)]
pub(super) fn reset_pack_build_count() {
    PACK_BUILDS.with(|builds| builds.set(0));
}

#[cfg(test)]
pub(super) fn pack_build_count() -> usize {
    PACK_BUILDS.with(Cell::get)
}

fn inspect_inventory(
    pack: &[u8],
    base_id: Hash,
    candidate_id: Hash,
    changes: &[UpdateChange],
    limits: &PartialLimits,
) -> Result<(), PartialError> {
    let inventory = decode_inventory(pack, candidate_id, limits)?;
    let candidate = &inventory.candidate;
    if candidate.parents != [base_id]
        || candidate.message.len() > limits.max_commit_message_bytes
        || candidate.message_hash != [0; 32]
        || candidate.content_digest != [0; 32]
        || verify_commit(candidate).is_err()
    {
        return Err(PartialError::CommitMismatch);
    }
    let mut expected = BTreeSet::from([candidate_id]);
    let mut representation_lengths = BTreeMap::new();
    let mut total_changed_bytes = 0usize;
    for change in changes {
        total_changed_bytes = inspect_change(
            change,
            candidate,
            &inventory.objects,
            &mut expected,
            &mut representation_lengths,
            total_changed_bytes,
            limits,
        )?;
    }
    if inventory.ids != expected {
        return Err(PartialError::InvalidUpdatePack);
    }
    Ok(())
}

fn decode_inventory(
    pack: &[u8],
    candidate_id: Hash,
    limits: &PartialLimits,
) -> Result<DecodedInventory, PartialError> {
    let pack_version = pack
        .get(4..8)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .map(u32::from_le_bytes)
        .ok_or(PartialError::InvalidUpdatePack)?;
    let object_count = pack
        .get(8..12)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .map(u32::from_le_bytes)
        .ok_or(PartialError::InvalidUpdatePack)?;
    if pack_version != 1 {
        return Err(PartialError::InvalidUpdatePack);
    }
    if usize::try_from(object_count).map_err(|_| PartialError::ValidationBudgetExceeded)?
        > limits.max_update_objects
    {
        return Err(PartialError::ValidationBudgetExceeded);
    }
    let mut entries = PackEntries::new(pack).map_err(|_| PartialError::InvalidUpdatePack)?;
    if !entries.is_raw_only() {
        return Err(PartialError::InvalidUpdatePack);
    }
    let mut ids = BTreeSet::new();
    let mut objects = BTreeMap::new();
    let mut prior = None;
    let mut candidate = None;
    for entry in &mut entries {
        let PackEntry::Raw { bytes } = entry.map_err(|_| PartialError::InvalidUpdatePack)? else {
            return Err(PartialError::InvalidUpdatePack);
        };
        if bytes.len() > limits.max_object_bytes {
            return Err(PartialError::SubmissionTooLarge);
        }
        match bytes.first().copied() {
            Some(tag) if tag == ObjectType::Tree as u8 => preflight_tree(bytes.as_ref(), limits)?,
            Some(tag) if tag == ObjectType::Blob as u8 || tag == ObjectType::ChunkedBlob as u8 => {
                preflight_file(bytes.as_ref(), limits)?;
            }
            Some(tag) if tag == ObjectType::Commit as u8 => {
                preflight_candidate(bytes.as_ref(), limits)?;
            }
            _ => return Err(PartialError::InvalidUpdatePack),
        }
        let object = deserialize(bytes.as_ref()).map_err(|_| PartialError::InvalidUpdatePack)?;
        if serialize(&object).map_err(|_| PartialError::InvalidUpdatePack)? != bytes.as_ref() {
            return Err(PartialError::InvalidUpdatePack);
        }
        let id = id_from_object(&object, bytes.as_ref());
        if prior.is_some_and(|previous| previous >= id) || !ids.insert(id) {
            return Err(PartialError::InvalidUpdatePack);
        }
        prior = Some(id);
        if id == candidate_id {
            let Object::Commit(commit) = &object else {
                return Err(PartialError::InvalidUpdatePack);
            };
            candidate = Some(commit.clone());
        }
        objects.insert(id, object);
    }
    Ok(DecodedInventory {
        ids,
        objects,
        candidate: candidate.ok_or(PartialError::InvalidUpdatePack)?,
    })
}

fn inspect_change(
    change: &UpdateChange,
    candidate: &Commit,
    objects: &BTreeMap<Hash, Object>,
    expected: &mut BTreeSet<Hash>,
    representation_lengths: &mut BTreeMap<Hash, usize>,
    mut total_changed_bytes: usize,
    limits: &PartialLimits,
) -> Result<usize, PartialError> {
    let mut tree_id = candidate.tree_hash;
    for (index, component) in change.path.iter().enumerate() {
        expected.insert(tree_id);
        let Some(Object::Tree(tree)) = objects.get(&tree_id) else {
            return Err(PartialError::InvalidUpdatePack);
        };
        let entry = tree
            .entries
            .iter()
            .find(|entry| &entry.name == component)
            .ok_or(PartialError::InvalidUpdatePack)?;
        if index + 1 == change.path.len() {
            if entry.mode != change.old_mode || entry.object_hash != change.new_id {
                return Err(PartialError::InvalidUpdatePack);
            }
            expected.insert(change.new_id);
            let file_len = validate_changed_representation(
                change.new_id,
                objects,
                expected,
                representation_lengths,
                limits,
            )?;
            total_changed_bytes = total_changed_bytes
                .checked_add(file_len)
                .ok_or(PartialError::SubmissionTooLarge)?;
            if total_changed_bytes > limits.max_total_selected_bytes {
                return Err(PartialError::SubmissionTooLarge);
            }
        } else {
            if entry.mode != EntryMode::Tree {
                return Err(PartialError::InvalidUpdatePack);
            }
            tree_id = entry.object_hash;
        }
    }
    Ok(total_changed_bytes)
}

fn preflight_candidate(bytes: &[u8], limits: &PartialLimits) -> Result<(), PartialError> {
    const TREE_AND_PARENT_COUNT: usize = 6 + 32 + 4;
    if bytes.first() != Some(&(ObjectType::Commit as u8)) || bytes.len() < TREE_AND_PARENT_COUNT {
        return Err(PartialError::InvalidUpdatePack);
    }
    let parent_count = read_u32_le(bytes, 6 + 32)?;
    if parent_count != 1 {
        return Err(PartialError::CommitMismatch);
    }
    let author_header = TREE_AND_PARENT_COUNT
        .checked_add(32)
        .ok_or(PartialError::SubmissionTooLarge)?;
    let author_len_offset = author_header
        .checked_add(1)
        .ok_or(PartialError::SubmissionTooLarge)?;
    let author_len = bytes
        .get(author_len_offset..author_len_offset + 2)
        .and_then(|value| <[u8; 2]>::try_from(value).ok())
        .map(u16::from_le_bytes)
        .map(usize::from)
        .ok_or(PartialError::InvalidUpdatePack)?;
    let message_len_offset = author_len_offset
        .checked_add(2)
        .and_then(|offset| offset.checked_add(author_len))
        .ok_or(PartialError::SubmissionTooLarge)?;
    let message_len = usize::try_from(read_u32_le(bytes, message_len_offset)?)
        .map_err(|_| PartialError::SubmissionTooLarge)?;
    if message_len > limits.max_commit_message_bytes {
        return Err(PartialError::SubmissionTooLarge);
    }
    Ok(())
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Result<u32, PartialError> {
    bytes
        .get(offset..offset + 4)
        .and_then(|value| <[u8; 4]>::try_from(value).ok())
        .map(u32::from_le_bytes)
        .ok_or(PartialError::InvalidUpdatePack)
}

fn validate_changed_representation(
    id: Hash,
    objects: &BTreeMap<Hash, Object>,
    expected: &mut BTreeSet<Hash>,
    cache: &mut BTreeMap<Hash, usize>,
    limits: &PartialLimits,
) -> Result<usize, PartialError> {
    if let Some(len) = cache.get(&id) {
        return Ok(*len);
    }
    let len = match objects.get(&id) {
        Some(Object::Blob(blob)) => blob.data.len(),
        Some(Object::ChunkedBlob(manifest)) => {
            validate_manifest_size(manifest, limits)?;
            let mut sum = 0u64;
            for (index, chunk_id) in manifest.chunks.iter().enumerate() {
                note_decode_chunk_occurrences(1);
                expected.insert(*chunk_id);
                let Some(Object::Blob(chunk)) = objects.get(chunk_id) else {
                    return Err(PartialError::InvalidUpdatePack);
                };
                validate_chunk_occurrence(manifest, index, chunk.data.len())?;
                sum = add_chunk_len(sum, chunk.data.len(), manifest.total_size)?;
            }
            if sum != manifest.total_size {
                return Err(PartialError::InvalidChunkLayout);
            }
            usize::try_from(manifest.total_size).map_err(|_| PartialError::SubmissionTooLarge)?
        }
        _ => return Err(PartialError::InvalidUpdatePack),
    };
    if len > limits.max_selected_file_bytes {
        return Err(PartialError::SubmissionTooLarge);
    }
    cache.insert(id, len);
    Ok(len)
}

#[cfg(test)]
fn note_decode_chunk_occurrences(count: usize) {
    DECODE_CHUNK_OCCURRENCES.with(|occurrences| occurrences.set(occurrences.get() + count));
}

#[cfg(not(test))]
fn note_decode_chunk_occurrences(_count: usize) {}

#[cfg(test)]
pub(super) fn reset_decode_chunk_occurrences() {
    DECODE_CHUNK_OCCURRENCES.with(|occurrences| occurrences.set(0));
}

#[cfg(test)]
pub(super) fn decode_chunk_occurrences() -> usize {
    DECODE_CHUNK_OCCURRENCES.with(Cell::get)
}

fn validate_update_shape(
    update: &PartialUpdate,
    limits: &PartialLimits,
) -> Result<(), PartialError> {
    if !limits.is_v1_subset()
        || update.changes.is_empty()
        || update.changes.len() > limits.max_changed_paths
        || update.pack_bytes.len() > limits.max_raw_pack_bytes
        || pack_key(&update.pack_bytes) != update.pack_hash
    {
        return Err(PartialError::SubmissionTooLarge);
    }
    let paths = update
        .changes
        .iter()
        .map(|change| change.path.clone())
        .collect::<Vec<_>>();
    validate_paths(&paths, limits)
}

fn update_change(change: &PreparedChange) -> UpdateChange {
    UpdateChange {
        path: change.path.clone(),
        old_mode: change.old_mode,
        old_id: change.old_id,
        new_id: change.new_id,
    }
}

fn insert_borrowed<'a>(
    objects: &mut BTreeMap<Hash, &'a [u8]>,
    id: Hash,
    bytes: &'a [u8],
    predicted_pack_len: &mut usize,
    limits: &PartialLimits,
) -> Result<(), PartialError> {
    if let Some(existing) = objects.get(&id) {
        if *existing != bytes {
            return Err(PartialError::NonCanonical);
        }
    } else {
        if objects.len() >= limits.max_update_objects {
            return Err(PartialError::ValidationBudgetExceeded);
        }
        *predicted_pack_len = charge_raw_entry(*predicted_pack_len, bytes.len(), limits)?;
        objects.insert(id, bytes);
    }
    Ok(())
}

fn charge_raw_entry(
    current: usize,
    bytes_len: usize,
    limits: &PartialLimits,
) -> Result<usize, PartialError> {
    let next = current
        .checked_add(5)
        .and_then(|n| n.checked_add(bytes_len))
        .ok_or(PartialError::SubmissionTooLarge)?;
    if next > limits.max_raw_pack_bytes {
        return Err(PartialError::SubmissionTooLarge);
    }
    Ok(next)
}

fn encoded_len(changes: &[UpdateChange], pack_len: usize) -> Result<usize, PartialError> {
    let mut total = FIXED_WITHOUT_CHANGES_OR_PACK
        .checked_add(varint_len(changes.len()))
        .ok_or(PartialError::SubmissionTooLarge)?;
    for change in changes {
        total = total
            .checked_add(varint_len(change.path.len()))
            .ok_or(PartialError::SubmissionTooLarge)?;
        for component in &change.path {
            total = total
                .checked_add(varint_len(component.len()))
                .and_then(|n| n.checked_add(component.len()))
                .ok_or(PartialError::SubmissionTooLarge)?;
        }
        total = total
            .checked_add(1 + 32 + 32)
            .ok_or(PartialError::SubmissionTooLarge)?;
    }
    total = total
        .checked_add(varint_len(pack_len))
        .ok_or(PartialError::SubmissionTooLarge)?;
    total
        .checked_add(pack_len)
        .ok_or(PartialError::SubmissionTooLarge)
}

fn write_varint(out: &mut Vec<u8>, mut value: usize) {
    loop {
        let mut byte = u8::try_from(value & 0x7f).expect("seven bits always fit in u8");
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            return;
        }
    }
}

fn varint_len(mut value: usize) -> usize {
    let mut len = 1;
    while value >= 0x80 {
        value >>= 7;
        len += 1;
    }
    len
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], PartialError> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or(PartialError::NonCanonical)?;
        let bytes = self
            .bytes
            .get(self.pos..end)
            .ok_or(PartialError::NonCanonical)?;
        self.pos = end;
        Ok(bytes)
    }

    fn byte(&mut self) -> Result<u8, PartialError> {
        Ok(self.take(1)?[0])
    }

    fn hash(&mut self) -> Result<Hash, PartialError> {
        self.take(32)?
            .try_into()
            .map_err(|_| PartialError::NonCanonical)
    }

    fn u64(&mut self) -> Result<u64, PartialError> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| PartialError::NonCanonical)?,
        ))
    }

    fn varint(&mut self) -> Result<usize, PartialError> {
        let start = self.pos;
        let mut value = 0usize;
        let mut shift = 0u32;
        loop {
            let byte = self.byte()?;
            let low = usize::from(byte & 0x7f);
            value = value
                .checked_add(low.checked_shl(shift).ok_or(PartialError::NonCanonical)?)
                .ok_or(PartialError::NonCanonical)?;
            if byte & 0x80 == 0 {
                if self.pos - start != varint_len(value) {
                    return Err(PartialError::NonCanonical);
                }
                return Ok(value);
            }
            shift = shift.checked_add(7).ok_or(PartialError::NonCanonical)?;
            if shift >= usize::BITS {
                return Err(PartialError::NonCanonical);
            }
        }
    }
}
