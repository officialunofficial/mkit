//! Packfile writer / reader — conformant to `docs/SPEC-PACKFILE.md`.
//!
//! Layout (SPEC-PACKFILE §1, §2, §3, §8):
//!
//! ```text
//! [4B  magic            "MKIT"]                       offset 0
//! [4B  version u32 LE  == 1   ]
//! [4B  entry_count u32 LE     ]
//!   for each entry:
//!     [u8  entry_type]                                0x00 raw | 0x02 delta
//!     [u32 LE payload_len]                            length of payload only
//!     [payload_len bytes payload]
//! [32B trailer = BLAKE3 of all preceding bytes]
//! ```
//!
//! Entry types (SPEC-PACKFILE §3):
//!
//! * `0x00` raw  — payload is a fully serialised mkit object.
//! * `0x01`      — RESERVED, MUST be rejected.
//! * `0x02` delta — payload is `[32B base_hash][SPEC-DELTA stream]`.
//!
//! Caps (SPEC-PACKFILE §5):
//!
//! * `entry_count <= 10_000_000`
//! * total `payload_len` sum `<= 4 GiB`
//!
//! Delta-base ordering rule (SPEC-PACKFILE §4): every delta entry's
//! `base_hash` MUST appear earlier in the same pack as a raw entry, OR
//! already exist in the destination object store.
//!
//! The pack key (SPEC-PACKFILE §7) is `packs/<lower-hex BLAKE3 of entire
//! pack>`. The trailer is then redundant w.r.t. that key, but it lets a
//! streaming reader detect bit-rot before the whole pack has been
//! hashed end-to-end.

use crate::delta;
use crate::hash::{self, Hash};
use crate::object::{MkitError, Object};
use crate::store::{MAX_RAW_OBJECT_SIZE, ObjectStore};
use std::sync::Arc;

/// ASCII magic ("MKIT") at the start of every v1 pack.
pub const MAGIC: &[u8; 4] = b"MKIT";
/// Current packfile version. Reader rejects anything else.
pub const VERSION: u32 = 1;

/// Hard cap on entries (SPEC-PACKFILE §5).
pub const MAX_ENTRIES: u32 = 10_000_000;
/// Hard cap on the sum of payload bytes across all entries.
pub const MAX_TOTAL_PAYLOAD: u64 = 4 * 1024 * 1024 * 1024;
/// Trailer is a 32-byte raw BLAKE3 digest.
pub const TRAILER_LEN: usize = 32;

/// Header is `[4B magic][4B version][4B entry_count]`.
pub const HEADER_LEN: usize = 4 + 4 + 4;
/// Per-entry framing overhead is `[1B type][4B payload_len]`.
pub const ENTRY_FRAME_LEN: usize = 1 + 4;

/// Packfile errors. Distinct from [`MkitError`] so callers can match on
/// pack-specific failures (trailer mismatch, base-missing) without
/// catching every object decode error.
#[derive(Debug, thiserror::Error)]
pub enum PackError {
    #[error("packfile is shorter than the {HEADER_LEN}-byte header + {TRAILER_LEN}-byte trailer")]
    PackfileTooShort,
    #[error("first 4 bytes are not ASCII \"MKIT\"")]
    InvalidMagic,
    #[error("version {0} is not supported (v1 only)")]
    UnsupportedVersion(u32),
    #[error("entry_type {0:#04x} is not 0x00 (raw) or 0x02 (delta)")]
    InvalidEntryType(u8),
    #[error("entry_count {0} exceeds the {MAX_ENTRIES} cap")]
    TooManyObjects(u32),
    #[error("sum of payload_len exceeds {MAX_TOTAL_PAYLOAD} bytes")]
    PackfileTooLarge,
    #[error("entry payload extends past the trailer offset")]
    UnexpectedEof,
    #[error("trailer BLAKE3 mismatch — packfile is corrupt or truncated")]
    PackfileCorrupted,
    #[error("delta entry references base hash {0} which is not in this pack or the store")]
    DeltaBaseMissing(String),
    #[error("delta entry payload is shorter than the 32-byte base hash prefix")]
    DeltaEntryTruncated,
    #[error("delta reconstruction failed: {0}")]
    DeltaApply(#[from] MkitError),
    #[error("pack entry is not a canonical storable object: {0}")]
    InvalidObject(MkitError),
    #[error("pack entry resolves to pack-only delta object")]
    NonStorableObject,
    #[error("pack contains trailing bytes after declared entries")]
    TrailingData,
    #[error("store I/O failure: {0}")]
    Store(#[from] crate::store::StoreError),
}

/// Result of an unpack: which entries were stored, plus a count of
/// delta resolutions vs raw writes. Useful for transport/CLI summaries.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnpackReport {
    pub raw_count: u32,
    pub delta_count: u32,
    /// Hashes inserted into the store this unpack call.
    pub stored: Vec<Hash>,
}

/// Builds a packfile in memory, enforcing entry/payload caps and
/// recording entries in insertion order. Call [`Self::finish`] to obtain
/// the final packfile bytes (header + entries + trailer).
#[derive(Debug, Default)]
pub struct PackWriter {
    // Buffered entries. Each `(entry_type, payload)` pair is written
    // verbatim by `finish`; the writer adds the per-entry frame.
    entries: Vec<(u8, Vec<u8>)>,
    total_payload: u64,
}

impl PackWriter {
    /// Create an empty writer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a raw object entry. `bytes` is the fully serialised object
    /// payload; `hash_of_bytes` is the BLAKE3 of those same bytes —
    /// callers usually have it on hand from the object store, so we take
    /// it explicitly to avoid an extra BLAKE3 pass over the same buffer.
    /// Returns the same hash for chaining.
    pub fn push_raw(&mut self, hash_of_bytes: Hash, bytes: Vec<u8>) -> Result<Hash, PackError> {
        self.check_caps_for(bytes.len())?;
        self.total_payload += bytes.len() as u64;
        self.entries.push((0x00, bytes));
        Ok(hash_of_bytes)
    }

    /// Append a delta entry. `base_hash` MUST refer to an earlier raw
    /// entry in this pack OR an object already in the destination store.
    /// `delta_stream` MUST be a valid SPEC-DELTA stream — we don't
    /// re-validate here (the writer is trusted), but the reader will.
    pub fn push_delta(&mut self, base_hash: &Hash, delta_stream: &[u8]) -> Result<(), PackError> {
        let payload_len = TRAILER_LEN + delta_stream.len();
        self.check_caps_for(payload_len)?;
        let mut payload = Vec::with_capacity(payload_len);
        payload.extend_from_slice(base_hash);
        payload.extend_from_slice(delta_stream);
        self.total_payload += payload.len() as u64;
        self.entries.push((0x02, payload));
        Ok(())
    }

    fn check_caps_for(&self, add_len: usize) -> Result<(), PackError> {
        let next_count = self.entries.len() as u64 + 1;
        if next_count > u64::from(MAX_ENTRIES) {
            return Err(PackError::TooManyObjects(MAX_ENTRIES + 1));
        }
        let next_total = self.total_payload.saturating_add(add_len as u64);
        if next_total > MAX_TOTAL_PAYLOAD {
            return Err(PackError::PackfileTooLarge);
        }
        Ok(())
    }

    /// Number of entries pushed so far. Useful for sizing diagnostics.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Serialise the pack: header + entries + trailer. The trailer is
    /// `BLAKE3(everything_before_trailer)`. The whole pack's BLAKE3 is
    /// the on-disk pack key — see [`pack_key`].
    pub fn finish(self) -> Result<Vec<u8>, PackError> {
        let count: u32 = self
            .entries
            .len()
            .try_into()
            .map_err(|_| PackError::TooManyObjects(MAX_ENTRIES + 1))?;
        if count > MAX_ENTRIES {
            return Err(PackError::TooManyObjects(count));
        }

        // Pre-size: header + per-entry overhead + payloads + trailer.
        let mut size = HEADER_LEN + TRAILER_LEN;
        for (_, p) in &self.entries {
            size += ENTRY_FRAME_LEN + p.len();
        }
        let mut buf = Vec::with_capacity(size);

        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&VERSION.to_le_bytes());
        buf.extend_from_slice(&count.to_le_bytes());
        for (etype, payload) in self.entries {
            buf.push(etype);
            let plen: u32 = payload
                .len()
                .try_into()
                .map_err(|_| PackError::PackfileTooLarge)?;
            buf.extend_from_slice(&plen.to_le_bytes());
            buf.extend_from_slice(&payload);
        }
        // Trailer over everything written so far.
        let trailer = hash::hash(&buf);
        buf.extend_from_slice(&trailer);
        Ok(buf)
    }
}

/// Compute the on-disk pack key: BLAKE3 of the entire packfile bytes
/// (including the trailer). SPEC-PACKFILE §7. Returns the bare digest;
/// callers prepend `packs/` and lower-hex-encode for the storage path.
#[must_use]
pub fn pack_key(pack_bytes: &[u8]) -> Hash {
    hash::hash(pack_bytes)
}

/// Collect the `base_hash` of every `0x02` delta entry in `pack_bytes`,
/// without resolving or storing anything.
///
/// This lets a caller pre-fetch bases that may live OUTSIDE the pack (e.g.
/// objects a legacy per-object remote stored individually) before calling
/// [`PackReader::read`], so delta resolution never fails part-way through a
/// pack. Raw entries are skipped; duplicates are de-duplicated.
///
/// Only the header (magic/version) and entry framing are validated — the
/// trailer is intentionally NOT verified here, because [`PackReader::read`]
/// re-verifies the whole pack (trailer included) before storing anything.
///
/// # Errors
///
/// Returns the same framing [`PackError`] variants as [`PackReader::read`]
/// for a malformed header or out-of-bounds entry.
///
/// # Panics
///
/// The `try_into` calls on fixed 4-byte slices are statically guaranteed by
/// the preceding bounds checks; they `expect`-panic only if slice-bounds
/// elision is wrong.
pub fn delta_base_hashes(pack_bytes: &[u8]) -> Result<Vec<Hash>, PackError> {
    if pack_bytes.len() < HEADER_LEN + TRAILER_LEN {
        return Err(PackError::PackfileTooShort);
    }
    if &pack_bytes[..4] != MAGIC.as_slice() {
        return Err(PackError::InvalidMagic);
    }
    let version = u32::from_le_bytes(pack_bytes[4..8].try_into().expect("4 bytes"));
    if version != VERSION {
        return Err(PackError::UnsupportedVersion(version));
    }
    let count = u32::from_le_bytes(pack_bytes[8..12].try_into().expect("4 bytes"));
    if count > MAX_ENTRIES {
        return Err(PackError::TooManyObjects(count));
    }
    // Entries live between the header and the 32-byte trailer.
    let split = pack_bytes.len() - TRAILER_LEN;

    let mut bases = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut pos = HEADER_LEN;
    for _ in 0..count {
        if pos + ENTRY_FRAME_LEN > split {
            return Err(PackError::UnexpectedEof);
        }
        let etype = pack_bytes[pos];
        pos += 1;
        let payload_len =
            u32::from_le_bytes(pack_bytes[pos..pos + 4].try_into().expect("4 bytes")) as usize;
        pos += 4;
        if pos + payload_len > split {
            return Err(PackError::UnexpectedEof);
        }
        if etype == 0x02 {
            if payload_len < TRAILER_LEN {
                return Err(PackError::DeltaEntryTruncated);
            }
            let mut base = [0u8; 32];
            base.copy_from_slice(&pack_bytes[pos..pos + TRAILER_LEN]);
            if seen.insert(base) {
                bases.push(base);
            }
        }
        pos += payload_len;
    }
    Ok(bases)
}

/// Streaming-style packfile reader. Verifies header, trailer, entry
/// framing, and the base-before-delta ordering rule. Reconstructs delta
/// targets and writes every resolved object to `store`.
#[derive(Debug)]
pub struct PackReader;

impl PackReader {
    /// Verify and unpack `pack_bytes` into `store`. Returns counts of
    /// raw vs. delta entries plus the list of stored hashes (in pack
    /// order, deduped within this call).
    ///
    /// # Errors
    ///
    /// Returns the matching [`PackError`] variant on any malformed
    /// input or trailer mismatch. The store is not modified if the
    /// trailer fails verification.
    ///
    /// # Panics
    ///
    /// The internal `try_into` calls on fixed-size byte slices are
    /// statically guaranteed to succeed (we slice exactly 4 bytes for
    /// every `u32::from_le_bytes`). They `expect`-panic only if the
    /// compiler's slice-bounds elision is wrong.
    pub fn read(pack_bytes: &[u8], store: &ObjectStore) -> Result<UnpackReport, PackError> {
        // 1. Length sanity: must fit header + trailer at minimum.
        if pack_bytes.len() < HEADER_LEN + TRAILER_LEN {
            return Err(PackError::PackfileTooShort);
        }
        // 2. Magic.
        if &pack_bytes[..4] != MAGIC.as_slice() {
            return Err(PackError::InvalidMagic);
        }
        // 3. Version.
        let version = u32::from_le_bytes(pack_bytes[4..8].try_into().expect("4 bytes"));
        if version != VERSION {
            return Err(PackError::UnsupportedVersion(version));
        }
        // 4. Trailer must match BEFORE we touch the store. SPEC-PACKFILE §8.
        let split = pack_bytes.len() - TRAILER_LEN;
        let body = &pack_bytes[..split];
        let trailer = &pack_bytes[split..];
        let computed = hash::hash(body);
        if computed.as_slice() != trailer {
            return Err(PackError::PackfileCorrupted);
        }
        // 5. Entry count + cap.
        let count = u32::from_le_bytes(pack_bytes[8..12].try_into().expect("4 bytes"));
        if count > MAX_ENTRIES {
            return Err(PackError::TooManyObjects(count));
        }
        // Quick lower bound sanity: each entry is at least ENTRY_FRAME_LEN bytes.
        let body_after_header = body.len() - HEADER_LEN;
        if u64::from(count) * ENTRY_FRAME_LEN as u64 > body_after_header as u64 {
            return Err(PackError::TooManyObjects(count));
        }

        let mut report = UnpackReport::default();
        let mut pending_writes: Vec<(Hash, Arc<[u8]>)> = Vec::new();
        // Track raw entries we wrote in *this* pack so subsequent delta
        // entries can resolve their base from memory before falling back
        // to the on-disk store. We keep the resolved object bytes (raw
        // serialised SPEC-OBJECTS payload) so the delta apply doesn't
        // need to re-read them.
        let mut in_pack: std::collections::HashMap<Hash, Arc<[u8]>> =
            std::collections::HashMap::new();
        let mut total_payload: u64 = 0;
        let mut pos = HEADER_LEN;

        for _ in 0..count {
            // Frame: [type][payload_len].
            if pos + ENTRY_FRAME_LEN > split {
                return Err(PackError::UnexpectedEof);
            }
            let etype = pack_bytes[pos];
            pos += 1;
            let payload_len =
                u32::from_le_bytes(pack_bytes[pos..pos + 4].try_into().expect("4 bytes")) as usize;
            pos += 4;

            total_payload = total_payload.saturating_add(payload_len as u64);
            if total_payload > MAX_TOTAL_PAYLOAD {
                return Err(PackError::PackfileTooLarge);
            }
            if pos + payload_len > split {
                return Err(PackError::UnexpectedEof);
            }
            let payload = &pack_bytes[pos..pos + payload_len];
            pos += payload_len;

            match etype {
                0x00 => {
                    // raw — validate and stage for writing after the whole pack parses.
                    validate_storable_object(payload)?;
                    // Address by the dispatched id (merkle root for
                    // Tree/ChunkedBlob, BLAKE3 otherwise) so the unpacked
                    // object lands under the same key every sink uses.
                    let stored_hash = crate::store::object_id_from_bytes(payload);
                    let bytes: Arc<[u8]> = Arc::from(payload);
                    in_pack.insert(stored_hash, Arc::clone(&bytes));
                    pending_writes.push((stored_hash, bytes));
                    report.raw_count += 1;
                    report.stored.push(stored_hash);
                }
                0x02 => {
                    // delta — payload is [32B base_hash][stream].
                    if payload.len() < TRAILER_LEN {
                        return Err(PackError::DeltaEntryTruncated);
                    }
                    let mut base_hash = [0u8; 32];
                    base_hash.copy_from_slice(&payload[..TRAILER_LEN]);
                    let stream = &payload[TRAILER_LEN..];
                    // Resolve base: in-pack first, then on-disk.
                    let base_bytes: std::borrow::Cow<'_, [u8]> =
                        if let Some(b) = in_pack.get(&base_hash) {
                            std::borrow::Cow::Borrowed(b.as_ref())
                        } else if store.contains(&base_hash) {
                            let bytes = store.read(&base_hash)?;
                            validate_storable_object(&bytes)?;
                            std::borrow::Cow::Owned(bytes)
                        } else {
                            return Err(PackError::DeltaBaseMissing(hash::to_hex(&base_hash)));
                        };
                    validate_delta_result_size(stream)?;
                    let resolved = delta::decode(base_bytes.as_ref(), stream)?;
                    validate_storable_object(&resolved)?;
                    let stored_hash = crate::store::object_id_from_bytes(&resolved);
                    let bytes: Arc<[u8]> = Arc::from(resolved);
                    in_pack.insert(stored_hash, Arc::clone(&bytes));
                    pending_writes.push((stored_hash, bytes));
                    report.delta_count += 1;
                    report.stored.push(stored_hash);
                }
                0x01 => return Err(PackError::InvalidEntryType(0x01)),
                other => return Err(PackError::InvalidEntryType(other)),
            }
        }

        if pos != split {
            return Err(PackError::TrailingData);
        }

        // Batched durability: one full flush for the whole pack instead
        // of one per object. The caller's ref update happens after
        // `read` returns, so the commit-before-reference ordering holds.
        let batch = store.batch();
        for (h, bytes) in pending_writes {
            // Every entry was BLAKE3-hashed above (trailer-verified
            // pack, hash recorded in the report); skip the re-hash.
            batch.write_prehashed(h, &[&bytes])?;
        }
        batch.commit()?;

        Ok(report)
    }
}

fn validate_storable_object(bytes: &[u8]) -> Result<(), PackError> {
    if bytes.len() > MAX_RAW_OBJECT_SIZE {
        return Err(PackError::Store(crate::store::StoreError::ObjectTooLarge));
    }
    match crate::serialize::deserialize(bytes).map_err(PackError::InvalidObject)? {
        Object::Delta(_) => Err(PackError::NonStorableObject),
        Object::Blob(_)
        | Object::Tree(_)
        | Object::Commit(_)
        | Object::Remix(_)
        | Object::ChunkedBlob(_)
        | Object::Tag(_) => Ok(()),
    }
}

fn validate_delta_result_size(stream: &[u8]) -> Result<(), PackError> {
    if stream.len() < delta::HEADER_LEN {
        return Err(PackError::DeltaApply(MkitError::UnexpectedEof));
    }
    let result_len = u32::from_le_bytes(stream[5..9].try_into().expect("4 bytes")) as usize;
    if result_len > MAX_RAW_OBJECT_SIZE {
        return Err(PackError::Store(crate::store::StoreError::ObjectTooLarge));
    }
    Ok(())
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn fresh_store() -> (TempDir, ObjectStore) {
        let dir = TempDir::new().unwrap();
        let store = ObjectStore::init(dir.path()).unwrap();
        (dir, store)
    }

    fn write_blob_via_serialize(payload: &[u8]) -> Vec<u8> {
        // Use the serialize/object stack so the bytes are a real mkit
        // object — important because `store.write` accepts any bytes
        // but unpack-time delta apply produces what serialize would.
        let blob = crate::object::Object::Blob(crate::object::Blob {
            data: payload.to_vec(),
        });
        crate::serialize::serialize(&blob).expect("serialize blob")
    }

    fn finish_pack_body(mut body: Vec<u8>) -> Vec<u8> {
        let trailer = hash::hash(&body);
        body.extend_from_slice(&trailer);
        body
    }

    #[test]
    fn empty_pack_is_44_bytes() {
        let pack = PackWriter::new().finish().unwrap();
        assert_eq!(pack.len(), HEADER_LEN + TRAILER_LEN);
        assert_eq!(&pack[..4], MAGIC);
        assert_eq!(u32::from_le_bytes(pack[4..8].try_into().unwrap()), VERSION);
        assert_eq!(u32::from_le_bytes(pack[8..12].try_into().unwrap()), 0);

        let (_dir, store) = fresh_store();
        let report = PackReader::read(&pack, &store).unwrap();
        assert_eq!(report.raw_count, 0);
        assert_eq!(report.delta_count, 0);
        assert!(report.stored.is_empty());
    }

    #[test]
    fn unpack_writes_objects_via_single_batch_flush() {
        // clone/fetch receive N objects per pack; durability must cost
        // O(1) full flushes per pack, not O(N).
        use crate::batch::testing::{Ev, RecordingSyncer};
        use std::sync::Arc;

        let mut w = PackWriter::new();
        let mut blobs = Vec::new();
        for i in 0u32..30 {
            let blob = write_blob_via_serialize(format!("pack object {i}").as_bytes());
            w.push_raw(hash::hash(&blob), blob.clone()).unwrap();
            blobs.push(blob);
        }
        let pack = w.finish().unwrap();

        let (_dir, mut store) = fresh_store();
        let rec = Arc::new(RecordingSyncer::default());
        store.set_syncer(rec.clone());

        let report = PackReader::read(&pack, &store).unwrap();
        assert_eq!(report.raw_count, 30);

        let fulls = rec
            .events()
            .iter()
            .filter(|e| matches!(e, Ev::Full(_)))
            .count();
        assert_eq!(
            fulls, 2,
            "unpack flush cost must be constant, not O(objects)"
        );
        for blob in &blobs {
            assert_eq!(store.read(&hash::hash(blob)).unwrap(), *blob);
        }
    }

    #[test]
    fn single_raw_roundtrip() {
        let blob = write_blob_via_serialize(b"hello packfile");
        let h = hash::hash(&blob);

        let mut w = PackWriter::new();
        w.push_raw(h, blob.clone()).unwrap();
        let pack = w.finish().unwrap();

        let (_dir, store) = fresh_store();
        let report = PackReader::read(&pack, &store).unwrap();
        assert_eq!(report.raw_count, 1);
        assert_eq!(report.delta_count, 0);
        assert_eq!(report.stored, vec![h]);
        assert_eq!(store.read(&h).unwrap(), blob);
    }

    #[test]
    fn raw_then_delta_resolves_in_pack() {
        // Two near-identical blobs. Delta should reconstruct the second.
        let mut content_base = vec![0u8; 1024];
        for (i, b) in content_base.iter_mut().enumerate() {
            *b = u8::try_from(i % 251).expect("modulo < 256");
        }
        let mut content_target = content_base.clone();
        content_target[500] = 0xFF;
        content_target[501] = 0xFE;

        let base_obj = write_blob_via_serialize(&content_base);
        let target_obj = write_blob_via_serialize(&content_target);
        let base_hash = hash::hash(&base_obj);
        let target_hash = hash::hash(&target_obj);

        let stream = delta::encode(&base_obj, &target_obj).unwrap();

        let mut w = PackWriter::new();
        w.push_raw(base_hash, base_obj.clone()).unwrap();
        w.push_delta(&base_hash, &stream).unwrap();
        let pack = w.finish().unwrap();

        let (_dir, store) = fresh_store();
        let report = PackReader::read(&pack, &store).unwrap();
        assert_eq!(report.raw_count, 1);
        assert_eq!(report.delta_count, 1);
        assert_eq!(report.stored, vec![base_hash, target_hash]);
        assert_eq!(store.read(&target_hash).unwrap(), target_obj);
    }

    #[test]
    fn delta_base_hashes_lists_delta_bases_only() {
        // One raw blob + two deltas against two different bases. The scan
        // must return exactly the two (deduped) base hashes, ignoring raw.
        let base_a = write_blob_via_serialize(b"base alpha content here padding");
        let base_b = write_blob_via_serialize(b"base bravo content here padding");
        let ha = hash::hash(&base_a);
        let hb = hash::hash(&base_b);
        let target_a = write_blob_via_serialize(b"base alpha content here PADDED!");
        let target_b = write_blob_via_serialize(b"base bravo content here PADDED!");
        let stream_a = delta::encode(&base_a, &target_a).unwrap();
        let stream_b = delta::encode(&base_b, &target_b).unwrap();

        let mut w = PackWriter::new();
        w.push_raw(ha, base_a).unwrap(); // a raw entry — must be ignored
        w.push_delta(&ha, &stream_a).unwrap();
        w.push_delta(&hb, &stream_b).unwrap();
        w.push_delta(&ha, &stream_a).unwrap(); // duplicate base — deduped
        let pack = w.finish().unwrap();

        let mut bases = delta_base_hashes(&pack).unwrap();
        bases.sort_unstable();
        let mut expected = vec![ha, hb];
        expected.sort_unstable();
        assert_eq!(bases, expected);
    }

    #[test]
    fn delta_base_hashes_rejects_bad_magic() {
        let mut pack = PackWriter::new().finish().unwrap();
        pack[0] = b'X';
        assert!(matches!(
            delta_base_hashes(&pack),
            Err(PackError::InvalidMagic)
        ));
    }

    #[test]
    fn rejects_raw_payload_that_is_not_canonical_object_without_store_write() {
        let payload = b"not a serialized mkit object".to_vec();
        let payload_hash = hash::hash(&payload);
        let mut body = Vec::new();
        body.extend_from_slice(MAGIC);
        body.extend_from_slice(&VERSION.to_le_bytes());
        body.extend_from_slice(&1u32.to_le_bytes());
        body.push(0x00);
        let payload_len = u32::try_from(payload.len()).unwrap();
        body.extend_from_slice(&payload_len.to_le_bytes());
        body.extend_from_slice(&payload);
        let pack = finish_pack_body(body);

        let (_dir, store) = fresh_store();
        let err = PackReader::read(&pack, &store).unwrap_err();
        assert!(matches!(err, PackError::InvalidObject(_)), "got {err:?}");
        assert!(!store.contains(&payload_hash));
    }

    #[test]
    fn rejects_raw_delta_object_without_store_write() {
        let delta = crate::object::Object::Delta(crate::object::Delta {
            base_hash: [0xAB; 32],
            result_size: 0,
            instructions: Vec::new(),
        });
        let payload = crate::serialize::serialize(&delta).unwrap();
        let payload_hash = hash::hash(&payload);
        let mut w = PackWriter::new();
        w.push_raw(payload_hash, payload).unwrap();
        let pack = w.finish().unwrap();

        let (_dir, store) = fresh_store();
        let err = PackReader::read(&pack, &store).unwrap_err();
        assert!(matches!(err, PackError::NonStorableObject), "got {err:?}");
        assert!(!store.contains(&payload_hash));
    }

    #[test]
    fn rejects_delta_resolving_to_non_object_without_partial_store_write() {
        let base_obj = write_blob_via_serialize(b"base bytes");
        let base_hash = hash::hash(&base_obj);
        let invalid_target = b"not a serialized object".to_vec();
        let invalid_hash = hash::hash(&invalid_target);
        let stream = delta::encode(&base_obj, &invalid_target).unwrap();

        let mut w = PackWriter::new();
        w.push_raw(base_hash, base_obj).unwrap();
        w.push_delta(&base_hash, &stream).unwrap();
        let pack = w.finish().unwrap();

        let (_dir, store) = fresh_store();
        let err = PackReader::read(&pack, &store).unwrap_err();
        assert!(matches!(err, PackError::InvalidObject(_)), "got {err:?}");
        assert!(!store.contains(&base_hash));
        assert!(!store.contains(&invalid_hash));
    }

    #[test]
    fn rejects_delta_result_over_object_cap_without_partial_store_write() {
        let base_obj = write_blob_via_serialize(b"base bytes");
        let base_hash = hash::hash(&base_obj);
        let mut stream = Vec::new();
        stream.push(delta::STREAM_VERSION);
        stream.extend_from_slice(&u32::try_from(base_obj.len()).unwrap().to_le_bytes());
        stream.extend_from_slice(
            &u32::try_from(MAX_RAW_OBJECT_SIZE + 1)
                .unwrap()
                .to_le_bytes(),
        );

        let mut w = PackWriter::new();
        w.push_raw(base_hash, base_obj).unwrap();
        w.push_delta(&base_hash, &stream).unwrap();
        let pack = w.finish().unwrap();

        let (_dir, store) = fresh_store();
        let err = PackReader::read(&pack, &store).unwrap_err();
        assert!(
            matches!(
                err,
                PackError::Store(crate::store::StoreError::ObjectTooLarge)
            ),
            "got {err:?}"
        );
        assert!(!store.contains(&base_hash));
    }

    #[test]
    fn rejects_trailing_bytes_after_declared_entries_without_store_write() {
        let blob = write_blob_via_serialize(b"trailing bytes test");
        let blob_hash = hash::hash(&blob);
        let mut body = Vec::new();
        body.extend_from_slice(MAGIC);
        body.extend_from_slice(&VERSION.to_le_bytes());
        body.extend_from_slice(&1u32.to_le_bytes());
        body.push(0x00);
        let blob_len = u32::try_from(blob.len()).unwrap();
        body.extend_from_slice(&blob_len.to_le_bytes());
        body.extend_from_slice(&blob);
        body.extend_from_slice(b"junk");
        let pack = finish_pack_body(body);

        let (_dir, store) = fresh_store();
        let err = PackReader::read(&pack, &store).unwrap_err();
        assert!(matches!(err, PackError::TrailingData), "got {err:?}");
        assert!(!store.contains(&blob_hash));
    }

    #[test]
    fn rejects_invalid_magic() {
        // Use an arbitrary invalid 4-byte sequence; the rename gate
        // forbids spelling out the upstream pre-rename magic literally.
        let mut pack = PackWriter::new().finish().unwrap();
        pack[0] = b'X';
        pack[1] = b'X';
        pack[2] = b'X';
        pack[3] = b'X';
        let (_dir, store) = fresh_store();
        let err = PackReader::read(&pack, &store).unwrap_err();
        assert!(matches!(err, PackError::InvalidMagic));
    }

    #[test]
    fn rejects_unknown_version() {
        let mut pack = PackWriter::new().finish().unwrap();
        // version is u32 LE at offset 4
        pack[4] = 99;
        // Corrupt trailer so the version check fires first — but
        // SPEC-PACKFILE §8 says trailer is checked before entries,
        // and we want UnsupportedVersion. Trailer check happens after
        // version check in our impl (see read()), so just leave the
        // trailer; it will fail UnsupportedVersion on byte 4.
        let (_dir, store) = fresh_store();
        let err = PackReader::read(&pack, &store).unwrap_err();
        assert!(matches!(err, PackError::UnsupportedVersion(99)));
    }

    #[test]
    fn rejects_truncated_pack() {
        let pack = vec![b'M', b'K']; // only 2 bytes
        let (_dir, store) = fresh_store();
        let err = PackReader::read(&pack, &store).unwrap_err();
        assert!(matches!(err, PackError::PackfileTooShort));
    }

    #[test]
    fn rejects_bit_flipped_trailer() {
        let blob = write_blob_via_serialize(b"trailer test");
        let h = hash::hash(&blob);
        let mut w = PackWriter::new();
        w.push_raw(h, blob).unwrap();
        let mut pack = w.finish().unwrap();
        let last = pack.len() - 1;
        pack[last] ^= 0x01; // flip one bit
        let (_dir, store) = fresh_store();
        let err = PackReader::read(&pack, &store).unwrap_err();
        assert!(matches!(err, PackError::PackfileCorrupted));
    }

    #[test]
    fn rejects_reserved_entry_type_0x01() {
        // Hand-build a pack with one entry of type 0x01.
        let mut buf = Vec::new();
        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&VERSION.to_le_bytes());
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.push(0x01); // RESERVED type
        buf.extend_from_slice(&0u32.to_le_bytes()); // payload_len = 0
        let trailer = hash::hash(&buf);
        buf.extend_from_slice(&trailer);

        let (_dir, store) = fresh_store();
        let err = PackReader::read(&buf, &store).unwrap_err();
        assert!(matches!(err, PackError::InvalidEntryType(0x01)));
    }

    #[test]
    fn rejects_unknown_entry_type() {
        let mut buf = Vec::new();
        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&VERSION.to_le_bytes());
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.push(0x77); // unknown
        buf.extend_from_slice(&0u32.to_le_bytes());
        let trailer = hash::hash(&buf);
        buf.extend_from_slice(&trailer);

        let (_dir, store) = fresh_store();
        let err = PackReader::read(&buf, &store).unwrap_err();
        assert!(matches!(err, PackError::InvalidEntryType(0x77)));
    }

    #[test]
    fn delta_base_missing_is_loud() {
        let mut fake_base = [0u8; 32];
        fake_base[0] = 0xAB;
        // Build a minimal SPEC-DELTA stream that targets a nonexistent base.
        let mut stream = Vec::new();
        stream.push(0x01); // version
        stream.extend_from_slice(&0u32.to_le_bytes()); // base_len
        stream.extend_from_slice(&0u32.to_le_bytes()); // result_len
        let mut w = PackWriter::new();
        w.push_delta(&fake_base, &stream).unwrap();
        let pack = w.finish().unwrap();

        let (_dir, store) = fresh_store();
        let err = PackReader::read(&pack, &store).unwrap_err();
        assert!(matches!(err, PackError::DeltaBaseMissing(_)), "got {err:?}");
    }

    #[test]
    fn entry_payload_past_trailer_rejected() {
        let mut buf = Vec::new();
        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&VERSION.to_le_bytes());
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.push(0x00);
        buf.extend_from_slice(&1_000_000u32.to_le_bytes());
        // No payload bytes follow.
        let trailer = hash::hash(&buf);
        buf.extend_from_slice(&trailer);

        let (_dir, store) = fresh_store();
        let err = PackReader::read(&buf, &store).unwrap_err();
        assert!(matches!(err, PackError::UnexpectedEof));
    }

    #[test]
    fn entry_count_over_cap_rejected() {
        let mut buf = Vec::new();
        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&VERSION.to_le_bytes());
        buf.extend_from_slice(&u32::MAX.to_le_bytes());
        // Add a fake trailer so trailer-check passes — wait, it can't
        // pass since the body is bogus. Compute it correctly so the
        // trailer is the not-the-failure path; then the count cap must
        // fire first per read() ordering.
        let trailer = hash::hash(&buf);
        buf.extend_from_slice(&trailer);

        let (_dir, store) = fresh_store();
        let err = PackReader::read(&buf, &store).unwrap_err();
        // count cap fires after trailer verify in our impl. Either is
        // acceptable; assert one of them.
        assert!(
            matches!(err, PackError::TooManyObjects(_)),
            "expected TooManyObjects, got {err:?}"
        );
    }

    #[test]
    fn pack_key_is_blake3_of_pack_bytes() {
        let blob = write_blob_via_serialize(b"key test");
        let h = hash::hash(&blob);
        let mut w = PackWriter::new();
        w.push_raw(h, blob).unwrap();
        let pack = w.finish().unwrap();
        assert_eq!(pack_key(&pack), hash::hash(&pack));
    }

    #[test]
    fn delta_resolves_against_pre_existing_store_object() {
        let (_dir, store) = fresh_store();
        // Plant the base in the store first.
        let mut content_base = vec![0u8; 256];
        for (i, b) in content_base.iter_mut().enumerate() {
            *b = u8::try_from(i % 251).expect("modulo < 256");
        }
        let base_obj = write_blob_via_serialize(&content_base);
        let base_hash = store.write(&base_obj).unwrap();

        // Pack contains ONLY a delta; the base must be resolved from disk.
        let mut content_target = content_base.clone();
        content_target[100] = 0xAA;
        let target_obj = write_blob_via_serialize(&content_target);
        let target_hash = hash::hash(&target_obj);
        let stream = delta::encode(&base_obj, &target_obj).unwrap();

        let mut w = PackWriter::new();
        w.push_delta(&base_hash, &stream).unwrap();
        let pack = w.finish().unwrap();

        let report = PackReader::read(&pack, &store).unwrap();
        assert_eq!(report.delta_count, 1);
        assert_eq!(report.raw_count, 0);
        assert_eq!(store.read(&target_hash).unwrap(), target_obj);
    }
}
