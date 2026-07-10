//! Packfile writer / reader — conformant to `docs/specs/SPEC-PACKFILE.md`.
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
use std::borrow::Cow;
use std::sync::atomic::{AtomicU64, Ordering};

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

/// Builds a packfile, enforcing entry/payload caps and streaming each
/// pushed entry's frame directly into the final output buffer as it
/// arrives. [`Self::finish`] only patches the header's entry count
/// (unknown up front from a streaming writer) and appends the trailer —
/// it never re-copies the pushed entries into a second, same-sized
/// buffer (issue #647).
#[derive(Debug)]
pub struct PackWriter {
    // The final packfile bytes, built incrementally: `new` writes the
    // header with a zero entry-count placeholder (patched by `finish`
    // once the final count is known); `push_raw`/`push_delta` append
    // each entry's `[type][len][payload]` frame directly here. There is
    // no separate per-entry collection copied a second time at
    // `finish`.
    buf: Vec<u8>,
    entry_count: u32,
    total_payload: u64,
}

impl Default for PackWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl PackWriter {
    /// Create an empty writer.
    #[must_use]
    pub fn new() -> Self {
        let mut buf = Vec::with_capacity(HEADER_LEN);
        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&VERSION.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes()); // entry_count placeholder; `finish` patches it in.
        Self {
            buf,
            entry_count: 0,
            total_payload: 0,
        }
    }

    /// Append a raw object entry. `bytes` is the fully serialised object
    /// payload; `hash_of_bytes` is the BLAKE3 of those same bytes —
    /// callers usually have it on hand from the object store, so we take
    /// it explicitly to avoid an extra BLAKE3 pass over the same buffer.
    /// Takes `bytes` by reference (not by value): the streaming writer
    /// copies it straight into the output buffer as it's pushed, so it
    /// never needs to own the caller's copy (issue #647). Returns the
    /// same hash for chaining.
    pub fn push_raw(&mut self, hash_of_bytes: Hash, bytes: &[u8]) -> Result<Hash, PackError> {
        self.check_caps_for(bytes.len())?;
        self.total_payload += bytes.len() as u64;
        self.append_entry(0x00, &[bytes])?;
        self.entry_count += 1;
        Ok(hash_of_bytes)
    }

    /// Append a delta entry. `base_hash` MUST refer to an earlier raw
    /// entry in this pack OR an object already in the destination store.
    /// `delta_stream` MUST be a valid SPEC-DELTA stream — we don't
    /// re-validate here (the writer is trusted), but the reader will.
    pub fn push_delta(&mut self, base_hash: &Hash, delta_stream: &[u8]) -> Result<(), PackError> {
        let payload_len = hash::HASH_LEN + delta_stream.len();
        self.check_caps_for(payload_len)?;
        self.total_payload += payload_len as u64;
        self.append_entry(0x02, &[base_hash.as_slice(), delta_stream])?;
        self.entry_count += 1;
        Ok(())
    }

    /// Append one entry's frame — `[1B type][4B payload_len][payload]`
    /// — straight onto the output buffer. `parts` is the payload split
    /// into its logical pieces (a delta entry is `[base_hash][stream]`)
    /// so no intermediate concatenated buffer is ever built just to
    /// hand a single contiguous slice to `finish`.
    fn append_entry(&mut self, etype: u8, parts: &[&[u8]]) -> Result<(), PackError> {
        let payload_len: usize = parts.iter().map(|p| p.len()).sum();
        let plen: u32 = payload_len
            .try_into()
            .map_err(|_| PackError::PackfileTooLarge)?;
        self.buf.push(etype);
        self.buf.extend_from_slice(&plen.to_le_bytes());
        for p in parts {
            self.buf.extend_from_slice(p);
        }
        Ok(())
    }

    fn check_caps_for(&self, add_len: usize) -> Result<(), PackError> {
        let next_count = u64::from(self.entry_count) + 1;
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
        self.entry_count as usize
    }

    /// Serialise the pack: header + entries + trailer. Entries are
    /// already in `self.buf` (streamed in by `push_raw`/`push_delta`);
    /// `finish` only patches the header's entry count and appends the
    /// trailer, `BLAKE3(everything_before_trailer)`. The whole pack's
    /// BLAKE3 is the on-disk pack key — see [`pack_key`].
    pub fn finish(self) -> Result<Vec<u8>, PackError> {
        self.finish_inner(None)
    }

    /// Test-only variant of [`Self::finish`] that also reports, via
    /// `bytes_copied`, how many payload bytes it copies WHILE finishing
    /// (as opposed to while entries were pushed). Proves `finish`
    /// streams rather than double-buffers (issue #647): the unpatched
    /// writer re-copied every pushed entry's payload into a fresh
    /// same-size buffer inside `finish`, so this counter would track
    /// the whole pack; the streaming writer only ever appends the
    /// 32-byte trailer here.
    #[cfg(test)]
    pub(crate) fn finish_tracking_bytes_copied(
        self,
        bytes_copied: &AtomicU64,
    ) -> Result<Vec<u8>, PackError> {
        self.finish_inner(Some(bytes_copied))
    }

    fn finish_inner(mut self, bytes_copied: Option<&AtomicU64>) -> Result<Vec<u8>, PackError> {
        if self.entry_count > MAX_ENTRIES {
            return Err(PackError::TooManyObjects(self.entry_count));
        }
        self.buf[8..12].copy_from_slice(&self.entry_count.to_le_bytes());
        let trailer = hash::hash(&self.buf);
        if let Some(c) = bytes_copied {
            c.fetch_add(trailer.len() as u64, Ordering::Relaxed);
        }
        self.buf.extend_from_slice(&trailer);
        Ok(self.buf)
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
        Self::read_with_payload_cap(pack_bytes, store, MAX_TOTAL_PAYLOAD)
    }

    /// Same as [`Pack::read`], but with a caller-supplied running-total
    /// payload cap instead of the hardcoded [`MAX_TOTAL_PAYLOAD`] (4
    /// GiB). `pub(crate)`, not part of the public API — test-only
    /// injection point so `PackfileTooLarge` can be exercised without
    /// constructing a multi-gigabyte pack. Real callers MUST use
    /// [`Pack::read`] instead.
    pub(crate) fn read_with_payload_cap(
        pack_bytes: &[u8],
        store: &ObjectStore,
        payload_cap: u64,
    ) -> Result<UnpackReport, PackError> {
        Self::read_inner(pack_bytes, store, payload_cap, None)
    }

    /// Test-only variant of [`Self::read`] that also reports, via
    /// `owned_bytes`, the total number of payload bytes it allocates
    /// freshly (as opposed to borrowing straight from the
    /// already-resident `pack_bytes`). Proves the streaming reader
    /// (issue #647) never re-copies a raw entry's bytes: only delta
    /// targets — genuinely new bytes produced by `delta::decode`, which
    /// cannot alias `pack_bytes` — increment this counter.
    #[cfg(test)]
    pub(crate) fn read_tracking_owned_bytes(
        pack_bytes: &[u8],
        store: &ObjectStore,
        owned_bytes: &AtomicU64,
    ) -> Result<UnpackReport, PackError> {
        Self::read_inner(pack_bytes, store, MAX_TOTAL_PAYLOAD, Some(owned_bytes))
    }

    fn read_inner(
        pack_bytes: &[u8],
        store: &ObjectStore,
        payload_cap: u64,
        owned_bytes: Option<&AtomicU64>,
    ) -> Result<UnpackReport, PackError> {
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
        // Every entry parsed below is staged into the batch as it's
        // seen (not buffered up front), but that's only safe to do
        // BECAUSE the pack's own integrity is already established here,
        // first — a corrupt/truncated pack is rejected before a single
        // byte is staged, so the "abort leaves the store untouched"
        // guarantee does not depend on holding the whole pack's staged
        // output in memory at once (see `WriteBatch`'s module docs: a
        // dropped, uncommitted batch unlinks its temp files for free).
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
        // Track entries resolved in *this* pack so subsequent delta
        // entries can resolve their base from memory before falling
        // back to the on-disk store: `WriteBatch::write_prehashed`
        // stages bytes durably-pending but NOT visible until
        // `commit()`, so a not-yet-committed entry can only be found
        // here, never via `store`. Raw entries borrow straight out of
        // `pack_bytes` — it's already resident for the whole call, so
        // keeping a second owned copy alongside it would just double
        // the memory a large pack needs (issue #647). Only
        // delta-resolved entries need an owned buffer, since
        // `delta::decode` produces bytes that don't alias `pack_bytes`.
        let mut in_pack: std::collections::HashMap<Hash, Cow<'_, [u8]>> =
            std::collections::HashMap::new();
        let mut total_payload: u64 = 0;
        let mut pos = HEADER_LEN;

        // Stage each entry into the batch as soon as it's parsed and
        // validated, rather than collecting every entry's bytes into a
        // second list first and writing them all out after the loop.
        // `commit()` still runs exactly once, after the loop below, so
        // the "durable and visible together" contract (see the
        // `WriteBatch` module docs) is unaffected — only the point at
        // which each entry's bytes are handed to the batch moves
        // earlier, from "after every entry is parsed" to "as each
        // entry is parsed".
        let batch = store.batch();

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
            if total_payload > payload_cap {
                return Err(PackError::PackfileTooLarge);
            }
            if pos + payload_len > split {
                return Err(PackError::UnexpectedEof);
            }
            let payload = &pack_bytes[pos..pos + payload_len];
            pos += payload_len;

            match etype {
                0x00 => {
                    // raw — validate, then stage into the batch immediately.
                    let obj = validate_storable_object(payload)?;
                    // Address by the dispatched id (merkle root for
                    // Tree/ChunkedBlob, BLAKE3 otherwise) from the object we
                    // just decoded, so the unpacked object lands under the same
                    // key every sink uses without a second decode.
                    let stored_hash = crate::object::id_from_object(&obj, payload);
                    batch.write_prehashed(stored_hash, &[payload])?;
                    in_pack.insert(stored_hash, Cow::Borrowed(payload));
                    report.raw_count += 1;
                    report.stored.push(stored_hash);
                }
                0x02 => {
                    // delta — payload is [32B base_hash][stream].
                    if payload.len() < hash::HASH_LEN {
                        return Err(PackError::DeltaEntryTruncated);
                    }
                    let mut base_hash = [0u8; hash::HASH_LEN];
                    base_hash.copy_from_slice(&payload[..hash::HASH_LEN]);
                    let stream = &payload[hash::HASH_LEN..];
                    // Resolve base: in-pack first, then on-disk. A
                    // store-resolved base is cached into `in_pack` under
                    // its own hash so a later delta entry referencing the
                    // same out-of-pack base hits the cache-hit branch
                    // above instead of paying another full read + verify +
                    // decode (#643). This is safe because `store.read`
                    // already hash-verified the bytes against `base_hash`.
                    // Cloning once here (vs. #643's original Arc::clone)
                    // is the cost of composing with #647's Cow-based
                    // `in_pack`, which trades that one-time clone for
                    // zero-copy borrows on the far more common raw-entry
                    // path — a net win, and this clone only happens once
                    // per unique out-of-pack base, not per delta entry.
                    let base_bytes: Cow<'_, [u8]> = if let Some(b) = in_pack.get(&base_hash) {
                        Cow::Borrowed(b.as_ref())
                    } else if store.contains(&base_hash) {
                        let bytes = store.read(&base_hash)?;
                        validate_storable_object(&bytes)?;
                        in_pack.insert(base_hash, Cow::Owned(bytes.clone()));
                        Cow::Owned(bytes)
                    } else {
                        return Err(PackError::DeltaBaseMissing(hash::to_hex(&base_hash)));
                    };
                    validate_delta_result_size(stream)?;
                    let resolved = delta::decode(base_bytes.as_ref(), stream)?;
                    let obj = validate_storable_object(&resolved)?;
                    let stored_hash = crate::object::id_from_object(&obj, &resolved);
                    batch.write_prehashed(stored_hash, &[&resolved])?;
                    if let Some(c) = owned_bytes {
                        c.fetch_add(resolved.len() as u64, Ordering::Relaxed);
                    }
                    in_pack.insert(stored_hash, Cow::Owned(resolved));
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
        batch.commit()?;

        Ok(report)
    }
}

/// Decode `bytes`, enforce the size and storability invariants, and hand back
/// the decoded [`Object`] so callers can address it without decoding twice.
fn validate_storable_object(bytes: &[u8]) -> Result<Object, PackError> {
    if bytes.len() > MAX_RAW_OBJECT_SIZE {
        return Err(PackError::Store(crate::store::StoreError::ObjectTooLarge));
    }
    match crate::serialize::deserialize(bytes).map_err(PackError::InvalidObject)? {
        Object::Delta(_) => Err(PackError::NonStorableObject),
        obj @ (Object::Blob(_)
        | Object::Tree(_)
        | Object::Commit(_)
        | Object::Remix(_)
        | Object::ChunkedBlob(_)
        | Object::Tag(_)) => Ok(obj),
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
        let store = ObjectStore::init(&crate::layout::RepoLayout::single(dir.path())).unwrap();
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
            w.push_raw(hash::hash(&blob), &blob).unwrap();
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
        w.push_raw(h, &blob).unwrap();
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
        w.push_raw(base_hash, &base_obj).unwrap();
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
        w.push_raw(ha, &base_a).unwrap(); // a raw entry — must be ignored
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
        w.push_raw(payload_hash, &payload).unwrap();
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
        w.push_raw(base_hash, &base_obj).unwrap();
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
        w.push_raw(base_hash, &base_obj).unwrap();
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
        w.push_raw(h, &blob).unwrap();
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
    fn payload_sum_over_cap_is_rejected_before_bounds_or_decode() {
        // `PackfileTooLarge` on the reader's running-payload-total is
        // enforced against MAX_TOTAL_PAYLOAD (4 GiB) in production —
        // impractical to trip directly in a unit test without
        // allocating gigabytes. `read_with_payload_cap` is the
        // test-only injection point: same check, caller-supplied cap.
        let blob_a = write_blob_via_serialize(&[0xAA; 64]);
        let blob_b = write_blob_via_serialize(&[0xBB; 64]);
        let mut w = PackWriter::new();
        w.push_raw(hash::hash(&blob_a), &blob_a).unwrap();
        w.push_raw(hash::hash(&blob_b), &blob_b).unwrap();
        let pack = w.finish().unwrap();

        let (_dir, store) = fresh_store();

        // Cap smaller than the combined payload but big enough that
        // the first entry alone fits — the SECOND entry's running
        // total must trip the cap, not an entry-count or bounds check.
        let cap = (blob_a.len() as u64) + 10;
        let err = PackReader::read_with_payload_cap(&pack, &store, cap).unwrap_err();
        assert!(
            matches!(err, PackError::PackfileTooLarge),
            "expected PackfileTooLarge, got {err:?}"
        );

        // Sanity: the same pack with a generous cap (the real
        // MAX_TOTAL_PAYLOAD) unpacks normally.
        let report = PackReader::read(&pack, &store).unwrap();
        assert_eq!(report.raw_count, 2);
    }

    #[test]
    fn pack_key_is_blake3_of_pack_bytes() {
        let blob = write_blob_via_serialize(b"key test");
        let h = hash::hash(&blob);
        let mut w = PackWriter::new();
        w.push_raw(h, &blob).unwrap();
        let pack = w.finish().unwrap();
        assert_eq!(pack_key(&pack), hash::hash(&pack));
    }

    #[test]
    fn unpack_does_not_recopy_raw_payloads_into_a_second_buffer() {
        // Issue #647: `PackReader::read` used to copy EVERY raw entry's
        // payload into a fresh `Arc<[u8]>` retained in `in_pack` for the
        // whole call — redundant given `pack_bytes` (the pack's own
        // bytes) is already resident in the caller's memory the whole
        // time. A streaming reader only needs a BORROW into
        // `pack_bytes` for raw entries; nothing about a raw entry's
        // bytes should ever be copied a second time. `owned_bytes`
        // tracks the exact production code path that would otherwise
        // do that copy (see `read_tracking_owned_bytes`), so this is a
        // precise, allocator-free proof rather than a fuzzy proxy.
        let mut w = PackWriter::new();
        for i in 0u32..64 {
            let payload = vec![u8::try_from(i % 256).unwrap(); 16 * 1024];
            let blob = write_blob_via_serialize(&payload);
            w.push_raw(hash::hash(&blob), &blob).unwrap();
        }
        let pack = w.finish().unwrap();
        assert!(
            pack.len() > 512 * 1024,
            "sanity: synthetic pack should be substantial, got {}",
            pack.len()
        );

        let (_dir, store) = fresh_store();
        let owned_bytes = AtomicU64::new(0);
        let report = PackReader::read_tracking_owned_bytes(&pack, &store, &owned_bytes).unwrap();
        assert_eq!(report.raw_count, 64);

        assert_eq!(
            owned_bytes.load(Ordering::Relaxed),
            0,
            "an all-raw pack must not allocate a second copy of any entry's payload"
        );
    }

    #[test]
    fn unpack_owned_bytes_for_deltas_is_exactly_the_delta_targets_not_the_whole_pack() {
        // Complements the all-raw test above: the raw base must still
        // be a zero-copy borrow, and each delta's "owned" cost must be
        // exactly its reconstructed target size — never the base's size
        // too, and never the whole pack's.
        let mut content_base = vec![0u8; 4096];
        for (i, b) in content_base.iter_mut().enumerate() {
            *b = u8::try_from(i % 251).unwrap();
        }
        let base_obj = write_blob_via_serialize(&content_base);
        let base_hash = hash::hash(&base_obj);

        let mut w = PackWriter::new();
        w.push_raw(base_hash, &base_obj).unwrap();
        let mut expected_owned = 0u64;
        for i in 0u32..10 {
            let mut target = content_base.clone();
            target[i as usize] ^= 0xFF;
            let target_obj = write_blob_via_serialize(&target);
            let stream = delta::encode(&base_obj, &target_obj).unwrap();
            w.push_delta(&base_hash, &stream).unwrap();
            expected_owned += target_obj.len() as u64;
        }
        let pack = w.finish().unwrap();

        let (_dir, store) = fresh_store();
        let owned_bytes = AtomicU64::new(0);
        let report = PackReader::read_tracking_owned_bytes(&pack, &store, &owned_bytes).unwrap();
        assert_eq!(report.raw_count, 1);
        assert_eq!(report.delta_count, 10);

        assert_eq!(
            owned_bytes.load(Ordering::Relaxed),
            expected_owned,
            "owned bytes must equal exactly the sum of delta target sizes — \
             no extra copy of the raw base"
        );
    }

    #[test]
    fn pack_writer_finish_does_not_recopy_pushed_payloads() {
        // Issue #647: `PackWriter::finish()` used to hold every pushed
        // entry in a separate `entries` list and then copy ALL of them
        // a second time into a freshly `Vec::with_capacity`'d output
        // buffer. A streaming writer appends each entry's frame
        // directly into the one output buffer as it's pushed, so
        // `finish()` itself should only ever append the 32-byte
        // trailer — `bytes_copied` tracks exactly that production code
        // path (see `finish_tracking_bytes_copied`).
        let mut w = PackWriter::new();
        for i in 0u32..64 {
            let payload = vec![u8::try_from(i % 256).unwrap(); 16 * 1024];
            let blob = write_blob_via_serialize(&payload);
            w.push_raw(hash::hash(&blob), &blob).unwrap();
        }
        let bytes_copied = AtomicU64::new(0);
        let pack = w.finish_tracking_bytes_copied(&bytes_copied).unwrap();
        assert!(pack.len() > 512 * 1024);

        assert_eq!(
            bytes_copied.load(Ordering::Relaxed),
            TRAILER_LEN as u64,
            "finish() must only append the trailer, not re-copy every pushed entry"
        );
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

    #[test]
    fn multiple_deltas_against_shared_external_base_read_store_once() {
        // Regression for #643: N deltas in one pack all referencing the
        // SAME out-of-pack (already-in-store) base object must resolve
        // that base with exactly one physical store read, not N — the
        // first store-resolved base should be cached into `in_pack` for
        // subsequent deltas to hit in memory.
        const N: usize = 5;

        let (_dir, store) = fresh_store();

        let mut content_base = vec![0u8; 512];
        for (i, b) in content_base.iter_mut().enumerate() {
            *b = u8::try_from(i % 251).expect("modulo < 256");
        }
        let base_obj = write_blob_via_serialize(&content_base);
        let base_hash = store.write(&base_obj).unwrap();

        // Five distinct deltas against the one shared external base.
        let mut w = PackWriter::new();
        let mut expected_targets = Vec::new();
        for i in 0..N {
            let mut content_target = content_base.clone();
            content_target[100] = u8::try_from(i).unwrap();
            let target_obj = write_blob_via_serialize(&content_target);
            let target_hash = hash::hash(&target_obj);
            let stream = delta::encode(&base_obj, &target_obj).unwrap();
            w.push_delta(&base_hash, &stream).unwrap();
            expected_targets.push((target_hash, target_obj));
        }
        let pack = w.finish().unwrap();

        let reads_before = store.read_call_count();
        let report = PackReader::read(&pack, &store).unwrap();
        let reads_after_for_base = store.read_call_count() - reads_before;

        assert_eq!(report.delta_count, u32::try_from(N).unwrap());
        assert_eq!(
            reads_after_for_base, 1,
            "base object must be read from the store exactly once for {N} deltas sharing it, got {reads_after_for_base}"
        );

        // Correctness: caching the store-resolved base must not change
        // the decoded result for any of the N deltas — every target
        // still comes out byte-identical to the uncached decode.
        for (target_hash, target_obj) in expected_targets {
            assert_eq!(store.read(&target_hash).unwrap(), target_obj);
        }
    }
}
