//! Packfile writer / reader — conformant to `docs/specs/SPEC-PACKFILE.md`.
//!
//! Layout (SPEC-PACKFILE §1, §2, §3, §8):
//!
//! ```text
//! [4B  magic            "MKIT"]                       offset 0
//! [4B  version u32 LE  == 1 or 2]
//! [4B  entry_count u32 LE     ]
//!   for each entry:
//!     [u8  entry_type]           0x00 raw | 0x02 delta | 0x03 zstd-raw | 0x04 zstd-delta
//!     [u32 LE payload_len]                            length of payload only
//!     [payload_len bytes payload]
//! [32B trailer = BLAKE3 of all preceding bytes]
//! ```
//!
//! Entry types (SPEC-PACKFILE §3):
//!
//! * `0x00` raw        — payload is a fully serialised mkit object.
//! * `0x01`             — RESERVED, MUST be rejected.
//! * `0x02` delta       — payload is `[32B base_hash][SPEC-DELTA stream]`.
//! * `0x03` zstd-raw    — v2 only. payload is `[4B uncompressed_len LE][zstd frame]`;
//!   the frame decompresses to exactly what a `0x00` payload would be.
//! * `0x04` zstd-delta  — v2 only. payload is `[32B base_hash][4B uncompressed_len LE][zstd frame]`;
//!   `base_hash` stays uncompressed, the frame decompresses to exactly
//!   what a `0x02` entry's post-base-hash bytes would be.
//!
//! **Version selection is writer policy, not caller policy**
//! (SPEC-PACKFILE §1): [`PackWriter`] emits `version = 1` when the
//! finished pack contains no `0x03`/`0x04` entries, and `version = 2`
//! the moment it contains at least one — even in an otherwise-mixed
//! pack. `0x03`/`0x04` are illegal inside a `version = 1` pack; a
//! reader seeing one there rejects with `InvalidEntryType` exactly as
//! it would for any other unrecognized type (SPEC-PACKFILE §3).
//!
//! **Compression is per-entry**, not a whole-pack stream: every
//! `0x03`/`0x04` entry carries its own independent zstd frame, so
//! existing framing/caps/trailer semantics (§2, §5, §8) are unchanged
//! and decompression memory is bounded to one entry at a time.
//! Decoding a `0x03`/`0x04` entry is bomb-guarded: the claimed
//! `uncompressed_len` is checked against [`MAX_RAW_OBJECT_SIZE`]
//! *before* any decompression allocation, decompression itself is
//! capacity-bounded to that claim, and the actual decompressed length
//! is re-checked against the claim afterward (`DecompressedSizeMismatch`
//! / `DecompressedSizeOverCap`).
//!
//! Caps (SPEC-PACKFILE §5, unchanged by v2 — measured on the *wire*
//! size; the decompressed-side cap above is separate and new):
//!
//! * `entry_count <= 10_000_000`
//! * total `payload_len` sum `<= 4 GiB`
//!
//! Delta-base ordering rule (SPEC-PACKFILE §4): every delta entry's
//! (`0x02` or `0x04`) `base_hash` MUST appear earlier in the same pack
//! as a raw entry, OR already exist in the destination object store.
//! `0x04`'s `base_hash` is never compressed, so this never requires
//! decompression to evaluate.
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

/// ASCII magic ("MKIT") at the start of every pack, v1 or v2.
pub const MAGIC: &[u8; 4] = b"MKIT";
/// Packfile version emitted when a pack contains no compressed
/// (`0x03`/`0x04`) entries. Also the minimum version any reader
/// accepts.
pub const VERSION: u32 = 1;
/// Packfile version emitted the moment a pack contains at least one
/// compressed (`0x03`/`0x04`) entry (SPEC-PACKFILE §1, §9). Readers
/// accept both `VERSION` and `VERSION_V2`; only `VERSION_V2` packs may
/// contain `0x03`/`0x04` entries.
pub const VERSION_V2: u32 = 2;

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
/// Byte offset of the 4-byte `version` field within the header —
/// right after the 4-byte magic. `PackWriter::finish` patches this
/// once the final v1-vs-v2 decision is known (mirrors
/// `ENTRY_COUNT_OFFSET` below).
pub const VERSION_OFFSET: usize = 4;
/// Byte offset of the 4-byte `entry_count` field within the header —
/// after the 4-byte magic and 4-byte version fields. Found hardcoded
/// as the literal range `8..12` at four call sites during the
/// epic-#634 code review; named here instead, consistent with this
/// file's existing `HEADER_LEN`/`TRAILER_LEN` convention.
pub const ENTRY_COUNT_OFFSET: usize = 8;

/// Compression candidates shorter than this are never compressed
/// (SPEC-PACKFILE §3.3) — per-entry zstd framing overhead and CPU
/// cost isn't worth it for tiny payloads. Only meaningful when the
/// `pack-zstd` feature is compiled in (see `maybe_compress`).
#[cfg(feature = "pack-zstd")]
const MIN_COMPRESS_LEN: usize = 64;
/// zstd compression level `PackWriter` uses for `0x03`/`0x04` entries.
/// The library default (`ZSTD_CLEVEL_DEFAULT`); no benchmark evidence
/// in issue #646 justified deviating from it.
#[cfg(feature = "pack-zstd")]
const ZSTD_LEVEL: i32 = 3;
/// Byte length of a `0x03`/`0x04` entry's `uncompressed_len` length
/// prefix. Part of the wire format regardless of whether this build
/// can itself produce/consume `0x03`/`0x04` entries.
const ZSTD_LEN_PREFIX: usize = 4;

/// Packfile errors. Distinct from [`MkitError`] so callers can match on
/// pack-specific failures (trailer mismatch, base-missing) without
/// catching every object decode error.
#[derive(Debug, thiserror::Error)]
pub enum PackError {
    #[error("packfile is shorter than the {HEADER_LEN}-byte header + {TRAILER_LEN}-byte trailer")]
    PackfileTooShort,
    #[error("first 4 bytes are not ASCII \"MKIT\"")]
    InvalidMagic,
    #[error("version {0} is not supported (v1 or v2 only)")]
    UnsupportedVersion(u32),
    #[error(
        "entry_type {0:#04x} is not 0x00 (raw), 0x02 (delta), 0x03 (zstd-raw), or 0x04 \
         (zstd-delta) — or is a v2-only entry type inside a version-1 pack"
    )]
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
    /// `0x03`/`0x04` payload shorter than its `[uncompressed_len]`
    /// length-prefix header (SPEC-PACKFILE §3.3, §3.4) — distinct from
    /// `DeltaEntryTruncated`, which covers the 32-byte `base_hash`
    /// prefix a `0x04` entry has in front of this.
    #[error("zstd entry payload is shorter than its length-prefix header")]
    ZstdEntryTruncated,
    /// Claimed `uncompressed_len` exceeds [`MAX_RAW_OBJECT_SIZE`] —
    /// rejected before any decompression allocation is attempted
    /// (SPEC-PACKFILE §3.3 bomb-guarding).
    #[error(
        "zstd entry's claimed decompressed size {0} exceeds the {MAX_RAW_OBJECT_SIZE}-byte cap"
    )]
    DecompressedSizeOverCap(usize),
    /// The zstd frame decompressed successfully but produced a
    /// different byte count than the entry's claimed
    /// `uncompressed_len` (SPEC-PACKFILE §3.3 bomb-guarding).
    #[error("zstd entry claims {0} decompressed bytes but produced {1}")]
    DecompressedSizeMismatch(usize, usize),
    /// The zstd frame itself is corrupt / not a valid zstd stream.
    #[error("zstd decompression failed: {0}")]
    ZstdDecompress(String),
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

/// A raw entry whose pack-compression decision has already been made by
/// [`PackWriter::prepare_raw`], off any [`PackWriter`] instance — the
/// CPU-bound step, safe to run in parallel across entries before any of
/// them touch the writer's sequential state. Feed it to
/// [`PackWriter::push_prepared_raw`] to append it in order.
#[derive(Debug)]
pub struct PreparedRaw {
    hash: Hash,
    bytes: Vec<u8>,
    frame: Option<Vec<u8>>,
}

impl PreparedRaw {
    /// Conservative (uncompressed) wire-size bound for this entry —
    /// the same quantity a caller would use, pre-compression, to decide
    /// whether pushing it risks exceeding a payload cap (compression
    /// only ever shrinks the actual wire size, never grows it).
    #[must_use]
    pub fn conservative_len(&self) -> usize {
        self.bytes.len()
    }
}

/// The delta-entry counterpart of [`PreparedRaw`], produced by
/// [`PackWriter::prepare_delta`] and appended via
/// [`PackWriter::push_prepared_delta`].
#[derive(Debug)]
pub struct PreparedDelta {
    base: Hash,
    stream: Vec<u8>,
    frame: Option<Vec<u8>>,
}

impl PreparedDelta {
    /// Conservative (uncompressed) wire-size bound for this entry — see
    /// [`PreparedRaw::conservative_len`].
    #[must_use]
    pub fn conservative_len(&self) -> usize {
        hash::HASH_LEN + self.stream.len()
    }
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
    // Set the first time `push_raw`/`push_delta` emits a `0x03`/`0x04`
    // entry. `finish` reads this to decide the header's `version`
    // field (SPEC-PACKFILE §1's writer version-selection rule) — v2
    // the moment ANY entry ended up compressed, v1 otherwise.
    has_compressed_entry: bool,
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
            has_compressed_entry: false,
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
    ///
    /// Applies the SPEC-PACKFILE §3.3 compression policy transparently:
    /// if `bytes` compresses under zstd strictly smaller on the wire
    /// (and is long enough to bother, see `MIN_COMPRESS_LEN`), this
    /// emits a `0x03` zstd-raw entry instead of `0x00` raw — callers
    /// never need to opt in. Either way the returned/stored identity
    /// (`hash_of_bytes`) is unchanged; only the wire encoding differs.
    pub fn push_raw(&mut self, hash_of_bytes: Hash, bytes: &[u8]) -> Result<Hash, PackError> {
        let frame = maybe_compress(bytes);
        self.append_raw_frame(hash_of_bytes, bytes, frame)
    }

    /// Pure (no `&self`) compression step for a raw entry, split out of
    /// [`Self::push_raw`] so a caller building a pack out of many
    /// independent objects (e.g. a push serialising a whole plan) can
    /// run the CPU-bound zstd compression for each entry off the
    /// thread-pool of its choosing — in parallel, since one entry's
    /// compression never depends on another's — and only then replay
    /// the writer's sequential, order-preserving append via
    /// [`Self::push_prepared_raw`].
    ///
    /// Takes `bytes` by value (unlike `push_raw`'s `&[u8]`): callers
    /// with a single object already own the bytes fresh out of the
    /// object store, and a fan-out across a thread pool needs an owned,
    /// `'static` value to move into each task anyway, so there is no
    /// zero-copy path to preserve here the way `push_raw` does.
    #[must_use]
    pub fn prepare_raw(hash_of_bytes: Hash, bytes: Vec<u8>) -> PreparedRaw {
        let frame = maybe_compress(&bytes);
        PreparedRaw {
            hash: hash_of_bytes,
            bytes,
            frame,
        }
    }

    /// Append a [`PreparedRaw`] produced by [`Self::prepare_raw`].
    /// Identical wire result and cap-check semantics to `push_raw`
    /// called on the same bytes — compression already happened, so
    /// this only replays the cheap bookkeeping + buffer append.
    pub fn push_prepared_raw(&mut self, entry: PreparedRaw) -> Result<Hash, PackError> {
        self.append_raw_frame(entry.hash, &entry.bytes, entry.frame)
    }

    /// Shared tail of `push_raw`/`push_prepared_raw`: given `bytes` and
    /// an already-decided `frame` (zstd output, or `None` when
    /// compression wasn't worth it), do the cap check, bookkeeping, and
    /// buffer append. The only difference between the two public
    /// entry points is where `frame` was computed.
    fn append_raw_frame(
        &mut self,
        hash_of_bytes: Hash,
        bytes: &[u8],
        frame: Option<Vec<u8>>,
    ) -> Result<Hash, PackError> {
        if let Some(frame) = frame {
            let uncompressed_len: u32 = bytes
                .len()
                .try_into()
                .map_err(|_| PackError::PackfileTooLarge)?;
            let payload_len = ZSTD_LEN_PREFIX + frame.len();
            self.check_caps_for(payload_len)?;
            self.total_payload += payload_len as u64;
            self.append_entry(0x03, &[&uncompressed_len.to_le_bytes(), &frame])?;
            self.has_compressed_entry = true;
        } else {
            self.check_caps_for(bytes.len())?;
            self.total_payload += bytes.len() as u64;
            self.append_entry(0x00, &[bytes])?;
        }
        self.entry_count += 1;
        Ok(hash_of_bytes)
    }

    /// Append a delta entry. `base_hash` MUST refer to an earlier raw
    /// entry in this pack OR an object already in the destination store.
    /// `delta_stream` MUST be a valid SPEC-DELTA stream — we don't
    /// re-validate here (the writer is trusted), but the reader will.
    ///
    /// Applies the same §3.3 compression policy as [`Self::push_raw`],
    /// but ONLY to `delta_stream` — `base_hash` is always written
    /// uncompressed (SPEC-PACKFILE §3.4), so ordering/base-discovery
    /// logic never needs to decompress anything. Emits `0x04`
    /// zstd-delta when the stream compresses strictly smaller on the
    /// wire and is long enough to bother; `0x02` delta otherwise.
    pub fn push_delta(&mut self, base_hash: &Hash, delta_stream: &[u8]) -> Result<(), PackError> {
        let frame = maybe_compress(delta_stream);
        self.append_delta_frame(base_hash, delta_stream, frame)
    }

    /// Pure (no `&self`) compression step for a delta entry — the
    /// delta-entry counterpart of [`Self::prepare_raw`]; see its doc
    /// comment for why this exists and how it's meant to be used (fan
    /// out `prepare_delta` across a thread pool, then replay results in
    /// order via [`Self::push_prepared_delta`]).
    #[must_use]
    pub fn prepare_delta(base_hash: Hash, delta_stream: Vec<u8>) -> PreparedDelta {
        let frame = maybe_compress(&delta_stream);
        PreparedDelta {
            base: base_hash,
            stream: delta_stream,
            frame,
        }
    }

    /// Append a [`PreparedDelta`] produced by [`Self::prepare_delta`].
    /// Identical wire result and cap-check semantics to `push_delta`
    /// called on the same base/stream.
    pub fn push_prepared_delta(&mut self, entry: PreparedDelta) -> Result<(), PackError> {
        self.append_delta_frame(&entry.base, &entry.stream, entry.frame)
    }

    /// Shared tail of `push_delta`/`push_prepared_delta` — see
    /// [`Self::append_raw_frame`]'s doc comment for the analogous raw-entry
    /// split.
    fn append_delta_frame(
        &mut self,
        base_hash: &Hash,
        delta_stream: &[u8],
        frame: Option<Vec<u8>>,
    ) -> Result<(), PackError> {
        if let Some(frame) = frame {
            let uncompressed_len: u32 = delta_stream
                .len()
                .try_into()
                .map_err(|_| PackError::PackfileTooLarge)?;
            let payload_len = hash::HASH_LEN + ZSTD_LEN_PREFIX + frame.len();
            self.check_caps_for(payload_len)?;
            self.total_payload += payload_len as u64;
            self.append_entry(
                0x04,
                &[
                    base_hash.as_slice(),
                    &uncompressed_len.to_le_bytes(),
                    &frame,
                ],
            )?;
            self.has_compressed_entry = true;
        } else {
            let payload_len = hash::HASH_LEN + delta_stream.len();
            self.check_caps_for(payload_len)?;
            self.total_payload += payload_len as u64;
            self.append_entry(0x02, &[base_hash.as_slice(), delta_stream])?;
        }
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

    /// Sum of wire payload bytes pushed so far — the quantity the
    /// writer's own internal cap check compares against
    /// [`MAX_TOTAL_PAYLOAD`]. Measured post-compression (SPEC-PACKFILE
    /// §5): each `push_raw`/`push_delta` call adds the *wire* payload
    /// length, not the caller's uncompressed input length. Callers
    /// deciding whether to seal a pack before pushing another entry can
    /// use a conservative uncompressed-length estimate against this
    /// value — the actual wire cost is never more than that estimate,
    /// since compression is only ever applied when it's strictly
    /// smaller (see `maybe_compress`).
    #[must_use]
    pub fn total_payload(&self) -> u64 {
        self.total_payload
    }

    /// Serialise the pack: header + entries + trailer. Entries are
    /// already in `self.buf` (streamed in by `push_raw`/`push_delta`);
    /// `finish` patches the header's `version` (SPEC-PACKFILE §1: v2
    /// iff at least one entry ended up compressed, v1 otherwise) and
    /// `entry_count`, then appends the trailer,
    /// `BLAKE3(everything_before_trailer)`. The whole pack's BLAKE3 is
    /// the on-disk pack key — see [`pack_key`].
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
        let version = if self.has_compressed_entry {
            VERSION_V2
        } else {
            VERSION
        };
        self.buf[VERSION_OFFSET..VERSION_OFFSET + 4].copy_from_slice(&version.to_le_bytes());
        self.buf[ENTRY_COUNT_OFFSET..ENTRY_COUNT_OFFSET + 4]
            .copy_from_slice(&self.entry_count.to_le_bytes());
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

/// SPEC-PACKFILE §3.3 writer compression policy: compress `data` with
/// zstd and return the frame ONLY if doing so is worth it — `data` is
/// at least [`MIN_COMPRESS_LEN`] bytes AND the compressed frame plus
/// its `ZSTD_LEN_PREFIX`-byte length prefix is strictly smaller than
/// `data` itself. Mirrors `transfer.rs`'s `try_delta` gate's
/// "strictly smaller or don't bother" posture. Returns `None` (never
/// an error) on any compression failure or when compression isn't
/// worth it — compression is a pure wire-size optimization, so a
/// writer always has a correct fallback (emit the entry uncompressed)
/// rather than a new failure mode to propagate.
#[cfg(feature = "pack-zstd")]
fn maybe_compress(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < MIN_COMPRESS_LEN {
        return None;
    }
    let compressed = zstd::bulk::compress(data, ZSTD_LEVEL).ok()?;
    if ZSTD_LEN_PREFIX + compressed.len() < data.len() {
        Some(compressed)
    } else {
        None
    }
}

#[cfg(not(feature = "pack-zstd"))]
fn maybe_compress(_data: &[u8]) -> Option<Vec<u8>> {
    // No compression backend compiled in (e.g. mkit-wasm, which opts
    // out of `pack-zstd` for wasm32-buildability — see mkit-core's
    // Cargo.toml). Every pack this build writes is a valid v1 pack;
    // it just never uses the v2-only entry types.
    None
}

/// Parse and decompress a `0x03`/`0x04`-style `[uncompressed_len][zstd
/// frame]` payload, enforcing SPEC-PACKFILE §3.3's bomb-guarding
/// before any decompression allocation: the claimed length is checked
/// against [`MAX_RAW_OBJECT_SIZE`] first, decompression is bounded to
/// that claim, and the actual decompressed length is re-checked
/// against the claim afterward.
fn decompress_zstd_entry(payload: &[u8]) -> Result<Vec<u8>, PackError> {
    if payload.len() < ZSTD_LEN_PREFIX {
        return Err(PackError::ZstdEntryTruncated);
    }
    let uncompressed_len =
        u32::from_le_bytes(payload[..ZSTD_LEN_PREFIX].try_into().expect("4 bytes")) as usize;
    if uncompressed_len > MAX_RAW_OBJECT_SIZE {
        return Err(PackError::DecompressedSizeOverCap(uncompressed_len));
    }
    let frame = &payload[ZSTD_LEN_PREFIX..];
    let decompressed = zstd_decompress_capped(frame, uncompressed_len)?;
    if decompressed.len() != uncompressed_len {
        return Err(PackError::DecompressedSizeMismatch(
            uncompressed_len,
            decompressed.len(),
        ));
    }
    Ok(decompressed)
}

/// Decompress `frame`, bounding the allocation to `capacity` bytes
/// (already checked against [`MAX_RAW_OBJECT_SIZE`] by the caller) so
/// a corrupt or hostile frame can't force an over-large allocation.
#[cfg(feature = "pack-zstd")]
fn zstd_decompress_capped(frame: &[u8], capacity: usize) -> Result<Vec<u8>, PackError> {
    zstd::bulk::decompress(frame, capacity).map_err(|e| PackError::ZstdDecompress(e.to_string()))
}

#[cfg(not(feature = "pack-zstd"))]
fn zstd_decompress_capped(_frame: &[u8], _capacity: usize) -> Result<Vec<u8>, PackError> {
    Err(PackError::ZstdDecompress(
        "this build was compiled without the `pack-zstd` feature".to_string(),
    ))
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
    if version != VERSION && version != VERSION_V2 {
        return Err(PackError::UnsupportedVersion(version));
    }
    let count = u32::from_le_bytes(
        pack_bytes[ENTRY_COUNT_OFFSET..ENTRY_COUNT_OFFSET + 4]
            .try_into()
            .expect("4 bytes"),
    );
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
        // `0x04`'s base_hash sits at the same offset (byte 0 of the
        // payload) as `0x02`'s and is always uncompressed
        // (SPEC-PACKFILE §3.4), so both entry types are scanned the
        // same way here — no decompression needed to pre-fetch bases.
        if etype == 0x02 || etype == 0x04 {
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
        // Steps 1-5 (length/magic/version/trailer/entry-count) live in
        // `validate_pack_header` — pulled out purely to keep this
        // function's entry-parsing loop under clippy's line-count cap;
        // no behavior moves, just where it's written.
        let (version, split, count) = validate_pack_header(pack_bytes)?;

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
                    stage_raw_object(
                        &batch,
                        &mut in_pack,
                        &mut report,
                        owned_bytes,
                        Cow::Borrowed(payload),
                    )?;
                }
                0x02 => {
                    // delta — payload is [32B base_hash][stream].
                    if payload.len() < hash::HASH_LEN {
                        return Err(PackError::DeltaEntryTruncated);
                    }
                    let mut base_hash = [0u8; hash::HASH_LEN];
                    base_hash.copy_from_slice(&payload[..hash::HASH_LEN]);
                    let stream = &payload[hash::HASH_LEN..];
                    stage_delta_target(
                        store,
                        &batch,
                        &mut in_pack,
                        &mut report,
                        owned_bytes,
                        base_hash,
                        stream,
                    )?;
                }
                0x03 if version == VERSION_V2 => {
                    // zstd-raw — payload is [4B uncompressed_len][zstd frame]
                    // (SPEC-PACKFILE §3.3). Decompress, then treat exactly
                    // like a 0x00 raw entry.
                    let obj_bytes = decompress_zstd_entry(payload)?;
                    stage_raw_object(
                        &batch,
                        &mut in_pack,
                        &mut report,
                        owned_bytes,
                        Cow::Owned(obj_bytes),
                    )?;
                }
                0x04 if version == VERSION_V2 => {
                    // zstd-delta — payload is [32B base_hash (uncompressed)]
                    // [4B uncompressed_len][zstd frame] (SPEC-PACKFILE §3.4).
                    if payload.len() < hash::HASH_LEN {
                        return Err(PackError::DeltaEntryTruncated);
                    }
                    let mut base_hash = [0u8; hash::HASH_LEN];
                    base_hash.copy_from_slice(&payload[..hash::HASH_LEN]);
                    let stream = decompress_zstd_entry(&payload[hash::HASH_LEN..])?;
                    stage_delta_target(
                        store,
                        &batch,
                        &mut in_pack,
                        &mut report,
                        owned_bytes,
                        base_hash,
                        &stream,
                    )?;
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

/// SPEC-PACKFILE §1/§5/§8 steps 1-5: length sanity, magic, version,
/// trailer verification (BEFORE anything touches the store), and
/// entry-count cap. Returns `(version, split, count)` — `split` is the
/// byte offset where the trailer begins (entries live in
/// `pack_bytes[HEADER_LEN..split]`). Split out of
/// [`PackReader::read_inner`] purely to keep that function's
/// entry-parsing loop under clippy's line-count cap; no check moves,
/// reorders, or changes behavior.
fn validate_pack_header(pack_bytes: &[u8]) -> Result<(u32, usize, u32), PackError> {
    // 1. Length sanity: must fit header + trailer at minimum.
    if pack_bytes.len() < HEADER_LEN + TRAILER_LEN {
        return Err(PackError::PackfileTooShort);
    }
    // 2. Magic.
    if &pack_bytes[..4] != MAGIC.as_slice() {
        return Err(PackError::InvalidMagic);
    }
    // 3. Version. v1 and v2 both decode here; only v2 packs may
    // contain `0x03`/`0x04` entries (enforced per-entry by the caller).
    let version = u32::from_le_bytes(pack_bytes[4..8].try_into().expect("4 bytes"));
    if version != VERSION && version != VERSION_V2 {
        return Err(PackError::UnsupportedVersion(version));
    }
    // 4. Trailer must match BEFORE we touch the store. SPEC-PACKFILE §8.
    // Every entry parsed by the caller is staged into its batch as
    // it's seen (not buffered up front), but that's only safe to do
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
    let count = u32::from_le_bytes(
        pack_bytes[ENTRY_COUNT_OFFSET..ENTRY_COUNT_OFFSET + 4]
            .try_into()
            .expect("4 bytes"),
    );
    if count > MAX_ENTRIES {
        return Err(PackError::TooManyObjects(count));
    }
    // Quick lower bound sanity: each entry is at least ENTRY_FRAME_LEN bytes.
    let body_after_header = body.len() - HEADER_LEN;
    if u64::from(count) * ENTRY_FRAME_LEN as u64 > body_after_header as u64 {
        return Err(PackError::TooManyObjects(count));
    }
    Ok((version, split, count))
}

/// Validate `payload` as a canonical storable object and stage it into
/// `batch`/`in_pack`/`report`. Shared by the `0x00` and `0x03` branches
/// of [`PackReader::read_inner`] — they differ only in whether
/// `payload` is a zero-copy borrow straight out of `pack_bytes` (`0x00`)
/// or an owned buffer produced by decompression (`0x03`); `owned_bytes`
/// is credited only for the latter (`Cow::Owned`), preserving the
/// zero-copy accounting issue #647 established for raw entries.
fn stage_raw_object<'p>(
    batch: &crate::batch::WriteBatch<'_>,
    in_pack: &mut std::collections::HashMap<Hash, Cow<'p, [u8]>>,
    report: &mut UnpackReport,
    owned_bytes: Option<&AtomicU64>,
    payload: Cow<'p, [u8]>,
) -> Result<(), PackError> {
    let obj = validate_storable_object(&payload)?;
    // Address by the dispatched id (merkle root for Tree/ChunkedBlob,
    // BLAKE3 otherwise) from the object we just decoded, so the
    // unpacked object lands under the same key every sink uses without
    // a second decode.
    let stored_hash = crate::object::id_from_object(&obj, &payload);
    batch.write_prehashed(stored_hash, &[payload.as_ref()])?;
    if let (Cow::Owned(_), Some(c)) = (&payload, owned_bytes) {
        c.fetch_add(payload.len() as u64, Ordering::Relaxed);
    }
    in_pack.insert(stored_hash, payload);
    report.raw_count += 1;
    report.stored.push(stored_hash);
    Ok(())
}

/// Resolve a delta's base, decode `stream` against it, and stage the
/// reconstructed target into `batch`/`in_pack`/`report`. Shared by the
/// `0x02` and `0x04` branches of [`PackReader::read_inner`] — `0x04`
/// differs only in how `stream` was sourced (decompressed vs. borrowed
/// straight from `pack_bytes`), not in how base resolution, delta
/// decoding, or staging work.
#[allow(clippy::too_many_arguments)]
fn stage_delta_target(
    store: &ObjectStore,
    batch: &crate::batch::WriteBatch<'_>,
    in_pack: &mut std::collections::HashMap<Hash, Cow<'_, [u8]>>,
    report: &mut UnpackReport,
    owned_bytes: Option<&AtomicU64>,
    base_hash: Hash,
    stream: &[u8],
) -> Result<(), PackError> {
    let resolved = resolve_delta_target(store, in_pack, base_hash, stream)?;
    let obj = validate_storable_object(&resolved)?;
    let stored_hash = crate::object::id_from_object(&obj, &resolved);
    batch.write_prehashed(stored_hash, &[&resolved])?;
    if let Some(c) = owned_bytes {
        c.fetch_add(resolved.len() as u64, Ordering::Relaxed);
    }
    in_pack.insert(stored_hash, Cow::Owned(resolved));
    report.delta_count += 1;
    report.stored.push(stored_hash);
    Ok(())
}

/// Resolve a delta's base (in-pack first, then on-disk store) and decode
/// `stream` against it. Shared by the `0x02` and `0x04` branches of
/// [`PackReader::read_inner`] — `0x04` differs only in how `stream` was
/// sourced (decompressed vs. borrowed straight from `pack_bytes`), not
/// in how base resolution or delta decoding work.
fn resolve_delta_target(
    store: &ObjectStore,
    in_pack: &mut std::collections::HashMap<Hash, Cow<'_, [u8]>>,
    base_hash: Hash,
    stream: &[u8],
) -> Result<Vec<u8>, PackError> {
    // Resolve base: in-pack first, then on-disk. A store-resolved base
    // is cached into `in_pack` under its own hash so a later delta
    // entry referencing the same out-of-pack base hits the cache-hit
    // branch above instead of paying another full read + verify +
    // decode (#643). This is safe because `store.read` already
    // hash-verified the bytes against `base_hash`. Cloning once here
    // (vs. #643's original Arc::clone) is the cost of composing with
    // #647's Cow-based `in_pack`, which trades that one-time clone for
    // zero-copy borrows on the far more common raw-entry path — a net
    // win, and this clone only happens once per unique out-of-pack
    // base, not per delta entry.
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
    Ok(resolved)
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

    /// Deterministic, high-entropy filler for tests that specifically
    /// exercise UNCOMPRESSED-entry behavior (zero-copy borrows, exact
    /// on-wire cap arithmetic) and therefore need payloads the §3.3
    /// writer policy will decline to compress. A simple LCG byte
    /// stream is enough: zstd's LZ+entropy stages find no exploitable
    /// redundancy in it, unlike a repeated-byte or short-period
    /// pattern, so `4 + compressed_len < raw_len` never holds and
    /// these payloads stay `0x00`/`0x02` exactly as before this
    /// change. (Payloads elsewhere in this file that use a short
    /// repeating pattern are fine to leave as-is — those tests assert
    /// only functional round-trip correctness, not wire-format byte
    /// counts, so whether they end up compressed doesn't affect them.)
    fn incompressible_bytes(seed: u64, len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        let mut state = seed | 1; // odd seed keeps the LCG full-period
        for chunk in buf.chunks_mut(8) {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let bytes = state.to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        buf
    }

    #[test]
    fn empty_pack_is_44_bytes() {
        let pack = PackWriter::new().finish().unwrap();
        assert_eq!(pack.len(), HEADER_LEN + TRAILER_LEN);
        assert_eq!(&pack[..4], MAGIC);
        assert_eq!(u32::from_le_bytes(pack[4..8].try_into().unwrap()), VERSION);
        assert_eq!(
            u32::from_le_bytes(
                pack[ENTRY_COUNT_OFFSET..ENTRY_COUNT_OFFSET + 4]
                    .try_into()
                    .unwrap()
            ),
            0
        );

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
    fn total_payload_tracks_wire_sum_for_mixed_raw_and_delta() {
        // issue #831: push-side pack-splitting decisions read
        // `total_payload()` to decide when to seal a pack, so it must
        // track the writer's real running wire-payload sum — checked
        // here against both a plain raw entry and a delta entry, and
        // bounded by the uncompressed input sizes (compression only
        // ever makes the wire payload smaller, never larger).
        let mut w = PackWriter::new();
        assert_eq!(w.total_payload(), 0);

        // Incompressible (random-ish) bytes so `maybe_compress` doesn't
        // shrink them — keeps the assertion exact rather than "at most".
        let raw = write_blob_via_serialize(&incompressible_bytes(0xA11C_E000, 2048));
        let raw_hash = hash::hash(&raw);
        w.push_raw(raw_hash, &raw).unwrap();
        assert_eq!(w.total_payload(), raw.len() as u64);

        let base = write_blob_via_serialize(&incompressible_bytes(0xB0BA_1000, 2048));
        let base_hash = hash::hash(&base);
        let target = write_blob_via_serialize(&incompressible_bytes(0xC0FF_EE00, 2048));
        let stream = delta::encode(&base, &target).unwrap();
        let before_delta = w.total_payload();
        w.push_delta(&base_hash, &stream).unwrap();
        let delta_wire_len = w.total_payload() - before_delta;

        // The writer never emits more wire bytes than the caller handed
        // it (delta payload = base_hash + stream, uncompressed worst
        // case), and `total_payload` must equal the sum of what was
        // actually appended so far.
        assert!(delta_wire_len <= (hash::HASH_LEN + stream.len()) as u64);
        assert_eq!(w.total_payload(), before_delta + delta_wire_len);
        assert!(w.total_payload() <= raw.len() as u64 + (hash::HASH_LEN + stream.len()) as u64);
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
        // Incompressible filler (not `[0xAA; 64]`/`[0xBB; 64]`, which
        // the §3.3 writer policy would shrink to a handful of
        // compressed bytes): this test's cap arithmetic below assumes
        // `blob_a.len()`/`blob_b.len()` ARE the on-wire sizes.
        let blob_a = write_blob_via_serialize(&incompressible_bytes(0xA5A5, 64));
        let blob_b = write_blob_via_serialize(&incompressible_bytes(0xB6B6, 64));
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
        // Incompressible filler: a repeated-byte 16 KiB payload would
        // trip the §3.3 writer policy into emitting `0x03` zstd-raw
        // instead of `0x00` raw, which genuinely DOES need an owned
        // decompression buffer — that's not what this test is about.
        let mut w = PackWriter::new();
        for i in 0u32..64 {
            let payload = incompressible_bytes(0x1000_0000 + u64::from(i), 16 * 1024);
            let blob = write_blob_via_serialize(&payload);
            w.push_raw(hash::hash(&blob), &blob).unwrap();
        }
        let pack = w.finish().unwrap();
        assert!(
            pack.len() > 512 * 1024,
            "sanity: synthetic pack should be substantial, got {}",
            pack.len()
        );
        assert_eq!(
            u32::from_le_bytes(pack[VERSION_OFFSET..VERSION_OFFSET + 4].try_into().unwrap()),
            VERSION,
            "sanity: incompressible filler must stay an uncompressed v1 pack"
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
        // too, and never the whole pack's. Incompressible base content,
        // same rationale as that test: a compressible base would
        // legitimately need an owned decompression buffer, which is
        // not what this test measures.
        let content_base = incompressible_bytes(0x2BAD_2BAD, 4096);
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
        // Incompressible filler (see the comment in
        // `unpack_does_not_recopy_raw_payloads_into_a_second_buffer`):
        // a repeated-byte payload would shrink dramatically under the
        // §3.3 writer policy, invalidating the `pack.len() > 512 KiB`
        // sanity check below, which has nothing to do with what this
        // test is proving.
        let mut w = PackWriter::new();
        for i in 0u32..64 {
            let payload = incompressible_bytes(0x2000_0000 + u64::from(i), 16 * 1024);
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

    // =====================================================================
    // SPEC-PACKFILE v2: zstd-compressed entries (issue #646)
    // =====================================================================

    /// Highly-compressible synthetic payload: `MIN_COMPRESS_LEN` (64) is
    /// the writer's floor, so use something well past it — a single
    /// repeated byte is the easiest thing for zstd to shrink hard.
    fn compressible_bytes(len: usize) -> Vec<u8> {
        vec![0x42u8; len]
    }

    #[test]
    #[cfg(feature = "pack-zstd")]
    fn compressed_raw_entry_roundtrips() {
        let payload = compressible_bytes(4096);
        let blob = write_blob_via_serialize(&payload);
        let h = hash::hash(&blob);

        let mut w = PackWriter::new();
        w.push_raw(h, &blob).unwrap();
        let pack = w.finish().unwrap();

        assert_eq!(
            u32::from_le_bytes(pack[VERSION_OFFSET..VERSION_OFFSET + 4].try_into().unwrap()),
            VERSION_V2,
            "a pack containing a compressed entry must be emitted as version 2"
        );
        assert_eq!(
            pack[HEADER_LEN], 0x03,
            "a highly-compressible raw payload must be emitted as 0x03 zstd-raw"
        );

        let (_dir, store) = fresh_store();
        let report = PackReader::read(&pack, &store).unwrap();
        assert_eq!(report.raw_count, 1);
        assert_eq!(report.delta_count, 0);
        assert_eq!(report.stored, vec![h]);
        assert_eq!(
            store.read(&h).unwrap(),
            blob,
            "recovered object must be byte-identical to the pre-compression original"
        );
    }

    #[test]
    #[cfg(feature = "pack-zstd")]
    fn compressed_delta_entry_roundtrips() {
        // Base and target share (almost) nothing, so `delta::encode`
        // emits a stream dominated by one big INSERT of the target's
        // highly-compressible content — long and repetitive enough for
        // the §3.3 writer policy to compress it into a 0x04 entry.
        let base_obj =
            write_blob_via_serialize(b"delta base filler bytes, not compressible-target-shaped");
        let base_hash = hash::hash(&base_obj);
        let target_content = compressible_bytes(4096);
        let target_obj = write_blob_via_serialize(&target_content);
        let target_hash = hash::hash(&target_obj);
        let stream = delta::encode(&base_obj, &target_obj).unwrap();
        assert!(
            stream.len() >= 64,
            "sanity: delta stream must clear the writer's compression-candidate floor, got {}",
            stream.len()
        );

        let mut w = PackWriter::new();
        w.push_raw(base_hash, &base_obj).unwrap();
        w.push_delta(&base_hash, &stream).unwrap();
        let pack = w.finish().unwrap();

        assert_eq!(
            u32::from_le_bytes(pack[VERSION_OFFSET..VERSION_OFFSET + 4].try_into().unwrap()),
            VERSION_V2,
            "a pack containing a compressed entry must be emitted as version 2"
        );
        // Walk past the first (raw base) entry's frame to find the
        // second entry's type byte.
        let base_payload_len =
            u32::from_le_bytes(pack[HEADER_LEN + 1..HEADER_LEN + 5].try_into().unwrap()) as usize;
        let second_entry_type_offset = HEADER_LEN + ENTRY_FRAME_LEN + base_payload_len;
        assert_eq!(
            pack[second_entry_type_offset], 0x04,
            "a highly-compressible delta stream must be emitted as 0x04 zstd-delta"
        );

        let (_dir, store) = fresh_store();
        let report = PackReader::read(&pack, &store).unwrap();
        assert_eq!(report.raw_count, 1);
        assert_eq!(report.delta_count, 1);
        assert_eq!(report.stored, vec![base_hash, target_hash]);
        assert_eq!(
            store.read(&target_hash).unwrap(),
            target_obj,
            "recovered delta target must be byte-identical to the pre-compression original"
        );
    }

    #[test]
    fn rejects_v2_entry_type_in_v1_pack() {
        // Hand-build a version-1-declared pack with one 0x03 entry —
        // even though 0x03's byte layout is otherwise well-formed, it
        // MUST be rejected because the header says version 1
        // (SPEC-PACKFILE §3).
        let mut buf = Vec::new();
        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&VERSION.to_le_bytes()); // version = 1
        buf.extend_from_slice(&1u32.to_le_bytes()); // entry_count = 1
        buf.push(0x03);
        let inner_payload = 0u32.to_le_bytes(); // uncompressed_len = 0, no frame bytes
        buf.extend_from_slice(&u32::try_from(inner_payload.len()).unwrap().to_le_bytes());
        buf.extend_from_slice(&inner_payload);
        let pack = finish_pack_body(buf);

        let (_dir, store) = fresh_store();
        let err = PackReader::read(&pack, &store).unwrap_err();
        assert!(
            matches!(err, PackError::InvalidEntryType(0x03)),
            "got {err:?}"
        );
    }

    #[test]
    #[cfg(feature = "pack-zstd")]
    fn rejects_decompressed_len_mismatch() {
        // Build a real compressed pack, then tamper the payload so the
        // claimed `uncompressed_len` no longer matches what the frame
        // actually decompresses to.
        let payload = compressible_bytes(4096);
        let blob = write_blob_via_serialize(&payload);
        let h = hash::hash(&blob);
        let mut w = PackWriter::new();
        w.push_raw(h, &blob).unwrap();
        let mut pack = w.finish().unwrap();

        assert_eq!(pack[HEADER_LEN], 0x03, "sanity: must be a zstd-raw entry");
        let len_prefix_offset = HEADER_LEN + ENTRY_FRAME_LEN;
        let claimed_len = u32::from_le_bytes(
            pack[len_prefix_offset..len_prefix_offset + 4]
                .try_into()
                .unwrap(),
        );
        // Lie about the length: claim one byte more than the frame
        // actually decompresses to. The trailer no longer matches the
        // tampered body, so recompute it (this test targets the
        // length-mismatch check specifically, not trailer verification,
        // which is already covered by `rejects_bit_flipped_trailer`).
        pack[len_prefix_offset..len_prefix_offset + 4]
            .copy_from_slice(&(claimed_len + 1).to_le_bytes());
        let split = pack.len() - TRAILER_LEN;
        let new_trailer = hash::hash(&pack[..split]);
        pack[split..].copy_from_slice(&new_trailer);

        let (_dir, store) = fresh_store();
        let err = PackReader::read(&pack, &store).unwrap_err();
        assert!(
            matches!(err, PackError::DecompressedSizeMismatch(_, _)),
            "got {err:?}"
        );
        assert!(!store.contains(&h));
    }

    #[test]
    #[cfg(feature = "pack-zstd")]
    fn rejects_decompressed_len_over_object_cap() {
        // A `0x03` entry claiming a decompressed size over
        // MAX_RAW_OBJECT_SIZE must be rejected before any decompression
        // is attempted — hand-build the entry rather than actually
        // producing a >1 GiB frame.
        let claimed_len = u32::try_from(MAX_RAW_OBJECT_SIZE + 1).unwrap();
        let mut buf = Vec::new();
        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&VERSION_V2.to_le_bytes());
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.push(0x03);
        // Payload: [4B claimed uncompressed_len][tiny bogus "frame"].
        // The over-cap check must fire before the (bogus) frame is
        // ever touched, so its content doesn't need to be valid zstd.
        let mut inner = Vec::new();
        inner.extend_from_slice(&claimed_len.to_le_bytes());
        inner.extend_from_slice(&[0u8; 8]);
        buf.extend_from_slice(&u32::try_from(inner.len()).unwrap().to_le_bytes());
        buf.extend_from_slice(&inner);
        let pack = finish_pack_body(buf);

        let (_dir, store) = fresh_store();
        let err = PackReader::read(&pack, &store).unwrap_err();
        assert!(
            matches!(err, PackError::DecompressedSizeOverCap(n) if n == claimed_len as usize),
            "got {err:?}"
        );
    }
}
