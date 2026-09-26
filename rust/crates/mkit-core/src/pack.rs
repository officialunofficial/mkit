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
//! / `DecompressedSizeOverCap`). The payload must be exactly one
//! Zstandard frame. The C decoder (`pack-zstd`) serves reads when it is
//! compiled in; otherwise the pure-Rust, decode-only `pack-ruzstd`
//! backend does, under the same checks; with neither, a compressed entry
//! fails closed.
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
//! decompression to evaluate. The "destination object store" is the
//! [`DeltaBaseSource`] the decoder is given: the local [`ObjectStore`]
//! for [`PackReader::read`], or a repository-scoped source for the
//! store-less [`decode_entries_with`].
//!
//! The pack key (SPEC-PACKFILE §7) is `packs/<lower-hex BLAKE3 of entire
//! pack>`. The trailer is then redundant w.r.t. that key, but it lets a
//! streaming reader detect bit-rot before the whole pack has been
//! hashed end-to-end.

pub mod rewrite;
use crate::delta;
use crate::hash::{self, Hash};
use crate::object::{MkitError, Object};
use crate::store::{MAX_RAW_OBJECT_SIZE, ObjectStore};
pub use rewrite::{Rewritten, rewrite_excluding};
use std::borrow::Cow;
use std::ops::Range;
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
    /// [`PackWriter::new_raw_only`] refuses delta entries (`push_delta` /
    /// `push_prepared_delta`). Compression is skipped rather than
    /// rejected on the raw path.
    #[error("pack writer is in raw-only mode and does not accept delta entries")]
    RawOnly,
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
    /// The object hash this entry was prepared for — lets a caller
    /// batching many entries (and a test asserting order-preservation
    /// across that batching) identify which input produced which
    /// prepared output without re-deriving it.
    #[must_use]
    pub fn hash(&self) -> Hash {
        self.hash
    }

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
    /// The delta base hash this entry was prepared against — see
    /// [`PreparedRaw::hash`].
    #[must_use]
    pub fn base(&self) -> Hash {
        self.base
    }

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
    // When true, `push_raw` never compresses, `push_delta` /
    // `push_prepared_delta` return [`PackError::RawOnly`], and `finish`
    // always emits a v1 pack of `0x00` entries. The closure profile
    // (SPEC-DISCLOSURE) is the consumer: a wasm verifier has no zstd.
    raw_only: bool,
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
            raw_only: false,
        }
    }

    /// A writer that never compresses and never accepts deltas.
    ///
    /// Every `push_raw` emits a `0x00` entry even when the `pack-zstd`
    /// feature is on and the payload is highly compressible.
    /// `push_delta` / `push_prepared_delta` return [`PackError::RawOnly`].
    /// [`Self::finish`] always emits a v1 pack. This is the closure
    /// profile's carrier (SPEC-DISCLOSURE): a wasm verifier is built
    /// without `pack-zstd` and can only consume raw v1 packs.
    #[must_use]
    pub fn new_raw_only() -> Self {
        let mut w = Self::new();
        w.raw_only = true;
        w
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
        let frame = if self.raw_only {
            None
        } else {
            maybe_compress(bytes)
        };
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
        let frame = if self.raw_only { None } else { entry.frame };
        self.append_raw_frame(entry.hash, &entry.bytes, frame)
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
        if self.raw_only {
            return Err(PackError::RawOnly);
        }
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
        if self.raw_only {
            return Err(PackError::RawOnly);
        }
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
    maybe_compress_capped(data, MAX_RAW_OBJECT_SIZE)
}

#[cfg(feature = "pack-zstd")]
fn maybe_compress_capped(data: &[u8], max_len: usize) -> Option<Vec<u8>> {
    // SPEC-PACKFILE §3.3: a reader rejects any `uncompressed_len` over
    // MAX_RAW_OBJECT_SIZE, so a larger payload is written uncompressed.
    if data.len() > max_len {
        return None;
    }
    if data.len() < MIN_COMPRESS_LEN {
        return None;
    }
    let compressed = ZSTD_COMPRESSOR
        .with(|c| c.borrow_mut().compress(data))
        .ok()?;
    if ZSTD_LEN_PREFIX + compressed.len() < data.len() {
        Some(compressed)
    } else {
        None
    }
}

#[cfg(feature = "pack-zstd")]
thread_local! {
    // Per-thread reused `zstd::bulk::Compressor`, keyed off the same
    // `ZSTD_LEVEL` every call in this build uses. `zstd::bulk::compress`
    // (the plain free function) allocates and initializes a fresh
    // `Compressor` — and its underlying `CCtx` — on every single call; on
    // the push-path's per-entry compression fan-out
    // (`build_and_upload_packs`'s rayon fan-out over
    // `prepare_raw`/`prepare_delta`, `pack_build_fanout`) that means one
    // CCtx alloc/init per object compressed. A one-shot
    // `Compressor::compress` call carries no state across calls (it is
    // not a streaming encoder), so reusing the same context across every
    // object a given thread compresses is behavior-preserving — same
    // level, same output bytes — and turns that per-object setup cost
    // into a one-time cost per worker thread.
    static ZSTD_COMPRESSOR: std::cell::RefCell<zstd::bulk::Compressor<'static>> =
        std::cell::RefCell::new(
            zstd::bulk::Compressor::new(ZSTD_LEVEL).expect("ZSTD_LEVEL is a valid zstd level"),
        );
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
    decompress_zstd_entry_with(payload, zstd_decompress_capped)
}

/// [`decompress_zstd_entry`] over an explicit backend, so the
/// differential tests can drive the C and pure-Rust decoders through the
/// exact same claim / length checks.
fn decompress_zstd_entry_with(
    payload: &[u8],
    backend: fn(&[u8], usize) -> Result<Vec<u8>, PackError>,
) -> Result<Vec<u8>, PackError> {
    if payload.len() < ZSTD_LEN_PREFIX {
        return Err(PackError::ZstdEntryTruncated);
    }
    let uncompressed_len =
        u32::from_le_bytes(payload[..ZSTD_LEN_PREFIX].try_into().expect("4 bytes")) as usize;
    if uncompressed_len > MAX_RAW_OBJECT_SIZE {
        return Err(PackError::DecompressedSizeOverCap(uncompressed_len));
    }
    let frame = &payload[ZSTD_LEN_PREFIX..];
    let decompressed = backend(frame, uncompressed_len)?;
    if decompressed.len() != uncompressed_len {
        return Err(PackError::DecompressedSizeMismatch(
            uncompressed_len,
            decompressed.len(),
        ));
    }
    Ok(decompressed)
}

/// RFC 8878 §3.1.1 Zstandard frame magic number, as it appears on the
/// wire (`0xFD2FB528` little-endian). SPEC-PACKFILE §3.3 allows exactly
/// one such frame per entry: a skippable frame (`0x184D2A5?`) or a
/// legacy pre-RFC frame magic is rejected by both backends.
#[cfg(any(feature = "pack-zstd", feature = "pack-ruzstd"))]
const ZSTD_FRAME_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

/// Both backends' first check: the payload must open with the one
/// Zstandard frame magic SPEC-PACKFILE §3.3 permits.
#[cfg(any(feature = "pack-zstd", feature = "pack-ruzstd"))]
fn require_zstd_frame_magic(frame: &[u8]) -> Result<(), PackError> {
    if frame.starts_with(&ZSTD_FRAME_MAGIC) {
        Ok(())
    } else {
        Err(PackError::ZstdDecompress(
            "entry payload does not start with a Zstandard frame magic \
             (skippable and legacy frames are not allowed)"
                .to_string(),
        ))
    }
}

/// Decompress `frame` — exactly one Zstandard frame, nothing before or
/// after it — bounding the allocation to `capacity` bytes (already
/// checked against [`MAX_RAW_OBJECT_SIZE`] by the caller) so a corrupt
/// or hostile frame can't force an over-large allocation. The C decoder
/// (`pack-zstd`) is selected whenever it is compiled in.
#[cfg(feature = "pack-zstd")]
fn zstd_decompress_capped(frame: &[u8], capacity: usize) -> Result<Vec<u8>, PackError> {
    require_zstd_frame_magic(frame)?;
    // `ZSTD_decompressDCtx` (behind `bulk::decompress`) would otherwise
    // decode concatenated frames and skip skippable ones.
    match zstd::zstd_safe::find_frame_compressed_size(frame) {
        Ok(n) if n == frame.len() => {}
        Ok(n) => {
            return Err(PackError::ZstdDecompress(format!(
                "{} byte(s) after the entry's single zstd frame",
                frame.len() - n
            )));
        }
        Err(code) => {
            return Err(PackError::ZstdDecompress(
                zstd::zstd_safe::get_error_name(code).to_string(),
            ));
        }
    }
    zstd::bulk::decompress(frame, capacity).map_err(|e| PackError::ZstdDecompress(e.to_string()))
}

/// Without the C library, the pure-Rust decoder serves every read.
#[cfg(all(not(feature = "pack-zstd"), feature = "pack-ruzstd"))]
fn zstd_decompress_capped(frame: &[u8], capacity: usize) -> Result<Vec<u8>, PackError> {
    ruzstd_decompress_capped(frame, capacity)
}

#[cfg(not(any(feature = "pack-zstd", feature = "pack-ruzstd")))]
fn zstd_decompress_capped(_frame: &[u8], _capacity: usize) -> Result<Vec<u8>, PackError> {
    Err(PackError::ZstdDecompress(
        "this build was compiled without the `pack-zstd` or `pack-ruzstd` feature".to_string(),
    ))
}

/// Smallest window the pure-Rust decoder accepts regardless of the
/// claim: 8 MiB (`windowLog` 23) covers every non-ultra zstd level's
/// default window, so a frame written by a streaming encoder with no
/// pledged size still decodes. Frames declaring a window above
/// `max(claim, this)` are rejected (fail-closed; the C one-shot decoder
/// would accept them). Bounding the window bounds the decoder's own
/// buffer: it keeps up to one window of not-yet-emitted output (see
/// [`ruzstd_decompress_capped`] for the overall peak, about 3× the claim).
#[cfg(feature = "pack-ruzstd")]
#[cfg_attr(all(feature = "pack-zstd", not(test)), allow(dead_code))]
const RUZSTD_MIN_WINDOW_LIMIT: u64 = 8 << 20;

/// Pure-Rust (`ruzstd`) decode of exactly one Zstandard frame, bounded
/// to `capacity` output bytes. Compiled whenever `pack-ruzstd` is on,
/// including alongside `pack-zstd`, so the differential tests can run
/// both backends over the same inputs.
///
/// Matches the C path's accept/reject decisions and error variants:
/// a declared frame content size must not exceed `capacity` and must
/// equal the decoded length; output past `capacity` is an error, not a
/// short read; a content checksum, when present, must match; nothing
/// may follow the frame. At most `capacity + 1` bytes are ever read out.
///
/// Memory: `capacity` is attacker-chosen (up to 1 GiB) and is not
/// pre-allocated; the output grows with the decoded bytes, so a frame
/// that stops short costs only what it produced. A frame that really
/// decodes to the claim peaks at about **3× the claim**, against about 1×
/// on the C path: ruzstd's ring buffer rounds its capacity up to a power
/// of two and holds up to one window (the whole frame, for single-segment
/// frames) of not-yet-emitted output, while `read_to_end` grows the output
/// `Vec` by doubling. Measured: a 16 KiB RLE payload claiming 512 MiB
/// reaches about 1.55 GiB RSS (C: about 0.54 GiB). Pre-sizing the output
/// to the claim would cut the doubling but allocate the full claim for
/// frames that never deliver it, so it is not done; a caller-set
/// decoded-size budget is WP-4.8a's.
///
/// With `pack-zstd` also on, only the differential tests call it.
#[cfg(feature = "pack-ruzstd")]
#[cfg_attr(all(feature = "pack-zstd", not(test)), allow(dead_code))]
pub(crate) fn ruzstd_decompress_capped(
    frame: &[u8],
    capacity: usize,
) -> Result<Vec<u8>, PackError> {
    use ruzstd::decoding::{FrameDecoder, StreamingDecoder};
    use std::io::Read as _;

    fn fail(msg: impl std::fmt::Display) -> PackError {
        PackError::ZstdDecompress(msg.to_string())
    }

    require_zstd_frame_magic(frame)?;
    let cap = u64::try_from(capacity).unwrap_or(u64::MAX);
    let mut decoder = FrameDecoder::new();
    decoder.set_max_window_size(cap.max(RUZSTD_MIN_WINDOW_LIMIT));
    let mut src = frame;
    let mut stream = StreamingDecoder::new_with_decoder(&mut src, decoder).map_err(fail)?;

    // RFC 8878 §3.1.1.1.1. The header parsed, so the descriptor byte
    // after the magic exists. ruzstd ignores the reserved bit, which a
    // decoder must refuse (the C decoder does).
    let descriptor = frame[ZSTD_FRAME_MAGIC.len()];
    if descriptor & 0x08 != 0 {
        return Err(fail("zstd frame descriptor has its reserved bit set"));
    }
    // A content size is present iff the FCS flag or the single-segment
    // flag is set.
    let declared =
        (descriptor >> 6 != 0 || descriptor & 0x20 != 0).then(|| stream.decoder.content_size());
    if let Some(n) = declared
        && n > cap
    {
        return Err(fail(format_args!(
            "frame content size {n} exceeds the claimed {capacity} bytes"
        )));
    }

    let mut out = Vec::new();
    (&mut stream)
        .take(cap.saturating_add(1))
        .read_to_end(&mut out)
        .map_err(fail)?;
    if out.len() > capacity {
        return Err(fail(format_args!(
            "zstd frame decompresses past the claimed {capacity} bytes"
        )));
    }
    let decoder = &stream.decoder;
    if !decoder.is_finished() {
        return Err(fail("zstd frame ended before its last block"));
    }
    // RFC 8878 §3.1.1.2.4: no block may decode to more than
    // `min(Window_Size, 128 KiB)`. ruzstd does not check it; the C
    // decoder does for compressed blocks. Per-block sizes are not
    // observable here, so a windowed frame whose window is under 128 KiB
    // may not decode past its window at all (fail-closed for raw-block
    // and multi-block tiny-window frames, which no default encoder
    // setting produces).
    if descriptor & 0x20 == 0 {
        let window_descriptor = frame[ZSTD_FRAME_MAGIC.len() + 1];
        let base = 1u64 << (10 + (window_descriptor >> 3));
        let window = base + (base >> 3) * u64::from(window_descriptor & 7);
        if window < 128 * 1024 && out.len() as u64 > window {
            return Err(fail(format_args!(
                "zstd frame decodes {} bytes through a {window}-byte window",
                out.len()
            )));
        }
    }
    if let Some(n) = declared
        && n != out.len() as u64
    {
        return Err(fail(format_args!(
            "frame content size {n} does not match the {} decoded bytes",
            out.len()
        )));
    }
    if let Some(stored) = decoder.get_checksum_from_data()
        && decoder.get_calculated_checksum() != Some(stored)
    {
        return Err(fail("zstd frame content checksum mismatch"));
    }
    drop(stream);
    if !src.is_empty() {
        return Err(fail(format_args!(
            "{} byte(s) after the entry's single zstd frame",
            src.len()
        )));
    }
    ruzstd_check_reserved_fields(frame).map_err(fail)?;
    Ok(out)
}

/// Re-walk an already-decoded frame's blocks (RFC 8878 §3.1.1.2–3) for
/// the reserved fields ruzstd ignores and the C decoder rejects: the
/// sequences section's `Symbol_Compression_Modes` reserved bits. Without
/// this, a frame the C path refuses would decode here — a fail-open
/// divergence between the native and Workers readers.
#[cfg(feature = "pack-ruzstd")]
#[cfg_attr(all(feature = "pack-zstd", not(test)), allow(dead_code))]
fn ruzstd_check_reserved_fields(frame: &[u8]) -> Result<(), &'static str> {
    const MALFORMED: &str = "malformed zstd frame";
    let byte = |i: usize| frame.get(i).copied().ok_or(MALFORMED);
    let descriptor = byte(ZSTD_FRAME_MAGIC.len())?;
    let single_segment = descriptor & 0x20 != 0;
    let fcs_len = match descriptor >> 6 {
        0 => usize::from(single_segment),
        1 => 2,
        2 => 4,
        _ => 8,
    };
    let mut pos = ZSTD_FRAME_MAGIC.len()
        + 1
        + usize::from(!single_segment)
        + [0, 1, 2, 4][usize::from(descriptor & 3)]
        + fcs_len;
    loop {
        let header = u32::from_le_bytes([byte(pos)?, byte(pos + 1)?, byte(pos + 2)?, 0]);
        pos += 3;
        let size = (header >> 3) as usize;
        let body_len = match (header >> 1) & 3 {
            1 => 1, // RLE: one byte, repeated `size` times
            _ => size,
        };
        let body = frame.get(pos..pos + body_len).ok_or(MALFORMED)?;
        if (header >> 1) & 3 == 2 && ruzstd_sequence_modes(body)? & 3 != 0 {
            return Err("zstd sequences section has its reserved mode bits set");
        }
        pos += body_len;
        if header & 1 == 1 {
            return Ok(());
        }
    }
}

/// The `Symbol_Compression_Modes` byte of a compressed block, or `0` when
/// the block has no sequences (RFC 8878 §3.1.1.3.1.1, §3.1.1.3.2.1).
#[cfg(feature = "pack-ruzstd")]
#[cfg_attr(all(feature = "pack-zstd", not(test)), allow(dead_code))]
fn ruzstd_sequence_modes(block: &[u8]) -> Result<u8, &'static str> {
    const MALFORMED: &str = "malformed zstd block";
    // Header fields are assembled in `u64`, never `usize`: the 5-byte
    // literals header spans 40 bits, which overflows a 32-bit `usize`
    // (wasm32) and silently drops the compressed size's top bits.
    let byte = |i: usize| block.get(i).copied().ok_or(MALFORMED).map(u64::from);
    let b0 = byte(0)?;
    // Literals section: header, then its content.
    let (header_len, content_len) = match (b0 & 3, (b0 >> 2) & 3) {
        // Raw / RLE literals: 5-, 12- or 20-bit regenerated size.
        (kind @ (0 | 1), format) => {
            let (len, regen) = match format {
                0 | 2 => (1, b0 >> 3),
                1 => (2, (b0 >> 4) | (byte(1)? << 4)),
                _ => (3, (b0 >> 4) | (byte(1)? << 4) | (byte(2)? << 12)),
            };
            (len, if kind == 0 { regen } else { 1 })
        }
        // Compressed / treeless literals: 10-, 14- or 18-bit sizes.
        (_, format) => {
            let (len, bits) = match format {
                0 | 1 => (3, 10),
                2 => (4, 14),
                _ => (5, 18),
            };
            let mut h = 0u64;
            for i in (0..len).rev() {
                h = (h << 8) | byte(i)?;
            }
            (len, (h >> (4 + bits)) & ((1 << bits) - 1))
        }
    };
    // At most 20 bits, so it fits any `usize`.
    let content_len = usize::try_from(content_len).map_err(|_| MALFORMED)?;
    let seq = header_len + content_len;
    let modes_at = match byte(seq)? {
        0 => return Ok(0),
        n if n < 128 => seq + 1,
        255 => seq + 3,
        _ => seq + 2,
    };
    block.get(modes_at).copied().ok_or(MALFORMED)
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
        // `payload_len > split - pos`, not `pos + payload_len > split`: the
        // sum overflows a 32-bit `usize` (wasm32) for `payload_len` near
        // `u32::MAX`. The frame check above keeps `pos <= split`.
        if payload_len > split - pos {
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
        // One frame parser: [`PackEntries`] owns header/trailer/cap/type
        // validation and decompression.
        let pack_entries = PackEntries::new_with_payload_cap(pack_bytes, payload_cap)?;

        // Track entries resolved in *this* pack so delta entries can
        // resolve their base from memory before falling back to the
        // on-disk store: `WriteBatch::write_prehashed` stages bytes
        // durably-pending but NOT visible until `commit()`, so a
        // not-yet-committed entry can only be found here, never via
        // `store`.
        let mut in_pack: std::collections::HashMap<Hash, Cow<'_, [u8]>> =
            std::collections::HashMap::new();

        let batch = store.batch();
        // The destination store is this reader's external delta-base
        // source (SPEC-PACKFILE §3.2). Monomorphic: `&ObjectStore`'s
        // `DeltaBaseSource` impl is the same `contains` + `read` pair as
        // before the seam existed, so this path pays no dispatch cost.
        let mut bases = store;

        // Phase 1 (sequential, cheap relative to phase 2): drain
        // `PackEntries` — already validated and decompressed — into one
        // `Vec<Entry>` indexed by pack position. `PackEntries::new`
        // already ran the framing/cap/type validation before yielding
        // anything, so a malformed pack fails via the `?` above before
        // any staging; a mid-stream error from `.next()` (re-running
        // that same per-entry validation, since the iterator has to
        // stay store-less/reusable — see `PackEntries`'s doc) surfaces
        // here, equally before any staging.
        let mut entries: Vec<Entry<'_>> = Vec::with_capacity(pack_entries.entry_count());
        for entry in pack_entries {
            entries.push(match entry? {
                PackEntry::Raw { bytes } => Entry::Raw(bytes),
                PackEntry::Delta { base, stream } => Entry::Delta { base, stream },
            });
        }

        // Phase 2: raw entries. Validate and hash each one — independent
        // per entry, so on a native build with enough of them this fans
        // out across a scoped thread pool instead of running one at a
        // time on the calling thread (see `stage_raw_entries`). This is
        // the read-side counterpart of `PackWriter::prepare_raw`/
        // `push_prepared_raw` on the write side. Staging into `batch`
        // also happens here (concurrently — `write_prehashed` is safe
        // for that), but staging into `in_pack` is deferred to phase 3
        // below: SPEC-PACKFILE §4 requires a delta's base to appear
        // *earlier in the pack*, so a raw entry must only become
        // visible to delta resolution once phase 3's scan actually
        // reaches its pack position, not the instant phase 2 happens to
        // finish computing it.
        //
        // Each raw entry's *own* validation is independent of every
        // other entry, so phase 2 always runs it for the whole pack
        // regardless of position — but a malformed raw entry at
        // position 5 must not be reported ahead of, say, a delta at
        // position 0 with a missing base: the old single-loop reader
        // would have hit position 0 first and never looked at position
        // 5 at all. `stage_raw_entries` never fails the whole batch on
        // the first bad one — it returns every raw entry's own outcome,
        // success or failure, in the same relative order `raw_frames`
        // lists them in (both its sequential and parallel branch
        // preserve that order — see its doc) — so phase 3 below only
        // *reports* a raw entry's problem once its sequential scan
        // actually reaches that entry, exactly like the old reader.
        let raw_frames: Vec<&[u8]> = entries
            .iter()
            .filter_map(|e| match e {
                Entry::Raw(payload) => Some(payload.as_ref()),
                Entry::Delta { .. } => None,
            })
            .collect();
        let mut raw_results = stage_raw_entries(&batch, &raw_frames).into_iter();

        // Phase 3 (sequential, single pass over `entries` in original
        // pack order): replay every position exactly as the old
        // single-loop reader did. A raw entry reports its
        // phase-2-computed result (the CPU-heavy work is already done;
        // this is just bookkeeping, and an `Err` surfaces here — at
        // this position — instead of back in phase 2) and, on success,
        // stages it into `in_pack`; a delta entry resolves its base
        // from `in_pack`/`store` and stages the decoded target — so a
        // delta can only ever see raw entries at strictly earlier
        // positions, preserving the base-before-delta ordering rule.
        let mut report = UnpackReport::default();
        for entry in entries {
            match entry {
                Entry::Raw(payload) => {
                    let stored_hash = raw_results
                        .next()
                        .expect("every Entry::Raw has a phase-2 result")?;
                    if let (Cow::Owned(_), Some(c)) = (&payload, owned_bytes) {
                        c.fetch_add(payload.len() as u64, Ordering::Relaxed);
                    }
                    in_pack.insert(stored_hash, payload);
                    report.raw_count += 1;
                    report.stored.push(stored_hash);
                }
                Entry::Delta { base, stream } => {
                    let stored_hash = stage_delta_target(
                        &mut bases,
                        &batch,
                        &mut in_pack,
                        owned_bytes,
                        base,
                        stream.as_ref(),
                    )?;
                    report.delta_count += 1;
                    report.stored.push(stored_hash);
                }
            }
        }

        // Batched durability: one full flush for the whole pack instead
        // of one per object. The caller's ref update happens after
        // `read` returns, so the commit-before-reference ordering holds.
        batch.commit()?;

        Ok(report)
    }
}

/// Where a delta's *external* base — one that is not an earlier entry
/// of the same pack — may come from.
///
/// SPEC-PACKFILE §3.2's "destination object store" is the implementor:
/// the local [`ObjectStore`] on a client, and on a server the pushing
/// repository's own membership. A server MUST NOT back this with a
/// global content store or another repository's objects: whether a
/// delta resolves would then reveal that some other repository holds
/// the base (PRD §6.5 repository isolation, no existence oracles).
///
/// The seam is generic, never `dyn`: [`PackReader::read`] instantiates
/// it with `&ObjectStore` so the hot unpack path stays monomorphic.
pub trait DeltaBaseSource {
    /// Whether [`Self::base`] returns bytes already verified to be the
    /// object named by the requested id (the store's `read` verifies).
    ///
    /// When `false` (the default), the decoder deserializes the bytes
    /// and re-derives the id itself; anything that is not a storable
    /// canonical object with exactly the requested id is treated as
    /// absent ([`PackError::DeltaBaseMissing`]), so an untrusted source
    /// can never smuggle a different object in as a base. Set it to
    /// `true` only when `base` itself guarantees that identity, as
    /// `ObjectStore::read` does; the decoder then skips the re-derive.
    const VERIFIED: bool = false;

    /// Canonical object bytes for `id`, or `None` when this source may
    /// not provide it. "Not permitted" and "does not exist" MUST both
    /// be `None`: the decoder reports them identically, by design.
    ///
    /// # Errors
    ///
    /// A source failure (I/O, backend error) that is not an answer
    /// about `id`. It aborts the decode.
    fn base(&mut self, id: &Hash) -> Result<Option<Vec<u8>>, PackError>;
}

/// A [`DeltaBaseSource`] with no external bases: a pack must be
/// self-contained (every delta's base an earlier entry). Used for
/// closure-profile packs, pack rewrites and tests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoExternalBases;

impl DeltaBaseSource for NoExternalBases {
    fn base(&mut self, _id: &Hash) -> Result<Option<Vec<u8>>, PackError> {
        Ok(None)
    }
}

impl DeltaBaseSource for &ObjectStore {
    /// `ObjectStore::read` BLAKE3/BMT-verifies the bytes against `id`
    /// and fails with `HashMismatch` otherwise.
    const VERIFIED: bool = true;

    fn base(&mut self, id: &Hash) -> Result<Option<Vec<u8>>, PackError> {
        if self.contains(id) {
            Ok(Some(self.read(id)?))
        } else {
            Ok(None)
        }
    }
}

/// One entry handed to [`decode_entries_with`]'s sink, in pack order.
#[derive(Debug)]
#[non_exhaustive]
pub struct DecodedEntry<'a> {
    /// The entry's object id, re-derived from `bytes` (BLAKE3, or the
    /// BMT root for `Tree`/`ChunkedBlob`).
    pub id: Hash,
    /// Canonical object bytes: the raw payload (decompressed for
    /// `0x03`), or the reconstructed delta target.
    pub bytes: &'a [u8],
    /// `bytes` decoded, so the consumer need not deserialize again.
    pub object: Object,
    /// `true` for a `0x02`/`0x04` delta target, `false` for a raw entry.
    pub from_delta: bool,
}

/// Summary of a successful [`decode_entries_with`] call.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DecodeReport {
    /// Raw (`0x00`/`0x03`) entries decoded.
    pub raw_count: usize,
    /// Delta (`0x02`/`0x04`) entries reconstructed.
    pub delta_count: usize,
    /// Every entry's id, in pack order (a repeated entry repeats here,
    /// as in [`UnpackReport::stored`]).
    pub ids: Vec<Hash>,
}

/// Resource limits for [`decode_entries_with`].
///
/// A pack's wire size says little about what decoding it allocates: a
/// `0x03`/`0x04` entry may claim up to [`MAX_RAW_OBJECT_SIZE`] bytes from a
/// few-byte zstd frame, a delta may declare a result of the same size
/// from a short run of copies, and a tiny delta may name a huge external
/// base. A decoder that held all of that until the pack ends would let a
/// sub-kilobyte pack pin gigabytes. [`decode_entries_with`] therefore
/// charges every such allocation against [`Self::max_decoded_bytes`] and
/// rejects the pack with [`PackError::PackfileTooLarge`] once the total
/// passes it.
///
/// The budget is **per call**. It bounds one decode, not a process: a
/// server running several decodes at once (WP-4.7) must size it from its
/// isolate's memory limit divided by its decode concurrency. The default,
/// [`Self::DEFAULT_MAX_DECODED_BYTES`] (1 GiB), equals the largest object
/// the format allows ([`MAX_RAW_OBJECT_SIZE`]) so that any single valid
/// object decodes; it is not sized for a constrained isolate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct DecodeLimits {
    /// Cap on the bytes one decode may hold beyond the pack itself: every
    /// `0x03`/`0x04` entry's claimed `uncompressed_len`, every delta's
    /// declared result length, and every external base fetched from the
    /// [`DeltaBaseSource`] while it is cached. `0x00` payloads are borrowed
    /// from the pack and do not count. An external base is measured once
    /// fetched, so the peak can pass the cap by the one base whose fetch
    /// trips it.
    pub max_decoded_bytes: u64,
}

impl DecodeLimits {
    /// Default [`Self::max_decoded_bytes`]: 1 GiB, the maximum object size
    /// ([`MAX_RAW_OBJECT_SIZE`]). Servers set their own (see the type docs).
    pub const DEFAULT_MAX_DECODED_BYTES: u64 = MAX_RAW_OBJECT_SIZE as u64;

    /// These limits with [`Self::max_decoded_bytes`] set to `bytes`.
    #[must_use]
    pub const fn with_max_decoded_bytes(mut self, bytes: u64) -> Self {
        self.max_decoded_bytes = bytes;
        self
    }
}

impl Default for DecodeLimits {
    fn default() -> Self {
        Self {
            max_decoded_bytes: Self::DEFAULT_MAX_DECODED_BYTES,
        }
    }
}

/// Running total of a decode's claimed allocations against
/// [`DecodeLimits::max_decoded_bytes`].
struct DecodeBudget {
    used: u64,
    max: u64,
}

impl DecodeBudget {
    fn charge(&mut self, bytes: u64) -> Result<(), PackError> {
        self.used = self.used.saturating_add(bytes);
        if self.used > self.max {
            return Err(PackError::PackfileTooLarge);
        }
        Ok(())
    }
}

/// The decode path's [`DeltaBaseSource`]: forwards to the caller's source
/// and charges each base it returns against the decode budget, remembering
/// the charge so [`Self::release`] can credit it back once no later delta
/// needs that base. [`PackReader::read`] never uses this.
struct ChargedBases<'b, B> {
    inner: &'b mut B,
    budget: DecodeBudget,
    charged: std::collections::HashMap<Hash, u64>,
}

impl<B: DeltaBaseSource> DeltaBaseSource for ChargedBases<'_, B> {
    const VERIFIED: bool = B::VERIFIED;

    fn base(&mut self, id: &Hash) -> Result<Option<Vec<u8>>, PackError> {
        let Some(bytes) = self.inner.base(id)? else {
            return Ok(None);
        };
        let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        self.budget.charge(len)?;
        let held = self.charged.entry(*id).or_default();
        *held = held.saturating_add(len);
        Ok(Some(bytes))
    }
}

impl<B> ChargedBases<'_, B> {
    /// Credit back the charge for external base `id`, if it had one.
    fn release(&mut self, id: &Hash) {
        if let Some(len) = self.charged.remove(id) {
            self.budget.used = self.budget.used.saturating_sub(len);
        }
    }
}

/// Little-endian `u32` at `at` in `bytes`, if all four bytes are there.
fn le_u32_at(bytes: &[u8], at: usize) -> Option<u64> {
    let field: [u8; 4] = bytes.get(at..at.checked_add(4)?)?.try_into().ok()?;
    Some(u64::from(u32::from_le_bytes(field)))
}

/// Charge every `0x03`/`0x04` entry's claimed decompressed size, reading
/// only its uncompressed-length prefix. Runs after [`PackEntries::new`]
/// has validated the framing (every frame lies inside the body, which is
/// why the bounds here can only fall short on a malformed pack) and
/// before anything is decompressed. A payload too short to carry its
/// prefix is left for the drain to reject.
fn charge_compressed_claims(pack: &[u8], budget: &mut DecodeBudget) -> Result<(), PackError> {
    let split = pack.len() - TRAILER_LEN;
    let mut pos = HEADER_LEN;
    while pos < split {
        let etype = pack[pos];
        let payload_len = le_u32_at(pack, pos + 1)
            .and_then(|len| usize::try_from(len).ok())
            .ok_or(PackError::UnexpectedEof)?;
        let start = pos + ENTRY_FRAME_LEN;
        if payload_len > split.saturating_sub(start) {
            return Err(PackError::UnexpectedEof);
        }
        let payload = &pack[start..start + payload_len];
        let claim = match etype {
            0x03 => le_u32_at(payload, 0),
            0x04 => le_u32_at(payload, hash::HASH_LEN),
            _ => None,
        };
        if let Some(claim) = claim {
            budget.charge(claim)?;
        }
        pos = start + payload_len;
    }
    Ok(())
}

/// Store-less decode of `pack` over an explicit [`DeltaBaseSource`].
///
/// Validates the pack exactly as [`PackReader::read`] does — header,
/// trailer, caps and framing via [`PackEntries`], every entry drained
/// (and `0x03`/`0x04` decompressed) before any entry is judged — then,
/// in pack order, validates each raw payload as a storable canonical
/// object, resolves each delta against an earlier entry or else
/// `bases`, validates the reconstructed target, and hands every entry to
/// `sink`. Given `&ObjectStore` as `bases`, and limits the pack fits in,
/// it accepts and rejects exactly the packs `PackReader::read` does
/// against that store, with the same errors in the same order, but
/// writes nothing.
///
/// Memory is bounded by `limits` (see [`DecodeLimits`]): every
/// compressed entry's claimed size is charged before anything is
/// decompressed, every delta's declared result length before any delta
/// is applied, and every external base as it is fetched. An entry or an
/// external base stays resident only until the last delta that names it
/// as its base; an external base's charge is then credited back.
///
/// External bases are fetched only for a delta whose base is not an
/// earlier entry, at most once per distinct base while it is needed, and
/// never recursively: a base is a canonical object, never a pack-only
/// delta.
///
/// # Errors
///
/// [`PackError::PackfileTooLarge`] when the decoded size passes
/// `limits.max_decoded_bytes`: claims are checked ahead of every
/// per-entry error except framing, an external base when the delta that
/// names it is reached. Otherwise the first [`PackError`] in pack order,
/// or the first error `sink` returns. `sink` may already have seen earlier
/// entries when an error is returned; a consumer staging them must
/// discard that staging.
pub fn decode_entries_with<B: DeltaBaseSource>(
    pack: &[u8],
    bases: &mut B,
    limits: DecodeLimits,
    mut sink: impl FnMut(DecodedEntry<'_>) -> Result<(), PackError>,
) -> Result<DecodeReport, PackError> {
    let pack_entries = PackEntries::new(pack)?;
    let mut budget = DecodeBudget {
        used: 0,
        max: limits.max_decoded_bytes,
    };
    charge_compressed_claims(pack, &mut budget)?;

    let mut entries: Vec<PackEntry<'_>> = Vec::with_capacity(pack_entries.entry_count());
    for entry in pack_entries {
        entries.push(entry?);
    }

    // Charge every delta's declared result length before applying any
    // (a stream too short for its header fails at apply time), and count
    // how many deltas name each base: an entry stays resident only while
    // a later delta still needs it.
    let mut uses: std::collections::HashMap<Hash, usize> = std::collections::HashMap::new();
    for entry in &entries {
        if let PackEntry::Delta { base, stream } = entry {
            if let Some(result_len) = le_u32_at(stream, 5) {
                budget.charge(result_len)?;
            }
            let n = uses.entry(*base).or_default();
            *n = n.saturating_add(1);
        }
    }

    let mut bases = ChargedBases {
        inner: bases,
        budget,
        charged: std::collections::HashMap::new(),
    };
    let mut in_pack: std::collections::HashMap<Hash, Cow<'_, [u8]>> =
        std::collections::HashMap::new();
    let mut report = DecodeReport {
        ids: Vec::with_capacity(entries.len()),
        ..DecodeReport::default()
    };
    for entry in entries {
        match entry {
            PackEntry::Raw { bytes } => {
                let object = validate_storable_object(&bytes)?;
                let id = crate::object::id_from_object(&object, &bytes);
                sink(DecodedEntry {
                    id,
                    bytes: bytes.as_ref(),
                    object,
                    from_delta: false,
                })?;
                if uses.contains_key(&id) {
                    in_pack.insert(id, bytes);
                }
                report.raw_count += 1;
                report.ids.push(id);
            }
            PackEntry::Delta { base, stream } => {
                let resolved =
                    resolve_delta_target(&mut bases, &mut in_pack, base, stream.as_ref())?;
                drop(stream);
                // This delta was one of `base`'s uses. After the last one
                // the base is dropped and, if external, its charge credited.
                if let Some(left) = uses.get_mut(&base) {
                    *left = left.saturating_sub(1);
                    if *left == 0 {
                        uses.remove(&base);
                        in_pack.remove(&base);
                        bases.release(&base);
                    }
                }
                let object = validate_storable_object(&resolved)?;
                let id = crate::object::id_from_object(&object, &resolved);
                sink(DecodedEntry {
                    id,
                    bytes: &resolved,
                    object,
                    from_delta: true,
                })?;
                if uses.contains_key(&id) {
                    in_pack.insert(id, Cow::Owned(resolved));
                }
                report.delta_count += 1;
                report.ids.push(id);
            }
        }
    }
    Ok(report)
}

/// One packfile entry, tracked through [`PackReader::read_inner`]'s
/// three phases in the original pack order they were parsed in
/// (`PackEntries` already validated framing/types and decompressed
/// `0x03`/`0x04`, so there is nothing left to classify here beyond raw
/// vs. delta). Phase 2 (see [`stage_raw_entries`]) computes each
/// `Raw` entry's result — success or failure — into a queue
/// (`raw_results` in `read_inner`) consumed in the same relative order
/// this vec's `Raw` entries appear in, so there is nothing that can
/// fall out of sync between the two.
enum Entry<'p> {
    Raw(Cow<'p, [u8]>),
    Delta { base: Hash, stream: Cow<'p, [u8]> },
}

/// Per-raw-entry results returned by
/// [`stage_raw_entries`]/[`stage_raw_entries_parallel`], in the same
/// relative order `frames` listed them in. A per-entry `Err` is data,
/// not a reason to stop early: see [`stage_raw_entries`]'s doc for why
/// the whole batch always runs to completion.
type RawStageResults = Vec<Result<Hash, PackError>>;

/// Validate and hash every raw entry in `frames` — already decompressed
/// by [`PackEntries`] — staging each one into `batch` as it's hashed.
/// Independent per entry (`WriteBatch::write_prehashed` is documented
/// safe to call concurrently — see its doc comment, which was written
/// anticipating exactly this), so below a small-pack threshold this
/// runs a plain sequential loop, and at or above it (native builds
/// only — wasm32 has no threads) fans the work out across a scoped
/// thread pool sized to the machine. This is the read-side counterpart
/// of the write path's `PackWriter::prepare_raw`/`push_prepared_raw`
/// split.
///
/// Never fails as a whole: every frame's own `Result` is returned,
/// in `frames`' order, instead of short-circuiting the batch on the
/// first bad one. A raw entry's validation can't depend on any other
/// entry, so there's no correctness reason to stop early — and doing
/// so would let a malformed raw entry at, say, pack position 5 preempt
/// a delta at position 0 with a missing base, which the pre-fan-out
/// single-loop reader would have rejected first (it never got past
/// position 0). [`PackReader::read_inner`]'s phase 3 is what decides,
/// in pack order, which entry's problem is actually reported.
fn stage_raw_entries(batch: &crate::batch::WriteBatch<'_>, frames: &[&[u8]]) -> RawStageResults {
    #[cfg(not(target_arch = "wasm32"))]
    {
        // Below this many entries per available thread, thread-spawn
        // overhead isn't worth it — the same sequential/parallel
        // crossover shape `mkit-cli`'s own fan-outs use (see
        // `fanout::threshold` there), tuned here by the
        // `pack_unpack_fanout` bench.
        const ENTRIES_PER_THREAD: usize = 8;
        let threads = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
        if threads > 1 && frames.len() >= ENTRIES_PER_THREAD.saturating_mul(threads) {
            return stage_raw_entries_parallel(batch, frames, threads);
        }
    }
    frames
        .iter()
        .map(|payload| prepare_and_stage_raw(batch, payload))
        .collect()
}

/// Parallel branch of [`stage_raw_entries`]: split `frames` into
/// `threads` contiguous chunks and process each chunk sequentially on
/// its own scoped thread, preserving `frames`' order in the returned
/// `Vec` (chunks are joined in creation order, and each chunk's own
/// results stay in its slice order). `std::thread::scope` (not a
/// persistent pool) is deliberate — `mkit-core` stays
/// dependency-neutral and wasm-clean (unlike `mkit-cli`, which already
/// carries `rayon` for its own fan-outs — see that crate's
/// `Cargo.toml`), and this call is already gated by
/// [`stage_raw_entries`]'s threshold so the per-call spawn cost is only
/// paid when there is enough work to amortize it.
#[cfg(not(target_arch = "wasm32"))]
fn stage_raw_entries_parallel(
    batch: &crate::batch::WriteBatch<'_>,
    frames: &[&[u8]],
    threads: usize,
) -> RawStageResults {
    let chunk_size = frames.len().div_ceil(threads).max(1);
    let mut out = Vec::with_capacity(frames.len());
    std::thread::scope(|scope| {
        let handles: Vec<_> = frames
            .chunks(chunk_size)
            .map(|chunk| {
                scope.spawn(move || {
                    chunk
                        .iter()
                        .map(|payload| prepare_and_stage_raw(batch, payload))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        for handle in handles {
            out.extend(handle.join().expect("pack unpack worker thread panicked"));
        }
    });
    out
}

/// Pure per-entry step shared by both branches of [`stage_raw_entries`]:
/// validate `payload` (already decompressed by [`PackEntries`]) as a
/// canonical storable object, compute its dispatched id, and stage it
/// into `batch`. Touches no state shared across entries — `batch` is
/// the one exception, and it is `&self`-based with its own internal
/// locking specifically so this is safe to call from many threads at
/// once.
fn prepare_and_stage_raw(
    batch: &crate::batch::WriteBatch<'_>,
    payload: &[u8],
) -> Result<Hash, PackError> {
    let obj = validate_storable_object(payload)?;
    // Address by the dispatched id (merkle root for Tree/ChunkedBlob,
    // BLAKE3 otherwise) from the object we just decoded, so the
    // unpacked object lands under the same key every sink uses without
    // a second decode.
    let stored_hash = crate::object::id_from_object(&obj, payload);
    batch.write_prehashed(stored_hash, &[payload])?;
    Ok(stored_hash)
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

/// One decoded pack entry, with `0x03`/`0x04` already decompressed into
/// the matching uncompressed variant when the `pack-zstd` feature is
/// compiled in.
///
/// The closure profile (SPEC-DISCLOSURE) accepts only [`Self::Raw`]
/// produced from a `0x00` wire type — see [`PackEntries::is_raw_only`].
#[derive(Debug)]
pub enum PackEntry<'a> {
    /// A fully serialised mkit object (`0x00`, or decompressed `0x03`).
    /// Raw (`0x00`) payloads borrow the pack bytes; decompressed `0x03`
    /// payloads own a buffer.
    Raw { bytes: Cow<'a, [u8]> },
    /// A delta (`0x02`, or decompressed `0x04`) against `base`.
    Delta { base: Hash, stream: Cow<'a, [u8]> },
}

/// Store-less iterator over a packfile's entries.
///
/// [`Self::new`] validates the header, trailer, entry-count cap, and
/// the running payload-sum cap *before* yielding anything, and scans
/// entry types (without decompressing) so [`Self::is_raw_only`] is
/// known up front. Iteration then walks the same frames, decompressing
/// `0x03`/`0x04` when `pack-zstd` is compiled in. Canonical-object
/// validation of raw payloads is left to the consumer
/// ([`PackReader::read`] still rejects non-storable objects before
/// they touch the store).
///
/// [`PackReader::read`] consumes this iterator so there is one frame
/// parser.
#[derive(Debug)]
pub struct PackEntries<'a> {
    bytes: &'a [u8],
    version: u32,
    split: usize,
    count: u32,
    pos: usize,
    yielded: u32,
    raw_only: bool,
    first_non_raw: Option<u32>,
    last_payload_range: Option<Range<usize>>,
    done: bool,
}

impl<'a> PackEntries<'a> {
    /// Total entry count declared in the pack header — the header
    /// field this iterator validates every position against (`self.pos
    /// == self.count`⇒ done), exposed so a caller collecting every
    /// entry into a `Vec` up front (as [`PackReader::read_inner`]'s
    /// phase 1 does) can size it exactly instead of growing it one
    /// `push` at a time.
    pub(crate) fn entry_count(&self) -> usize {
        self.count as usize
    }

    /// Validate `bytes` as a packfile and prepare to iterate its entries.
    ///
    /// # Errors
    ///
    /// The same framing [`PackError`] variants as [`PackReader::read`]:
    /// short input, bad magic/version/trailer, over-cap entry count or
    /// payload sum, unknown entry type, trailing data.
    pub fn new(bytes: &'a [u8]) -> Result<Self, PackError> {
        Self::new_with_payload_cap(bytes, MAX_TOTAL_PAYLOAD)
    }

    pub(crate) fn new_with_payload_cap(
        bytes: &'a [u8],
        payload_cap: u64,
    ) -> Result<Self, PackError> {
        let (version, split, count) = validate_pack_header(bytes)?;
        let mut pos = HEADER_LEN;
        let mut total_payload: u64 = 0;
        let mut raw_only = true;
        let mut first_non_raw = None;
        for i in 0..count {
            if pos + ENTRY_FRAME_LEN > split {
                return Err(PackError::UnexpectedEof);
            }
            let etype = bytes[pos];
            pos += 1;
            let payload_len =
                u32::from_le_bytes(bytes[pos..pos + 4].try_into().expect("4 bytes")) as usize;
            pos += 4;
            total_payload = total_payload.saturating_add(payload_len as u64);
            if total_payload > payload_cap {
                return Err(PackError::PackfileTooLarge);
            }
            // Overflow-free on 32-bit `usize`; see `delta_base_hashes`.
            if payload_len > split - pos {
                return Err(PackError::UnexpectedEof);
            }
            match etype {
                0x00 => {}
                0x02 => {
                    if payload_len < hash::HASH_LEN {
                        return Err(PackError::DeltaEntryTruncated);
                    }
                    if first_non_raw.is_none() {
                        first_non_raw = Some(i);
                    }
                    raw_only = false;
                }
                0x03 if version == VERSION_V2 => {
                    if first_non_raw.is_none() {
                        first_non_raw = Some(i);
                    }
                    raw_only = false;
                }
                0x04 if version == VERSION_V2 => {
                    if payload_len < hash::HASH_LEN {
                        return Err(PackError::DeltaEntryTruncated);
                    }
                    if first_non_raw.is_none() {
                        first_non_raw = Some(i);
                    }
                    raw_only = false;
                }
                0x01 => return Err(PackError::InvalidEntryType(0x01)),
                other => return Err(PackError::InvalidEntryType(other)),
            }
            pos += payload_len;
        }
        if pos != split {
            return Err(PackError::TrailingData);
        }
        Ok(Self {
            bytes,
            version,
            split,
            count,
            pos: HEADER_LEN,
            yielded: 0,
            raw_only,
            first_non_raw,
            last_payload_range: None,
            done: false,
        })
    }

    /// True iff every entry is wire type `0x00` (including the empty
    /// pack). Computed during [`Self::new`] by scanning entry types
    /// without decompressing — a wasm verifier can reject a non-raw
    /// pack before touching zstd.
    #[must_use]
    pub fn is_raw_only(&self) -> bool {
        self.raw_only
    }

    /// Index of the first non-`0x00` entry, if any.
    #[must_use]
    pub fn first_non_raw_index(&self) -> Option<u32> {
        self.first_non_raw
    }

    /// Byte range of the payload returned by the most recent successful
    /// iteration, relative to the original pack buffer. `None` before the
    /// first item. For a raw-only pack, this is the borrowed object slice;
    /// compressed entries, which are rejected by the closure profile, still
    /// report the encoded payload range rather than the decompressed buffer.
    #[must_use]
    pub(crate) fn last_payload_range(&self) -> Option<Range<usize>> {
        self.last_payload_range.clone()
    }

    fn next_entry(&mut self) -> Result<PackEntry<'a>, PackError> {
        if self.pos + ENTRY_FRAME_LEN > self.split {
            return Err(PackError::UnexpectedEof);
        }
        let etype = self.bytes[self.pos];
        self.pos += 1;
        let payload_len = u32::from_le_bytes(
            self.bytes[self.pos..self.pos + 4]
                .try_into()
                .expect("4 bytes"),
        ) as usize;
        self.pos += 4;
        // Overflow-free on 32-bit `usize`; see `delta_base_hashes`.
        if payload_len > self.split - self.pos {
            return Err(PackError::UnexpectedEof);
        }
        let payload_start = self.pos;
        let payload_end = self.pos + payload_len;
        let payload = &self.bytes[payload_start..payload_end];
        self.last_payload_range = Some(payload_start..payload_end);
        self.pos = payload_end;
        self.yielded += 1;
        match etype {
            0x00 => Ok(PackEntry::Raw {
                bytes: Cow::Borrowed(payload),
            }),
            0x02 => {
                if payload.len() < hash::HASH_LEN {
                    return Err(PackError::DeltaEntryTruncated);
                }
                let mut base = [0u8; hash::HASH_LEN];
                base.copy_from_slice(&payload[..hash::HASH_LEN]);
                Ok(PackEntry::Delta {
                    base,
                    stream: Cow::Borrowed(&payload[hash::HASH_LEN..]),
                })
            }
            0x03 if self.version == VERSION_V2 => {
                let obj_bytes = decompress_zstd_entry(payload)?;
                Ok(PackEntry::Raw {
                    bytes: Cow::Owned(obj_bytes),
                })
            }
            0x04 if self.version == VERSION_V2 => {
                if payload.len() < hash::HASH_LEN {
                    return Err(PackError::DeltaEntryTruncated);
                }
                let mut base = [0u8; hash::HASH_LEN];
                base.copy_from_slice(&payload[..hash::HASH_LEN]);
                let stream = decompress_zstd_entry(&payload[hash::HASH_LEN..])?;
                Ok(PackEntry::Delta {
                    base,
                    stream: Cow::Owned(stream),
                })
            }
            0x01 => Err(PackError::InvalidEntryType(0x01)),
            other => Err(PackError::InvalidEntryType(other)),
        }
    }
}

impl<'a> Iterator for PackEntries<'a> {
    type Item = Result<PackEntry<'a>, PackError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.yielded >= self.count {
            self.done = true;
            return None;
        }
        match self.next_entry() {
            Ok(entry) => Some(Ok(entry)),
            Err(e) => {
                self.done = true;
                Some(Err(e))
            }
        }
    }
}

/// Resolve a delta's base, decode `stream` against it, and stage the
/// reconstructed target into `batch`/`in_pack`. `0x04` deltas differ
/// from `0x02` only in how `stream` was sourced by [`PackEntries`]
/// (decompressed vs. borrowed straight from `pack_bytes`), not in how
/// base resolution, delta decoding, or staging work here. Returns the
/// stored hash; `read_inner`'s phase 3 builds [`UnpackReport`] itself
/// as it walks `entries` in pack order, so this function doesn't need
/// to touch it.
fn stage_delta_target<B: DeltaBaseSource>(
    bases: &mut B,
    batch: &crate::batch::WriteBatch<'_>,
    in_pack: &mut std::collections::HashMap<Hash, Cow<'_, [u8]>>,
    owned_bytes: Option<&AtomicU64>,
    base_hash: Hash,
    stream: &[u8],
) -> Result<Hash, PackError> {
    let resolved = resolve_delta_target(bases, in_pack, base_hash, stream)?;
    let obj = validate_storable_object(&resolved)?;
    let stored_hash = crate::object::id_from_object(&obj, &resolved);
    batch.write_prehashed(stored_hash, &[&resolved])?;
    if let Some(c) = owned_bytes {
        c.fetch_add(resolved.len() as u64, Ordering::Relaxed);
    }
    in_pack.insert(stored_hash, Cow::Owned(resolved));
    Ok(stored_hash)
}

/// Resolve a delta's base (in-pack first, then the external
/// [`DeltaBaseSource`]) and decode `stream` against it. Shared by the
/// `0x02` and `0x04` branches of [`PackReader::read_inner`] and by
/// [`decode_entries_with`] — `0x04` differs only in how `stream` was
/// sourced (decompressed vs. borrowed straight from `pack_bytes`), not
/// in how base resolution or delta decoding work.
fn resolve_delta_target<B: DeltaBaseSource>(
    bases: &mut B,
    in_pack: &mut std::collections::HashMap<Hash, Cow<'_, [u8]>>,
    base_hash: Hash,
    stream: &[u8],
) -> Result<Vec<u8>, PackError> {
    // Resolve base: in-pack first, then the external source. An
    // externally resolved base is cached into `in_pack` under its own
    // hash so a later delta entry referencing the same out-of-pack base
    // hits the cache-hit branch above instead of paying another full
    // read + verify + decode (#643). This is safe because
    // `external_base` has already established that the bytes are the
    // object `base_hash` names (the store's `read` hash-verifies; an
    // unverified source is re-derived there). Cloning once here (vs.
    // #643's original Arc::clone) is the cost of composing with #647's
    // Cow-based `in_pack`, which trades that one-time clone for
    // zero-copy borrows on the far more common raw-entry path — a net
    // win, and this clone only happens once per unique out-of-pack
    // base, not per delta entry.
    let base_bytes: Cow<'_, [u8]> = if let Some(b) = in_pack.get(&base_hash) {
        Cow::Borrowed(b.as_ref())
    } else if let Some(bytes) = external_base(bases, &base_hash)? {
        in_pack.insert(base_hash, Cow::Owned(bytes.clone()));
        Cow::Owned(bytes)
    } else {
        return Err(PackError::DeltaBaseMissing(hash::to_hex(&base_hash)));
    };
    validate_delta_result_size(stream)?;
    let resolved = delta::decode(base_bytes.as_ref(), stream)?;
    Ok(resolved)
}

/// Fetch an external delta base from `bases` and establish that it is the
/// storable canonical object `id` names, or report it absent.
///
/// A [`DeltaBaseSource::VERIFIED`] source (the local [`ObjectStore`])
/// already hash-verified the bytes, so this runs exactly the pre-seam
/// store path: a non-storable object is a loud error. Any other source
/// is untrusted for identity: bytes that do not deserialize to a
/// storable object whose re-derived id is `id` are treated as absent,
/// so the caller reports [`PackError::DeltaBaseMissing`] — the same
/// error bytes as a base the source does not have at all.
fn external_base<B: DeltaBaseSource>(
    bases: &mut B,
    id: &Hash,
) -> Result<Option<Vec<u8>>, PackError> {
    let Some(bytes) = bases.base(id)? else {
        return Ok(None);
    };
    if B::VERIFIED {
        validate_storable_object(&bytes)?;
        return Ok(Some(bytes));
    }
    match validate_storable_object(&bytes) {
        Ok(obj) if crate::object::id_from_object(&obj, &bytes) == *id => Ok(Some(bytes)),
        _ => Ok(None),
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
mod zstd_tests;

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

    // =================================================================
    // `prepare_raw`/`push_prepared_raw` and `prepare_delta`/
    // `push_prepared_delta` — the pure-compression / sequential-append
    // split added so a caller (mkit-cli's `build_and_upload_packs`) can
    // run compression across a thread pool before replaying the
    // append in order. Must produce byte-identical output to the
    // original `push_raw`/`push_delta` and preserve call order when
    // interleaved with them — a future refactor of `append_raw_frame`/
    // `append_delta_frame` (the shared tail both paths funnel through)
    // must not let the two paths drift apart.
    // =================================================================

    #[test]
    fn prepared_raw_produces_identical_pack_bytes_to_push_raw() {
        let blob = write_blob_via_serialize(b"hello prepared packfile");
        let h = hash::hash(&blob);

        let mut direct = PackWriter::new();
        direct.push_raw(h, &blob).unwrap();
        let direct_pack = direct.finish().unwrap();

        let prepared = PackWriter::prepare_raw(h, blob.clone());
        assert_eq!(prepared.hash(), h);
        assert_eq!(prepared.conservative_len(), blob.len());
        let mut via_prepared = PackWriter::new();
        via_prepared.push_prepared_raw(prepared).unwrap();
        let prepared_pack = via_prepared.finish().unwrap();

        assert_eq!(
            direct_pack, prepared_pack,
            "push_raw and prepare_raw+push_prepared_raw must produce byte-identical packs"
        );
    }

    #[test]
    fn prepared_delta_produces_identical_pack_bytes_to_push_delta() {
        let base = write_blob_via_serialize(&incompressible_bytes(0xD00D_0000, 2048));
        let target = write_blob_via_serialize(&incompressible_bytes(0xFEED_0000, 2048));
        let base_hash = hash::hash(&base);
        let stream = delta::encode(&base, &target).unwrap();

        let mut direct = PackWriter::new();
        direct.push_delta(&base_hash, &stream).unwrap();
        let direct_pack = direct.finish().unwrap();

        let prepared = PackWriter::prepare_delta(base_hash, stream.clone());
        assert_eq!(prepared.base(), base_hash);
        let mut via_prepared = PackWriter::new();
        via_prepared.push_prepared_delta(prepared).unwrap();
        let prepared_pack = via_prepared.finish().unwrap();

        assert_eq!(
            direct_pack, prepared_pack,
            "push_delta and prepare_delta+push_prepared_delta must produce byte-identical packs"
        );
    }

    #[test]
    fn prepared_and_direct_entries_interleave_in_push_order() {
        // A caller mixing a compression-fan-out batch's prepared
        // entries with directly-pushed ones (e.g. across a
        // pack-splitting boundary) must see them land in the pack in
        // exactly the order they were pushed, whichever path each one
        // took.
        let a = write_blob_via_serialize(b"first entry, pushed directly");
        let ha = hash::hash(&a);
        let b = write_blob_via_serialize(b"second entry, pushed via prepare");
        let hb = hash::hash(&b);

        let mut w = PackWriter::new();
        w.push_raw(ha, &a).unwrap();
        let prepared_b = PackWriter::prepare_raw(hb, b.clone());
        w.push_prepared_raw(prepared_b).unwrap();
        let pack = w.finish().unwrap();

        let (_dir, store) = fresh_store();
        let report = PackReader::read(&pack, &store).unwrap();
        assert_eq!(
            report.stored,
            vec![ha, hb],
            "entries must appear in push order regardless of which path prepared them"
        );
        assert_eq!(store.read(&ha).unwrap(), a);
        assert_eq!(store.read(&hb).unwrap(), b);
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
    fn delta_before_its_base_in_pack_order_is_rejected() {
        // SPEC-PACKFILE §4: a delta's base MUST appear earlier in the
        // pack as a raw entry (or already exist in the destination
        // store) — never later. Same fixture as
        // `raw_then_delta_resolves_in_pack`, but with the delta and its
        // raw base swapped so the base comes *after* the delta that
        // references it. The base is genuinely absent from both the
        // pack-so-far and the (empty) store at the point the delta is
        // read, so this must fail exactly like a base that's missing
        // outright — never silently succeed by resolving against a
        // same-pack entry the reader hasn't reached yet.
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

        let stream = delta::encode(&base_obj, &target_obj).unwrap();

        let mut w = PackWriter::new();
        w.push_delta(&base_hash, &stream).unwrap();
        w.push_raw(base_hash, &base_obj).unwrap();
        let pack = w.finish().unwrap();

        let (_dir, store) = fresh_store();
        let err = PackReader::read(&pack, &store).unwrap_err();
        assert!(matches!(err, PackError::DeltaBaseMissing(_)), "got {err:?}");
        // Nothing from this rejected pack should be visible — not even
        // the raw base entry that appeared after the bad delta.
        assert!(!store.contains(&base_hash));
    }

    #[test]
    fn delta_before_its_base_is_rejected_under_parallel_raw_fanout() {
        // Same defect as `delta_before_its_base_in_pack_order_is_rejected`,
        // but with enough raw entries ahead of the base (200 — comfortably
        // over `stage_raw_entries`'s `ENTRIES_PER_THREAD * threads` on any
        // CI runner up to dozens of cores) to force phase 2's parallel
        // `std::thread::scope` fan-out rather than its small-pack
        // sequential fallback. The base-before-delta rule must hold
        // regardless of how phase 2 schedules raw-entry work across
        // threads.
        let mut content_base = vec![0u8; 256];
        for (i, b) in content_base.iter_mut().enumerate() {
            *b = u8::try_from(i % 251).expect("modulo < 256");
        }
        let mut content_target = content_base.clone();
        content_target[10] = 0xFF;

        let base_obj = write_blob_via_serialize(&content_base);
        let target_obj = write_blob_via_serialize(&content_target);
        let base_hash = hash::hash(&base_obj);
        let stream = delta::encode(&base_obj, &target_obj).unwrap();

        let mut w = PackWriter::new();
        w.push_delta(&base_hash, &stream).unwrap();
        for i in 0..200u32 {
            let mut filler = vec![0u8; 64];
            for (j, b) in filler.iter_mut().enumerate() {
                *b = u8::try_from((i as usize + j) % 251).expect("modulo < 256");
            }
            let obj = write_blob_via_serialize(&filler);
            w.push_raw(hash::hash(&obj), &obj).unwrap();
        }
        w.push_raw(base_hash, &base_obj).unwrap();
        let pack = w.finish().unwrap();

        let (_dir, store) = fresh_store();
        let err = PackReader::read(&pack, &store).unwrap_err();
        assert!(matches!(err, PackError::DeltaBaseMissing(_)), "got {err:?}");
        assert!(!store.contains(&base_hash));
    }

    #[test]
    fn earlier_delta_base_missing_wins_over_later_malformed_raw_entry() {
        // Phase 2 validates every raw entry in the pack up front
        // (independent per entry, so it can fan out across threads),
        // but phase 3 decides *in pack order* which single problem is
        // actually reported. A delta at position 0 with a missing base
        // must win over a malformed raw entry at a later position —
        // the pre-fan-out single-loop reader would have rejected
        // position 0 and never even looked at the later one. 200
        // well-formed raw fillers keep phase 2 on its parallel branch
        // (comfortably over `stage_raw_entries`'s threshold on any CI
        // runner), with one malformed entry mixed in among them.
        let base_obj = write_blob_via_serialize(&[0u8; 64]);
        let target_obj = write_blob_via_serialize(&[1u8; 64]);
        let base_hash = hash::hash(&base_obj);
        let stream = delta::encode(&base_obj, &target_obj).unwrap();

        let mut w = PackWriter::new();
        w.push_delta(&base_hash, &stream).unwrap();
        for i in 0..200u32 {
            if i == 100 {
                // Not a canonical storable object — fails phase 2's
                // `validate_storable_object` with `PackError::InvalidObject`.
                w.push_raw([0xEE; 32], b"not a valid mkit object").unwrap();
                continue;
            }
            let mut filler = vec![0u8; 64];
            for (j, b) in filler.iter_mut().enumerate() {
                *b = u8::try_from((i as usize + j) % 251).expect("modulo < 256");
            }
            let obj = write_blob_via_serialize(&filler);
            w.push_raw(hash::hash(&obj), &obj).unwrap();
        }
        w.push_raw(base_hash, &base_obj).unwrap();
        let pack = w.finish().unwrap();

        let (_dir, store) = fresh_store();
        let err = PackReader::read(&pack, &store).unwrap_err();
        assert!(
            matches!(err, PackError::DeltaBaseMissing(_)),
            "position 0's missing-base error must win over the malformed raw \
             entry at a later position, got {err:?}"
        );
        assert!(!store.contains(&base_hash));
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
    #[cfg(feature = "pack-zstd")]
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

    #[test]
    #[cfg(feature = "pack-zstd")]
    fn raw_only_writer_emits_v1_raw_for_compressible_payload() {
        let payload = compressible_bytes(1024 * 1024);
        let blob = write_blob_via_serialize(&payload);
        let h = hash::hash(&blob);
        let mut w = PackWriter::new_raw_only();
        w.push_raw(h, &blob).unwrap();
        let pack = w.finish().unwrap();

        assert_eq!(
            u32::from_le_bytes(pack[VERSION_OFFSET..VERSION_OFFSET + 4].try_into().unwrap()),
            VERSION,
            "raw-only writer must finish as v1"
        );
        assert_eq!(pack[HEADER_LEN], 0x00, "every entry must be 0x00");
        let entries = PackEntries::new(&pack).unwrap();
        assert!(entries.is_raw_only());
        assert_eq!(entries.first_non_raw_index(), None);

        let (_dir, store) = fresh_store();
        let report = PackReader::read(&pack, &store).unwrap();
        assert_eq!(report.raw_count, 1);
        assert_eq!(store.read(&h).unwrap(), blob);
    }

    #[test]
    fn raw_only_writer_rejects_deltas() {
        let mut w = PackWriter::new_raw_only();
        let err = w.push_delta(&[0u8; 32], &[0u8; 16]).unwrap_err();
        assert!(matches!(err, PackError::RawOnly));
        let prepared = PackWriter::prepare_delta([1u8; 32], vec![0u8; 16]);
        let err = w.push_prepared_delta(prepared).unwrap_err();
        assert!(matches!(err, PackError::RawOnly));
    }

    #[test]
    fn pack_entries_agrees_with_reader_on_empty_and_raw() {
        let mut w = PackWriter::new_raw_only();
        let blob = write_blob_via_serialize(b"pack-entries");
        let h = hash::hash(&blob);
        w.push_raw(h, &blob).unwrap();
        let pack = w.finish().unwrap();

        let entries: Vec<_> = PackEntries::new(&pack)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(entries.len(), 1);
        match &entries[0] {
            PackEntry::Raw { bytes } => assert_eq!(bytes.as_ref(), blob.as_slice()),
            PackEntry::Delta { .. } => panic!("expected raw"),
        }

        let (_dir, store) = fresh_store();
        PackReader::read(&pack, &store).unwrap();
        assert_eq!(store.read(&h).unwrap(), blob);
    }

    // =====================================================================
    // `DeltaBaseSource` seam / `decode_entries_with` (WP-4.2)
    // =====================================================================

    /// `(target id, target bytes, delta stream against the base)`.
    type Variant = (Hash, Vec<u8>, Vec<u8>);
    /// `(id, bytes, from_delta)` as a decode sink saw it.
    type Seen = (Hash, Vec<u8>, bool);

    /// A 512-byte base blob and `n` single-byte variants of it, with
    /// their delta streams against the base.
    fn base_and_variants(n: usize) -> (Vec<u8>, Hash, Vec<Variant>) {
        let mut content = vec![0u8; 512];
        for (i, b) in content.iter_mut().enumerate() {
            *b = u8::try_from(i % 251).expect("modulo < 256");
        }
        let base = write_blob_via_serialize(&content);
        let base_hash = hash::hash(&base);
        let variants = (0..n)
            .map(|i| {
                let mut c = content.clone();
                c[100] = u8::try_from(i).unwrap() ^ 0xA5;
                let target = write_blob_via_serialize(&c);
                let stream = delta::encode(&base, &target).unwrap();
                (hash::hash(&target), target, stream)
            })
            .collect();
        (base, base_hash, variants)
    }

    /// Decode `pack` through `bases`, collecting what the sink saw.
    fn decode_collect<B: DeltaBaseSource>(
        pack: &[u8],
        bases: &mut B,
    ) -> Result<(DecodeReport, Vec<Seen>), PackError> {
        let mut seen = Vec::new();
        let report = decode_entries_with(pack, bases, DecodeLimits::default(), |e| {
            assert_eq!(e.id, crate::object::id_from_object(&e.object, e.bytes));
            seen.push((e.id, e.bytes.to_vec(), e.from_delta));
            Ok(())
        })?;
        Ok((report, seen))
    }

    /// Self-contained test packs of every entry shape the writer emits
    /// (raw, raw + in-pack delta, and — under `pack-zstd` — `0x03`/`0x04`).
    fn self_contained_packs() -> Vec<Vec<u8>> {
        let mut packs = vec![PackWriter::new().finish().unwrap()];

        let mut w = PackWriter::new();
        for i in 0..20u32 {
            let blob = write_blob_via_serialize(&incompressible_bytes(u64::from(i), 256));
            w.push_raw(hash::hash(&blob), &blob).unwrap();
        }
        packs.push(w.finish().unwrap());

        let (base, base_hash, variants) = base_and_variants(3);
        let mut w = PackWriter::new();
        w.push_raw(base_hash, &base).unwrap();
        for (_, _, stream) in &variants {
            w.push_delta(&base_hash, stream).unwrap();
        }
        // Chain: a delta whose base is itself an earlier delta target.
        let (t0_hash, t0, _) = &variants[0];
        let mut chained = t0.clone();
        let last = chained.len() - 1;
        chained[last] ^= 0x01;
        w.push_delta(t0_hash, &delta::encode(t0, &chained).unwrap())
            .unwrap();
        packs.push(w.finish().unwrap());

        let tree = crate::serialize::serialize(&Object::Tree(crate::object::Tree {
            entries: vec![crate::object::TreeEntry {
                name: b"f".to_vec(),
                mode: crate::object::EntryMode::Blob,
                object_hash: base_hash,
            }],
        }))
        .unwrap();
        let mut w = PackWriter::new_raw_only();
        w.push_raw(crate::object::object_id_from_bytes(&tree), &tree)
            .unwrap();
        w.push_raw(base_hash, &base).unwrap();
        packs.push(w.finish().unwrap());

        #[cfg(feature = "pack-zstd")]
        {
            let base = write_blob_via_serialize(b"delta base filler, not target-shaped");
            let base_hash = hash::hash(&base);
            let target = write_blob_via_serialize(&compressible_bytes(4096));
            let raw = write_blob_via_serialize(&compressible_bytes(8192));
            let mut w = PackWriter::new();
            w.push_raw(hash::hash(&raw), &raw).unwrap();
            w.push_raw(base_hash, &base).unwrap();
            w.push_delta(&base_hash, &delta::encode(&base, &target).unwrap())
                .unwrap();
            let pack = w.finish().unwrap();
            assert_eq!(pack[HEADER_LEN], 0x03, "sanity: zstd-raw entry");
            packs.push(pack);
        }
        packs
    }

    #[test]
    fn decode_with_no_external_bases_matches_reader() {
        for pack in self_contained_packs() {
            let (_dir, store) = fresh_store();
            let unpacked = PackReader::read(&pack, &store).unwrap();
            let (report, seen) = decode_collect(&pack, &mut NoExternalBases).unwrap();

            assert_eq!(report.ids, unpacked.stored);
            assert_eq!(report.raw_count, unpacked.raw_count as usize);
            assert_eq!(report.delta_count, unpacked.delta_count as usize);
            assert_eq!(
                seen.iter().filter(|s| s.2).count(),
                unpacked.delta_count as usize
            );
            for (id, bytes, _) in &seen {
                assert_eq!(&store.read(id).unwrap(), bytes, "same bytes under {id:?}");
            }
            assert_eq!(seen.iter().map(|s| s.0).collect::<Vec<_>>(), report.ids);
        }
    }

    #[test]
    fn decode_rejects_exactly_what_reader_rejects() {
        // The reader has no decode budget, so compare against an unbounded
        // decoder (the over-cap delta would otherwise trip the budget first).
        let unbounded = DecodeLimits::default().with_max_decoded_bytes(u64::MAX);
        // Every error-precedence pack pinned above must fail the same way
        // through the store-less decoder.
        let base_obj = write_blob_via_serialize(&[0u8; 64]);
        let target_obj = write_blob_via_serialize(&[1u8; 64]);
        let base_hash = hash::hash(&base_obj);
        let stream = delta::encode(&base_obj, &target_obj).unwrap();
        let mut w = PackWriter::new();
        w.push_delta(&base_hash, &stream).unwrap();
        for i in 0..200u32 {
            if i == 100 {
                w.push_raw([0xEE; 32], b"not a valid mkit object").unwrap();
                continue;
            }
            let obj = write_blob_via_serialize(&i.to_le_bytes());
            w.push_raw(hash::hash(&obj), &obj).unwrap();
        }
        w.push_raw(base_hash, &base_obj).unwrap();
        let delta_first = w.finish().unwrap();

        let mut w = PackWriter::new();
        w.push_raw([0xEE; 32], b"not a valid mkit object").unwrap();
        w.push_delta(&base_hash, &stream).unwrap();
        let raw_first = w.finish().unwrap();

        let mut w = PackWriter::new();
        w.push_raw(base_hash, &base_obj).unwrap();
        let oversized = {
            let mut s = stream.clone();
            s[5..9].copy_from_slice(
                &u32::try_from(MAX_RAW_OBJECT_SIZE + 1)
                    .unwrap()
                    .to_le_bytes(),
            );
            s
        };
        w.push_delta(&base_hash, &oversized).unwrap();
        let over_cap = w.finish().unwrap();

        let mut flipped = PackWriter::new().finish().unwrap();
        flipped[HEADER_LEN] ^= 0x01;

        for pack in [delta_first, raw_first, over_cap, flipped] {
            let (_dir, store) = fresh_store();
            let reader = PackReader::read(&pack, &store).unwrap_err();
            let decoder = decode_entries_with(&pack, &mut NoExternalBases, unbounded, |_| Ok(()))
                .unwrap_err();
            assert_eq!(reader.to_string(), decoder.to_string());
        }
    }

    #[test]
    fn external_base_outside_source_is_delta_base_missing() {
        // The base exists — in a store the decoder is not given. A
        // membership-scoped source that does not list it, and a source
        // with no external bases at all, must both fail exactly as a base
        // that exists nowhere does.
        struct Membership<'s> {
            store: &'s ObjectStore,
            members: std::collections::BTreeSet<Hash>,
        }
        impl DeltaBaseSource for Membership<'_> {
            fn base(&mut self, id: &Hash) -> Result<Option<Vec<u8>>, PackError> {
                if !self.members.contains(id) {
                    return Ok(None);
                }
                Ok(Some(self.store.read(id)?))
            }
        }

        let (_other_dir, other_repo) = fresh_store();
        let (base, base_hash, variants) = base_and_variants(1);
        other_repo.write(&base).unwrap();
        let mut w = PackWriter::new();
        w.push_delta(&base_hash, &variants[0].2).unwrap();
        let pack = w.finish().unwrap();

        let (_dir, empty) = fresh_store();
        let nowhere = PackReader::read(&pack, &empty).unwrap_err().to_string();
        assert_eq!(
            nowhere,
            PackError::DeltaBaseMissing(hash::to_hex(&base_hash)).to_string()
        );

        let mut sink_calls = 0usize;
        let no_ext =
            decode_entries_with(&pack, &mut NoExternalBases, DecodeLimits::default(), |_| {
                sink_calls += 1;
                Ok(())
            })
            .unwrap_err();
        assert_eq!(no_ext.to_string(), nowhere);

        let mut scoped = Membership {
            store: &other_repo,
            members: std::collections::BTreeSet::new(),
        };
        let not_member = decode_entries_with(&pack, &mut scoped, DecodeLimits::default(), |_| {
            sink_calls += 1;
            Ok(())
        })
        .unwrap_err();
        assert_eq!(not_member.to_string(), nowhere);
        assert_eq!(sink_calls, 0);

        // Once the base IS a member, the same pack decodes.
        scoped.members.insert(base_hash);
        let (report, seen) = decode_collect(&pack, &mut scoped).unwrap();
        assert_eq!(report.ids, vec![variants[0].0]);
        assert_eq!(seen[0].1, variants[0].1);
        assert!(seen[0].2);
    }

    #[test]
    fn untrusted_source_returning_wrong_bytes_is_rejected() {
        struct Lying {
            answer: Vec<u8>,
        }
        impl DeltaBaseSource for Lying {
            fn base(&mut self, _id: &Hash) -> Result<Option<Vec<u8>>, PackError> {
                Ok(Some(self.answer.clone()))
            }
        }

        let (base, base_hash, variants) = base_and_variants(1);
        let mut w = PackWriter::new();
        w.push_delta(&base_hash, &variants[0].2).unwrap();
        let pack = w.finish().unwrap();
        let expected = PackError::DeltaBaseMissing(hash::to_hex(&base_hash)).to_string();

        // A different, perfectly valid object; bytes that are not an
        // object; and a pack-only delta object: none may stand in.
        let impostor = write_blob_via_serialize(b"a different valid object");
        let delta_obj = crate::serialize::serialize(&Object::Delta(crate::object::Delta {
            base_hash,
            result_size: 0,
            instructions: vec![],
        }))
        .unwrap();
        for answer in [impostor, b"garbage".to_vec(), delta_obj] {
            let mut emitted = Vec::new();
            let err =
                decode_entries_with(&pack, &mut Lying { answer }, DecodeLimits::default(), |e| {
                    emitted.push(e.id);
                    Ok(())
                })
                .unwrap_err();
            assert_eq!(err.to_string(), expected);
            assert!(emitted.is_empty(), "no target may be emitted");
        }

        // The genuine bytes from the same untrusted source are accepted.
        let (report, _) = decode_collect(&pack, &mut Lying { answer: base }).unwrap();
        assert_eq!(report.ids, vec![variants[0].0]);
    }

    #[test]
    fn store_source_is_verified_once() {
        // `multiple_deltas_against_shared_external_base_read_store_once`,
        // through the store-less decoder with `&ObjectStore` as source.
        const N: usize = 5;
        let (_dir, store) = fresh_store();
        let (base, base_hash, variants) = base_and_variants(N);
        store.write(&base).unwrap();
        let mut w = PackWriter::new();
        for (_, _, stream) in &variants {
            w.push_delta(&base_hash, stream).unwrap();
        }
        let pack = w.finish().unwrap();

        let reads_before = store.read_call_count();
        let mut source = &store;
        let (report, seen) = decode_collect(&pack, &mut source).unwrap();
        assert_eq!(store.read_call_count() - reads_before, 1);
        assert_eq!(report.delta_count, N);
        for ((id, bytes, _), (want_id, want, _)) in seen.iter().zip(&variants) {
            assert_eq!(id, want_id);
            assert_eq!(bytes, want);
        }
        // Store-less: nothing was written.
        for (id, _, _) in &variants {
            assert!(!store.contains(id));
        }
    }

    #[test]
    fn corrupt_store_base_is_a_loud_store_error() {
        // The verified store path keeps its pre-seam behavior: a base whose
        // on-disk bytes no longer hash to its id is `Store(HashMismatch)`,
        // not a silent "missing".
        use std::io::{Seek, Write};
        let (_dir, store) = fresh_store();
        let (base, base_hash, variants) = base_and_variants(1);
        store.write(&base).unwrap();
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(store.path_for(&base_hash))
            .unwrap();
        f.seek(std::io::SeekFrom::End(-1)).unwrap();
        f.write_all(&[base[base.len() - 1] ^ 0xFF]).unwrap();
        drop(f);
        let mut w = PackWriter::new();
        w.push_delta(&base_hash, &variants[0].2).unwrap();
        let pack = w.finish().unwrap();

        let reader = PackReader::read(&pack, &store).unwrap_err();
        let mut source = &store;
        let decoder = decode_entries_with(&pack, &mut source, DecodeLimits::default(), |_| Ok(()))
            .unwrap_err();
        assert!(matches!(reader, PackError::Store(_)), "{reader:?}");
        assert_eq!(reader.to_string(), decoder.to_string());
    }

    /// The WP-4.2 review's memory probe: one 64 KiB raw base, then `n`
    /// deltas, each a valid SPEC-DELTA stream that rebuilds a distinct
    /// `target_len`-byte blob purely by copying base bytes (a few bytes of
    /// wire per 64 KiB of result; `pack-zstd` shrinks it further).
    /// Returns the pack and the ids of the delta targets.
    fn delta_bomb(n: u32, target_len: usize) -> (Vec<u8>, Vec<Hash>) {
        let base = write_blob_via_serialize(&vec![0u8; 65536]);
        let base_hash = hash::hash(&base);
        let zeros_at = u32::try_from(base.len() - 65536).unwrap();
        // Blob prologue + length for a `target_len`-byte blob.
        let mut prologue = write_blob_via_serialize(&[]);
        let len_at = prologue.len() - 4;
        prologue[len_at..].copy_from_slice(&u32::try_from(target_len).unwrap().to_le_bytes());
        let total = prologue.len() + target_len;

        let mut w = PackWriter::new();
        w.push_raw(base_hash, &base).unwrap();
        let mut ids = Vec::new();
        for i in 0..n {
            let mut s = vec![delta::STREAM_VERSION];
            s.extend_from_slice(&u32::try_from(base.len()).unwrap().to_le_bytes());
            s.extend_from_slice(&u32::try_from(total).unwrap().to_le_bytes());
            s.push(u8::try_from(prologue.len()).unwrap());
            s.extend_from_slice(&prologue);
            // Four distinguishing data bytes, then zeros copied from base.
            s.push(4);
            s.extend_from_slice(&i.to_le_bytes());
            let mut left = target_len - 4;
            while left > 0 {
                let len = left.min(65535);
                s.push(delta::OP_COPY);
                s.extend_from_slice(&zeros_at.to_le_bytes());
                s.extend_from_slice(&u16::try_from(len).unwrap().to_le_bytes());
                left -= len;
            }
            w.push_delta(&base_hash, &s).unwrap();
            let mut data = vec![0u8; target_len];
            data[..4].copy_from_slice(&i.to_le_bytes());
            ids.push(hash::hash(&write_blob_via_serialize(&data)));
        }
        (w.finish().unwrap(), ids)
    }

    #[test]
    fn delta_bomb_is_rejected_before_any_delta_is_applied() {
        // 16 deltas declaring 128 MiB each (2 GiB in all) from a pack of a
        // few hundred KiB at most: over the default 1 GiB budget, so the
        // decode fails before it applies (allocates) a single target.
        let (pack, _) = delta_bomb(16, 128 << 20);
        assert!(pack.len() < 512 * 1024, "pack is {} bytes", pack.len());
        let mut sink_calls = 0usize;
        let err = decode_entries_with(&pack, &mut NoExternalBases, DecodeLimits::default(), |_| {
            sink_calls += 1;
            Ok(())
        })
        .unwrap_err();
        assert!(matches!(err, PackError::PackfileTooLarge), "{err:?}");
        assert_eq!(sink_calls, 0, "rejected before the first entry is judged");
    }

    #[test]
    fn decode_budget_is_caller_set() {
        // The same construction at a small size decodes to real objects
        // under a budget that covers it, and fails under one just short of
        // the declared results alone. (Under `pack-zstd` the writer also
        // compresses the streams, whose claims are charged too, so the
        // exact boundary depends on the build.)
        const TARGET: usize = 256 * 1024;
        let (pack, ids) = delta_bomb(3, TARGET);
        let declared = 3 * (TARGET as u64 + 10);

        let fits = DecodeLimits::default().with_max_decoded_bytes(2 * declared);
        let (_dir, store) = fresh_store();
        let unpacked = PackReader::read(&pack, &store).unwrap();
        let mut seen = Vec::new();
        let report = decode_entries_with(&pack, &mut NoExternalBases, fits, |e| {
            seen.push(e.id);
            Ok(())
        })
        .unwrap();
        assert_eq!(report.ids, unpacked.stored);
        assert_eq!(seen[1..], ids[..]);

        let short = DecodeLimits::default().with_max_decoded_bytes(declared - 1);
        let err = decode_entries_with(&pack, &mut NoExternalBases, short, |_| Ok(())).unwrap_err();
        assert!(matches!(err, PackError::PackfileTooLarge), "{err:?}");
    }

    #[test]
    fn compressed_claims_are_charged_before_decompression() {
        // A v2 `0x03` entry claiming 512 MiB behind a bogus frame: a
        // decoder that decompressed first would fail on the frame; the
        // budget must reject on the claim alone.
        let claimed = u32::try_from(512usize << 20).unwrap();
        let mut buf = Vec::new();
        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&VERSION_V2.to_le_bytes());
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.push(0x03);
        let mut inner = claimed.to_le_bytes().to_vec();
        inner.extend_from_slice(&[0u8; 8]);
        buf.extend_from_slice(&u32::try_from(inner.len()).unwrap().to_le_bytes());
        buf.extend_from_slice(&inner);
        let pack = finish_pack_body(buf);

        let small = DecodeLimits::default().with_max_decoded_bytes(1 << 20);
        let err = decode_entries_with(&pack, &mut NoExternalBases, small, |_| Ok(())).unwrap_err();
        assert!(matches!(err, PackError::PackfileTooLarge), "{err:?}");
        // Within budget, the frame itself is what fails.
        let err = decode_entries_with(&pack, &mut NoExternalBases, DecodeLimits::default(), |_| {
            Ok(())
        })
        .unwrap_err();
        assert!(!matches!(err, PackError::PackfileTooLarge), "{err:?}");
    }

    #[test]
    fn payload_len_u32_max_is_a_clean_error() {
        // `pos + payload_len` used to overflow a 32-bit `usize` (wasm32)
        // here; the checks are now subtraction-based. 64-bit hosts get the
        // same clean `UnexpectedEof`; `mkit-core-wasm-check` runs the
        // wasm32 lane.
        let blob = write_blob_via_serialize(&[1, 2, 3]);
        let mut w = PackWriter::new_raw_only();
        w.push_raw(hash::hash(&blob), &blob).unwrap();
        let mut pack = w.finish().unwrap();
        pack[HEADER_LEN + 1..HEADER_LEN + 5].copy_from_slice(&u32::MAX.to_le_bytes());
        let split = pack.len() - TRAILER_LEN;
        let trailer = hash::hash(&pack[..split]);
        pack[split..].copy_from_slice(&trailer);

        assert!(matches!(
            PackEntries::new(&pack).unwrap_err(),
            PackError::UnexpectedEof
        ));
        assert!(matches!(
            delta_base_hashes(&pack).unwrap_err(),
            PackError::UnexpectedEof
        ));
        let err = decode_entries_with(&pack, &mut NoExternalBases, DecodeLimits::default(), |_| {
            Ok(())
        })
        .unwrap_err();
        assert!(matches!(err, PackError::UnexpectedEof), "{err:?}");
    }

    #[test]
    fn only_named_bases_stay_resident() {
        // Behavioral pin for the retention rule: an entry no delta names
        // is dropped after the sink, yet a later delta against an earlier
        // *named* entry (raw or delta target) still resolves.
        let (base, base_hash, variants) = base_and_variants(2);
        let unrelated = write_blob_via_serialize(b"never a base");
        let (t0_hash, t0, _) = &variants[0];
        let mut chained = t0.clone();
        let last = chained.len() - 1;
        chained[last] ^= 0x01;
        let mut w = PackWriter::new();
        w.push_raw(hash::hash(&unrelated), &unrelated).unwrap();
        w.push_raw(base_hash, &base).unwrap();
        w.push_delta(&base_hash, &variants[0].2).unwrap();
        w.push_delta(t0_hash, &delta::encode(t0, &chained).unwrap())
            .unwrap();
        let pack = w.finish().unwrap();
        let (_dir, store) = fresh_store();
        let unpacked = PackReader::read(&pack, &store).unwrap();
        let (report, _) = decode_collect(&pack, &mut NoExternalBases).unwrap();
        assert_eq!(report.ids, unpacked.stored);
    }

    /// A repository-membership source over in-memory objects, counting
    /// fetches (the review's `bomb ext` shape: bases live only here).
    struct Members {
        objects: std::collections::HashMap<Hash, Vec<u8>>,
        fetches: usize,
    }

    impl DeltaBaseSource for Members {
        fn base(&mut self, id: &Hash) -> Result<Option<Vec<u8>>, PackError> {
            self.fetches += 1;
            Ok(self.objects.get(id).cloned())
        }
    }

    /// Two 600 KiB member blobs and a tiny delta against each: `(source,
    /// [(base id, delta stream)])`. Each delta rebuilds a small blob, so
    /// its declared result is a few hundred bytes.
    fn large_member_bases() -> (Members, Vec<(Hash, Vec<u8>)>) {
        let mut objects = std::collections::HashMap::new();
        let mut deltas = Vec::new();
        for seed in [1u64, 2] {
            let base = write_blob_via_serialize(&incompressible_bytes(seed, 600 * 1024));
            let id = hash::hash(&base);
            let target = write_blob_via_serialize(&base[10..300]);
            deltas.push((id, delta::encode(&base, &target).unwrap()));
            objects.insert(id, base);
        }
        (
            Members {
                objects,
                fetches: 0,
            },
            deltas,
        )
    }

    fn pack_of_deltas(deltas: &[&(Hash, Vec<u8>)]) -> Vec<u8> {
        let mut w = PackWriter::new();
        for (base, stream) in deltas {
            w.push_delta(base, stream).unwrap();
        }
        w.finish().unwrap()
    }

    #[test]
    fn external_bases_are_charged_against_the_budget() {
        let one_mib = DecodeLimits::default().with_max_decoded_bytes(1 << 20);
        let (mut members, deltas) = large_member_bases();

        // A then B then A: A must stay cached while B is fetched, so the
        // two 600 KiB bases are held at once and pass the 1 MiB budget at
        // B's fetch. Only the first delta reaches the sink.
        let pack = pack_of_deltas(&[&deltas[0], &deltas[1], &deltas[0]]);
        let mut sink_calls = 0usize;
        let err = decode_entries_with(&pack, &mut members, one_mib, |_| {
            sink_calls += 1;
            Ok(())
        })
        .unwrap_err();
        assert!(matches!(err, PackError::PackfileTooLarge), "{err:?}");
        assert_eq!(sink_calls, 1);

        // A single base larger than the budget fails before any sink call.
        let half_mib = DecodeLimits::default().with_max_decoded_bytes(512 * 1024);
        let pack = pack_of_deltas(&[&deltas[0]]);
        let mut sink_calls = 0usize;
        let err = decode_entries_with(&pack, &mut members, half_mib, |_| {
            sink_calls += 1;
            Ok(())
        })
        .unwrap_err();
        assert!(matches!(err, PackError::PackfileTooLarge), "{err:?}");
        assert_eq!(sink_calls, 0);
    }

    #[test]
    fn external_base_charge_is_released_after_its_last_use() {
        // A, A, then B: A's last use comes before B is fetched, so A is
        // dropped and its charge credited back; the peak is one base, and
        // the same 1 MiB budget accepts the pack. A is fetched once.
        let one_mib = DecodeLimits::default().with_max_decoded_bytes(1 << 20);
        let (mut members, deltas) = large_member_bases();
        let pack = pack_of_deltas(&[&deltas[0], &deltas[0], &deltas[1]]);
        let report = decode_entries_with(&pack, &mut members, one_mib, |_| Ok(())).unwrap();
        assert_eq!(report.delta_count, 3);
        assert_eq!(members.fetches, 2);
    }

    #[test]
    fn sink_error_stops_decode() {
        let mut w = PackWriter::new();
        let mut ids = Vec::new();
        for i in 0..5u32 {
            let blob = write_blob_via_serialize(&i.to_le_bytes());
            ids.push(w.push_raw(hash::hash(&blob), &blob).unwrap());
        }
        let pack = w.finish().unwrap();

        let mut seen = Vec::new();
        let err = decode_entries_with(&pack, &mut NoExternalBases, DecodeLimits::default(), |e| {
            seen.push(e.id);
            if seen.len() == 2 {
                return Err(PackError::TrailingData);
            }
            Ok(())
        })
        .unwrap_err();
        assert!(matches!(err, PackError::TrailingData), "{err:?}");
        assert_eq!(seen, ids[..2]);
    }

    #[test]
    fn pack_entries_is_raw_only_false_for_delta() {
        let base = write_blob_via_serialize(b"base-for-delta-scan");
        let base_hash = hash::hash(&base);
        let target = write_blob_via_serialize(b"target-for-delta-scan!");
        let stream = delta::encode(&base, &target).unwrap();
        let mut w = PackWriter::new();
        w.push_raw(base_hash, &base).unwrap();
        w.push_delta(&base_hash, &stream).unwrap();
        let pack = w.finish().unwrap();
        let entries = PackEntries::new(&pack).unwrap();
        assert!(!entries.is_raw_only());
        assert_eq!(entries.first_non_raw_index(), Some(1));
    }
}
