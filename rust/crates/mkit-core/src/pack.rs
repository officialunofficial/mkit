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

pub mod window;

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
    let len = zstd_entry_len(payload)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(len)
        .map_err(|_| PackError::PackfileTooLarge)?;
    decompress_zstd_into(payload, &mut output)?;
    Ok(output)
}

/// [`decompress_zstd_entry`] over an explicit backend, so the
/// differential tests can drive the C and pure-Rust decoders through the
/// exact same claim / length checks.
#[cfg(all(test, feature = "pack-ruzstd"))]
fn decompress_zstd_entry_with(
    payload: &[u8],
    backend: fn(&[u8], usize) -> Result<Vec<u8>, PackError>,
) -> Result<Vec<u8>, PackError> {
    let (uncompressed_len, frame) = zstd_claim(payload)?;
    let decompressed = backend(frame, uncompressed_len)?;
    if decompressed.len() != uncompressed_len {
        return Err(PackError::DecompressedSizeMismatch(
            uncompressed_len,
            decompressed.len(),
        ));
    }
    Ok(decompressed)
}

fn zstd_claim(payload: &[u8]) -> Result<(usize, &[u8]), PackError> {
    if payload.len() < ZSTD_LEN_PREFIX {
        return Err(PackError::ZstdEntryTruncated);
    }
    let uncompressed_len =
        u32::from_le_bytes(payload[..ZSTD_LEN_PREFIX].try_into().expect("4 bytes")) as usize;
    if uncompressed_len > MAX_RAW_OBJECT_SIZE {
        return Err(PackError::DecompressedSizeOverCap(uncompressed_len));
    }
    let frame = &payload[ZSTD_LEN_PREFIX..];
    Ok((uncompressed_len, frame))
}

fn zstd_entry_len(payload: &[u8]) -> Result<usize, PackError> {
    zstd_claim(payload).map(|(len, _)| len)
}

/// Reserve and charge before calling this; neither backend grows or zero-fills
/// the output. Shared by lazy unpack and buffered/window entry decoding.
fn decompress_zstd_into(payload: &[u8], output: &mut Vec<u8>) -> Result<(), PackError> {
    let (len, frame) = zstd_claim(payload)?;
    output.clear();
    zstd_decompress_into(frame, len, output)?;
    if output.len() != len {
        return Err(PackError::DecompressedSizeMismatch(len, output.len()));
    }
    Ok(())
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
fn zstd_decompress_into(
    frame: &[u8],
    capacity: usize,
    output: &mut Vec<u8>,
) -> Result<(), PackError> {
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
    let mut decoder =
        zstd::bulk::Decompressor::new().map_err(|e| PackError::ZstdDecompress(e.to_string()))?;
    decoder
        .decompress_to_buffer(frame, output)
        .map_err(|e| PackError::ZstdDecompress(e.to_string()))?;
    if output.len() > capacity {
        return Err(PackError::ZstdDecompress(
            "zstd frame exceeds its claim".to_string(),
        ));
    }
    Ok(())
}

#[cfg(all(feature = "pack-zstd", test))]
fn zstd_decompress_capped(frame: &[u8], capacity: usize) -> Result<Vec<u8>, PackError> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| PackError::PackfileTooLarge)?;
    zstd_decompress_into(frame, capacity, &mut output)?;
    Ok(output)
}

/// Without the C library, the pure-Rust decoder serves every read.
#[cfg(all(not(feature = "pack-zstd"), feature = "pack-ruzstd"))]
fn zstd_decompress_into(
    frame: &[u8],
    capacity: usize,
    output: &mut Vec<u8>,
) -> Result<(), PackError> {
    ruzstd_decompress_into(frame, capacity, output)
}

#[cfg(not(any(feature = "pack-zstd", feature = "pack-ruzstd")))]
fn zstd_decompress_into(
    _frame: &[u8],
    _capacity: usize,
    _output: &mut Vec<u8>,
) -> Result<(), PackError> {
    Err(PackError::ZstdDecompress(
        "this build was compiled without the `pack-zstd` or `pack-ruzstd` feature".to_string(),
    ))
}

/// Fixed pure-Rust decode window cap: 8 MiB (`windowLog` 23).
/// This covers the default windows of non-ultra zstd levels. Larger windows
/// fail closed even if the output claim is larger; native C keeps its policy.
#[cfg(feature = "pack-ruzstd")]
#[cfg_attr(all(feature = "pack-zstd", not(test)), allow(dead_code))]
const RUZSTD_WINDOW_LIMIT: u64 = 8 << 20;

/// Read the base and result lengths from a zstd-compressed SPEC-DELTA v1 header.
///
/// `frame` is the zstd frame alone, without the pack frame, base hash or
/// uncompressed-length prefix. Only the nine-byte delta header is read out;
/// no allocation is sized from the delta stream's claim or result length.
/// The pure-Rust backend uses the patched block bound and fixed 8 MiB window.
/// Its working memory remains within the existing 28 MiB allowance, even when
/// it retains window history before emitting the prefix. C-only builds use a
/// streaming decoder with the same window cap. The decoder is dropped here,
/// before the caller performs its ordinary budgeted decode.
///
/// This is a prefix inspection, not full frame or delta validation. Callers
/// must still decode and verify the complete object after checking metadata.
///
/// # Errors
/// Unsupported compression, malformed/truncated compression or delta header.
pub fn peek_delta_header(frame: &[u8]) -> Result<(u32, u32), PackError> {
    let mut header = [0; delta::HEADER_LEN];
    read_delta_header_prefix(frame, &mut header)?;
    if header[0] != delta::STREAM_VERSION {
        return Err(PackError::DeltaApply(MkitError::UnsupportedObjectVersion));
    }
    Ok((
        u32::from_le_bytes([header[1], header[2], header[3], header[4]]),
        u32::from_le_bytes([header[5], header[6], header[7], header[8]]),
    ))
}

#[cfg(feature = "pack-ruzstd")]
fn read_delta_header_prefix(
    frame: &[u8],
    header: &mut [u8; delta::HEADER_LEN],
) -> Result<(), PackError> {
    use ruzstd::decoding::{FrameDecoder, StreamingDecoder};
    use std::io::Read as _;
    require_zstd_frame_magic(frame)?;
    let mut decoder = FrameDecoder::new();
    decoder.set_max_window_size(RUZSTD_WINDOW_LIMIT);
    let mut stream = StreamingDecoder::new_with_decoder(frame, decoder)
        .map_err(|error| PackError::ZstdDecompress(error.to_string()))?;
    stream
        .read_exact(header)
        .map_err(|error| PackError::ZstdDecompress(error.to_string()))
}

#[cfg(all(feature = "pack-zstd", not(feature = "pack-ruzstd")))]
fn read_delta_header_prefix(
    frame: &[u8],
    header: &mut [u8; delta::HEADER_LEN],
) -> Result<(), PackError> {
    use std::io::Read as _;
    require_zstd_frame_magic(frame)?;
    let mut stream = zstd::stream::read::Decoder::with_buffer(frame)
        .map_err(|error| PackError::ZstdDecompress(error.to_string()))?
        .single_frame();
    stream
        .window_log_max(23)
        .map_err(|error| PackError::ZstdDecompress(error.to_string()))?;
    stream
        .read_exact(header)
        .map_err(|error| PackError::ZstdDecompress(error.to_string()))
}

#[cfg(not(any(feature = "pack-zstd", feature = "pack-ruzstd")))]
fn read_delta_header_prefix(
    frame: &[u8],
    _header: &mut [u8; delta::HEADER_LEN],
) -> Result<(), PackError> {
    zstd_decompress_into(frame, 0, &mut Vec::new())
}

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
/// Memory: the output is reserved fallibly to the claim without zero-filling.
/// Unpack charges that reservation before allocation. The pure-Rust decoder's
/// ring buffer is separate working memory. With the fixed 8 MiB window and
/// vendored RFC block preflight, working allocations stay below 28 MiB,
/// including old/new ring allocations during growth and bounded block scratch.
/// This fixed allowance is outside the owned-payload resident cap, as for the window reader's
/// carry/output budget. No output allocation grows past the admitted claim.
///
/// Allocating adapter for differential tests. Production decode supplies its
/// already reserved output to `ruzstd_decompress_into` when `pack-zstd` is off,
/// and to the C `zstd_decompress_into` when it is on.
#[cfg(feature = "pack-ruzstd")]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn ruzstd_decompress_capped(
    frame: &[u8],
    capacity: usize,
) -> Result<Vec<u8>, PackError> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| PackError::PackfileTooLarge)?;
    ruzstd_decompress_into(frame, capacity, &mut output)?;
    Ok(output)
}

#[cfg(feature = "pack-ruzstd")]
#[cfg_attr(all(feature = "pack-zstd", not(test)), allow(dead_code))]
fn ruzstd_decompress_into(
    frame: &[u8],
    capacity: usize,
    output: &mut Vec<u8>,
) -> Result<(), PackError> {
    use ruzstd::decoding::{FrameDecoder, StreamingDecoder};
    use std::io::Read as _;

    fn fail(msg: impl std::fmt::Display) -> PackError {
        PackError::ZstdDecompress(msg.to_string())
    }

    require_zstd_frame_magic(frame)?;
    let cap = u64::try_from(capacity).unwrap_or(u64::MAX);
    let mut decoder = FrameDecoder::new();
    decoder.set_max_window_size(RUZSTD_WINDOW_LIMIT);
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

    let out = output;
    out.clear();
    let mut chunk = [0; 8192];
    // ruzstd's in-memory decoder never yields Interrupted.
    loop {
        // Probe one extra byte without allocating past the claim.
        let room = capacity.saturating_sub(out.len());
        let take = room.saturating_add(1).min(chunk.len());
        let n = stream.read(&mut chunk[..take]).map_err(fail)?;
        if n == 0 {
            break;
        }
        if n > room {
            return Err(fail(format_args!(
                "zstd frame decompresses past the claimed {capacity} bytes"
            )));
        }
        out.extend_from_slice(&chunk[..n]);
    }
    let decoder = &stream.decoder;
    if !decoder.is_finished() {
        return Err(fail("zstd frame ended before its last block"));
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
    Ok(())
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
        if ENTRY_FRAME_LEN > split - pos {
            return Err(PackError::UnexpectedEof);
        }
        let etype = pack_bytes[pos];
        pos = pos.checked_add(1).ok_or(PackError::UnexpectedEof)?;
        let payload_len = u32::from_le_bytes(
            pack_bytes[pos..pos.checked_add(4).ok_or(PackError::UnexpectedEof)?]
                .try_into()
                .expect("4 bytes"),
        ) as usize;
        pos = pos.checked_add(4).ok_or(PackError::UnexpectedEof)?;
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
            base.copy_from_slice(
                &pack_bytes[pos..pos
                    .checked_add(TRAILER_LEN)
                    .ok_or(PackError::UnexpectedEof)?],
            );
            if seen.insert(base) {
                bases.push(base);
            }
        }
        pos = pos
            .checked_add(payload_len)
            .ok_or(PackError::UnexpectedEof)?;
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
    /// targets and successfully staged compressed raw payloads increment
    /// this counter. Borrowed raw entries never increment it.
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
        let budget = ResidentBudget::new(resident_bytes_cap(pack_bytes.len()), owned_bytes);
        Self::read_with_budget(pack_bytes, store, payload_cap, &budget)
    }

    fn read_with_budget(
        pack_bytes: &[u8],
        store: &ObjectStore,
        payload_cap: u64,
        budget: &ResidentBudget<'_>,
    ) -> Result<UnpackReport, PackError> {
        let mut parser = PackEntries::new_with_payload_cap(pack_bytes, payload_cap)?;
        // Phase 1 retains only borrowed wire frames. Count uses without
        // decompressing, and remember the final position naming each base.
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(parser.entry_count())
            .map_err(|_| PackError::PackfileTooLarge)?;
        let mut uses: std::collections::HashMap<Hash, BaseUses> = std::collections::HashMap::new();
        for position in 0..parser.entry_count() {
            let entry = parser.next_encoded_entry()?;
            if let Entry::Delta { base, .. } = entry {
                let usage = uses.entry(base).or_default();
                usage.remaining += 1;
                usage.last_position = position;
            }
            entries.push(entry);
        }
        let batch = store.batch();
        // Phase 2 keeps the native fan-out. Each worker decompresses its
        // current raw frame, stages it, and drops unneeded owned bytes.
        let raw_frames: Vec<_> = entries
            .iter()
            .enumerate()
            .filter_map(|(position, entry)| match entry {
                Entry::Raw(payload) => Some((position, *payload)),
                Entry::Delta { .. } => None,
            })
            .collect();
        let raw_results = stage_raw_entries(&batch, &raw_frames, &uses, budget);
        finish_pack_read(entries, raw_results, uses, budget, store, batch)
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

    /// Fetch with allocation admission. The default charges after `base`
    /// returns; sources that know the length first should override this to
    /// call `admit` before allocating, as `&ObjectStore` does. Before
    /// returning `Some(bytes)`, every override must successfully invoke
    /// `admit` exactly once with `bytes.len()` and propagate its error.
    ///
    /// # Errors
    /// Returns a source failure or the error from `admit`.
    fn base_with_admission(
        &mut self,
        id: &Hash,
        admit: impl FnOnce(usize) -> Result<(), PackError>,
    ) -> Result<Option<Vec<u8>>, PackError> {
        let Some(bytes) = self.base(id)? else {
            return Ok(None);
        };
        admit(bytes.len())?;
        Ok(Some(bytes))
    }
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

    fn base_with_admission(
        &mut self,
        id: &Hash,
        admit: impl FnOnce(usize) -> Result<(), PackError>,
    ) -> Result<Option<Vec<u8>>, PackError> {
        if !self.contains(id) {
            return Ok(None);
        }
        self.read_with_allocator(id, |len| {
            admit(len)?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(len)
                .map_err(|_| PackError::PackfileTooLarge)?;
            Ok(bytes)
        })
        .map(Some)
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
    /// Offset of the complete encoded frame in the source pack.
    pub frame_offset: u64,
    /// Length of the complete encoded frame, including type and length.
    pub frame_length: u64,
    /// Encoded frame type (`0x00`, `0x02`, `0x03`, or `0x04`).
    pub wire_type: u8,
    /// Delta base id, if this frame is a delta.
    pub delta_base: Option<Hash>,
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
    entry_geometry: Option<(u64, u64)>,
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
    /// Bound encoded payloads and delta streams separately from canonical bytes.
    #[must_use]
    pub const fn with_entry_geometry(mut self, frame: u64, delta_stream: u64) -> Self {
        self.entry_geometry = Some((frame, delta_stream));
        self
    }

    fn check_frame(&self, kind: u8, payload: &[u8]) -> Result<(), PackError> {
        if let Some((frame, stream)) = self.entry_geometry {
            let bytes = payload.len() as u64;
            if bytes > frame || (kind == 2 && bytes > stream.saturating_add(32)) {
                return Err(PackError::PackfileTooLarge);
            }
            if kind == 4
                && zstd_claim(payload.get(32..).ok_or(PackError::DeltaEntryTruncated)?)?.0 as u64
                    > stream
            {
                return Err(PackError::PackfileTooLarge);
            }
        }
        Ok(())
    }
}

impl Default for DecodeLimits {
    fn default() -> Self {
        Self {
            max_decoded_bytes: Self::DEFAULT_MAX_DECODED_BYTES,
            entry_geometry: None,
        }
    }
}

/// Running total of a decode's claimed allocations against
/// [`DecodeLimits::max_decoded_bytes`].
// Distinct from ResidentBudget: compressed and delta claims accumulate over
// the entire storeless decode; only external-base charges are credited on last
// use, matching DecodeLimits. PackReader uses the peak resident cap instead.
#[derive(Debug)]
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
    budget: &'b mut DecodeBudget,
    charged: &'b mut std::collections::HashMap<Hash, u64>,
}

impl<B: DeltaBaseSource> DeltaBaseSource for ChargedBases<'_, B> {
    const VERIFIED: bool = B::VERIFIED;

    fn base(&mut self, id: &Hash) -> Result<Option<Vec<u8>>, PackError> {
        self.base_with_admission(id, |_| Ok(()))
    }

    fn base_with_admission(
        &mut self,
        id: &Hash,
        admit: impl FnOnce(usize) -> Result<(), PackError>,
    ) -> Result<Option<Vec<u8>>, PackError> {
        self.inner.base_with_admission(id, |len| {
            let charged_len = u64::try_from(len).map_err(|_| PackError::PackfileTooLarge)?;
            self.budget.charge(charged_len)?;
            admit(len)?;
            let held = self.charged.entry(*id).or_default();
            *held = held.saturating_add(charged_len);
            Ok(())
        })
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

#[derive(Debug)]
struct CursorFrame<'a> {
    entry: PackEntry<'a>,
    frame_offset: u64,
    frame_length: u64,
    wire_type: u8,
    delta_base: Option<Hash>,
}

/// A store-less pack decoder that pauses at an unresolved external base.
///
/// [`Self::new`] performs the same framing and allocation preflight as
/// [`decode_entries_with`]. Each successful entry reaches the sink exactly
/// once across calls to [`Self::resume`]; a missing base leaves its frame at
/// the cursor so the caller can supply that base and resume. Other errors
/// end the decode. The same cumulative budget spans every resume call.
#[derive(Debug)]
pub struct PackDecodeCursor<'a> {
    entries: Vec<Option<CursorFrame<'a>>>,
    next: usize,
    budget: DecodeBudget,
    charged: std::collections::HashMap<Hash, u64>,
    uses: std::collections::HashMap<Hash, usize>,
    in_pack: std::collections::HashMap<Hash, Cow<'a, [u8]>>,
    report: Option<DecodeReport>,
}

impl<'a> PackDecodeCursor<'a> {
    /// Preflight one content-addressed pack without fetching external bases.
    ///
    /// # Errors
    /// Invalid framing, unsupported content, or a decoded-size claim over
    /// `limits` is returned before the sink observes any entry.
    pub fn new(pack: &'a [u8], limits: DecodeLimits) -> Result<Self, PackError> {
        let mut pack_entries = PackEntries::new(pack)?;
        let mut budget = DecodeBudget {
            used: 0,
            max: limits.max_decoded_bytes,
        };
        charge_compressed_claims(pack, &mut budget)?;

        let mut entries = Vec::with_capacity(pack_entries.entry_count());
        while let Some(entry) = pack_entries.next() {
            let entry = entry?;
            let payload = pack_entries
                .last_payload_range()
                .ok_or(PackError::UnexpectedEof)?;
            limits.check_frame(
                pack[payload.start - ENTRY_FRAME_LEN],
                &pack[payload.clone()],
            )?;
            let offset = payload
                .start
                .checked_sub(ENTRY_FRAME_LEN)
                .ok_or(PackError::UnexpectedEof)?;
            let delta_base = match &entry {
                PackEntry::Delta { base, .. } => Some(*base),
                PackEntry::Raw { .. } => None,
            };
            entries.push(Some(CursorFrame {
                entry,
                frame_offset: offset as u64,
                frame_length: (payload.end - offset) as u64,
                wire_type: pack[offset],
                delta_base,
            }));
        }

        // As in decode_entries_with, all delta result claims precede the
        // first object validation; base charges are added only on use.
        let mut uses = std::collections::HashMap::new();
        for frame in entries.iter().flatten() {
            if let PackEntry::Delta { base, stream } = &frame.entry {
                if let Some(result_len) = le_u32_at(stream, 5) {
                    budget.charge(result_len)?;
                }
                let n = uses.entry(*base).or_insert(0usize);
                *n = n.saturating_add(1);
            }
        }
        Ok(Self {
            report: Some(DecodeReport {
                ids: Vec::with_capacity(entries.len()),
                ..DecodeReport::default()
            }),
            entries,
            next: 0,
            budget,
            charged: std::collections::HashMap::new(),
            uses,
            in_pack: std::collections::HashMap::new(),
        })
    }

    /// Set the remaining decode's allocation cap. A caller retaining
    /// external objects beside this cursor can lower the cap as those
    /// objects accumulate. Earlier claims and live bases stay charged.
    ///
    /// # Errors
    /// [`PackError::PackfileTooLarge`] if bytes already charged exceed
    /// `max`; the previous cap is kept in that case.
    pub fn set_max_decoded_bytes(&mut self, max: u64) -> Result<(), PackError> {
        if self.budget.used > max {
            return Err(PackError::PackfileTooLarge);
        }
        self.budget.max = max;
        Ok(())
    }

    /// Continue from the first unprocessed frame.
    ///
    /// # Errors
    /// [`PackError::DeltaBaseMissing`] leaves the current frame ready to
    /// retry after `bases` gains that id. Any other error is terminal. The
    /// sink may have seen earlier entries when either error is returned.
    #[allow(clippy::too_many_lines)] // One stateful loop preserves frame order and charges.
    pub fn resume<B: DeltaBaseSource>(
        &mut self,
        bases: &mut B,
        mut sink: impl FnMut(DecodedEntry<'_>) -> Result<(), PackError>,
    ) -> Result<DecodeReport, PackError> {
        if self.report.is_none() {
            return Err(PackError::PackfileCorrupted);
        }
        let mut bases = ChargedBases {
            inner: bases,
            budget: &mut self.budget,
            charged: &mut self.charged,
        };
        while self.next < self.entries.len() {
            let frame = self.entries[self.next]
                .take()
                .ok_or(PackError::PackfileCorrupted)?;
            let CursorFrame {
                entry,
                frame_offset,
                frame_length,
                wire_type,
                delta_base,
            } = frame;
            match entry {
                PackEntry::Raw { bytes } => {
                    let object = validate_storable_object(&bytes)?;
                    let id = crate::object::id_from_object(&object, &bytes);
                    sink(DecodedEntry {
                        id,
                        bytes: bytes.as_ref(),
                        object,
                        from_delta: false,
                        frame_offset,
                        frame_length,
                        wire_type,
                        delta_base,
                    })?;
                    if self.uses.contains_key(&id) {
                        self.in_pack.insert(id, bytes);
                    }
                    let report = self.report.as_mut().ok_or(PackError::PackfileCorrupted)?;
                    report.raw_count += 1;
                    report.ids.push(id);
                }
                PackEntry::Delta { base, stream } => {
                    // A source may return invalid bytes, which is publicly
                    // indistinguishable from absence. Undo that attempted
                    // base's charge before a caller retries with good bytes.
                    let before_used = bases.budget.used;
                    let before_charged = bases.charged.get(&base).copied();
                    let resolved = match resolve_delta_target(
                        &mut bases,
                        &mut self.in_pack,
                        base,
                        stream.as_ref(),
                    ) {
                        Ok(resolved) => resolved,
                        Err(error @ PackError::DeltaBaseMissing(_)) => {
                            bases.budget.used = before_used;
                            match before_charged {
                                Some(len) => {
                                    bases.charged.insert(base, len);
                                }
                                None => {
                                    bases.charged.remove(&base);
                                }
                            }
                            self.entries[self.next] = Some(CursorFrame {
                                entry: PackEntry::Delta { base, stream },
                                frame_offset,
                                frame_length,
                                wire_type,
                                delta_base,
                            });
                            return Err(error);
                        }
                        Err(error) => return Err(error),
                    };
                    drop(stream);
                    if let Some(left) = self.uses.get_mut(&base) {
                        *left = left.saturating_sub(1);
                        if *left == 0 {
                            self.uses.remove(&base);
                            self.in_pack.remove(&base);
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
                        frame_offset,
                        frame_length,
                        wire_type,
                        delta_base,
                    })?;
                    if self.uses.contains_key(&id) {
                        self.in_pack.insert(id, Cow::Owned(resolved));
                    }
                    let report = self.report.as_mut().ok_or(PackError::PackfileCorrupted)?;
                    report.delta_count += 1;
                    report.ids.push(id);
                }
            }
            self.next += 1;
        }
        self.report.take().ok_or(PackError::PackfileCorrupted)
    }
}

/// Store-less decode of `pack` over an explicit [`DeltaBaseSource`].
///
/// Validates the pack exactly as [`PackReader::read`] does — header,
/// trailer, caps and framing via [`PackEntries`], every entry drained
/// (and `0x03`/`0x04` decompressed) before any entry is judged — then,
/// in pack order, validates each raw payload as a storable canonical
/// object, resolves each delta against an earlier entry or else
/// `bases`, validates the reconstructed target, and hands every entry to
/// `sink`, without writing to the store. Given `&ObjectStore` as `bases`
/// and non-binding limits, it decodes the same valid objects as
/// `PackReader::read`. Its cumulative-budget and decompression preflight
/// precede object validation; lazy unpack instead reports errors as their
/// pack positions are reached, so malformed packs can differ in error order.
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
/// names it is reached. After preflight, the first [`PackError`] in pack
/// order, or the first error `sink` returns. `sink` may already have seen earlier
/// entries when an error is returned; a consumer staging them must
/// discard that staging.
pub fn decode_entries_with<B: DeltaBaseSource>(
    pack: &[u8],
    bases: &mut B,
    limits: DecodeLimits,
    sink: impl FnMut(DecodedEntry<'_>) -> Result<(), PackError>,
) -> Result<DecodeReport, PackError> {
    PackDecodeCursor::new(pack, limits)?.resume(bases, sink)
}

/// Decode one complete encoded frame, using the same payload parser and
/// repository-supplied base contract as [`decode_entries_with`]. The caller
/// authenticates the containing pack and its frame offset separately.
///
/// # Errors
/// Invalid framing, unsupported version, missing or invalid base, decoded
/// object, or a result beyond `limits`.
pub fn decode_frame_with<B: DeltaBaseSource>(
    frame: &[u8],
    version: u32,
    bases: &mut B,
    limits: DecodeLimits,
) -> Result<(Hash, Vec<u8>), PackError> {
    if version != VERSION && version != VERSION_V2 {
        return Err(PackError::UnsupportedVersion(version));
    }
    if frame.len() < ENTRY_FRAME_LEN {
        return Err(PackError::UnexpectedEof);
    }
    let payload_len = u32::from_le_bytes(
        frame[1..5]
            .try_into()
            .map_err(|_| PackError::UnexpectedEof)?,
    ) as usize;
    if Some(frame.len()) != ENTRY_FRAME_LEN.checked_add(payload_len) {
        return Err(PackError::UnexpectedEof);
    }
    let payload = &frame[ENTRY_FRAME_LEN..];
    limits.check_frame(frame[0], payload)?;
    match frame[0] {
        0x00 if payload.len() as u64 > limits.max_decoded_bytes => {
            return Err(PackError::PackfileTooLarge);
        }
        0x03 if zstd_claim(payload)?.0 as u64 > limits.max_decoded_bytes => {
            return Err(PackError::PackfileTooLarge);
        }
        0x04 if payload.len() >= hash::HASH_LEN
            && zstd_claim(&payload[hash::HASH_LEN..])?.0 as u64
                > limits
                    .entry_geometry
                    .map_or(limits.max_decoded_bytes, |(_, stream)| stream) =>
        {
            return Err(PackError::PackfileTooLarge);
        }
        _ => {}
    }
    decode_entry_with(
        decode_payload(frame[0], version, &frame[ENTRY_FRAME_LEN..])?,
        bases,
        limits,
    )
}

/// Resolve one already-framed entry, such as a [`window::WindowReader`]
/// yield, into its canonical bytes and id, with the payload rules of
/// [`decode_frame_with`]: a delta's base comes only from `bases`, and the
/// result is a storable canonical object bounded by `limits`.
///
/// # Errors
/// A missing or invalid base, an invalid object, or a result beyond `limits`.
pub fn decode_entry_with<B: DeltaBaseSource>(
    entry: PackEntry<'_>,
    bases: &mut B,
    limits: DecodeLimits,
) -> Result<(Hash, Vec<u8>), PackError> {
    let bytes = match entry {
        PackEntry::Raw { bytes } => bytes.into_owned(),
        PackEntry::Delta { base, stream } => {
            if limits
                .entry_geometry
                .is_some_and(|(_, cap)| stream.len() as u64 > cap)
                || validate_delta_result_size(stream.as_ref())? as u64 > limits.max_decoded_bytes
            {
                return Err(PackError::PackfileTooLarge);
            }
            resolve_delta_target(
                bases,
                &mut std::collections::HashMap::new(),
                base,
                stream.as_ref(),
            )?
        }
    };
    if bytes.len() as u64 > limits.max_decoded_bytes {
        return Err(PackError::PackfileTooLarge);
    }
    let object = validate_storable_object(&bytes)?;
    let id = crate::object::id_from_object(&object, &bytes);
    Ok((id, bytes))
}

/// Replay staging results in pack order; deferred admissions are strict here.
fn finish_pack_read<'b>(
    entries: Vec<Entry<'_>>,
    raw_results: RawStageResults<'b>,
    mut uses: std::collections::HashMap<Hash, BaseUses>,
    budget: &'b ResidentBudget<'_>,
    store: &ObjectStore,
    batch: crate::batch::WriteBatch<'_>,
) -> Result<UnpackReport, PackError> {
    let mut bases = store;
    let mut raw_results = raw_results.into_iter();
    let mut in_pack = std::collections::HashMap::new();
    let mut report = UnpackReport::default();
    // Phase 3 exposes bases only at their pack position and releases
    // them immediately after their last use, including cached store bases.
    for (position, entry) in entries.into_iter().enumerate() {
        match entry {
            Entry::Raw(payload) => {
                let (stored_hash, retained) = raw_results
                    .next()
                    .expect("raw frame result")
                    .unwrap_or_else(|| {
                        prepare_and_stage_raw(&batch, position, payload, &uses, budget)
                    })?;
                if has_remaining_uses(&uses, &stored_hash) {
                    if let Some(bytes) = retained {
                        in_pack.insert(stored_hash, ResidentBytes::Owned(bytes));
                    } else if let EncodedPayload::Plain(bytes) = payload {
                        in_pack.insert(stored_hash, ResidentBytes::Borrowed(bytes));
                    }
                }
                report.raw_count += 1;
                report.stored.push(stored_hash);
            }
            Entry::Delta { base, stream } => {
                let stream = stream.decode(budget)?;
                let stored_hash = stage_delta_target(
                    &mut bases,
                    &batch,
                    &mut in_pack,
                    &mut uses,
                    budget,
                    base,
                    stream.as_ref(),
                )?;
                report.delta_count += 1;
                report.stored.push(stored_hash);
            }
        }
    }
    batch.commit()?;
    Ok(report)
}

/// Owned payload cap: `max(2 * MAX_RAW_OBJECT_SIZE, 16 * pack_len)`.
/// The 2 GiB floor covers a maximum-size base plus target; a compressed delta
/// also charges its decoded stream, so a 1 GiB store base plus 1 GiB target
/// from a small pack is refused while that stream is resident.
/// Saturation avoids arithmetic traps on 32-bit hosts.
fn resident_bytes_cap(pack_len: usize) -> usize {
    MAX_RAW_OBJECT_SIZE
        .saturating_mul(2)
        .max(pack_len.saturating_mul(16))
}

/// Peak owned payload bytes, released with each reservation. Unlike
/// `DecodeBudget`, this applies to `PackReader::read` and bounds live
/// compressed output, delta targets and external bases rather than total work.
struct ResidentBudget<'a> {
    cap: usize,
    used: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    peak: std::sync::atomic::AtomicUsize,
    owned_bytes: Option<&'a AtomicU64>,
}

impl<'a> ResidentBudget<'a> {
    fn new(cap: usize, owned_bytes: Option<&'a AtomicU64>) -> Self {
        Self {
            cap,
            used: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            peak: std::sync::atomic::AtomicUsize::new(0),
            owned_bytes,
        }
    }

    fn charge(&self, len: usize) -> Result<Reservation<'_>, PackError> {
        let previous = self
            .used
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                used.checked_add(len).filter(|&total| total <= self.cap)
            })
            .map_err(|_| PackError::PackfileTooLarge)?;
        #[cfg(test)]
        self.peak.fetch_max(previous + len, Ordering::Relaxed);
        #[cfg(not(test))]
        let _ = previous;
        Ok(Reservation { budget: self, len })
    }

    fn allocate(&self, len: usize) -> Result<OwnedBytes<'_>, PackError> {
        self.charge(len)?.allocate()
    }

    fn record_owned(&self, len: usize) {
        if let Some(counter) = self.owned_bytes {
            counter.fetch_add(len as u64, Ordering::Relaxed);
        }
    }
}

struct Reservation<'a> {
    budget: &'a ResidentBudget<'a>,
    len: usize,
}

impl<'a> Reservation<'a> {
    fn allocate(self) -> Result<OwnedBytes<'a>, PackError> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(self.len)
            .map_err(|_| PackError::PackfileTooLarge)?;
        Ok(OwnedBytes {
            bytes,
            _reservation: self,
        })
    }
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        self.budget.used.fetch_sub(self.len, Ordering::Relaxed);
    }
}

struct OwnedBytes<'a> {
    bytes: Vec<u8>,
    _reservation: Reservation<'a>,
}

enum ResidentBytes<'p, 'b> {
    Borrowed(&'p [u8]),
    Owned(OwnedBytes<'b>),
}

impl AsRef<[u8]> for ResidentBytes<'_, '_> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Borrowed(bytes) => bytes,
            Self::Owned(bytes) => &bytes.bytes,
        }
    }
}

#[derive(Clone, Copy)]
enum EncodedPayload<'p> {
    Plain(&'p [u8]),
    Zstd(&'p [u8]),
}

impl<'p> EncodedPayload<'p> {
    fn decode<'b>(
        self,
        budget: &'b ResidentBudget<'_>,
    ) -> Result<ResidentBytes<'p, 'b>, PackError> {
        match self {
            Self::Plain(bytes) => Ok(ResidentBytes::Borrowed(bytes)),
            Self::Zstd(payload) => {
                let len = zstd_entry_len(payload)?;
                let mut output = budget.allocate(len)?;
                decompress_zstd_into(payload, &mut output.bytes)?;
                Ok(ResidentBytes::Owned(output))
            }
        }
    }

    /// Only a failed admission is deferred; allocation and decode errors are permanent.
    fn decode_for_staging<'b>(
        self,
        budget: &'b ResidentBudget<'_>,
    ) -> Result<Option<ResidentBytes<'p, 'b>>, PackError> {
        match self {
            Self::Plain(bytes) => Ok(Some(ResidentBytes::Borrowed(bytes))),
            Self::Zstd(payload) => {
                let len = zstd_entry_len(payload)?;
                let Ok(reservation) = budget.charge(len) else {
                    return Ok(None);
                };
                let mut output = reservation.allocate()?;
                decompress_zstd_into(payload, &mut output.bytes)?;
                Ok(Some(ResidentBytes::Owned(output)))
            }
        }
    }
}

#[derive(Clone, Copy)]
enum Entry<'p> {
    Raw(EncodedPayload<'p>),
    Delta {
        base: Hash,
        stream: EncodedPayload<'p>,
    },
}

#[derive(Default)]
struct BaseUses {
    remaining: usize,
    last_position: usize,
}

fn has_remaining_uses(uses: &std::collections::HashMap<Hash, BaseUses>, hash: &Hash) -> bool {
    uses.get(hash).is_some_and(|usage| usage.remaining != 0)
}

// None marks deferred admission or work skipped after an earlier failure.
type RawStageResult<'b> = Option<Result<(Hash, Option<OwnedBytes<'b>>), PackError>>;
type RawStageResults<'b> = Vec<RawStageResult<'b>>;

/// Validate, hash and stage independent raw frames, preserving result order.
/// Errors stay in the result queue until phase 3 reaches that pack position.
fn stage_raw_entries<'b>(
    batch: &crate::batch::WriteBatch<'_>,
    frames: &[(usize, EncodedPayload<'_>)],
    uses: &std::collections::HashMap<Hash, BaseUses>,
    budget: &'b ResidentBudget<'_>,
) -> RawStageResults<'b> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        const ENTRIES_PER_THREAD: usize = 8;
        let threads = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
        if threads > 1 && frames.len() >= ENTRIES_PER_THREAD.saturating_mul(threads) {
            return stage_raw_entries_parallel(batch, frames, uses, budget, threads);
        }
    }
    let first_failure = std::sync::atomic::AtomicUsize::new(usize::MAX);
    frames
        .iter()
        .map(|&(position, payload)| {
            stage_raw_in_phase_two(batch, position, payload, uses, budget, &first_failure)
        })
        .collect()
}

#[cfg(not(target_arch = "wasm32"))]
fn stage_raw_entries_parallel<'b>(
    batch: &crate::batch::WriteBatch<'_>,
    frames: &[(usize, EncodedPayload<'_>)],
    uses: &std::collections::HashMap<Hash, BaseUses>,
    budget: &'b ResidentBudget<'_>,
    threads: usize,
) -> RawStageResults<'b> {
    let first_failure = &std::sync::atomic::AtomicUsize::new(usize::MAX);
    let chunk_size = frames.len().div_ceil(threads).max(1);
    let mut out = Vec::with_capacity(frames.len());
    std::thread::scope(|scope| {
        let handles: Vec<_> = frames
            .chunks(chunk_size)
            .map(|chunk| {
                scope.spawn(move || {
                    chunk
                        .iter()
                        .map(|&(position, payload)| {
                            stage_raw_in_phase_two(
                                batch,
                                position,
                                payload,
                                uses,
                                budget,
                                first_failure,
                            )
                        })
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

fn stage_raw_in_phase_two<'b>(
    batch: &crate::batch::WriteBatch<'_>,
    position: usize,
    payload: EncodedPayload<'_>,
    uses: &std::collections::HashMap<Hash, BaseUses>,
    budget: &'b ResidentBudget<'_>,
    first_failure: &std::sync::atomic::AtomicUsize,
) -> RawStageResult<'b> {
    if position > first_failure.load(Ordering::Relaxed) {
        return None;
    }
    let result = match payload.decode_for_staging(budget) {
        Ok(Some(payload)) => stage_decoded_raw(batch, position, payload, uses, budget),
        Ok(None) => return None,
        Err(error) => Err(error),
    };
    if result.is_err() {
        first_failure.fetch_min(position, Ordering::Relaxed);
    }
    Some(result)
}

fn prepare_and_stage_raw<'b>(
    batch: &crate::batch::WriteBatch<'_>,
    position: usize,
    payload: EncodedPayload<'_>,
    uses: &std::collections::HashMap<Hash, BaseUses>,
    budget: &'b ResidentBudget<'_>,
) -> Result<(Hash, Option<OwnedBytes<'b>>), PackError> {
    stage_decoded_raw(batch, position, payload.decode(budget)?, uses, budget)
}

fn stage_decoded_raw<'b>(
    batch: &crate::batch::WriteBatch<'_>,
    position: usize,
    payload: ResidentBytes<'_, 'b>,
    uses: &std::collections::HashMap<Hash, BaseUses>,
    budget: &'b ResidentBudget<'_>,
) -> Result<(Hash, Option<OwnedBytes<'b>>), PackError> {
    let obj = validate_storable_object(payload.as_ref())?;
    let stored_hash = crate::object::id_from_object(&obj, payload.as_ref());
    batch.write_prehashed(stored_hash, &[payload.as_ref()])?;
    let retained = if let ResidentBytes::Owned(bytes) = payload {
        budget.record_owned(bytes.bytes.len());
        if uses
            .get(&stored_hash)
            .is_some_and(|usage| usage.last_position > position)
        {
            Some(bytes)
        } else {
            None
        }
    } else {
        None
    };
    Ok((stored_hash, retained))
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
/// [`PackReader::read`] consumes the same private frame parser, deferring
/// decompression until validation/staging or delta application.
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
            if ENTRY_FRAME_LEN > split - pos {
                return Err(PackError::UnexpectedEof);
            }
            let etype = bytes[pos];
            pos = pos.checked_add(1).ok_or(PackError::UnexpectedEof)?;
            let payload_len = u32::from_le_bytes(
                bytes[pos..pos.checked_add(4).ok_or(PackError::UnexpectedEof)?]
                    .try_into()
                    .expect("4 bytes"),
            ) as usize;
            pos = pos.checked_add(4).ok_or(PackError::UnexpectedEof)?;
            total_payload = total_payload.saturating_add(payload_len as u64);
            if total_payload > payload_cap {
                return Err(PackError::PackfileTooLarge);
            }
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
            pos = pos
                .checked_add(payload_len)
                .ok_or(PackError::UnexpectedEof)?;
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

    fn next_encoded_entry(&mut self) -> Result<Entry<'a>, PackError> {
        if ENTRY_FRAME_LEN > self.split - self.pos {
            return Err(PackError::UnexpectedEof);
        }
        let etype = self.bytes[self.pos];
        self.pos = self.pos.checked_add(1).ok_or(PackError::UnexpectedEof)?;
        let payload_len = u32::from_le_bytes(
            self.bytes[self.pos..self.pos.checked_add(4).ok_or(PackError::UnexpectedEof)?]
                .try_into()
                .expect("4 bytes"),
        ) as usize;
        self.pos = self.pos.checked_add(4).ok_or(PackError::UnexpectedEof)?;
        if payload_len > self.split - self.pos {
            return Err(PackError::UnexpectedEof);
        }
        let payload_start = self.pos;
        let payload_end = self
            .pos
            .checked_add(payload_len)
            .ok_or(PackError::UnexpectedEof)?;
        let payload = &self.bytes[payload_start..payload_end];
        self.last_payload_range = Some(payload_start..payload_end);
        self.pos = payload_end;
        self.yielded += 1;
        encoded_payload(etype, self.version, payload)
    }

    fn next_entry(&mut self) -> Result<PackEntry<'a>, PackError> {
        decode_encoded_payload(self.next_encoded_entry()?)
    }
}

// One type/payload parser shared by buffered iteration, lazy unpack and windows.
fn encoded_payload(etype: u8, version: u32, payload: &[u8]) -> Result<Entry<'_>, PackError> {
    match etype {
        0x00 => Ok(Entry::Raw(EncodedPayload::Plain(payload))),
        0x03 if version == VERSION_V2 => Ok(Entry::Raw(EncodedPayload::Zstd(payload))),
        0x02 | 0x04 if etype == 0x02 || version == VERSION_V2 => {
            if payload.len() < hash::HASH_LEN {
                return Err(PackError::DeltaEntryTruncated);
            }
            let base = payload[..hash::HASH_LEN].try_into().expect("32 bytes");
            let bytes = &payload[hash::HASH_LEN..];
            let stream = if etype == 0x02 {
                EncodedPayload::Plain(bytes)
            } else {
                EncodedPayload::Zstd(bytes)
            };
            Ok(Entry::Delta { base, stream })
        }
        other => Err(PackError::InvalidEntryType(other)),
    }
}

fn decode_encoded_payload(entry: Entry<'_>) -> Result<PackEntry<'_>, PackError> {
    fn decode(payload: EncodedPayload<'_>) -> Result<Cow<'_, [u8]>, PackError> {
        match payload {
            EncodedPayload::Plain(bytes) => Ok(Cow::Borrowed(bytes)),
            EncodedPayload::Zstd(bytes) => Ok(Cow::Owned(decompress_zstd_entry(bytes)?)),
        }
    }
    match entry {
        Entry::Raw(bytes) => Ok(PackEntry::Raw {
            bytes: decode(bytes)?,
        }),
        Entry::Delta { base, stream } => Ok(PackEntry::Delta {
            base,
            stream: decode(stream)?,
        }),
    }
}

// Framing is checked by each caller, payload interpretation is shared.
fn decode_payload(etype: u8, version: u32, payload: &[u8]) -> Result<PackEntry<'_>, PackError> {
    decode_encoded_payload(encoded_payload(etype, version, payload)?)
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

/// Apply a delta while charging the stream, cached base and declared target
/// before allocating. The use count is consumed before retaining the target,
/// which also handles identity deltas whose target hash equals their base.
fn stage_delta_target<'b, B: DeltaBaseSource>(
    bases: &mut B,
    batch: &crate::batch::WriteBatch<'_>,
    in_pack: &mut std::collections::HashMap<Hash, ResidentBytes<'_, 'b>>,
    uses: &mut std::collections::HashMap<Hash, BaseUses>,
    budget: &'b ResidentBudget<'_>,
    base_hash: Hash,
    stream: &[u8],
) -> Result<Hash, PackError> {
    if let std::collections::hash_map::Entry::Vacant(entry) = in_pack.entry(base_hash) {
        let mut reservation = None;
        let bytes = bases
            .base_with_admission(&base_hash, |len| {
                reservation = Some(budget.charge(len)?);
                Ok(())
            })?
            .ok_or_else(|| PackError::DeltaBaseMissing(hash::to_hex(&base_hash)))?;
        if !external_base_matches::<B>(&bytes, &base_hash)? {
            return Err(PackError::DeltaBaseMissing(hash::to_hex(&base_hash)));
        }
        entry.insert(ResidentBytes::Owned(OwnedBytes {
            bytes,
            _reservation: reservation.expect("source admitted its buffer"),
        }));
    }
    let result_len = validate_delta_result_size(stream)?;
    let mut resolved = budget.allocate(result_len)?;
    resolved.bytes =
        delta::decode_preallocated(in_pack[&base_hash].as_ref(), stream, resolved.bytes)?;
    let obj = validate_storable_object(&resolved.bytes)?;
    let stored_hash = crate::object::id_from_object(&obj, &resolved.bytes);
    batch.write_prehashed(stored_hash, &[&resolved.bytes])?;
    budget.record_owned(resolved.bytes.len());
    let usage = uses.get_mut(&base_hash).expect("counted delta base");
    usage.remaining -= 1;
    if usage.remaining == 0 {
        in_pack.remove(&base_hash);
    }
    if has_remaining_uses(uses, &stored_hash) {
        in_pack.insert(stored_hash, ResidentBytes::Owned(resolved));
    }
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
    Ok(external_base_matches::<B>(&bytes, id)?.then_some(bytes))
}

fn external_base_matches<B: DeltaBaseSource>(bytes: &[u8], id: &Hash) -> Result<bool, PackError> {
    if B::VERIFIED {
        validate_storable_object(bytes)?;
        return Ok(true);
    }
    Ok(matches!(validate_storable_object(bytes),
        Ok(obj) if crate::object::id_from_object(&obj, bytes) == *id))
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

fn validate_delta_result_size(stream: &[u8]) -> Result<usize, PackError> {
    if stream.len() < delta::HEADER_LEN {
        return Err(PackError::DeltaApply(MkitError::UnexpectedEof));
    }
    let result_len = u32::from_le_bytes(stream[5..9].try_into().expect("4 bytes")) as usize;
    if result_len > MAX_RAW_OBJECT_SIZE {
        return Err(PackError::Store(crate::store::StoreError::ObjectTooLarge));
    }
    Ok(result_len)
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
    fn unreferenced_delta_targets_do_not_accumulate() {
        let base = write_blob_via_serialize(&vec![b'a'; 64 * 1024]);
        let base_hash = hash::hash(&base);
        let mut writer = PackWriter::new();
        writer.push_raw(base_hash, &base).unwrap();
        for i in 0..8 {
            let mut content = vec![b'a'; 256 * 1024];
            content[0] = b'b' + i;
            let target = write_blob_via_serialize(&content);
            writer
                .push_delta(&base_hash, &delta::encode(&base, &target).unwrap())
                .unwrap();
        }
        let pack = writer.finish().unwrap();
        let (_dir, store) = fresh_store();
        let budget = ResidentBudget::new(resident_bytes_cap(pack.len()), None);
        PackReader::read_with_budget(&pack, &store, MAX_TOTAL_PAYLOAD, &budget).unwrap();
        assert!(budget.peak.load(Ordering::Relaxed) <= 512 * 1024);
        assert_eq!(budget.used.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn maximum_wire_lengths_return_framing_errors() {
        for len in [u32::MAX, u32::MAX - 4] {
            let mut body = Vec::from(MAGIC.as_slice());
            body.extend_from_slice(&VERSION.to_le_bytes());
            body.extend_from_slice(&1u32.to_le_bytes());
            body.push(0x00);
            body.extend_from_slice(&len.to_le_bytes());
            let pack = finish_pack_body(body);
            assert!(matches!(
                PackEntries::new(&pack),
                Err(PackError::UnexpectedEof)
            ));
            assert!(matches!(
                delta_base_hashes(&pack),
                Err(PackError::UnexpectedEof)
            ));
            let (_dir, store) = fresh_store();
            assert!(matches!(
                PackReader::read(&pack, &store),
                Err(PackError::UnexpectedEof)
            ));
            // Also exercise the iterator's defensive check independently
            // of the eager framing validation in its public constructor.
            let mut parser = PackEntries {
                bytes: &pack,
                version: VERSION,
                split: pack.len() - TRAILER_LEN,
                count: 1,
                pos: HEADER_LEN,
                yielded: 0,
                raw_only: true,
                first_non_raw: None,
                last_payload_range: None,
                done: false,
            };
            assert!(matches!(parser.next(), Some(Err(PackError::UnexpectedEof))));
        }
    }

    #[test]
    #[cfg(any(feature = "pack-zstd", feature = "pack-ruzstd"))]
    fn junk_zstd_claims_fail_without_zero_filling() {
        for etype in [0x03, 0x04] {
            for count in [16u32, 64, 256] {
                let mut body = Vec::from(MAGIC.as_slice());
                body.extend_from_slice(&VERSION_V2.to_le_bytes());
                body.extend_from_slice(&count.to_le_bytes());
                for _ in 0..count {
                    body.push(etype);
                    let base_len = if etype == 0x04 { hash::HASH_LEN } else { 0 };
                    body.extend_from_slice(&u32::try_from(base_len + 5).unwrap().to_le_bytes());
                    if etype == 0x04 {
                        body.extend_from_slice(&[0; hash::HASH_LEN]);
                    }
                    body.extend_from_slice(
                        &u32::try_from(MAX_RAW_OBJECT_SIZE).unwrap().to_le_bytes(),
                    );
                    body.push(0xAA);
                }
                let pack = finish_pack_body(body);
                let (_dir, store) = fresh_store();
                let started = std::time::Instant::now();
                assert!(matches!(
                    PackReader::read(&pack, &store),
                    Err(PackError::ZstdDecompress(_))
                ));
                let elapsed = started.elapsed();
                println!("junk zstd type=0x{etype:02x} N={count}: {elapsed:?}");
                assert!(
                    elapsed < std::time::Duration::from_secs(5),
                    "junk frames must not initialize the claimed buffers: {elapsed:?}"
                );
                assert!(store.iter_object_hashes().unwrap().is_empty());
            }
        }
    }

    #[test]
    fn resident_and_decode_limits_are_independent() {
        let base = write_blob_via_serialize(b"base payload");
        let target = write_blob_via_serialize(b"target payload");
        let mut writer = PackWriter::new();
        writer.push_raw(hash::hash(&base), &base).unwrap();
        let stream = delta::encode(&base, &target).unwrap();
        for _ in 0..3 {
            writer.push_delta(&hash::hash(&base), &stream).unwrap();
        }
        let pack = writer.finish().unwrap();
        let (_dir, store) = fresh_store();
        let resident = ResidentBudget::new(target.len(), None);
        PackReader::read_with_budget(&pack, &store, MAX_TOTAL_PAYLOAD, &resident).unwrap();
        assert_eq!(resident.used.load(Ordering::Relaxed), 0);
        // Each target fits simultaneously resident memory, but all three
        // declared targets together exceed the cumulative DecodeLimits.
        let low = DecodeLimits::default().with_max_decoded_bytes(target.len() as u64);
        let mut seen = 0;
        assert!(matches!(
            decode_entries_with(&pack, &mut NoExternalBases, low, |_| {
                seen += 1;
                Ok(())
            }),
            Err(PackError::PackfileTooLarge)
        ));
        assert_eq!(seen, 0);
        let high = DecodeLimits::default().with_max_decoded_bytes((3 * target.len()) as u64);
        decode_entries_with(&pack, &mut NoExternalBases, high, |_| Ok(())).unwrap();
        let (_dir, store) = fresh_store();
        let resident = ResidentBudget::new(target.len() - 1, None);
        assert!(matches!(
            PackReader::read_with_budget(&pack, &store, MAX_TOTAL_PAYLOAD, &resident),
            Err(PackError::PackfileTooLarge)
        ));
        assert_eq!(resident.peak.load(Ordering::Relaxed), 0);
        assert!(store.iter_object_hashes().unwrap().is_empty());
    }

    #[test]
    fn external_base_admission_charges_both_budgets() {
        let (_dir, store) = fresh_store();
        let bytes = write_blob_via_serialize(b"external base");
        let id = store.write(&bytes).unwrap();
        for (decoded_cap, resident_cap) in [
            (bytes.len() - 1, bytes.len()),
            (bytes.len(), bytes.len() - 1),
            (bytes.len(), bytes.len()),
        ] {
            let mut source = &store;
            let mut budget = DecodeBudget {
                used: 0,
                max: decoded_cap as u64,
            };
            let mut charged = std::collections::HashMap::new();
            let mut bases = ChargedBases {
                inner: &mut source,
                budget: &mut budget,
                charged: &mut charged,
            };
            let resident = ResidentBudget::new(resident_cap, None);
            let mut reservation = None;
            let result = bases.base_with_admission(&id, |len| {
                reservation = Some(resident.charge(len)?);
                Ok(())
            });
            if decoded_cap < bytes.len() || resident_cap < bytes.len() {
                assert!(matches!(result, Err(PackError::PackfileTooLarge)));
                assert!(reservation.is_none());
                assert_eq!(resident.peak.load(Ordering::Relaxed), 0);
            } else {
                assert_eq!(result.unwrap(), Some(bytes.clone()));
                assert_eq!(bases.budget.used, bytes.len() as u64);
                assert_eq!(resident.used.load(Ordering::Relaxed), bytes.len());
                bases.release(&id);
                drop(reservation);
                assert_eq!(bases.budget.used, 0);
                assert_eq!(resident.used.load(Ordering::Relaxed), 0);
            }
        }
    }

    #[test]
    fn provided_base_admission_preserves_existing_sources() {
        struct Source(Vec<u8>);
        impl DeltaBaseSource for Source {
            fn base(&mut self, _id: &Hash) -> Result<Option<Vec<u8>>, PackError> {
                Ok(Some(self.0.clone()))
            }
        }
        let mut source = Source(vec![1, 2, 3]);
        let mut admitted = None;
        assert_eq!(
            source
                .base_with_admission(&[0; 32], |len| {
                    admitted = Some(len);
                    Ok(())
                })
                .unwrap(),
            Some(vec![1, 2, 3])
        );
        assert_eq!(admitted, Some(3));
        assert!(matches!(
            source.base_with_admission(&[0; 32], |_| Err(PackError::PackfileTooLarge)),
            Err(PackError::PackfileTooLarge)
        ));
    }

    #[test]
    #[cfg(all(feature = "pack-zstd", not(target_arch = "wasm32")))]
    fn phase_two_budget_contention_retries_sequentially() {
        let bytes = write_blob_via_serialize(&vec![b'a'; 256 * 1024]);
        let mut writer = PackWriter::new();
        for _ in 0..16 {
            writer.push_raw(hash::hash(&bytes), &bytes).unwrap();
        }
        let pack = writer.finish().unwrap();
        let mut parser = PackEntries::new(&pack).unwrap();
        let frames: Vec<_> = (0..parser.entry_count())
            .map(|position| match parser.next_encoded_entry().unwrap() {
                Entry::Raw(payload @ EncodedPayload::Zstd(_)) => (position, payload),
                _ => panic!("expected compressed raw frame"),
            })
            .collect();
        for threads in [1, 2, 4] {
            let (_dir, store) = fresh_store();
            let batch = store.batch();
            let budget = ResidentBudget::new(bytes.len(), None);
            let uses = std::collections::HashMap::new();
            // Hold an in-flight worker's entire allowance until every other
            // worker has attempted admission, avoiding scheduler-dependent races.
            let in_flight = budget.allocate(bytes.len()).unwrap();
            let first_failure = std::sync::atomic::AtomicUsize::new(usize::MAX);
            assert!(
                stage_raw_in_phase_two(
                    &batch,
                    frames[0].0,
                    frames[0].1,
                    &uses,
                    &budget,
                    &first_failure
                )
                .is_none()
            );
            assert_eq!(first_failure.load(Ordering::Relaxed), usize::MAX);
            let results = stage_raw_entries_parallel(&batch, &frames, &uses, &budget, threads);
            assert_eq!(results.len(), frames.len());
            assert!(results.iter().all(Option::is_none));
            drop(in_flight);

            let entries = frames
                .iter()
                .map(|(_, payload)| Entry::Raw(*payload))
                .collect();
            let report = finish_pack_read(entries, results, uses, &budget, &store, batch).unwrap();
            assert_eq!(report.raw_count, 16);
            assert_eq!(report.delta_count, 0);
            assert_eq!(report.stored, vec![hash::hash(&bytes); 16]);
            assert_eq!(store.read(&hash::hash(&bytes)).unwrap(), bytes);
            assert_eq!(budget.peak.load(Ordering::Relaxed), bytes.len());
            assert_eq!(budget.used.load(Ordering::Relaxed), 0);
        }
    }

    #[test]
    fn phase_two_skips_after_the_first_permanent_failure() {
        let (_dir, store) = fresh_store();
        let batch = store.batch();
        let uses = std::collections::HashMap::new();
        let budget = ResidentBudget::new(1024, None);
        let first_failure = std::sync::atomic::AtomicUsize::new(usize::MAX);
        assert!(matches!(
            stage_raw_in_phase_two(
                &batch,
                7,
                EncodedPayload::Plain(b"garbage"),
                &uses,
                &budget,
                &first_failure
            ),
            Some(Err(PackError::InvalidObject(_)))
        ));
        let invalid_claim = u32::MAX.to_le_bytes();
        assert!(
            stage_raw_in_phase_two(
                &batch,
                19,
                EncodedPayload::Zstd(&invalid_claim),
                &uses,
                &budget,
                &first_failure
            )
            .is_none()
        );
        assert_eq!(budget.peak.load(Ordering::Relaxed), 0);
        let valid = write_blob_via_serialize(b"earlier pack position");
        assert!(matches!(
            stage_raw_in_phase_two(
                &batch,
                3,
                EncodedPayload::Plain(&valid),
                &uses,
                &budget,
                &first_failure
            ),
            Some(Ok(_))
        ));
        assert_eq!(first_failure.load(Ordering::Relaxed), 7);
        for _ in 0..2 {
            assert!(matches!(
                stage_raw_in_phase_two(
                    &batch,
                    2,
                    EncodedPayload::Plain(b"garbage"),
                    &uses,
                    &budget,
                    &first_failure
                ),
                Some(Err(PackError::InvalidObject(_)))
            ));
            assert_eq!(first_failure.load(Ordering::Relaxed), 2);
        }
    }

    #[test]
    #[cfg(feature = "pack-zstd")]
    fn deferred_raw_error_precedes_a_later_staging_failure() {
        let mut payload = 7u32.to_le_bytes().to_vec();
        payload.extend_from_slice(&zstd::bulk::compress(b"garbage", 3).unwrap());
        let over_cap = u32::try_from(MAX_RAW_OBJECT_SIZE + 1)
            .unwrap()
            .to_le_bytes();
        let (_dir, store) = fresh_store();
        let batch = store.batch();
        let uses = std::collections::HashMap::new();
        let budget = ResidentBudget::new(7, None);
        let first_failure = std::sync::atomic::AtomicUsize::new(usize::MAX);
        let in_flight = budget.allocate(7).unwrap();
        let earlier = EncodedPayload::Zstd(&payload);
        let later = EncodedPayload::Zstd(&over_cap);
        let deferred = stage_raw_in_phase_two(&batch, 0, earlier, &uses, &budget, &first_failure);
        assert!(deferred.is_none());
        let failed = stage_raw_in_phase_two(&batch, 1, later, &uses, &budget, &first_failure);
        assert!(matches!(
            failed,
            Some(Err(PackError::DecompressedSizeOverCap(_)))
        ));
        assert_eq!(first_failure.load(Ordering::Relaxed), 1);
        drop(in_flight);
        assert!(matches!(
            finish_pack_read(
                vec![Entry::Raw(earlier), Entry::Raw(later)],
                vec![deferred, failed],
                uses,
                &budget,
                &store,
                batch
            ),
            Err(PackError::InvalidObject(MkitError::InvalidObjectType(103)))
        ));
        assert_eq!(budget.used.load(Ordering::Relaxed), 0);
        assert!(!store.contains(&hash::hash(b"garbage")));
    }

    #[test]
    fn resident_cap_saturates_and_allocation_failure_is_an_error() {
        assert_eq!(resident_bytes_cap(0), 2 * MAX_RAW_OBJECT_SIZE);
        assert_eq!(
            resident_bytes_cap(MAX_RAW_OBJECT_SIZE),
            MAX_RAW_OBJECT_SIZE.saturating_mul(16)
        );
        assert_eq!(resident_bytes_cap(usize::MAX), usize::MAX);
        let budget = ResidentBudget::new(usize::MAX, None);
        assert!(matches!(
            budget.allocate(usize::MAX),
            Err(PackError::PackfileTooLarge)
        ));
        assert_eq!(budget.used.load(Ordering::Relaxed), 0);
        let _full = budget.charge(usize::MAX).unwrap();
        assert!(matches!(budget.charge(1), Err(PackError::PackfileTooLarge)));
    }

    /// Build a canonical large Blob using a tiny COPY stream without ever
    /// allocating its target in the fixture. The last byte distinguishes IDs.
    #[cfg(feature = "pack-zstd")]
    fn repeated_blob_delta(base_len: usize, target_len: usize, marker: u8) -> (Vec<u8>, Hash) {
        let prologue = crate::serialize::blob_prologue(target_len - 10).unwrap();
        let mut stream = vec![delta::STREAM_VERSION];
        stream.extend_from_slice(&u32::try_from(base_len).unwrap().to_le_bytes());
        stream.extend_from_slice(&u32::try_from(target_len).unwrap().to_le_bytes());
        stream.push(10);
        stream.extend_from_slice(&prologue);
        let mut remaining = target_len - prologue.len() - 1;
        let mut hasher = blake3::Hasher::new();
        hasher.update(&prologue);
        let block = vec![b'a'; usize::from(u16::MAX)];
        while remaining != 0 {
            let len = remaining.min(block.len());
            stream.push(0x80);
            stream.extend_from_slice(&10u32.to_le_bytes());
            stream.extend_from_slice(&u16::try_from(len).unwrap().to_le_bytes());
            hasher.update(&block[..len]);
            remaining -= len;
        }
        stream.extend_from_slice(&[1, marker]);
        hasher.update(&[marker]);
        (stream, *hasher.finalize().as_bytes())
    }

    #[test]
    #[cfg(feature = "pack-zstd")]
    fn compressed_delta_bomb_releases_targets_and_checks_cap_before_allocation() {
        const TARGET_LEN: usize = 128 * 1024 * 1024;
        let base = write_blob_via_serialize(&vec![b'a'; 64 * 1024]);
        let base_hash = hash::hash(&base);
        for consume_targets in [false, true] {
            let mut writer = PackWriter::new();
            writer.push_raw(base_hash, &base).unwrap();
            let mut expected = vec![base_hash];
            for marker in 0..3 {
                let (stream, target_hash) = repeated_blob_delta(base.len(), TARGET_LEN, marker);
                writer.push_delta(&base_hash, &stream).unwrap();
                expected.push(target_hash);
                if consume_targets {
                    // Consume each large target exactly once into a tiny
                    // object, so it is released before the next expansion.
                    let small = write_blob_via_serialize(&[marker]);
                    let mut stream = vec![delta::STREAM_VERSION];
                    stream.extend_from_slice(&u32::try_from(TARGET_LEN).unwrap().to_le_bytes());
                    stream.extend_from_slice(&u32::try_from(small.len()).unwrap().to_le_bytes());
                    stream.push(u8::try_from(small.len()).unwrap());
                    stream.extend_from_slice(&small);
                    writer.push_delta(&target_hash, &stream).unwrap();
                    expected.push(hash::hash(&small));
                }
            }
            let pack = writer.finish().unwrap();
            assert!(
                pack.len() < 2048,
                "fixture must remain a small compressed pack"
            );
            let (_dir, store) = fresh_store();
            let budget = ResidentBudget::new(resident_bytes_cap(pack.len()), None);
            let report =
                PackReader::read_with_budget(&pack, &store, MAX_TOTAL_PAYLOAD, &budget).unwrap();
            assert_eq!(report.stored, expected);
            assert_eq!(report.raw_count, 1);
            assert_eq!(report.delta_count, if consume_targets { 6 } else { 3 });
            assert!(budget.peak.load(Ordering::Relaxed) < TARGET_LEN + 128 * 1024);
            assert!(budget.peak.load(Ordering::Relaxed) <= budget.cap);
            assert_eq!(budget.used.load(Ordering::Relaxed), 0);
            for hash in expected {
                assert!(store.contains(&hash));
            }
            // Inject a lower cap to exercise the same production admission
            // check without allocating several GiB in the test suite.
            let (_dir, store) = fresh_store();
            let budget = ResidentBudget::new(TARGET_LEN - 1, None);
            assert!(matches!(
                PackReader::read_with_budget(&pack, &store, MAX_TOTAL_PAYLOAD, &budget),
                Err(PackError::PackfileTooLarge)
            ));
            assert!(
                budget.peak.load(Ordering::Relaxed) < 128 * 1024,
                "target allocation was not admitted"
            );
            assert_eq!(budget.used.load(Ordering::Relaxed), 0);
            assert!(!store.contains(&base_hash));
        }
    }

    #[test]
    #[cfg(feature = "pack-zstd")]
    fn compressed_raw_bomb_is_bounded_by_workers_and_retained_bases() {
        const CONTENT_LEN: usize = 4 * 1024 * 1024;
        let threads = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
        let count = 8 * threads;
        let mut writer = PackWriter::new();
        let mut content = vec![b'a'; CONTENT_LEN];
        for i in 0..count {
            content[..8].copy_from_slice(&(i as u64).to_le_bytes());
            let blob = write_blob_via_serialize(&content);
            writer.push_raw(hash::hash(&blob), &blob).unwrap();
        }
        let pack = writer.finish().unwrap();
        assert!(pack.len() < count * 1024);
        let (_dir, store) = fresh_store();
        let budget = ResidentBudget::new(resident_bytes_cap(pack.len()), None);
        let report =
            PackReader::read_with_budget(&pack, &store, MAX_TOTAL_PAYLOAD, &budget).unwrap();
        assert_eq!(report.raw_count as usize, count);
        assert!(budget.peak.load(Ordering::Relaxed) <= threads * (CONTENT_LEN + 10));
        assert!(budget.peak.load(Ordering::Relaxed) <= budget.cap);
        assert_eq!(budget.used.load(Ordering::Relaxed), 0);
        let (_dir, store) = fresh_store();
        let budget = ResidentBudget::new(CONTENT_LEN - 1, None);
        assert!(matches!(
            PackReader::read_with_budget(&pack, &store, MAX_TOTAL_PAYLOAD, &budget),
            Err(PackError::PackfileTooLarge)
        ));
        assert_eq!(
            budget.peak.load(Ordering::Relaxed),
            0,
            "zstd claim must be rejected before allocation"
        );
        assert_eq!(budget.used.load(Ordering::Relaxed), 0);
    }

    /// Copy of the parent reader's ownership/ordering algorithm, deliberately
    /// simple and unbounded; used only with small equivalence fixtures.
    fn parent_reader(pack: &[u8], store: &ObjectStore) -> Result<UnpackReport, PackError> {
        let entries: Vec<_> = PackEntries::new(pack)?.collect::<Result<_, _>>()?;
        let batch = store.batch();
        let mut in_pack: std::collections::HashMap<Hash, Cow<'_, [u8]>> =
            std::collections::HashMap::new();
        let mut report = UnpackReport::default();
        for entry in entries {
            let (bytes, is_delta) = match entry {
                PackEntry::Raw { bytes } => (bytes, false),
                PackEntry::Delta { base, stream } => {
                    if let std::collections::hash_map::Entry::Vacant(entry) = in_pack.entry(base) {
                        if !store.contains(&base) {
                            return Err(PackError::DeltaBaseMissing(hash::to_hex(&base)));
                        }
                        let bytes = store.read(&base)?;
                        validate_storable_object(&bytes)?;
                        entry.insert(Cow::Owned(bytes));
                    }
                    validate_delta_result_size(&stream)?;
                    (
                        Cow::Owned(delta::decode(in_pack[&base].as_ref(), &stream)?),
                        true,
                    )
                }
            };
            let obj = validate_storable_object(&bytes)?;
            let hash = crate::object::id_from_object(&obj, &bytes);
            batch.write_prehashed(hash, &[bytes.as_ref()])?;
            in_pack.insert(hash, bytes);
            if is_delta {
                report.delta_count += 1;
            } else {
                report.raw_count += 1;
            }
            report.stored.push(hash);
        }
        batch.commit()?;
        Ok(report)
    }

    #[test]
    fn retention_matches_parent_for_chains_duplicates_and_shared_bases() {
        let raw_base = write_blob_via_serialize(&vec![b'a'; 1024]);
        let first_target = write_blob_via_serialize(&vec![b'b'; 1024]);
        let second_target = write_blob_via_serialize(&vec![b'c'; 1024]);
        let shared_target = write_blob_via_serialize(&vec![b'd'; 1024]);
        let external = write_blob_via_serialize(b"external base");
        let object_hash = |bytes: &[u8]| hash::hash(bytes);
        let mut writer = PackWriter::new();
        writer.push_raw(object_hash(&raw_base), &raw_base).unwrap();
        writer
            .push_delta(
                &object_hash(&raw_base),
                &delta::encode(&raw_base, &first_target).unwrap(),
            )
            .unwrap();
        writer
            .push_delta(
                &object_hash(&raw_base),
                &delta::encode(&raw_base, &second_target).unwrap(),
            )
            .unwrap();
        writer
            .push_delta(
                &object_hash(&first_target),
                &delta::encode(&first_target, &shared_target).unwrap(),
            )
            .unwrap();
        // Raw duplicate after raw_base's final delta use must not re-retain raw_base.
        writer.push_raw(object_hash(&raw_base), &raw_base).unwrap();
        // Duplicate delta targets and identity targets share raw_base single key.
        writer
            .push_delta(
                &object_hash(&second_target),
                &delta::encode(&second_target, &shared_target).unwrap(),
            )
            .unwrap();
        writer
            .push_delta(
                &object_hash(&shared_target),
                &delta::encode(&shared_target, &shared_target).unwrap(),
            )
            .unwrap();
        writer
            .push_delta(
                &object_hash(&shared_target),
                &delta::encode(&shared_target, &first_target).unwrap(),
            )
            .unwrap();
        writer
            .push_delta(
                &object_hash(&external),
                &delta::encode(&external, &raw_base).unwrap(),
            )
            .unwrap();
        writer
            .push_delta(
                &object_hash(&external),
                &delta::encode(&external, &second_target).unwrap(),
            )
            .unwrap();
        let pack = writer.finish().unwrap();
        let (_old_dir, old_store) = fresh_store();
        let (_new_dir, new_store) = fresh_store();
        old_store.write(&external).unwrap();
        new_store.write(&external).unwrap();
        let old = parent_reader(&pack, &old_store).unwrap();
        let budget = ResidentBudget::new(resident_bytes_cap(pack.len()), None);
        let new =
            PackReader::read_with_budget(&pack, &new_store, MAX_TOTAL_PAYLOAD, &budget).unwrap();
        assert_eq!(new, old);
        assert_eq!(new.stored.len(), 10);
        assert_eq!(new_store.read_call_count(), 1);
        assert_eq!(budget.used.load(Ordering::Relaxed), 0);
        for bytes in [
            raw_base,
            first_target,
            second_target,
            shared_target,
            external,
        ] {
            assert_eq!(
                new_store.read(&object_hash(&bytes)).unwrap(),
                old_store.read(&object_hash(&bytes)).unwrap()
            );
        }
    }

    #[test]
    fn store_base_is_charged_once_and_released_on_last_use() {
        let (_dir, store) = fresh_store();
        let base = write_blob_via_serialize(b"external base payload");
        let target = write_blob_via_serialize(b"target payload");
        let base_hash = store.write(&base).unwrap();
        let target_hash = hash::hash(&target);
        let stream = delta::encode(&base, &target).unwrap();
        let budget = ResidentBudget::new(base.len() + target.len(), None);
        let batch = store.batch();
        let mut in_pack = std::collections::HashMap::new();
        let mut uses = std::collections::HashMap::from([(
            base_hash,
            BaseUses {
                remaining: 2,
                last_position: 1,
            },
        )]);
        for remaining in [1, 0] {
            assert_eq!(
                stage_delta_target(
                    &mut &store,
                    &batch,
                    &mut in_pack,
                    &mut uses,
                    &budget,
                    base_hash,
                    &stream
                )
                .unwrap(),
                target_hash
            );
            assert_eq!(uses[&base_hash].remaining, remaining);
            assert_eq!(in_pack.contains_key(&base_hash), remaining != 0);
            assert!(!in_pack.contains_key(&target_hash));
            assert_eq!(
                budget.used.load(Ordering::Relaxed),
                if remaining == 0 { 0 } else { base.len() }
            );
        }
        assert_eq!(store.read_call_count(), 1);
        assert_eq!(budget.peak.load(Ordering::Relaxed), budget.cap);
        // An insufficient base budget fails inside the store allocator,
        // before any buffer exists, and leaves the cache empty.
        drop(in_pack);
        let budget = ResidentBudget::new(base.len() - 1, None);
        let mut in_pack = std::collections::HashMap::new();
        let mut uses = std::collections::HashMap::from([(
            base_hash,
            BaseUses {
                remaining: 1,
                last_position: 0,
            },
        )]);
        assert!(matches!(
            stage_delta_target(
                &mut &store,
                &batch,
                &mut in_pack,
                &mut uses,
                &budget,
                base_hash,
                &stream
            ),
            Err(PackError::PackfileTooLarge)
        ));
        assert!(in_pack.is_empty());
        assert_eq!(budget.peak.load(Ordering::Relaxed), 0);
    }

    #[test]
    #[cfg(feature = "pack-zstd")]
    fn retained_compressed_raw_bases_share_the_resident_cap() {
        let first = write_blob_via_serialize(&vec![b'a'; 1024 * 1024]);
        let second = write_blob_via_serialize(&vec![b'b'; 1024 * 1024]);
        let mut writer = PackWriter::new();
        for bytes in [&first, &second] {
            writer.push_raw(hash::hash(bytes), bytes).unwrap();
        }
        for bytes in [&first, &second] {
            writer
                .push_delta(&hash::hash(bytes), &delta::encode(bytes, bytes).unwrap())
                .unwrap();
        }
        let pack = writer.finish().unwrap();
        let (_dir, store) = fresh_store();
        let budget = ResidentBudget::new(first.len() + second.len() - 1, None);
        assert!(matches!(
            PackReader::read_with_budget(&pack, &store, MAX_TOTAL_PAYLOAD, &budget),
            Err(PackError::PackfileTooLarge)
        ));
        assert_eq!(budget.peak.load(Ordering::Relaxed), first.len());
        assert_eq!(budget.used.load(Ordering::Relaxed), 0);
        assert!(!store.contains(&hash::hash(&first)));
        assert!(!store.contains(&hash::hash(&second)));
    }

    #[test]
    #[ignore = "decodes more than 200 MiB; run in the serial ignored-lane"]
    #[cfg(feature = "pack-zstd")]
    fn large_mixed_pack_decodes_under_production_resident_cap() {
        const GROUPS: u32 = 13;
        const RAW_LEN: usize = 16 * 1024 * 1024;
        const COMPRESSED_LEN: usize = 4 * 1024 * 1024;
        let started = std::time::Instant::now();
        let mut writer = PackWriter::new();
        let mut expected = Vec::new();
        // Model transfer-planner order: each raw base is immediately
        // followed by its delta, alternating binary and text-like files.
        for group in 0..GROUPS {
            for content in [
                incompressible_bytes(0xA000_0000 + u64::from(group), RAW_LEN),
                vec![u8::try_from(group).unwrap(); COMPRESSED_LEN],
            ] {
                let base = write_blob_via_serialize(&content);
                let base_hash = hash::hash(&base);
                writer.push_raw(base_hash, &base).unwrap();
                expected.push(base_hash);
                let mut target = base.clone();
                *target.last_mut().unwrap() ^= 0x80;
                let target_hash = hash::hash(&target);
                writer
                    .push_delta(&base_hash, &delta::encode(&base, &target).unwrap())
                    .unwrap();
                expected.push(target_hash);
            }
        }
        let pack = writer.finish().unwrap();
        // Require at least 200 MiB on the wire as well as reconstructed
        // content; highly compressed entries cannot satisfy this by claim.
        assert!(pack.len() >= 200 * 1024 * 1024);
        let mut parser = PackEntries::new(&pack).unwrap();
        let (mut raw, mut zstd, mut deltas) = (0, 0, 0);
        for _ in 0..parser.entry_count() {
            match parser.next_encoded_entry().unwrap() {
                Entry::Raw(EncodedPayload::Plain(_)) => raw += 1,
                Entry::Raw(EncodedPayload::Zstd(_)) => zstd += 1,
                Entry::Delta { .. } => deltas += 1,
            }
        }
        assert_eq!((raw, zstd, deltas), (GROUPS, GROUPS, 2 * GROUPS));
        let (_dir, store) = fresh_store();
        let budget = ResidentBudget::new(resident_bytes_cap(pack.len()), None);
        let report =
            PackReader::read_with_budget(&pack, &store, MAX_TOTAL_PAYLOAD, &budget).unwrap();
        assert_eq!(report.raw_count, 2 * GROUPS);
        assert_eq!(report.delta_count, 2 * GROUPS);
        assert_eq!(report.stored, expected);
        assert_eq!(budget.used.load(Ordering::Relaxed), 0);
        assert!(budget.peak.load(Ordering::Relaxed) <= budget.cap);
        // Verify every stored object through the real store identity check.
        for id in report.stored {
            store.read(&id).unwrap();
        }
        eprintln!(
            "large mixed pack: {} wire bytes, {} peak owned bytes, {:?}",
            pack.len(),
            budget.peak.load(Ordering::Relaxed),
            started.elapsed()
        );
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
    fn decoded_frame_metadata_reconstructs_the_same_object() {
        let blob = write_blob_via_serialize(b"frame metadata");
        let id = hash::hash(&blob);
        let mut writer = PackWriter::new_raw_only();
        writer.push_raw(id, &blob).unwrap();
        let pack = writer.finish().unwrap();
        let mut frames = Vec::new();
        decode_entries_with(
            &pack,
            &mut NoExternalBases,
            DecodeLimits::default(),
            |entry| {
                frames.push((
                    entry.id,
                    entry.frame_offset,
                    entry.frame_length,
                    entry.wire_type,
                    entry.delta_base,
                ));
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(frames.len(), 1);
        let (found, offset, length, kind, base) = frames[0];
        assert_eq!(found, id);
        assert_eq!(kind, 0);
        assert_eq!(base, None);
        let frame =
            &pack[usize::try_from(offset).unwrap()..usize::try_from(offset + length).unwrap()];
        let (decoded, bytes) = decode_frame_with(
            frame,
            VERSION,
            &mut NoExternalBases,
            DecodeLimits::default(),
        )
        .unwrap();
        assert_eq!((decoded, bytes), (id, blob));
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

    #[test]
    fn decode_cursor_resumes_at_two_external_bases_without_replaying_entries() {
        #[derive(Default)]
        struct Supplied(std::collections::HashMap<Hash, Vec<u8>>);
        impl DeltaBaseSource for Supplied {
            fn base(&mut self, id: &Hash) -> Result<Option<Vec<u8>>, PackError> {
                Ok(self.0.get(id).cloned())
            }
        }

        let raw_before = write_blob_via_serialize(b"before first base");
        let raw_between = write_blob_via_serialize(b"between bases");
        let base_a = write_blob_via_serialize(b"external base a");
        let base_b = write_blob_via_serialize(b"external base b");
        let target_a = write_blob_via_serialize(b"target a");
        let target_b = write_blob_via_serialize(b"target b");
        let base_a_id = hash::hash(&base_a);
        let second_id = hash::hash(&base_b);
        let mut writer = PackWriter::new();
        writer
            .push_raw(hash::hash(&raw_before), &raw_before)
            .unwrap();
        writer
            .push_delta(&base_a_id, &delta::encode(&base_a, &target_a).unwrap())
            .unwrap();
        writer
            .push_raw(hash::hash(&raw_between), &raw_between)
            .unwrap();
        writer
            .push_delta(&second_id, &delta::encode(&base_b, &target_b).unwrap())
            .unwrap();
        let pack = writer.finish().unwrap();

        let mut cursor = PackDecodeCursor::new(&pack, DecodeLimits::default()).unwrap();
        let mut supplied = Supplied::default();
        let mut seen = Vec::new();
        let first = cursor
            .resume(&mut supplied, |entry| {
                seen.push((entry.id, entry.bytes.to_vec(), entry.from_delta));
                Ok(())
            })
            .unwrap_err();
        assert!(
            matches!(first, PackError::DeltaBaseMissing(ref id) if *id == hash::to_hex(&base_a_id))
        );
        assert_eq!(seen.len(), 1);
        assert!(matches!(
            cursor.set_max_decoded_bytes(0),
            Err(PackError::PackfileTooLarge)
        ));
        cursor.set_max_decoded_bytes(4096).unwrap();

        supplied.0.insert(base_a_id, base_a.clone());
        let second = cursor
            .resume(&mut supplied, |entry| {
                seen.push((entry.id, entry.bytes.to_vec(), entry.from_delta));
                Ok(())
            })
            .unwrap_err();
        assert!(
            matches!(second, PackError::DeltaBaseMissing(ref id) if *id == hash::to_hex(&second_id))
        );
        assert_eq!(seen.len(), 3);

        supplied.0.insert(second_id, base_b.clone());
        let report = cursor
            .resume(&mut supplied, |entry| {
                seen.push((entry.id, entry.bytes.to_vec(), entry.from_delta));
                Ok(())
            })
            .unwrap();
        let (baseline_report, baseline_seen) = decode_collect(&pack, &mut supplied).unwrap();
        assert_eq!(report, baseline_report);
        assert_eq!(seen, baseline_seen);
        assert_eq!(report.ids.len(), 4);
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

/// Kani proof harnesses (`cargo kani -p mkit-core --no-default-features
/// -Z stubbing --harness pack_`, see `delta.rs`; the reader-side zstd
/// call is stubbed either way and the writer never compresses below
/// `MIN_COMPRESS_LEN`, so the feature does not change what is checked),
/// the model-checked counterparts of the `pack` and `pack_entries` fuzz
/// targets.
///
/// BLAKE3 is stubbed with a cheap deterministic `toy_hash`: the trailer
/// bytes stay fully symbolic, so both the §8 trailer-match and -mismatch
/// paths are explored, and the writer/reader round-trip still agrees on
/// one function. zstd (C FFI, not modelable) is stubbed with a
/// nondeterministic "fail, or return any <= 2-byte buffer" — a sound
/// over-approximation for panic-freedom of the surrounding framing code.
/// `PackReader::read` itself needs an on-disk `ObjectStore`, which Kani
/// cannot model. A store-free harness over its per-entry steps (entry
/// parsing + the storability gate) ran out of memory even for one 5-byte
/// entry frame: CBMC's symbolic execution of the `PackError` →
/// `StoreError` → `std::io::Error` drop glue dominates (~13 min), so
/// that composition is left to the `pack` fuzz target.
///
/// The `pack_window_cursor_*` harnesses cover the one new decoder surface
/// of the windowed reader (SPEC-PACKFILE §11): the persisted resumable
/// cursor (`window::WindowCursor::from_bytes`). Its framing path shares
/// `decode_payload` with `PackEntries`; `rewrite::rewrite_excluding`
/// parses through `PackEntries`/`decode_entries_with` and adds no decoder.
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Loop-free deterministic stand-in for BLAKE3: the first and last
    /// 16 bytes of `data` plus its length (loop-free so it does not
    /// interact with the global unwind bound).
    fn toy_hash(data: &[u8]) -> Hash {
        let mut h = [0u8; hash::HASH_LEN];
        let n = data.len().min(16);
        h[..n].copy_from_slice(&data[..n]);
        h[16..16 + n].copy_from_slice(&data[data.len() - n..]);
        #[allow(clippy::cast_possible_truncation)]
        {
            h[31] ^= data.len() as u8;
        }
        h
    }

    fn stub_zstd(_frame: &[u8], _capacity: usize) -> Result<Vec<u8>, PackError> {
        if kani::any() {
            return Err(PackError::ZstdDecompress(String::new()));
        }
        let buf: [u8; 2] = kani::any();
        let n: usize = kani::any_where(|&n| n <= 2);
        Ok(buf[..n].to_vec())
    }

    /// Symbolic pack with an entry area of exactly `BODY` bytes (header,
    /// body and trailer all symbolic). Harnesses call this once per
    /// concrete `BODY` so CBMC can constant-fold the pack length.
    fn any_pack<const BODY: usize>() -> Vec<u8> {
        let head: [u8; HEADER_LEN] = kani::any();
        let body: [u8; BODY] = kani::any();
        let trailer: [u8; TRAILER_LEN] = kani::any();
        let mut v = Vec::with_capacity(HEADER_LEN + BODY + TRAILER_LEN);
        v.extend_from_slice(&head);
        v.extend_from_slice(&body);
        v.extend_from_slice(&trailer);
        v
    }

    fn entries_at<const BODY: usize>() {
        let bytes = any_pack::<BODY>();
        let parsed = PackEntries::new(&bytes);
        let Ok(mut entries) = parsed else {
            kani::cover!(
                matches!(parsed, Err(PackError::PackfileCorrupted)),
                "bad_trailer"
            );
            kani::cover!(matches!(parsed, Err(PackError::TrailingData)), "trailing");
            return;
        };
        let split = bytes.len() - TRAILER_LEN;
        assert_eq!(&bytes[..4], MAGIC.as_slice());
        assert!(entries.version == VERSION || entries.version == VERSION_V2);
        assert_eq!(toy_hash(&bytes[..split]).as_slice(), &bytes[split..]);
        let count = entries.count;
        let raw_only = entries.is_raw_only();
        let v1 = entries.version == VERSION;
        let mut ok = 0u32;
        let mut failed = false;
        while let Some(item) = entries.next() {
            let r = entries.last_payload_range().expect("set after an item");
            assert!(HEADER_LEN + ENTRY_FRAME_LEN <= r.start && r.end <= split);
            match item {
                Ok(PackEntry::Raw { bytes: b }) => {
                    assert!(!v1 || matches!(b, Cow::Borrowed(_)));
                    ok += 1;
                }
                Ok(PackEntry::Delta { .. }) => {
                    assert!(!raw_only);
                    ok += 1;
                }
                Err(_) => {
                    assert!(!v1, "a v1 pack accepted by new() must iterate cleanly");
                    failed = true;
                }
            }
        }
        if !failed {
            assert_eq!(ok, count);
            assert_eq!(entries.pos, split);
        }
        kani::cover!(count == 2 && ok == 2, "two_entries");
        kani::cover!(!raw_only && ok >= 1, "delta_or_zstd_entry");
    }

    /// `pack_entries` target, 5-byte entry area (exactly one entry frame
    /// — type + length — with an empty payload, or a truncated/oversized
    /// one), header, frame and trailer all symbolic (so any magic,
    /// version, `entry_count` and trailer): `PackEntries::new` and full
    /// iteration never panic/overflow/read OOB. On `Ok`: magic/version
    /// valid (§1), trailer equals the hash of the preceding bytes (§8), a
    /// v1 pack yields exactly `entry_count` `Ok` items ending at the
    /// trailer with no gap (§3, §6), every payload range lies inside the
    /// entry area (§2), and `is_raw_only` ⇒ no delta item.
    ///
    /// Run with `-Z unstable-options --cbmc-args --unwindset memcmp.0:33`
    /// (the 32-byte trailer comparison); every other loop is bounded by
    /// the global unwind of 4, which keeps CBMC from unrolling the
    /// symbolic-`entry_count` loop 33 times. Unwinding assertions stay
    /// on, so a too-small bound fails loudly. One entry-area length per
    /// harness: 0..=6 (and 0..=12) in one harness did not finish within
    /// 15 min, and the empty (0-byte) area alone ran out of memory.
    #[kani::proof]
    #[kani::stub(crate::hash::hash, toy_hash)]
    #[kani::stub(zstd_decompress_capped, stub_zstd)]
    #[kani::unwind(4)]
    fn pack_entries_one_frame() {
        entries_at::<5>();
    }

    /// As above for a 10-byte entry area: two empty-payload entries (or
    /// one with a 5-byte payload).
    #[kani::proof]
    #[kani::stub(crate::hash::hash, toy_hash)]
    #[kani::stub(zstd_decompress_capped, stub_zstd)]
    #[kani::unwind(4)]
    fn pack_entries_two_entries() {
        entries_at::<10>();
    }

    fn writer_rt<const R: usize, const S: usize>(with_delta: bool) {
        let raw: [u8; R] = kani::any();
        let base: Hash = kani::any();
        let stream: [u8; S] = kani::any();

        let mut w = PackWriter::new();
        w.push_raw(hash::ZERO, &raw).expect("raw fits caps");
        if with_delta {
            w.push_delta(&base, &stream).expect("delta fits caps");
        }
        let pack = w.finish().expect("finish");

        let mut it = PackEntries::new(&pack).expect("own pack parses");
        assert_eq!(it.version, VERSION);
        assert_eq!(it.is_raw_only(), !with_delta);
        match it.next() {
            Some(Ok(PackEntry::Raw { bytes })) => {
                assert_eq!(bytes.as_ref(), raw);
            }
            _ => panic!("first entry must be the pushed raw payload"),
        }
        if with_delta {
            match it.next() {
                Some(Ok(PackEntry::Delta {
                    base: b,
                    stream: st,
                })) => {
                    assert_eq!(b, base);
                    assert_eq!(st.as_ref(), stream);
                }
                _ => panic!("second entry must be the pushed delta"),
            }
            assert_eq!(it.first_non_raw_index(), Some(1));
        }
        assert!(it.next().is_none());
    }

    /// Writer → reader round-trip (SPEC-PACKFILE §1–§3): a pack built by
    /// `PackWriter` from one raw entry of 1 symbolic byte is accepted by
    /// `PackEntries::new` as v1 (no compression below `MIN_COMPRESS_LEN`)
    /// and yields exactly the pushed entry. CBMC's symbolic execution of
    /// the `PackError` → `StoreError` → `std::io::Error` drop glue costs
    /// ~4 min per writer/reader pass here, so the bound is one entry
    /// shape (0..=2 bytes in one harness, and a raw + delta pack, ran out
    /// of memory; the delta writer path is covered by the unit tests).
    #[kani::proof]
    #[kani::stub(crate::hash::hash, toy_hash)]
    // Run with `-Z unstable-options --cbmc-args --unwindset memcmp.0:33`
    // (32-byte trailer / base-hash comparisons); <= 2 entries otherwise.
    #[kani::unwind(4)]
    fn pack_writer_roundtrip_raw() {
        writer_rt::<1, 0>(false);
    }

    /// Canary: with the trailer check in place, a single flipped body
    /// byte must be detectable — the checker has to falsify "every
    /// single-byte mutation of a valid pack still parses".
    #[kani::proof]
    #[kani::stub(crate::hash::hash, toy_hash)]
    // As above: `--cbmc-args --unwindset memcmp.0:33`.
    #[kani::unwind(4)]
    #[kani::should_panic]
    fn pack_canary_mutation_still_parses() {
        let mut w = PackWriter::new_raw_only();
        w.push_raw(hash::ZERO, b"ab").expect("raw fits caps");
        let mut pack = w.finish().expect("finish");
        let i: usize = kani::any_where(|&i| i < pack.len());
        let flip: u8 = kani::any_where(|&f| f != 0);
        pack[i] ^= flip;
        assert!(PackEntries::new(&pack).is_ok());
    }

    /// A checksum-valid symbolic cursor encoding (canonical v1 field
    /// order: see the `window::cursor` module doc) of `N` body bytes, all
    /// symbolic except the option tags (0/1) at the concrete `(offset,
    /// present)` positions in `tags` and the two tree depth bytes at
    /// `depths`, which are 0. A symbolic tag or depth byte (even one
    /// restricted to "valid or rejected") makes CBMC explore every
    /// layout after it (the reader's `Result` is merged at each return,
    /// so later field offsets become symbolic); that did not finish within
    /// 10 min. The (toy) checksum is appended
    /// so the checksum gate passes and every field parser and the
    /// geometry validation run on attacker-chosen values.
    fn cursor_bytes<const N: usize>(tags: &[(usize, bool)], depths: [usize; 2]) -> Vec<u8> {
        let mut body: [u8; N] = kani::any();
        for &(at, present) in tags {
            body[at] = u8::from(present);
        }
        for at in depths {
            body[at] = 0;
        }
        let mut out = Vec::with_capacity(N + hash::HASH_LEN);
        out.extend_from_slice(&body);
        out.extend_from_slice(&toy_hash(&body));
        out
    }

    /// Layout A (125-byte body): first-window boundary bound to the
    /// trailer anchor, no pack id requested, no first-non-raw index;
    /// current-window prefix commitment present; both trees empty.
    /// Offsets: version 0, four u64 + three u32 at 1..45, tags at 45
    /// (first-non-raw), 54 (expected), 55 (anchor) + digest, 88 (prefix)
    /// + digest, trees at 121/122 and 123/124.
    fn cursor_anchor() -> Vec<u8> {
        cursor_bytes::<125>(
            &[
                (45, false),
                (54, false),
                (55, true),
                (88, true),
                (122, false),
                (124, false),
            ],
            [121, 123],
        )
    }

    /// Resumable-cursor decoder (`window::WindowCursor::from_bytes`, the
    /// persisted state of the SPEC-PACKFILE §11 windowed reader) on a
    /// checksum-valid layout-A encoding whose every numeric field and
    /// digest is symbolic: decoding (field parsing, trailing-byte check,
    /// geometry validation) never panics, overflows
    /// or reads out of bounds; `cover` shows acceptance is reachable.
    /// (Also asserting that an accepted cursor re-encodes byte-exactly
    /// via `to_bytes`, and the pack-id-bound layout, each did not finish
    /// within 15 min; the round-trip stays with the `window` unit tests.)
    #[kani::proof]
    #[kani::stub(crate::hash::hash, toy_hash)]
    // Run with `-Z unstable-options --cbmc-args --unwindset memcmp.0:33`
    // (checksum comparison); the tree loops read no CVs.
    #[kani::unwind(7)]
    fn pack_window_cursor_decode() {
        let got = window::WindowCursor::from_bytes(&cursor_anchor());
        let ok = got.is_ok();
        // Skip the harness-side `PackError` drop glue (`Store` →
        // `std::io::Error`); nothing about dropping is checked here.
        core::mem::forget(got);
        kani::cover!(ok, "accepted_anchor_cursor");
    }

    /// A concrete, valid layout-A cursor (100-byte pack, 64 KiB windows,
    /// boundary right after the header, no entries; symbolic anchor and
    /// prefix digests) with `mask` XORed into the low byte of `pack_len`
    /// (offset 1, inside the checksummed body) after the checksum is
    /// computed. Every flipped `pack_len` in 44..=255 is still valid
    /// geometry for this cursor, so for those only the checksum rejects.
    fn flipped_cursor(mask: u8) -> Vec<u8> {
        let mut body = [0u8; 125];
        body[0] = 1; // cursor encoding version
        body[1..9].copy_from_slice(&100u64.to_le_bytes()); // pack_len
        body[9..17].copy_from_slice(&(64u64 << 10).to_le_bytes()); // window
        body[17..25].copy_from_slice(&12u64.to_le_bytes()); // pos
        body[33..37].copy_from_slice(&1u32.to_le_bytes()); // pack version
        body[55] = 1; // anchor present
        body[56..88].copy_from_slice(&kani::any::<Hash>());
        body[88] = 1; // window prefix present
        body[89..121].copy_from_slice(&kani::any::<Hash>());
        let mut out = body.to_vec();
        out.extend_from_slice(&toy_hash(&body));
        out[1] ^= mask;
        out
    }

    /// Checksum gate: the concrete cursor above decodes iff it is
    /// unmodified, i.e. every single-byte change to its `pack_len` field
    /// (most of which leave a still-valid cursor) is rejected. One
    /// `from_bytes` call per harness: each costs ~7 min of CBMC symbolic
    /// execution (~6.8M steps, much of it `PackError` → `StoreError` →
    /// `std::io::Error` machinery), so two calls did not finish within
    /// 15 min.
    #[kani::proof]
    #[kani::stub(crate::hash::hash, toy_hash)]
    // As above: `--cbmc-args --unwindset memcmp.0:33`.
    #[kani::unwind(7)]
    fn pack_window_cursor_flip_rejected() {
        let mask: u8 = kani::any();
        let got = window::WindowCursor::from_bytes(&flipped_cursor(mask));
        let ok = got.is_ok();
        core::mem::forget(got);
        assert_eq!(ok, mask == 0);
    }

    /// Canary: the checker must falsify "a flipped `pack_len` byte still
    /// decodes" (the negation of the property above).
    #[kani::proof]
    #[kani::stub(crate::hash::hash, toy_hash)]
    // As above: `--cbmc-args --unwindset memcmp.0:33`.
    #[kani::unwind(7)]
    #[kani::should_panic]
    fn pack_window_cursor_canary_flip_accepted() {
        let got =
            window::WindowCursor::from_bytes(&flipped_cursor(kani::any_where(|&m: &u8| m != 0)));
        let ok = got.is_ok();
        core::mem::forget(got);
        assert!(ok);
    }
}
