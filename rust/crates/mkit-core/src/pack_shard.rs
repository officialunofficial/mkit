//! Erasure-coded pack delivery via Reed-Solomon shards.
//!
//! This module is the in-process encode/reconstruct core for issue #159:
//! it wraps
//! `commonware_coding::ReedSolomon<Sha256>` so a producer can split a
//! pack into `N + K` shards and a consumer can reconstruct the pack
//! from any `N` of those shards.
//!
//! The wire format and motivation are normatively documented in
//! `docs/specs/SPEC-PACK-SHARDS.md`. The implementation here matches the v0
//! spec; transport-level shard fetch (HTTP, S3) is **out of scope** and
//! lands later under `mkit-transport-*`.
//!
//! # Threat model
//!
//! * Each [`Shard`] is a self-describing envelope carrying the
//!   commonware `Chunk` (shard payload + index + Merkle proof).
//! * Before passing a shard to the decoder, the receiver compares
//!   `BLAKE3(shard.bytes)` against the manifest entry in
//!   [`ShardSet::shard_hashes`]. A mismatch means the shard was
//!   tampered with in transit; the shard is rejected without ever
//!   reaching the Reed-Solomon decoder.
//! * After reconstruction, the recovered pack bytes are hashed with
//!   BLAKE3 and compared against [`ShardSet::pack_hash`]. This catches
//!   the (cryptographically unlikely) case where a coordinated attacker
//!   crafted shards that pass the Merkle check but reconstruct a
//!   different pack.
//!
//! # Feature gate
//!
//! This module is compiled only when `--features pack-shards` is set.
//! The default `mkit-core` build does **not** pull in the
//! `commonware-*` dep stack.
//!
//! # Defaults
//!
//! `Config { minimum_shards: 16, extra_shards: 4 }` — 20 total shards,
//! 25% redundancy. Any 16 of 20 shards reconstruct the pack. Tuning
//! lives in `docs/specs/SPEC-PACK-SHARDS.md` §6.

use std::num::{NonZeroU16, NonZeroUsize};
use std::sync::OnceLock;

use commonware_codec::{Decode, Encode};
use commonware_coding::{CodecConfig, Scheme as _};
use commonware_cryptography::Sha256;
use commonware_parallel::{Rayon, Sequential, Strategy};

use crate::hash::{self, HASH_LEN, Hash};

// Re-exports so callers don't need to depend on `commonware-coding` directly.
pub use commonware_coding::Config;
// Re-export so callers building an explicit strategy (e.g. via the
// `_with_strategy` entry points below) don't need a direct
// `commonware-parallel` dependency of their own.
pub use commonware_parallel::{Rayon as ParallelStrategy, Sequential as SequentialStrategy};

// Issue #653 evaluated swapping this to `ReedSolomon<Blake3>` to match
// the hash primitive mkit uses elsewhere (`history.rs`) and drop a
// redundant per-shard hash pass (the internal Merkle-tree build in
// `commonware-coding::reed_solomon::{encode, decode}` hashes every
// shard with `H::new()` — currently SHA-256 — completely separately
// from this module's own BLAKE3 `shard_hashes` envelope check).
//
// Deferred: `H` determines `Commitment` (the BMT root stored in
// `ShardSet::commitment`), and SPEC-PACK-SHARDS §4 pins that as
// "`ReedSolomon<Sha256>` with the `Sequential` parallel strategy.
// Producers and consumers MUST use the same scheme and digest." A
// producer on this hasher and a consumer on the old one would
// compute different commitments for the *same* shard set and every
// Merkle-proof check (`RsScheme::check`) would fail — a silent,
// total interop break between independent mkit processes, not a
// local behavior change. Fixing that needs a `MANIFEST_VERSION` bump
// (or an out-of-band hasher negotiation) and a spec update, which
// the issue's own "Out of scope" section excludes ("not touching...
// the shard wire format"). Tracked as a candidate for a follow-up
// issue instead of folded into this one.
type RsScheme = commonware_coding::ReedSolomon<Sha256>;
type Commitment = <RsScheme as commonware_coding::Scheme>::Commitment;
type RsChunk = <RsScheme as commonware_coding::Scheme>::Shard;

/// Pack length at (or above) which [`encode_pack_to_shards`] and
/// [`decode_pack_from_shards`] default to a parallel, `Rayon`-backed
/// `commonware-parallel` strategy instead of [`Sequential`].
///
/// Below this size the encode/decode core still does real per-shard
/// work (hashing each of `config.total_shards()` shards, and — on
/// decode — re-hashing any reconstructed shards to rebuild the BMT
/// consistency check), but a `rayon` thread pool's per-call dispatch
/// overhead (partitioning + joining ~20 small closures) is not
/// reliably smaller than just doing that work on the current thread.
/// 4 MiB is comfortably above [`SHARD_SIZE_THRESHOLD`] (1 MiB, below
/// which producers should not shard at all per SPEC-PACK-SHARDS §6),
/// so any pack that actually gets sharded and clears this threshold
/// has multi-hundred-KiB shards where the parallel win is real.
pub const PARALLEL_STRATEGY_THRESHOLD: usize = 4 * 1024 * 1024;

/// Returns `true` when a pack of `pack_len` bytes should default to
/// the parallel strategy. Kept as its own (private) function — rather
/// than inlined into the two call sites — so a unit test can pin the
/// threshold decision as a plain value comparison, independent of
/// whether a `Rayon` thread pool can actually be built in the test
/// environment.
fn should_use_parallel_strategy(pack_len: usize) -> bool {
    pack_len >= PARALLEL_STRATEGY_THRESHOLD
}

/// Lazily builds a single process-wide `Rayon` strategy, reused by
/// every encode/decode call that clears [`PARALLEL_STRATEGY_THRESHOLD`].
///
/// Building a `rayon::ThreadPool` spins up OS threads and initializes
/// its work-stealing queues, so we pay that cost once per process
/// rather than once per call. `Rayon` wraps an `Arc<ThreadPool>`, so
/// the clone returned to each caller is cheap. Returns `None` if the
/// pool could not be built (e.g. the OS refuses to spawn threads);
/// callers fall back to [`Sequential`] in that case.
fn shared_parallel_strategy() -> Option<Rayon> {
    static POOL: OnceLock<Option<Rayon>> = OnceLock::new();
    POOL.get_or_init(|| {
        let threads = std::thread::available_parallelism().map_or(1, NonZeroUsize::get);
        NonZeroUsize::new(threads).and_then(|n| Rayon::new(n).ok())
    })
    .clone()
}

/// Resolves the default strategy for a pack of `pack_len` bytes.
/// `None` means "use [`Sequential`]" — either because `pack_len` is
/// below [`PARALLEL_STRATEGY_THRESHOLD`], or because a parallel
/// strategy could not be built.
fn default_parallel_strategy_for_len(pack_len: usize) -> Option<Rayon> {
    if should_use_parallel_strategy(pack_len) {
        shared_parallel_strategy()
    } else {
        None
    }
}

/// Cap on the per-shard codec payload size accepted at decode time.
/// 4 GiB matches the existing packfile size cap (see
/// `crate::pack::MAX_TOTAL_PAYLOAD`); anything bigger could not have
/// originated from a valid mkit pack.
const MAX_SHARD_BYTES: usize = 4 * 1024 * 1024 * 1024;

/// Size below which a producer SHOULD NOT shard a pack.
///
/// Per SPEC-PACK-SHARDS §6 the per-shard Merkle-proof overhead
/// dominates for small packs, so producers serve them monolithically.
/// 1 MiB is the v0 cutoff; the constant is exported so transports and
/// CLI tooling agree on a single number.
pub const SHARD_SIZE_THRESHOLD: u64 = 1024 * 1024;

/// Wire-format magic for a serialised [`ShardSet`]. Spells "MKSH" —
/// "mkit-shards" — and lets a parser refuse to treat random bytes as a
/// manifest.
pub const MANIFEST_MAGIC: [u8; 4] = *b"MKSH";

/// Wire-format version for a serialised [`ShardSet`]. Bumped whenever
/// the on-the-wire layout changes in a non-backwards-compatible way.
pub const MANIFEST_VERSION: u8 = 0x01;

/// Total prologue size: magic (4) + version (1).
const MANIFEST_PROLOGUE_LEN: usize = 5;

/// Per SPEC-PACK-SHARDS §6, a manifest with the v0 default config is
/// `~ 32 * (T + 2)` bytes plus the prologue and config. We cap at
/// 1 MiB so a hostile peer can not stream gigabytes through the
/// deserialiser.
pub const MANIFEST_MAX_BYTES: usize = 1024 * 1024;

/// Default config: `(minimum_shards = 16, extra_shards = 4)`.
///
/// 20 total shards, any 16 of which reconstruct. See SPEC-PACK-SHARDS §6
/// for the rationale and when callers may want to tune these.
///
/// # Panics
///
/// Infallible — both `16` and `4` are nonzero. The `expect` calls
/// document intent; they cannot fire.
#[must_use]
pub fn default_config() -> Config {
    Config {
        minimum_shards: NonZeroU16::new(16).expect("16 != 0"),
        extra_shards: NonZeroU16::new(4).expect("4 != 0"),
    }
}

/// A single shard of an erasure-coded pack.
///
/// `bytes` is the codec-serialised commonware `Chunk` (shard payload +
/// index + Merkle proof). The receiver hashes these bytes with BLAKE3
/// and matches them against [`ShardSet::shard_hashes`] before decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shard {
    /// Shard index in `[0, minimum_shards + extra_shards)`.
    pub index: u16,
    /// Codec-serialised commonware `Chunk` payload. Opaque at this
    /// layer; the only operations performed against it are hashing and
    /// decoding via the commonware codec.
    pub bytes: Vec<u8>,
}

/// Manifest describing a set of shards encoding one pack.
///
/// In the wire protocol this is published alongside the shards under
/// `/packs/<pack_hash>/shards.manifest` (see SPEC-PACK-SHARDS §2). A
/// consumer fetches the manifest first, then fetches up to
/// `config.total_shards()` shards in parallel, rejecting any whose
/// BLAKE3 hash does not match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardSet {
    /// BLAKE3 of the original pack bytes. Verified after reconstruction
    /// as the final defence against shard-set forgery.
    pub pack_hash: Hash,
    /// Reed-Solomon `(minimum_shards, extra_shards)` configuration used
    /// to produce this shard set. The decoder MUST use the same
    /// configuration.
    pub config: Config,
    /// BLAKE3 of each shard's `bytes`, indexed by shard index.
    /// `shard_hashes.len()` MUST equal `config.total_shards()`.
    pub shard_hashes: Vec<Hash>,
    /// Commonware BMT root committing to all shards. Required by the
    /// commonware decoder for per-shard Merkle-proof checks. Stored
    /// here so the manifest is self-contained — a receiver does not
    /// need a second round-trip to fetch the commitment.
    pub commitment: Hash,
}

/// Errors produced by [`encode_pack_to_shards`] / [`decode_pack_from_shards`].
#[derive(Debug, thiserror::Error)]
pub enum ShardError {
    /// The Reed-Solomon encoder rejected the input. Typically means
    /// the pack is larger than `u32::MAX` bytes (commonware's limit).
    #[error("reed-solomon encode failed: {0}")]
    EncodeFailed(String),
    /// The Reed-Solomon decoder rejected the supplied shards. Usually
    /// triggered by too few shards, duplicate indices, or a Merkle
    /// proof that no longer matches the commitment.
    #[error("reed-solomon decode failed: {0}")]
    DecodeFailed(String),
    /// The codec layer could not parse a shard's `bytes`. Means the
    /// shard envelope is malformed — distinct from a BLAKE3 mismatch.
    #[error("shard codec decode failed at index {index}: {source}")]
    ShardCodecFailed {
        index: u16,
        #[source]
        source: commonware_codec::Error,
    },
    /// A shard's BLAKE3 hash does not match the manifest entry for its
    /// index. The shard is corrupt or maliciously substituted.
    #[error("shard {index} BLAKE3 mismatch (manifest tampered or shard corrupted)")]
    ShardHashMismatch { index: u16 },
    /// Manifest claims an index outside `0..total_shards`.
    #[error("shard index {index} is out of range for config (total = {total})")]
    IndexOutOfRange { index: u16, total: u32 },
    /// Duplicate shard index supplied to the decoder.
    #[error("duplicate shard index {index}")]
    DuplicateIndex { index: u16 },
    /// Manifest carries the wrong number of `shard_hashes` for the
    /// declared config.
    #[error(
        "manifest has {actual} shard_hashes, expected {expected} \
         (config.total_shards())"
    )]
    ManifestShardCountMismatch { actual: usize, expected: usize },
    /// Reconstruction produced bytes whose BLAKE3 does not match
    /// `manifest.pack_hash`. Cryptographically the manifest was forged.
    #[error("reconstructed pack hash does not match manifest.pack_hash")]
    PackHashMismatch,
    /// Caller passed fewer than `config.minimum_shards` shards.
    #[error("insufficient shards: {provided} < {minimum}")]
    InsufficientShards { provided: usize, minimum: u16 },
    /// The manifest wire bytes are shorter than the v0 prologue, do not
    /// begin with [`MANIFEST_MAGIC`], or carry an unrecognised
    /// [`MANIFEST_VERSION`].
    #[error("invalid manifest prologue: {0}")]
    InvalidManifestPrologue(&'static str),
    /// The manifest wire bytes are truncated — a length-prefixed field
    /// claims more bytes than remain in the buffer.
    #[error("unexpected eof while decoding manifest")]
    ManifestUnexpectedEof,
    /// The manifest carries trailing bytes after the last expected
    /// field. Most likely a producer / consumer version mismatch.
    #[error("trailing bytes after manifest body")]
    ManifestTrailingBytes,
    /// The manifest declares a `(minimum_shards, extra_shards)` pair
    /// whose components are zero — illegal at the SPEC level.
    #[error("manifest declares zero shard count (min={minimum}, extra={extra})")]
    ManifestZeroShardCount { minimum: u16, extra: u16 },
    /// The manifest exceeds [`MANIFEST_MAX_BYTES`].
    #[error("manifest is too large: {actual} > {max}")]
    ManifestTooLarge { actual: usize, max: usize },
}

/// Encode a pack into shards.
///
/// Produces `config.minimum_shards + config.extra_shards` shards and a
/// manifest committing to them. The pack itself is not modified.
///
/// # Errors
///
/// Returns [`ShardError::EncodeFailed`] if the underlying Reed-Solomon
/// encoder rejects the input (e.g. the pack exceeds `u32::MAX` bytes,
/// or `total_shards()` exceeds `u16::MAX`).
///
/// # Panics
///
/// Infallible — the only `expect` in the body asserts that commonware
/// never emits more than `u16::MAX` shards, which it enforces in
/// `ReedSolomon::encode` (`Error::TooManyTotalShards`).
pub fn encode_pack_to_shards(
    pack: &[u8],
    config: Config,
) -> Result<(Vec<Shard>, ShardSet), ShardError> {
    match default_parallel_strategy_for_len(pack.len()) {
        Some(strategy) => encode_pack_to_shards_with_strategy(pack, config, &strategy),
        None => encode_pack_to_shards_with_strategy(pack, config, &Sequential),
    }
}

/// Like [`encode_pack_to_shards`], but with an explicit
/// `commonware-parallel` [`Strategy`] instead of the size-based
/// default. Exists so callers (and tests / benches) can force a
/// specific strategy — e.g. to compare `Sequential` against a
/// `Rayon` pool of a given width — without going through the
/// pack-length heuristic.
///
/// # Errors
///
/// Same as [`encode_pack_to_shards`].
///
/// # Panics
///
/// Infallible — same as [`encode_pack_to_shards`]; the only `expect`
/// in the body asserts that commonware never emits more than
/// `u16::MAX` shards, which it enforces in `ReedSolomon::encode`
/// (`Error::TooManyTotalShards`).
pub fn encode_pack_to_shards_with_strategy<S: Strategy>(
    pack: &[u8],
    config: Config,
    strategy: &S,
) -> Result<(Vec<Shard>, ShardSet), ShardError> {
    let (commitment, chunks) = RsScheme::encode(&config, pack, strategy)
        .map_err(|e| ShardError::EncodeFailed(format!("{e:?}")))?;

    let total = config.total_shards() as usize;
    debug_assert_eq!(chunks.len(), total);

    // Per-shard codec-serialise + BLAKE3 hash. Each iteration only
    // touches its own chunk and produces its own output triple, so —
    // unlike the RS math above, which commonware parallelises
    // internally — this loop is ours to parallelise. We reuse the
    // same `strategy` so a caller who opts into a parallel strategy
    // gets the benefit here too, not just inside `RsScheme::encode`.
    // `map_collect_vec` preserves input order for every `Strategy`
    // impl (see commonware-parallel docs), so `results[i]` still
    // corresponds to shard index `i`.
    let results: Vec<(u16, Vec<u8>, Hash)> =
        strategy.map_collect_vec(chunks.into_iter().enumerate(), |(i, chunk)| {
            // `i < total <= u16::MAX` by commonware's own bound
            // (`Chunk::index: u16`), so the conversion is infallible.
            let index = u16::try_from(i).expect("commonware emits <= u16::MAX shards");
            let bytes = chunk.encode().to_vec();
            let h = hash::hash(&bytes);
            (index, bytes, h)
        });

    let mut shards = Vec::with_capacity(total);
    let mut shard_hashes = Vec::with_capacity(total);
    for (index, bytes, h) in results {
        shards.push(Shard { index, bytes });
        shard_hashes.push(h);
    }

    let manifest = ShardSet {
        pack_hash: hash::hash(pack),
        config,
        shard_hashes,
        commitment: digest_to_bytes(&commitment),
    };

    Ok((shards, manifest))
}

/// Decode a pack from a (possibly partial) set of shards.
///
/// The decoder:
///
/// 1. Verifies each shard's BLAKE3 against the manifest entry for its
///    index. Mismatched shards are dropped before they reach the
///    Reed-Solomon decoder.
/// 2. Deserialises each surviving shard as a commonware `Chunk`.
/// 3. Calls `ReedSolomon::check` on each chunk (Merkle-proof check
///    against `manifest.commitment`).
/// 4. Calls `ReedSolomon::decode` on the checked set.
/// 5. Verifies the reconstructed pack's BLAKE3 against
///    `manifest.pack_hash`.
///
/// # Errors
///
/// See [`ShardError`] for the full taxonomy. Any step's failure
/// short-circuits.
pub fn decode_pack_from_shards(
    shards: &[Shard],
    manifest: &ShardSet,
) -> Result<Vec<u8>, ShardError> {
    // The manifest doesn't carry the original pack length, so we use
    // the total wire size of the supplied shards (envelope + proof
    // overhead included) as a same-order-of-magnitude proxy for it.
    // Good enough for a coarse "is this worth a thread pool" gate.
    let size_hint: usize = shards.iter().map(|s| s.bytes.len()).sum();
    match default_parallel_strategy_for_len(size_hint) {
        Some(strategy) => decode_pack_from_shards_with_strategy(shards, manifest, &strategy),
        None => decode_pack_from_shards_with_strategy(shards, manifest, &Sequential),
    }
}

/// Like [`decode_pack_from_shards`], but with an explicit
/// `commonware-parallel` [`Strategy`] instead of the size-based
/// default. See [`encode_pack_to_shards_with_strategy`] for why this
/// exists.
///
/// # Errors
///
/// Same as [`decode_pack_from_shards`].
pub fn decode_pack_from_shards_with_strategy<S: Strategy>(
    shards: &[Shard],
    manifest: &ShardSet,
    strategy: &S,
) -> Result<Vec<u8>, ShardError> {
    let total = manifest.config.total_shards();
    if manifest.shard_hashes.len() != total as usize {
        return Err(ShardError::ManifestShardCountMismatch {
            actual: manifest.shard_hashes.len(),
            expected: total as usize,
        });
    }

    let minimum = manifest.config.minimum_shards.get();
    let commitment = bytes_to_digest(&manifest.commitment);
    let codec_cfg = CodecConfig {
        maximum_shard_size: MAX_SHARD_BYTES,
    };

    let mut seen = vec![false; total as usize];
    let mut checked = Vec::with_capacity(shards.len());

    for shard in shards {
        // (1) Range + duplicate index check.
        if u32::from(shard.index) >= total {
            return Err(ShardError::IndexOutOfRange {
                index: shard.index,
                total,
            });
        }
        let slot = &mut seen[shard.index as usize];
        if *slot {
            return Err(ShardError::DuplicateIndex { index: shard.index });
        }
        *slot = true;

        // (2) BLAKE3 tamper check against the manifest.
        let expected = &manifest.shard_hashes[shard.index as usize];
        if &hash::hash(&shard.bytes) != expected {
            return Err(ShardError::ShardHashMismatch { index: shard.index });
        }

        // (3) Codec decode → commonware `Chunk`.
        let chunk = RsChunk::decode_cfg(shard.bytes.as_slice(), &codec_cfg).map_err(|e| {
            ShardError::ShardCodecFailed {
                index: shard.index,
                source: e,
            }
        })?;

        // (4) Merkle-proof check against the commitment.
        let checked_shard = RsScheme::check(&manifest.config, &commitment, shard.index, &chunk)
            .map_err(|e| ShardError::DecodeFailed(format!("check({}): {e:?}", shard.index)))?;
        checked.push(checked_shard);
    }

    if checked.len() < usize::from(minimum) {
        return Err(ShardError::InsufficientShards {
            provided: checked.len(),
            minimum,
        });
    }

    // (5) Reed-Solomon decode.
    let pack = RsScheme::decode(&manifest.config, &commitment, checked.iter(), strategy)
        .map_err(|e| ShardError::DecodeFailed(format!("{e:?}")))?;

    // (6) Final BLAKE3 check.
    if hash::hash(&pack) != manifest.pack_hash {
        return Err(ShardError::PackHashMismatch);
    }

    Ok(pack)
}

/// Extract the raw 32 bytes from a commonware `Sha256` digest.
fn digest_to_bytes(d: &Commitment) -> [u8; HASH_LEN] {
    // `Sha256::Digest` derefs to `[u8; 32]`. We avoid relying on a
    // specific accessor name by going through `AsRef<[u8]>` which the
    // digest type implements.
    let slice: &[u8] = d.as_ref();
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(slice);
    out
}

/// Inverse of [`digest_to_bytes`]: reconstruct a commonware digest
/// from the 32 bytes stored in the manifest.
fn bytes_to_digest(b: &[u8; HASH_LEN]) -> Commitment {
    // `Sha256::Digest` is a 32-byte `Array` and only exposes
    // `From<[u8; 32]>`, not `TryFrom<&[u8]>`. Copy through a fixed
    // array to keep the bound surface narrow.
    use commonware_codec::FixedSize;
    debug_assert_eq!(<Commitment as FixedSize>::SIZE, HASH_LEN);
    Commitment::from(*b)
}

// ---------------------------------------------------------------------
// Manifest wire format (v0)
// ---------------------------------------------------------------------
//
// Layout (all multi-byte integers are little-endian):
//
//     offset  size  field
//     ------  ----  -----------------------------------------
//     0       4     magic = b"MKSH"
//     4       1     version = 0x01
//     5       32    pack_hash
//     37      2     config.minimum_shards
//     39      2     config.extra_shards
//     41      32    commitment
//     73      4     shard_hashes_len (== minimum + extra)
//     77      32*T  shard_hashes
//
// Total size for the v0 default `(16, 4)` config:
//     5 + 32 + 2 + 2 + 32 + 4 + 32*20 = 717 bytes.
//
// Rationale for adding a new format here rather than reusing
// `mkit_core::serialize`:
//   * `serialize.rs` is hard-coded to the [`Object`] enum and its
//     `MAGIC = "MKT1"` / `SCHEMA_VERSION` prologue. Shoehorning a
//     non-`Object` payload into that path would require widening its
//     public API and re-encoding every golden vector.
//   * The shard manifest is a transport artifact, not an object on
//     disk. Keeping its wire format colocated with the rest of the
//     pack-shard module keeps transport-integration changes scoped to one file.

/// Serialise a [`ShardSet`] into its v0 wire bytes.
///
/// The format is documented above and in SPEC-PACK-SHARDS §2. The
/// caller takes ownership of the returned `Vec`.
///
/// # Errors
///
/// Returns [`ShardError::ManifestShardCountMismatch`] if
/// `manifest.shard_hashes.len()` does not equal
/// `manifest.config.total_shards()` — we refuse to encode a manifest
/// whose vectors disagree with its config.
///
/// # Panics
///
/// Infallible: `config.total_shards()` is `u32` by commonware's own
/// bound and the `expect` documents intent. It cannot fire.
pub fn encode_manifest(manifest: &ShardSet) -> Result<Vec<u8>, ShardError> {
    let total = manifest.config.total_shards() as usize;
    if manifest.shard_hashes.len() != total {
        return Err(ShardError::ManifestShardCountMismatch {
            actual: manifest.shard_hashes.len(),
            expected: total,
        });
    }

    let body_len = MANIFEST_PROLOGUE_LEN + HASH_LEN + 2 + 2 + HASH_LEN + 4 + total * HASH_LEN;
    let mut out = Vec::with_capacity(body_len);
    out.extend_from_slice(&MANIFEST_MAGIC);
    out.push(MANIFEST_VERSION);
    out.extend_from_slice(&manifest.pack_hash);
    out.extend_from_slice(&manifest.config.minimum_shards.get().to_le_bytes());
    out.extend_from_slice(&manifest.config.extra_shards.get().to_le_bytes());
    out.extend_from_slice(&manifest.commitment);
    // Length-prefix the shard_hashes vector as u32 so the parser can
    // bail before allocating attacker-controlled capacity.
    out.extend_from_slice(
        &u32::try_from(total)
            .expect("total_shards fits in u32")
            .to_le_bytes(),
    );
    for h in &manifest.shard_hashes {
        out.extend_from_slice(h);
    }
    debug_assert_eq!(out.len(), body_len);
    Ok(out)
}

/// Deserialise a [`ShardSet`] from its v0 wire bytes.
///
/// Validates the prologue, the length-prefixed shard-hashes vector,
/// the per-config bounds, and rejects trailing bytes.
///
/// # Errors
///
/// * [`ShardError::ManifestTooLarge`] — input exceeds
///   [`MANIFEST_MAX_BYTES`].
/// * [`ShardError::InvalidManifestPrologue`] — magic / version
///   mismatch or input shorter than the prologue.
/// * [`ShardError::ManifestUnexpectedEof`] — any field claims more
///   bytes than remain in the buffer.
/// * [`ShardError::ManifestZeroShardCount`] — manifest declares
///   `(0, _)` or `(_, 0)`.
/// * [`ShardError::ManifestShardCountMismatch`] — declared
///   `shard_hashes_len` does not equal `minimum + extra`.
/// * [`ShardError::ManifestTrailingBytes`] — input has bytes after
///   the last hash.
pub fn decode_manifest(bytes: &[u8]) -> Result<ShardSet, ShardError> {
    if bytes.len() > MANIFEST_MAX_BYTES {
        return Err(ShardError::ManifestTooLarge {
            actual: bytes.len(),
            max: MANIFEST_MAX_BYTES,
        });
    }
    if bytes.len() < MANIFEST_PROLOGUE_LEN {
        return Err(ShardError::InvalidManifestPrologue(
            "input shorter than prologue",
        ));
    }
    if bytes[..4] != MANIFEST_MAGIC {
        return Err(ShardError::InvalidManifestPrologue("bad magic"));
    }
    if bytes[4] != MANIFEST_VERSION {
        return Err(ShardError::InvalidManifestPrologue("unsupported version"));
    }
    let mut pos = MANIFEST_PROLOGUE_LEN;

    // pack_hash
    if bytes.len() - pos < HASH_LEN {
        return Err(ShardError::ManifestUnexpectedEof);
    }
    let mut pack_hash = [0u8; HASH_LEN];
    pack_hash.copy_from_slice(&bytes[pos..pos + HASH_LEN]);
    pos += HASH_LEN;

    // config
    if bytes.len() - pos < 4 {
        return Err(ShardError::ManifestUnexpectedEof);
    }
    let minimum = u16::from_le_bytes([bytes[pos], bytes[pos + 1]]);
    let extra = u16::from_le_bytes([bytes[pos + 2], bytes[pos + 3]]);
    pos += 4;
    let minimum_nz =
        NonZeroU16::new(minimum).ok_or(ShardError::ManifestZeroShardCount { minimum, extra })?;
    let extra_nz =
        NonZeroU16::new(extra).ok_or(ShardError::ManifestZeroShardCount { minimum, extra })?;
    let config = Config {
        minimum_shards: minimum_nz,
        extra_shards: extra_nz,
    };
    let total = config.total_shards();

    // commitment
    if bytes.len() - pos < HASH_LEN {
        return Err(ShardError::ManifestUnexpectedEof);
    }
    let mut commitment = [0u8; HASH_LEN];
    commitment.copy_from_slice(&bytes[pos..pos + HASH_LEN]);
    pos += HASH_LEN;

    // shard_hashes_len
    if bytes.len() - pos < 4 {
        return Err(ShardError::ManifestUnexpectedEof);
    }
    let declared_len =
        u32::from_le_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);
    pos += 4;
    if declared_len != total {
        return Err(ShardError::ManifestShardCountMismatch {
            actual: declared_len as usize,
            expected: total as usize,
        });
    }
    // Cheap upper bound — reject impossible counts before allocating.
    if (declared_len as usize).saturating_mul(HASH_LEN) > bytes.len() - pos {
        return Err(ShardError::ManifestUnexpectedEof);
    }
    let mut shard_hashes = Vec::with_capacity(declared_len as usize);
    for _ in 0..declared_len {
        let mut h = [0u8; HASH_LEN];
        h.copy_from_slice(&bytes[pos..pos + HASH_LEN]);
        pos += HASH_LEN;
        shard_hashes.push(h);
    }

    if pos != bytes.len() {
        return Err(ShardError::ManifestTrailingBytes);
    }

    Ok(ShardSet {
        pack_hash,
        config,
        shard_hashes,
        commitment,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic 1-MiB pack-like payload. Not a real packfile —
    /// the shard layer treats its input as opaque bytes, so any byte
    /// stream with enough entropy exercises the encoder.
    fn synthetic_pack(bytes: usize) -> Vec<u8> {
        // Xorshift-style PRNG seeded with a fixed constant so the
        // tests are reproducible.
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut out = Vec::with_capacity(bytes);
        while out.len() < bytes {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            out.extend_from_slice(&x.to_le_bytes());
        }
        out.truncate(bytes);
        out
    }

    // ---- Strategy is a runtime parameter, not a hardcoded const ----
    //
    // Issue #653: `pack_shard.rs` used to pin
    // `const STRATEGY: Sequential = Sequential;` and pass `&STRATEGY`
    // into every `RsScheme::encode` / `RsScheme::decode` call — no
    // caller, test, or config could ever supply a different
    // `commonware_parallel::Strategy` impl. The tests below prove two
    // separate things:
    //
    // 1. `encode_pack_to_shards_with_strategy` /
    //    `decode_pack_from_shards_with_strategy` are generic over
    //    `S: Strategy` — a caller-supplied strategy compiles at all,
    //    which a hardcoded const could never allow.
    // 2. The supplied strategy is actually *invoked* by the encode /
    //    decode core (via a spy that counts calls into
    //    `Strategy::fold_init`), not merely accepted and discarded.

    /// A `Strategy` that counts how many times `fold_init` is invoked
    /// and otherwise behaves exactly like [`Sequential`]. Lets a test
    /// assert the supplied strategy was genuinely exercised by the
    /// encode/decode core, rather than silently ignored in favour of
    /// some other, hidden strategy.
    #[derive(Clone, Debug)]
    struct CountingStrategy {
        calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl CountingStrategy {
        fn new() -> Self {
            Self {
                calls: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl Strategy for CountingStrategy {
        fn fold_init<I, INIT, T, R, ID, F, RD>(
            &self,
            iter: I,
            init: INIT,
            identity: ID,
            fold_op: F,
            reduce_op: RD,
        ) -> R
        where
            I: IntoIterator<IntoIter: Send, Item: Send> + Send,
            INIT: Fn() -> T + Send + Sync,
            T: Send,
            R: Send,
            ID: Fn() -> R + Send + Sync,
            F: Fn(R, &mut T, I::Item) -> R + Send + Sync,
            RD: Fn(R, R) -> R + Send + Sync,
        {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Sequential.fold_init(iter, init, identity, fold_op, reduce_op)
        }

        fn join<A, B, RA, RB>(&self, a: A, b: B) -> (RA, RB)
        where
            A: FnOnce() -> RA + Send,
            B: FnOnce() -> RB + Send,
            RA: Send,
            RB: Send,
        {
            Sequential.join(a, b)
        }

        fn parallelism_hint(&self) -> usize {
            1
        }
    }

    #[test]
    fn explicit_strategy_is_actually_exercised_by_encode_and_decode() {
        let pack = synthetic_pack(64 * 1024);
        let config = default_config();
        let spy = CountingStrategy::new();

        let (shards, manifest) = encode_pack_to_shards_with_strategy(&pack, config, &spy).unwrap();
        let calls_after_encode = spy.calls();
        assert!(
            calls_after_encode > 0,
            "encode_pack_to_shards_with_strategy never invoked the supplied strategy"
        );

        let subset: Vec<Shard> = shards.into_iter().take(16).collect();
        let recovered = decode_pack_from_shards_with_strategy(&subset, &manifest, &spy).unwrap();
        assert_eq!(recovered, pack);
        assert!(
            spy.calls() > calls_after_encode,
            "decode_pack_from_shards_with_strategy never invoked the supplied strategy"
        );
    }

    #[test]
    fn round_trip_with_explicit_parallel_strategy() {
        // A pack well under `PARALLEL_STRATEGY_THRESHOLD` so this
        // stays a fast unit test, but still multi-shard: exercises a
        // genuine `Rayon` pool (not the spy above) end-to-end through
        // both the RS math and the per-shard hash loop.
        let pack = synthetic_pack(256 * 1024);
        let config = default_config();
        let strategy = Rayon::new(NonZeroUsize::new(2).unwrap()).expect("build rayon pool");

        let (shards, manifest) =
            encode_pack_to_shards_with_strategy(&pack, config, &strategy).unwrap();
        let subset: Vec<Shard> = shards.into_iter().take(16).collect();
        let recovered =
            decode_pack_from_shards_with_strategy(&subset, &manifest, &strategy).unwrap();
        assert_eq!(recovered, pack);
    }

    #[test]
    fn default_strategy_selection_is_a_runtime_threshold_not_a_const() {
        assert!(!should_use_parallel_strategy(0));
        assert!(!should_use_parallel_strategy(
            PARALLEL_STRATEGY_THRESHOLD - 1
        ));
        assert!(should_use_parallel_strategy(PARALLEL_STRATEGY_THRESHOLD));
        assert!(should_use_parallel_strategy(
            PARALLEL_STRATEGY_THRESHOLD + 1
        ));
    }

    #[test]
    fn default_encode_decode_round_trip_at_parallel_threshold() {
        // Exercises the size-based default (`encode_pack_to_shards` /
        // `decode_pack_from_shards`, no explicit strategy) at exactly
        // the threshold, so the parallel branch in
        // `default_parallel_strategy_for_len` actually runs.
        let pack = synthetic_pack(PARALLEL_STRATEGY_THRESHOLD);
        let config = default_config();
        let (shards, manifest) = encode_pack_to_shards(&pack, config).unwrap();
        let subset: Vec<Shard> = shards.into_iter().take(16).collect();
        let recovered = decode_pack_from_shards(&subset, &manifest).unwrap();
        assert_eq!(recovered, pack);
    }

    #[test]
    fn round_trip_default_config_1_mib_first_n_shards() {
        let pack = synthetic_pack(1024 * 1024);
        let config = default_config();
        let (shards, manifest) = encode_pack_to_shards(&pack, config).unwrap();

        assert_eq!(shards.len(), 20);
        assert_eq!(manifest.shard_hashes.len(), 20);
        assert_eq!(manifest.pack_hash, hash::hash(&pack));

        // Decode using shards 0..16 (the first `minimum_shards`).
        let subset: Vec<Shard> = shards.into_iter().take(16).collect();
        let recovered = decode_pack_from_shards(&subset, &manifest).unwrap();
        assert_eq!(recovered, pack);
    }

    #[test]
    fn lossy_round_trip_drops_shards_0_5_10_17() {
        let pack = synthetic_pack(1024 * 1024);
        let config = default_config();
        let (shards, manifest) = encode_pack_to_shards(&pack, config).unwrap();

        let dropped = [0u16, 5, 10, 17];
        let subset: Vec<Shard> = shards
            .into_iter()
            .filter(|s| !dropped.contains(&s.index))
            .collect();

        // Should be exactly 16 = minimum_shards remaining.
        assert_eq!(subset.len(), 16);

        let recovered = decode_pack_from_shards(&subset, &manifest).unwrap();
        assert_eq!(recovered, pack);
    }

    #[test]
    fn tampered_shard_is_rejected_before_decode() {
        let pack = synthetic_pack(256 * 1024);
        let config = default_config();
        let (mut shards, manifest) = encode_pack_to_shards(&pack, config).unwrap();

        // Flip a bit deep inside shard 0's bytes. The manifest entry
        // for shard 0 still reflects the *original* BLAKE3 (we did
        // not update it), so the tamper detection MUST fire.
        let last = shards[0].bytes.len() - 1;
        shards[0].bytes[last] ^= 0x01;

        let subset: Vec<Shard> = shards.into_iter().take(16).collect();
        let err = decode_pack_from_shards(&subset, &manifest).unwrap_err();
        assert!(
            matches!(err, ShardError::ShardHashMismatch { index: 0 }),
            "expected ShardHashMismatch{{index: 0}}, got {err:?}"
        );
    }

    #[test]
    fn index_out_of_range_is_rejected() {
        let pack = synthetic_pack(64 * 1024);
        let (_, manifest) = encode_pack_to_shards(&pack, default_config()).unwrap();
        let total = manifest.config.total_shards();

        // A shard claiming an index at (or beyond) the manifest's total
        // shard count. Its bytes never need to be real — the range
        // check fires before anything is hashed or decoded.
        let bogus = Shard {
            index: u16::try_from(total).unwrap(),
            bytes: vec![0u8; 32],
        };
        let err = decode_pack_from_shards(&[bogus], &manifest).unwrap_err();
        assert!(
            matches!(
                err,
                ShardError::IndexOutOfRange { index, total: t } if index == u16::try_from(total).unwrap() && t == total
            ),
            "expected IndexOutOfRange, got {err:?}"
        );
    }

    #[test]
    fn duplicate_index_is_rejected() {
        let pack = synthetic_pack(64 * 1024);
        let (shards, manifest) = encode_pack_to_shards(&pack, default_config()).unwrap();

        // Two entries claiming the SAME index: the first is the real,
        // correctly-hashed shard 0; the second is garbage. The
        // duplicate-index check on the second entry must fire before
        // its (bogus) bytes are ever hashed or decoded.
        let real_shard_0 = shards[0].clone();
        let impostor = Shard {
            index: 0,
            bytes: vec![0xFFu8; real_shard_0.bytes.len()],
        };
        let err = decode_pack_from_shards(&[real_shard_0, impostor], &manifest).unwrap_err();
        assert!(
            matches!(err, ShardError::DuplicateIndex { index: 0 }),
            "expected DuplicateIndex{{index: 0}}, got {err:?}"
        );
    }

    #[test]
    fn pack_hash_mismatch_on_forged_but_consistent_shard_set() {
        // A "forged-but-consistent" shard set: every per-shard hash,
        // the Merkle commitment, and the Reed-Solomon reconstruction
        // all check out — the manifest's final `pack_hash` is the only
        // thing that lies. This is the last line of defence (step 6)
        // after every other cross-check in `decode_pack_from_shards`
        // has already passed.
        let pack = synthetic_pack(256 * 1024);
        let (shards, mut manifest) = encode_pack_to_shards(&pack, default_config()).unwrap();
        manifest.pack_hash = hash::hash(b"not the real pack");

        let subset: Vec<Shard> = shards.into_iter().take(16).collect();
        let err = decode_pack_from_shards(&subset, &manifest).unwrap_err();
        assert!(
            matches!(err, ShardError::PackHashMismatch),
            "expected PackHashMismatch, got {err:?}"
        );
    }

    // ---- Manifest wire-format tests --------------------------------

    #[test]
    fn manifest_wire_format_round_trip_default_config() {
        let pack = synthetic_pack(64 * 1024);
        let (_, manifest) = encode_pack_to_shards(&pack, default_config()).unwrap();

        let bytes = encode_manifest(&manifest).unwrap();
        // Pin the v0 size for the default (16, 4) config.
        // 5 (prologue) + 32 (pack_hash) + 4 (config) + 32 (commitment)
        // + 4 (len) + 32 * 20 (hashes) = 717.
        assert_eq!(bytes.len(), 717);
        assert_eq!(&bytes[..4], &MANIFEST_MAGIC);
        assert_eq!(bytes[4], MANIFEST_VERSION);

        let decoded = decode_manifest(&bytes).unwrap();
        assert_eq!(decoded, manifest);
    }

    #[test]
    fn manifest_decode_rejects_bad_magic() {
        let pack = synthetic_pack(32 * 1024);
        let (_, manifest) = encode_pack_to_shards(&pack, default_config()).unwrap();
        let mut bytes = encode_manifest(&manifest).unwrap();
        bytes[0] = b'X';
        let err = decode_manifest(&bytes).unwrap_err();
        assert!(
            matches!(err, ShardError::InvalidManifestPrologue("bad magic")),
            "expected InvalidManifestPrologue(bad magic), got {err:?}"
        );
    }

    #[test]
    fn manifest_decode_rejects_unsupported_version() {
        let pack = synthetic_pack(32 * 1024);
        let (_, manifest) = encode_pack_to_shards(&pack, default_config()).unwrap();
        let mut bytes = encode_manifest(&manifest).unwrap();
        bytes[4] = 0xFF;
        let err = decode_manifest(&bytes).unwrap_err();
        assert!(
            matches!(
                err,
                ShardError::InvalidManifestPrologue("unsupported version")
            ),
            "expected InvalidManifestPrologue(unsupported version), got {err:?}"
        );
    }

    #[test]
    fn manifest_decode_rejects_trailing_bytes() {
        let pack = synthetic_pack(32 * 1024);
        let (_, manifest) = encode_pack_to_shards(&pack, default_config()).unwrap();
        let mut bytes = encode_manifest(&manifest).unwrap();
        bytes.push(0xAB);
        let err = decode_manifest(&bytes).unwrap_err();
        assert!(
            matches!(err, ShardError::ManifestTrailingBytes),
            "expected ManifestTrailingBytes, got {err:?}"
        );
    }

    #[test]
    fn manifest_decode_rejects_truncated_body() {
        let pack = synthetic_pack(32 * 1024);
        let (_, manifest) = encode_pack_to_shards(&pack, default_config()).unwrap();
        let mut bytes = encode_manifest(&manifest).unwrap();
        bytes.truncate(bytes.len() - 1);
        let err = decode_manifest(&bytes).unwrap_err();
        assert!(
            matches!(err, ShardError::ManifestUnexpectedEof),
            "expected ManifestUnexpectedEof, got {err:?}"
        );
    }

    #[test]
    fn manifest_decode_rejects_oversize_input() {
        // Construct a buffer that *claims* to be a valid manifest by
        // shape but exceeds the cap. We don't need a real manifest;
        // the size check fires before prologue parsing.
        let bytes = vec![0u8; MANIFEST_MAX_BYTES + 1];
        let err = decode_manifest(&bytes).unwrap_err();
        assert!(
            matches!(err, ShardError::ManifestTooLarge { .. }),
            "expected ManifestTooLarge, got {err:?}"
        );
    }

    #[test]
    fn manifest_decode_rejects_zero_config() {
        // Hand-craft a manifest with minimum_shards = 0.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&MANIFEST_MAGIC);
        bytes.push(MANIFEST_VERSION);
        bytes.extend_from_slice(&[0u8; HASH_LEN]); // pack_hash
        bytes.extend_from_slice(&0u16.to_le_bytes()); // minimum_shards = 0
        bytes.extend_from_slice(&4u16.to_le_bytes()); // extra_shards
        bytes.extend_from_slice(&[0u8; HASH_LEN]); // commitment
        bytes.extend_from_slice(&0u32.to_le_bytes()); // shard_hashes_len
        let err = decode_manifest(&bytes).unwrap_err();
        assert!(
            matches!(err, ShardError::ManifestZeroShardCount { .. }),
            "expected ManifestZeroShardCount, got {err:?}"
        );
    }

    #[test]
    fn insufficient_shards_returns_error() {
        let pack = synthetic_pack(64 * 1024);
        let config = default_config();
        let (shards, manifest) = encode_pack_to_shards(&pack, config).unwrap();

        // Only 15 of the 16 required shards.
        let subset: Vec<Shard> = shards.into_iter().take(15).collect();
        let err = decode_pack_from_shards(&subset, &manifest).unwrap_err();
        assert!(
            matches!(
                err,
                ShardError::InsufficientShards {
                    provided: 15,
                    minimum: 16,
                }
            ),
            "expected InsufficientShards{{15, 16}}, got {err:?}"
        );
    }
}
