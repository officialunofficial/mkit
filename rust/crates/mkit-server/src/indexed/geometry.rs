//! Indexed admission geometry: payload, canonical object and encoded frame bytes.
use mkit_core::pack::{DecodeLimits, PackError};
/// Largest unchunked file (and individual chunk) emitted by core/CLI ingest.
pub const PAYLOAD_BYTES: u64 = mkit_core::worktree::CHUNK_THRESHOLD;
/// Six-byte object prologue and four-byte Blob length.
pub const BLOB_FRAMING_BYTES: u64 = 6 + 4;
/// Maximum canonical entry, including metadata objects and chunk manifests.
pub const CANONICAL_BYTES: u64 = PAYLOAD_BYTES + BLOB_FRAMING_BYTES;
/// Worst all-INSERT delta framing; larger instruction streams are refused.
pub const DELTA_STREAM_BYTES: u64 = CANONICAL_BYTES + CANONICAL_BYTES.div_ceil(127) + 9;
/// `ChunkedBlob` prologue, total size, chunk size and chunk count.
pub const MANIFEST_FRAMING_BYTES: u64 = 6 + 8 + 4 + 4;
/// Manifest references under the canonical bound; logical bytes use the extraction allowance.
pub const MANIFEST_CHUNKS: u64 = (CANONICAL_BYTES - MANIFEST_FRAMING_BYTES) / 32;
/// Largest encoded payload, including compressed objects and delta streams.
pub const FRAME_PAYLOAD_BYTES: u64 = super::checkpoint::WINDOW_BYTES;
/// Frame kind and u32 encoded length, followed by its encoded payload.
pub const FRAME_BYTES: u64 = FRAME_PAYLOAD_BYTES + 5;
/// Fixed scheduled component allowance.
pub const RESIDENT_BYTES: u64 = 48 << 20;
pub(crate) const ENTRY_CACHE_BYTES: u64 = (8 << 20) - 8 * BLOB_FRAMING_BYTES;

/// Per-entry decoder allowance; smaller custom slices remain fail-closed.
#[must_use]
pub fn decode_limits(resident: u64, window: u64) -> DecodeLimits {
    entry_limits(
        CANONICAL_BYTES.min(
            resident
                .saturating_sub(window.saturating_mul(2))
                .saturating_sub(ENTRY_CACHE_BYTES)
                / 8,
        ),
    )
}
pub(crate) fn entry_limits(budget: u64) -> DecodeLimits {
    DecodeLimits::default()
        .with_max_decoded_bytes(budget)
        .with_entry_geometry(FRAME_PAYLOAD_BYTES, DELTA_STREAM_BYTES)
}
pub(crate) fn check_entry(canonical: u64, frame: u64) -> Result<(), PackError> {
    if canonical > CANONICAL_BYTES || frame > FRAME_BYTES {
        return Err(PackError::PackfileTooLarge);
    }
    Ok(())
}
const _: () =
    assert!(2 * FRAME_PAYLOAD_BYTES + ENTRY_CACHE_BYTES + 8 * CANONICAL_BYTES <= RESIDENT_BYTES);
// Preservation decoder scratch overlaps a frame, latest base and decoded stream.
const _: () = assert!(FRAME_BYTES + (28 << 20) + 2 * DELTA_STREAM_BYTES < RESIDENT_BYTES);

// Carried frames release idle windows before decoding; full-window copies do not triple.
const _: () = assert!(2 * FRAME_PAYLOAD_BYTES + 8 * CANONICAL_BYTES < RESIDENT_BYTES);
