## Purpose

This WP makes the multipart upload path real on the native filesystem backend. It also provides one shared
**storage multipart conformance suite** that every backend passes, and adds wire cases that exercise multipart through
the native server.

## A. Fixed (do not change)

1. **WP-1.11a's trait and semantics (read the merged code):**
   - `MultipartBlobStore`: `begin_multipart`, `begin_part` (returns a `PartSink` that verifies the CV before the part
     counts), `complete`, `abort`, and `MAX_PARTS`;
   - `SessionGone`;
   - `BlobKey::relative_path`;
   - the upload-marker namespace.
2. **STC §7.6:**
   - every part except the last is exactly `part_size`;
   - resending a part is idempotent;
   - completion makes the pack visible only if the merged root and the total match;
   - the server MAY abort the session on a mismatch.
3. **R-114:**
   - 1.11b covers FS, native wiring, the suite, and conf-native wire cases under `Feature::Multipart`;
   - 1.12 and 1.13 depend on 1.11b;
   - `mkit-transport-s3`'s multipart helpers are private and blocking; only `sigv4` is reusable.
4. **The FS blob store's durability discipline:** temp file, fsync, rename, then directory fsync. `sweep_stale_uploads`
   and the startup sweep of `server-spool`.

## B. Decided (do not change)

### B1. FS layout

- **Part files:** `<root>/server-uploads/<session>/<index>-<cvhex>`.
  - The session is the ticket id in hex.
  - The receipt tag is the file name, which includes the CV.
- **Writing a part:**
  - Parts are written through a temp file and renamed only after the CV verifies.
  - A re-upload whose CV verifies **replaces** the part, matching the memory backend.
- **`complete`:**
  - Streams the part files, in index order, through the existing `FsBlobStore::begin` pack sink. That sink fully
    re-verifies BLAKE3, fsyncs and renames.
  - Removes the session directory afterwards.
  - A tag that doesn't match a stored file → `SessionGone` or `Invalid`. Choose which, and document it (C).
- **`abort`:** removes the session directory. It is idempotent.
- **`MAX_PARTS` stays `u32::MAX`.

### B2. Sweep

- At startup, remove session directories older than **7 days** (the maximum ticket TTL). Never remove a younger one.
- Reuse the existing sweep machinery, extended to `server-uploads`.

### B3. Storage multipart suite

- Location: `mkit-server-conformance/src/storage/multipart.rs`, generic over `MultipartBlobStore`.
- Cases:
  - out-of-order parts;
  - a duplicate part;
  - replacing a verified part;
  - a CV mismatch leaves the old part intact;
  - a short or long part;
  - complete with a root or total mismatch: nothing becomes visible;
  - complete twice;
  - complete when the pack is already present;
  - abort, then `SessionGone`;
  - bounded memory (a chunk-counting sink);
  - crash leftovers never become visible.
- Run it for the **memory** and **FS** backends. WP-1.12 and WP-1.13 add R2 and S3 runs. Record that in R-132.

### B4. Wire cases under `Feature::Multipart`

- Add `Feature::Multipart` to `wire/profile.rs`, enabled for the memory and FS profiles only. S3 is excluded until
  WP-1.13.
- Cases:
  - a 3-part pack at the minimum 8 MiB part size (about 17 MiB total) through BeginUpload → UploadPart ×3 →
    CompleteUpload;
  - resume from client-held receipts after dropping client state;
  - no oracle across repositories: another repository's ticket and receipts can't complete this repository's upload;
  - a CompleteUpload root mismatch never becomes visible.
- Run them on the native binary baselines, FS + SQLite.

### B5. Native wiring

- UploadPart is already in `STREAMING` (1.11a). Verify the native server builds FS with multipart support, and that
  BeginUpload on FS creates sessions.
- Workers stay unsupported until WP-1.12: its R2 backend reports `supports_multipart = false`.

### B6. Plan

Add row **R-132**:

> WP-1.11b.
> - FS part layout `server-uploads/<session>/<index>-<cv>`, completed through the verifying pack sink.
> - Session directories older than 7 days are swept at startup.
> - The storage multipart suite lives in `mkit-server-conformance`; WP-1.12 and WP-1.13 must pass it.
> - `Feature::Multipart` wire cases cover memory and FS; S3 joins at 1.13, and Workers/R2 at 1.12.

## C. Your decisions

- `SessionGone` versus `Invalid` for a missing part file.
- The sweep integration.
- Test organisation.

## D. Escalate (stop and report) if

- Completion can't reuse the verifying pack sink without buffering whole parts.
- Production changes exceed 1,500 lines.

## Gates

- `just ci-server`
- `cargo nextest run --locked -p mkit-server -p mkit-server-native -p mkit-server-conformance --all-features`
- the wasm32 check
- `scripts/vcs-worker-conformance.sh` (default phase; multipart is excluded on Workers)
