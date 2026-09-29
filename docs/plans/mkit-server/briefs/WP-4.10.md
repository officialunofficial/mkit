# WP-4.10: D32 extraction into the global object CAS, holds and holders

## Purpose

In indexed mode, every Blob of at least 64 KiB (file content) and every ChunkedBlob is stored once, deployment-wide,
under its object id. A ChunkedBlob is stored as its reassembled content, with a chunk-offset sidecar. Each object is
protected by a hold while it is being extracted and by a holder row per repository afterwards. HTTP serving
(4.12/4.14b) can then serve file content directly, and GC (5.3) can reclaim objects safely. It stays
Stage-2-programmatic behind `IndexedConfig`.

## A. Fixed (do not change)

1. **SPEC-SERVER:**
   - §9.6: the extraction rules and the 64 KiB threshold, not advertised;
   - §13.2–§13.4:
     - holder writes advance the object's change sequence;
     - holder removal is conditional on it;
     - a hold is durable before bytes are reused;
     - `deleting` means retryable `unavailable`;
     - GC reconciles orphaned holders;
   - §14.2: extraction dedup, holds and holder recording check the blocklist; a blocked object is
     `permission_denied` `object blocked`.
2. **SPEC-HTTP-OBJECTS §5.1:** a Blob body is raw content; a ChunkedBlob body is the concatenated chunks, never the
   manifest.
3. **The blob-store contract** (`store/blob.rs`):
   - verify before visible;
   - `AlreadyPresent` is advisory and never used for accounting.
4. **R-130:** index `i` rows are write-once, with no `extracted` flag. **R-131:** 4.10a is dropped, and 4.10 absorbs
   `HolderV1`, releasing the hold in the same batch that records the holder. **R-148:** indexed mode is programmatic
   only, and Workers refuse it.
5. **The advance batch is unchanged:** 89 ops on D34 and 78 on Single, per #1212. Opaque mode is untouched.
6. **No oracle:** extraction outcomes never reach a response. Chunks come only from this push or this repository's
   membership. An extracted object is never a resolution source for `DownloadPack`, `PackExists` or the resolver.

## B. Decided (do not change)

- **B1. Keyspace (D-1).**
  - Add sibling namespaces in the existing blob store `B`:
    - `BlobNamespace::Object` → `<parent>/objects/<hex id>`;
    - `BlobNamespace::ObjectOffsets` → `<parent>/object-offsets/v1/<hex manifest id>`.
  - This needs no second store instance and no new `Pipeline` type parameter. Record it as an R-07 amendment.
  - Pack RPCs still build only `BlobKey::pack`.
- **B2. Root-verified sink.**
  - A defaulted `PackSink::commit_with_root(self, content_root: Hash)`: bytes become visible only if the length
    matches and `BLAKE3(raw) == content_root`.
  - Plain `commit()` refuses `Object` and `ObjectOffsets` keys.
  - Implement it on memory, FS, S3 and R2. **R2 withholds the last byte** until the root check passes.
  - **Multipart `complete` for `Object` keys** is checked against the same root, for objects over the backend's
    single-put cap: S3 5 GiB, R2 over the single-put default. Use server-computed part CVs, reusing 1.12/1.13 (D-4).
- **B3. `HolderV1 { seq, op_id }` (R-131).**
  - A codec with a golden test.
  - `seq` is the object's post-bump `c.seq`, so every holder write, including a re-record, advances it.
  - `op_id` is the consuming ticket id.
  - `add_holder` returns `first_holder`.
  - `remove_holder(expected_seq)` is guarded.
  - Hold and holder batches gain `NotAfter`.
  - Remove the stale "provisional / WP-4.10a" wording in `content_index.rs` and `keys.rs`.
  - Update the ContentIndex conformance cases on memory, SQLite, FS and the Worker loopback.
- **B4. Selection (D-3).** A pure function of the staged set:
  - every staged ChunkedBlob;
  - every staged Blob with data ≥ `IndexedConfig.extract_min_bytes` (default 65,536, validated ≥ 1, never
    advertised), **excluding Blobs referenced only as chunks by staged manifests**.
  - Record the carry-forward: a blob first seen only as a chunk and later referenced by a tree stays unextracted, and
    4.12 falls back to its pack entry.
- **B5. The per-object step** (`indexed/extract.rs`, runtime-agnostic):
  1. **Take the hold.** Its id is `BLAKE3("mkit-extract-hold:v1" ‖ ns ‖ repo ‖ ticket ‖ object)`, and its TTL is
     `min(MAX_HOLD_TTL_MS, max(1 h, apply window + relay lag bound + margin))`, renewed during long streams (D-9).
     - `Blocked` → `permission_denied` `object blocked`, without the §14.6 detail (D-7; that is 5.6's).
     - `deleting` or `Unavailable` → `pending(1000)`.
  2. **`head(Object(id))`.** If the object is present with the expected length, dedup and skip the upload.
  3. **Otherwise stream the content** and `commit_with_root`.
  4. **For a chunked object,** write the offsets sidecar:
     - `"MKOF"`, then u32 LE `chunk_count`, then `chunk_count + 1` × u64 LE;
     - it starts at 0 and ends at `total_size`;
     - this is 4.14a's `boundaries` shape.
  5. **Record the holder** with `add_holder(obj, (ns, repo), releases = hold)` in one ContentIndex batch.
- **B6. Chunk sources and verification.**
  - Chunks come from the staged map first, then `resolve::member_object`, which is repository-isolated. Each read is
    charged to the remaining `decode_budget`, and the member cache is dropped per chunk.
  - **Before commit, verify:**
    - each chunk's canonical bytes hash to `manifest.chunks[i]`, and its type is Blob;
    - the running length stays ≤ `total_size` and ends equal to it;
    - a plain Blob rehashes against its id.
  - Checked arithmetic throughout.
  - A failure is `unavailable` "verified pack content inconsistency". **No new public message.**
- **B7. Wiring (D-2).**
  - Extraction runs inline in `verify_ticketed`, for each pack that isn't already verified, **after its index rows
    and before its `Verified` CAS**.
  - `renew_all_pending` runs between objects and before each commit.
  - **Invariant:** `vs = Verified` ⇒ extracted, held and holder recorded.
  - The advance batch is unchanged.
- **B8. Extraction budget (D-6).** `IndexedConfig.max_extract_bytes`, default 4 × `max_pack_bytes`. Exceeding it
  answers the existing `invalid_argument` `pack exceeds indexed decode budget`.
- **B9. `new_to_store` (D-5).** Keep the ticket-bytes upper bound in indexed mode. The R-row line says it stays an
  upper bound until 5.3a adds pack holders.
- **B10. Worker side (D-8).**
  - Register a new registry row **4.10b**: "Worker: extraction slices and content relay hook". M4, Stage 2, deps 4.8
    and 4.10. It covers:
    - checkpointed alarm slices;
    - R2 multipart for large objects;
    - a content `RelayHook` rewriting `h` puts into `HolderV1` with a `c` guard;
    - the relay blocklist check;
    - hold lifetime across relay lag.
  - Workers keep refusing indexed mode.
- **B11. Boundaries.**
  - **Pack holders and the ticket hold** are 5.3a's.
  - **Stage-5 blocklist detail and relay takedown scheduling** are 5.6's.
  - **4.5's `holds_any`** is a membership probe, not a ContentIndex hold. Say so in the docs, because the names
    collide.
- **B12. Docs and plan.**
  - **R-163:** B1–B11, and the breakdown-vs-spec table from the fact sheet §2 (dropped 4.10a, no `extracted` flag,
    direct holder recording on native, the root-verified sink, advisory `AlreadyPresent`, all four backends).
  - The registry: add 4.10b, and repoint 4.8 and 4.12 dependents if needed.
  - A CHANGELOG line.
  - A SPEC-SERVER history row only if you add spec text.

## C. Your decisions

- The internal shapes of `extract.rs` and the streaming buffer.
- Fault-seam names for the crash matrix.
- How the multipart path computes part CVs.

## D. Escalate (stop and report) if

- The inline extraction can't keep the `Verified` invariant within the 30 s lease model, even with renewal.
- A backend can't do a root-verified commit without buffering a whole object in memory.
- Production code passes 2,000 lines. Cut in this order:
  1. the multipart path for over-cap objects, which becomes `unavailable` plus a carry-forward;
  2. then open the PR with series 1 and 2, and list 3 as not done.

## Tests (required)

1. **Blob namespaces:**
   - `relative_path` goldens;
   - `commit()` refuses `Object`;
   - `commit_with_root` with a wrong root or length leaves nothing visible on memory, FS, S3 (mock or MinIO) and R2
     (host mock);
   - a present key → `AlreadyPresent`, and R2 429 plus a present key → `AlreadyPresent`;
   - multipart `Object` completion is root-checked.
2. **ContentIndex:**
   - the `HolderV1` golden;
   - a re-record advances `seq` without changing the count;
   - a stale `remove_holder` is a no-op;
   - `first_holder`;
   - a hold or holder racing `block()` sees the block;
   - a passed `NotAfter` means no write;
   - conformance on all backends.
3. **Two repositories push the same large file:** one object, two holders, holds released, byte-identical responses.
4. **ChunkedBlob round trip** with staged chunks, member chunks and a mix. The offsets sidecar equals the boundaries
   and is accepted by `build_range_proof_from`.
5. **Corruption:** a chunk id or `total_size` mismatch, or a wrong-type chunk, commits nothing.
6. **The crash matrix:**
   - after the hold, before the put;
   - after the put, before the holder;
   - after the holder, before `Verified`;
   - mid-stream.

   At no instant is a present object without a hold or a holder.
7. **GC:** the hold beats `commit_collect`, and `deleting` → pending, then a retry re-uploads.
8. **Isolation:**
   - an extracted id is not served by `DownloadPack` or `PackExists`;
   - the resolver never reads `Object` keys;
   - a foreign-only chunk and a nonexistent chunk give identical answers.
9. **Threshold and selection:** 65,535 vs 65,536; a chunk-only blob is not extracted; a blob that is both a file and
   a chunk is extracted.
10. **Budgets:** `max_extract_bytes`, and peak memory within one chunk plus the window.
11. **Invariants:**
    - advance op counts unchanged;
    - opaque mode untouched;
    - Workers still refuse;
    - a lease lost mid-extraction gives pending, and the redo is idempotent.
12. **Native wire case:** an indexed push of a file over 1 MiB, then an object at `objects/<id>` with the expected
    length.

## Gates

- The common gate set.
- `just ci-server`, `ci-scripts` and `ci-security`.
- `cargo nextest run --locked -p mkit-core -p mkit-server -p mkit-server-native -p mkit-server-worker -p mkit-server-conformance --all-features`.
- The wasm32 check and the worker build (R2).
- `scripts/vcs-worker-conformance.sh` (default phase). Use a free `VCS_CONFORMANCE_PORT`; the default 8791 may be in
  use.
