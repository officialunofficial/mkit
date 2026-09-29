## Purpose

Tickets of more than `part_size` work on every production backend: FS (1.11b), R2 on the Worker, and native S3. Each
part is verified by its BLAKE3 subtree chaining value before it is stored. A completed pack is verified against its
BLAKE3 root before it becomes visible, and no backend MD5 or ETag is ever trusted. Expired tickets are closed with
exactly one `Expired` outcome, and their upload sessions are cleaned up.

## A. Fixed (do not change)

1. **The #1196 suite contract** (after its fix round), including:
   - out-of-order parts;
   - duplicate part → same tag;
   - replacing a verified part invalidates the old tag;
   - a CV mismatch keeps the old part;
   - a root or total mismatch makes nothing visible;
   - completing twice → `SessionGone`, or Ok with `AlreadyPresent`;
   - two concurrent completes → Ok or `SessionGone`, never `Invalid`;
   - abort → `SessionGone`;
   - crash leftovers are never visible;
   - bounded memory, measured with a counting allocator;
   - sessions opened through `begin_multipart_for_ticket`.
2. **R-114:** an MD5 ETag is never trusted, so BLAKE3 is verified or the WP escalates. **R-132:** the FS layout and
   the carry-forwards.
3. **STC §7.6:** part size 8–32 MiB (a power of two); `MAX_PARTS`; completion semantics; expiry.
4. **STC §7.7:** one outcome per reservation. An expired ticket's reservation gets `Expired`.
5. **Timer kind 2 is `TICKET_EXPIRY`.** Kinds 8 and 9 belong to the 3.2+3.3 bundle.

## B. Decided (do not change)

### Shared layout (all object stores)

**B1. Part objects keyed by CV.**
- Layout: `<prefix/>server-uploads/<session>/meta` (`{len, part_size}`) and `.../<index>-<cvhex>`, next to `packs/`
  and `upload-markers/v1/`.
- The session is the ticket id in hex.
- Every object is written with the existing verified, put-if-absent write.
- **A part is verified against its CV before it is visible:** on R2 the last byte is withheld until the CV checks; on
  S3 the part is spooled and verified before any request.
- A CV mismatch writes nothing. A different CV is a different key, so the old part stays.
- On commit, delete the sibling `<index>-*` objects so that a replacement invalidates the old tag. A concurrent
  same-index race may leave `Invalid` at complete; document it, since the client re-uploads.
- The tag is the CV.

**B2. Completion order.**
1. `head(final)`.
2. `meta` absent → `SessionGone`.
3. Assemble (B4/B6), with the whole pack's BLAKE3 verified before visibility.
4. A missing part while `meta` exists → `Invalid`.
5. After success, delete **`meta` first**, then the parts. A concurrent loser then sees `SessionGone`, never `Invalid`.

**Abort** lists by prefix and deletes everything; it is idempotent.

**B3. Bounded memory with in-process fakes.** `SimBucket` and `FakeS3` hold objects in RAM. Exclude their threads from
the counting allocator with a thread-local opt-out (on SimBucket's put threads, and on FakeS3's runtime threads via
`on_thread_start`). Don't weaken the claim.

### Part 1: WP-1.12 (R2 on the Worker)

- **B4. Completion.** Open `self.begin(final, len)`, bypassing `max_bytes`. Stream each part object's `get` into it in
  index order. The generalized `Withheld` re-verifies the whole BLAKE3 and only then releases the last byte of the
  conditional put.
  - **R2 native multipart is not used for client parts** (MD5 ETags; a failed re-upload loses the good part).
- **B5. `ObjectBucket` and limits.**
  - Add `list(prefix, cursor)` and `delete_many(keys)` for `EnvBucket` (wasm) and `SimBucket`.
  - Advertise an 8 MiB part size; the cap is 32 MiB.
  - A `MAX_PACK_BYTES` var: default 4 GiB, hard ceiling 4.995 GiB.
  - Remove the 64 MiB stopgap for ticketed multipart. It stays for the single-part `UploadPack`.
  - Part requests never reach a Durable Object.
  - Enable `Feature::Multipart` in `scripts/vcs-worker-conformance.sh` for the Worker profile.
  - **Measure and report in the PR:** UploadPart CPU per part size, and completion CPU per GiB, under `wrangler dev`.
  - The runbook notes that uploads need Workers Paid with `limits.cpu_ms` raised; 1.19 uses this.

### Part 2: WP-1.13 (native S3)

- **B6. Completion.**
  - `CreateMultipartUpload` on the final key.
  - `UploadPartCopy` for each part object, with bounded concurrency (8–16). The copy is server side, and the upload id
    is private to this request.
  - `CompleteMultipartUpload` with `If-None-Match: *`; a 412 means `AlreadyPresent`.
  - Then clean up, `meta` first.
  - A **200 response with an `<Error>` body** on UploadPartCopy or CompleteMultipartUpload is a failure.
  - Abort the private multipart upload on any failure.
  - Alternative, allowed only with proof: native multipart with `x-amz-checksum-sha256` bound into the receipt and the
    completion. It requires enforcement to be proven on **both** MinIO and R2's S3 API, and failing closed otherwise.
    Default to UploadPartCopy.
- **B7. Signing and dependencies.**
  - A native-local SigV4 signer supporting canonical queries and `x-amz-copy-source`, built from `sigv4`'s public
    helpers. **No semver bump** of `mkit-transport-s3`.
  - No XML dependency: build bodies with `format!`, and parse `UploadId`, `ETag` and `Error/Code` with small tag
    scanners.
- **B8. FakeS3 and wiring.**
  - FakeS3 gains Create/UploadPartCopy/Complete/AbortMultipartUpload and ListObjectsV2 with prefix and continuation:
    - the 5 MiB minimum part size;
    - uniform part sizes;
    - `InvalidPart`;
    - `If-None-Match`;
    - injection of a 200 with an error body;
    - strict 501 for everything else.
  - `supports_multipart = true`, and `Feature::Multipart` in `wire_s3_sqlite.rs`.
  - Add an `#[ignore]` MinIO multipart test using the testcontainers pattern from `transport_minio.rs`. Run it locally
    if Docker is available, and report the result.
- **B9. `CompleteUpload` gets the long deadline on native.** Add a `LONG` set next to `STREAMING` (`router.rs:~80`),
  using `stream_timeout`. Carry-forward for 1.18: the client uses a long timeout for CompleteUpload.
- **B10. The stalled-put test** (`s3_store stalled_put_is_abandoned_and_retried`).
  - Rerun it 3 times alone. #1082 may already have fixed it.
  - If it still fails: assert that the first status is `408`, accept `Created | AlreadyPresent`, and check the object's
    bytes.

### Part 3: WP-1.14 (ticket expiry; scope narrowed)

- **B11. Scope.** **1.14 is the kind-2 expiry handler only.**
  - Outcome delivery (kind 8), reconcile (kind 9) and "pre-M3 outbox retention" belong to the 3.2+3.3 bundle, which
    realizes P-9 with `NoOutcomes` plus its driver.
  - Until that bundle lands, `Expired` rows accumulate undelivered. Nothing is deployed; document it.
- **B12. `TicketExpiry<B: MultipartBlobStore>` (kind 2; the reference is the ticket id).**
  - Read `t`.
    - Absent → `Done` (it was consumed or aborted).
    - `expires_at_ms > now` → `Reschedule` at `expires_at`.
  - Otherwise read `o <rid>` (it must be `Ticketed{id}`), `ti`, `tc`, `tu`, `os` and `oc`. Then call
    `plan_ticket_close` without a second timer delete, and
    `OutboxBuilder::outcome(rid, Terminal(Expired{repository, occurred_at_ms}))` with `try_finish`. All of it is
    guarded, so a race with consumption fails the guard and re-reads.
  - With an `upload_session`: call `abort(BlobKey::pack(pack_id), session)` **before** returning the batch.
    - This is best-effort: log and count failures, and commit anyway. Lifecycle rules and the FS sweep catch leaks.
    - It is safe because consumption needs the marker and the blob, so completion already happened.
  - Cap it per tick at about 8 tickets, for the Worker Free plan's subrequest budget.
  - Synthetic `s:` reservations: close the ticket and write the terminal row the same way. The 3.3 driver acks them
    locally.
- **B13. Registration.**
  - Native: in the SQLite registry, with the store's blobs.
  - Worker: on the class that holds tickets. That is RefShard under D34; check `naming.rs` for the Single class. Use an
    `R2BlobStore<EnvBucket>` built from the DO's env.
- **B14. Docs and plan.**
  - STC §7.6 Expiry: the session is aborted best-effort.
  - INVARIANTS.
  - The runbook: R2 and S3 buckets expire `server-uploads/` after 8 days. FS keeps its startup sweep.
  - **R-144 (1.12), R-145 (1.13), R-146 (1.14):**
    - CV-keyed part objects;
    - no R2 multipart for client parts;
    - S3 assembly with UploadPartCopy;
    - the long `CompleteUpload` deadline;
    - the Worker pack cap;
    - the lifecycle rule;
    - 1.14's narrowed scope and the 3.3 ownership;
    - the measured CPU figures.
  - Update the registry text for 1.14 ("ticket expiry"; outbox retention moves to 3.3).
  - A CHANGELOG line per WP.

## C. Your decisions

- How `Withheld` is generalized to verify either the root or the subtree CV.
- `UploadPartCopy` concurrency, within 8–16.
- Module layout for the S3 multipart code, and the helpers for FakeS3.
- The per-tick expiry cap, if it differs from 8 (justify it).

## D. Escalate (stop and report) if

- Measured completion CPU on the Worker makes a 1 GiB pack infeasible within Workers Paid limits. Report the numbers;
  don't drop verification.
- A backend can't meet a suite contract case without trusting an MD5 or ETag.
- `mkit-transport-s3` would need a breaking change.
- Production code passes 3,000 lines. Then open the PR with the finished parts, and list the rest as not done.

## Tests (required)

1. The **full shared multipart suite** passes on R2 (over `SimBucket`) and on S3 (over FakeS3), including bounded
   memory with fake threads excluded.
2. **R2:**
   - a CV mismatch writes nothing and keeps the old part;
   - a replacement deletes its siblings;
   - completion verifies the whole root: a corrupted part object at rest makes nothing visible;
   - concurrent completes;
   - abort;
   - the multipart wire cases under `wrangler dev` (`vcs-worker-conformance.sh`, with Multipart enabled).
3. **S3:**
   - UploadPartCopy assembly;
   - a 200 with an error body is a failure, and the private upload is aborted;
   - `If-None-Match` gives `AlreadyPresent`;
   - ListObjectsV2 continuation;
   - the wire cases in `wire_s3_sqlite.rs`;
   - the `#[ignore]` MinIO test.
4. **Native:** CompleteUpload uses the long deadline; a slow completion past 30 s succeeds.
5. **Expiry:**
   - an expired ticket gets exactly one `Expired` row, and the ticket and its indexes are removed;
   - an unexpired ticket reschedules;
   - a consumed ticket is `Done`;
   - a race with consumption leaves exactly one terminal outcome;
   - the session is aborted, and a failed abort still commits;
   - the per-tick cap;
   - native and Worker registration (a timer fires on both).
6. **The stalled-put test** passes, or is adjusted per B10.

## Gates

- `just ci-server`, `just ci-scripts` and `just ci-security`
- `cargo nextest run --locked -p mkit-server -p mkit-server-native -p mkit-server-conformance -p mkit-server-worker --all-features`
- the wasm32 check and the worker build
- `scripts/vcs-worker-conformance.sh` (default phase, with Multipart enabled)
