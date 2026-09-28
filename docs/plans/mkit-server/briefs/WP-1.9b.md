## Purpose

This WP completes WP-1.9:
- UploadPack accepts a ticket token and streams the pack with no metadata access (STC §7.6/§7.7);
- the server records durable, unforgeable proof that the ticket holder streamed the full pack, so WP-1.10 can enforce
  PRD D15 ("an upload is always required when the repo lacks the pack");
- the advertised ticket threshold is enforced.

## A. Fixed (do not change)

1. **STC §7.6, §7.7 and §5.** A ticketed UploadPack:
   - is replay-exempt;
   - runs no Authorizer, no admission and no `pre_receive`;
   - **writes nothing to a metadata shard**;
   - verifies the token and the `pack:` commitment before reading data.

   Errors:
   - a missing, expired or unverifiable token → `failed_precondition`;
   - a binding mismatch → `permission_denied`;
   - never `resource_exhausted`.

   An un-ticketed upload that needs a ticket → `failed_precondition` (a ticket failure; the client calls BeginUpload).
2. **The 1.9a token API** (`upload/token.rs`):
   - `TicketKeys::verify(token, now_ms)` gives `failed_precondition` "invalid or expired upload ticket";
   - `check_binding(...)` gives `permission_denied` "upload ticket binding mismatch";
   - the clock is `clock.now_ms() + business_skew_ms`, as in BeginUpload.
3. **The blob store** is put-if-absent, and verifies BLAKE3(content) == key before anything is visible
   (`store/blob.rs`). `CommitOutcome` is advisory.
4. `server_info()` already advertises threshold 0 for Multi and non-default-admission deployments (`pipeline/info.rs`).

## B. Decided by the orchestrator (do not change)

### B.1 Entry point

- Add `Pipeline::open_ticketed_upload(a, pack_id, total, token)`. It returns the existing `UploadSession`, with a new
  `UploadMode::Ticketed`.
- Keep `open_upload`'s signature.
- `connect/service.rs` routes to the new function when `header.ticket_token` is non-empty, replacing the
  "not implemented yet" stub. Flip `connect_dispatch.rs`'s expectation.

**Order, all before reading any data:**
1. Header framing (existing errors).
2. Non-AuthV2 → `unimplemented` "ticketed UploadPack requires auth v2".
3. No ticket keys → `unimplemented` "upload tickets are not configured".
4. Header vs the signed `pack:` commitment → `unauthenticated` (existing message).
5. `verify_ticket(...)` (B.2), then a `pack_id`/`bytes` check against the header → `permission_denied`
   "upload ticket binding mismatch".
6. Open the sink, stream the **full** body and verify it, even when the pack is already stored globally. Never let the
   response depend on `CommitOutcome`.
7. Write the upload marker (B.3).
8. Respond.

**Skipped:** authorize, admission, `pre_receive`, the replay lookup and record, quota, and every `NamespaceStore` call.

**Faults:** only `AfterAuthenticate` and `AfterBlobCommit` apply.

### B.2 Shared helper (the same signature in 1.11a)

`rust/crates/mkit-server/src/upload/ticket_auth.rs`:

```rust
/// Verify a ticket token on the business clock and bind it to the caller.
/// Checks audience, repository and signer only; callers check pack/bytes/part fields.
pub(crate) fn verify_ticket(
    keys: &TicketKeys, token: &[u8], now_ms: u64,
    audience: &str, repository: &str, signer: &[u8; 32],
) -> Result<TicketClaims, ServerError>
```

Errors are exactly A.2's. Implement it with the existing `verify` and the binding logic; don't duplicate the MAC code.

### B.3 Upload marker (PRD D15 proof of upload)

`rust/crates/mkit-server/src/upload/marker.rs`:

```rust
pub(crate) const UPLOAD_MARKER_DOMAIN: &[u8] = b"mkit-upload-marker:v1\0";
/// Marker content: DOMAIN || ticket_id(32) || pack_id(32). Its blob key is BLAKE3(content).
pub(crate) fn upload_marker(ticket_id: &[u8; 32], pack_id: &Hash) -> (BlobKey, Vec<u8>)
pub(crate) async fn write_upload_marker<B: BlobStore>(blobs: &B, ticket_id: &[u8; 32], pack_id: &Hash) -> Result<(), StoreError>
```

- **Write it** after the pack blob commits, through the normal put-if-absent path. It is content-addressed, so it
  verifies like any blob, and a repeat write is a no-op.
- **Key namespace:** it MUST NOT be addressable as a pack.
  - If `BlobKey` can't express a separate namespace, add a variant (for example `BlobKey::UploadMarker(Hash)`, mapped
    to `upload-markers/v1/<hex>`) across the backends.
  - Pack RPCs (`PackExists`/`DownloadPack`) must never resolve a marker key.
- **The marker proves** that the holder of ticket T streamed and verified pack P. WP-1.10 will require it, along with
  the pack blob, before consuming a ticket.
- Add a golden of the marker's content bytes and key for one fixed (ticket, pack) pair in `rust/tests/golden/uploads/`,
  plus its MANIFEST pin.

### B.4 Threshold enforcement

- One function, `Pipeline::effective_threshold()`, is used by both `server_info()` and enforcement.
- An **un-ticketed** UploadPack with `total ≥ T`, in any auth mode other than transport identity (ssh/enc stay exempt;
  WP-1.15 owns implicit tickets), → `failed_precondition` "upload requires a ticket from BeginUpload".
  - It runs before any store read or write.
  - It **replaces** `require_pack_membership()` at `pipeline/upload.rs:~202`. **Delete** `require_pack_membership`.
- Multi without ticket keys refuses the same way, and BeginUpload there answers `unimplemented` (existing 1.9a
  behaviour).
- Empty packs: with T = 0, a 0-byte pack also needs a ticket, and BeginUpload refuses `bytes = 0`. **Accept this and
  document it** (clients never upload empty packs) in the STC §7.6 text as a sentence and in R-113.
- Flip the wire case `repository.packs_need_membership`, if 1.23b's version is in your base: an un-ticketed Multi
  UploadPack is now `failed_precondition`, not `unimplemented`.

### B.5 Startup refusal

`Pipeline::new` refuses non-default admission unless auth is v2 **and** ticket keys are configured, with an
`invalid_argument`: "admission requires auth v2 and upload ticket keys". It would otherwise advertise threshold 0 while
tickets are impossible.

### B.6 R-85: keep the legacy resume and make it normative

- Legacy (un-ticketed) UploadPack resume stays. It is reachable only below the threshold on single-repository
  deployments.
- **STC §7.1:** add a scoped **MAY**. A single-repository deployment MAY resume an un-ticketed UploadPack whose signed
  nonce is `in_flight` by re-reading the stream, as today.
- Make the matching §11 invariant edit.
- Update R-85's text: decided in WP-1.9b, and kept.
- Rewrite the `pipeline/upload.rs` module docs accordingly. Line ~46 ("ticketed uploads move to their target ref
  shard") is wrong: they touch no metadata.

### B.7 Plan

- **Add row R-113:**

  > WP-1.9b.
  > - A ticketed UploadPack touches no metadata; it writes a content-addressed upload marker
  >   (`BLAKE3(domain ‖ ticket ‖ pack)`) in a non-pack blob namespace, which WP-1.10 MUST require (with the pack blob)
  >   before consuming a ticket (PRD D15).
  > - The threshold is enforced (`failed_precondition`); empty packs need a ticket where T = 0 (accepted).
  > - Admission requires auth v2 and ticket keys.
  > - The legacy resume is kept as a single-repository MAY (R-85).
  > - UploadPack does not enforce `bytes ≤ part_size`.
  >
  > Markers are reclaimed by M5 GC.
- **Registry** (the 00-plan table and `registry.json`, if present):
  - split 1.9 into 1.9a (done) and 1.9b;
  - 1.10 depends on 1.9b;
  - leave the 1.11 rows to WP-1.11a.
- Add INVARIANTS "Ticketed UploadPack touches no metadata and always leaves a marker", with the enforcing test names,
  and a CHANGELOG entry.

## C. Your decisions

- The `BlobKey` namespace mechanism (B.3), within the "never addressable as a pack" rule.
- Test organisation.

## D. Escalate (stop and report) if

- The marker namespace needs more than ~200 non-test lines across backends.
- Any B item contradicts merged normative text that you can't reconcile by citation.

## Tests (required)

1. **Flow** (in process; memory and SQLite; Single, D34 and Multi):
   - a round trip with **zero** `NamespaceStore` calls (a spy), no replay row, no quota charge, and the marker
     present;
   - a retry with the same nonce and with a new one;
   - every token failure class, and every binding mismatch (another signer, another repository in Multi, another
     audience, pack or bytes): the stream is never read and nothing is stored;
   - the header-vs-commitment check wins;
   - a denying authorizer, a refusing `pre_receive` or a challenging admission doesn't affect a ticketed upload
     (admission spy count is 0);
   - streaming errors under a ticket;
   - a globally present pack gives the identical answer, and the marker is still written;
   - a fault after the blob put, then a retry.
2. **Threshold:**
   - Multi un-ticketed → `failed_precondition` with no store read;
   - Single with admission is refused at startup (B.5);
   - Single with a configured T = N: below N uses the legacy path, N and above are refused;
   - ssh is exempt;
   - a token with Open auth or no keys → `unimplemented`.
3. **Race:** concurrent ticketed uploads of the same pack (the same ticket, and tickets from different repositories)
   all succeed, the pack is stored once, and each ticket gets its marker.
4. **Marker:**
   - the golden;
   - `PackExists`/`DownloadPack` on a marker key answer as absent (Single and Multi).
5. **Wire** (native binary, the in-process baselines, and vcs-worker `--test-faults`):
   - `tickets.upload_pack_ticketed`;
   - `tickets.upload_pack_bad_token`;
   - `tickets.upload_pack_binding_denied`;
   - `tickets.upload_pack_expired_token` (TestFaults);
   - `repository.upload_needs_ticket` and `repository.ticketed_upload_multi` (MultiRepo).
6. **Unchanged:** the legacy resume tests and the `auth_v2.mjs --fault` parity test.

## Gates

- `just ci-server`
- `cargo nextest run --locked -p mkit-server -p mkit-server-native -p mkit-server-conformance -p mkit-server-worker --all-features`
- the wasm32 check and the worker build
- `scripts/vcs-worker-conformance.sh` (default, and `--test-faults`)
