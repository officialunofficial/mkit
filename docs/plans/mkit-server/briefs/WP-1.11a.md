## Purpose

This WP implements the multipart upload path of STC §7.6: `UploadPart` (client-streaming) and `CompleteUpload`
(unary). It is **stateless**, so it writes no metadata rows. Part receipts are server-MACed, and completion verifies
the merged BLAKE3 root before the pack becomes visible.

## A. Fixed (do not change)

1. **STC §7.6 / §7.7:**
   - the `part:<ticket>:<index>:<subtree>:<len>` commitment;
   - every part except the last is exactly `part_size`, and there are at most `max_parts`;
   - resending a part index is idempotent;
   - receipts bind the ticket, index, subtree, length and the backend tag;
   - completion verifies every receipt and makes the pack visible only if the merged root == `pack_id` **and** the
     length sum == `bytes`;
   - completion does not make the pack a member, and repeating it is idempotent;
   - **no replay record, no Authorizer, no admission, and nothing written to a metadata shard.**
2. **The error rows:**
   - a part or completion hash or length mismatch → `invalid_argument`;
   - a ticket, signer or commitment mismatch → `permission_denied`;
   - an expired or unknown ticket, or a token failure → `failed_precondition`;
   - a missing or late header → `invalid_argument`;
   - never `resource_exhausted`.
3. **Core helpers already exist:**
   - `ContentCommitment::Part` and `ExpectedCommitment::PartStream` (`mkit-core/src/write_auth.rs`);
   - `PartPlan`, `PartHasher`, `part_subtree_cv` and `merge_to_root` (`mkit-core/src/upload_parts.rs`).
4. **R-104:** receipts are MACed with `blake3::derive_key(PART_RECEIPT_CONTEXT = "mkit-server part receipt v1", secret)`,
   using the ticket key set: the first key signs, and every key verifies.
5. **Server config** already validates `part_size` (8–32 MiB, a power of two) and `max_parts` (`pipeline/info.rs`).

## B. Decided by the orchestrator (do not change)

### B.1 Procedures and auth

- Add `Procedure::UploadPart` (a streaming write) and `Procedure::CompleteUpload` (a unary write).
- Add `Commitment::Part{ticket, index, subtree, len}` in `op.rs`.
- `auth_v2` selects `ExpectedCommitment::PartStream` for UploadPart.
- Replace both `not_yet()` SECURITY stubs in `connect/service.rs` with authenticated handlers, and flip the
  `connect_dispatch.rs` assertion.
- **Refusals:**
  - no ticket keys → `unimplemented` "upload tickets are not configured";
  - a non-AuthV2 mode → `unimplemented` "UploadPart requires auth v2" / "CompleteUpload requires auth v2".
- The part path bypasses `write()`: no replay, no identify/authorize/admit, no lease, and **no `NamespaceStore` call**.

### B.2 UploadPart order (every step before any byte is stored)

1. The first message must be the header; otherwise `invalid_argument`, with the existing ProtocolError wording.
2. `verify_ticket(...)` on the business clock (`now + business_skew_ms`).
3. The commitment's ticket must equal `claims.ticket_id`, and its index must equal the header index; otherwise
   `permission_denied` "upload ticket binding mismatch".
4. `PartPlan::new(bytes, part_size, cfg.max_parts)`, then `check`. `NotMultipart`, `IndexOutOfRange`,
   `LengthMismatch` or `TooManyParts` → `invalid_argument`.
5. An empty `upload_session` on a multipart ticket → `failed_precondition` "invalid or expired upload ticket".
6. **Stream the part.**
   - An empty chunk message → `invalid_argument`.
   - An overrun → `invalid_argument` at the offending chunk.
   - A short part at stream end → `invalid_argument`.
   - A CV mismatch → `invalid_argument` "part subtree hash does not match its commitment".
7. Return the receipt.

**Hashing lives in the store.** A `PartSink` runs `PartHasher`, and the part counts only after its CV verifies, so a
bad re-upload never replaces a good part. The pipeline doesn't hash a second time.

### B.3 The `MultipartBlobStore` trait (in `store/blob.rs`; you may refine names)

```rust
pub trait MultipartBlobStore: BlobStore {
    type PartSink: PartSink;
    const MAX_PARTS: u32;
    async fn begin_multipart(&self, key: BlobKey, len: u64, part_size: u64) -> Result<Vec<u8> /*session*/, StoreError>;
    async fn begin_part(&self, key: BlobKey, session: &[u8], plan: &PartPlan, index: u32, expected_cv: [u8; 32]) -> Result<Self::PartSink, StoreError>;
    async fn complete(&self, key: BlobKey, session: &[u8], plan: &PartPlan, parts: &[PartRef /*index,len,tag*/]) -> Result<CommitOutcome, StoreError>;
    async fn abort(&self, key: BlobKey, session: &[u8]) -> Result<(), StoreError>; // WP-1.14 calls this
}
pub trait PartSink { /* write(chunk), commit(self) -> tag bytes, abort(self) */ }
```

Use the crate's existing async-trait style.
- Add a "session gone" signal (`StoreError` is `#[non_exhaustive]`), and the multipart `StorageOp` variants.
- `Pipeline::new` rejects `max_parts > B::MAX_PARTS`.
- **Implementations in this WP:**
  - memory: real;
  - FS, R2 and S3: stubs returning `Unsupported`;
  - `Blocking<S>`: forwards.
- Backends without multipart report it through a capability method used by B.5.

### B.4 Receipts

- **Format:**
  - version `0x01`;
  - key id (u8 length, then bytes);
  - `ticket_id` (32);
  - `index` (u32 BE);
  - `subtree` (32);
  - `len` (u64 BE);
  - tag (u16 length, ≤ 128 bytes);
  - a 32-byte BLAKE3-keyed MAC over everything before it.
- Expose a per-key-id receipt MAC key from `TicketKeys` without exposing the secrets.
- **Golden:** `rust/tests/golden/uploads/part-receipt-v1.json` (the mint bytes, plus one failure per class), with its
  MANIFEST pin.
- **An invalid receipt** (bad MAC, unknown key id, or malformed) → `invalid_argument` "invalid upload part receipt".
- **Operational rule** (runbook and STC): a key id is retired from the verify set only ≥ 7 days after rotation (the
  maximum ticket TTL), so an invalid receipt can only be a forgery.

### B.5 BeginUpload change (1.9a code)

- **When `bytes > part_size`:**
  - Check the backend's multipart capability **before admission**. An unsupported backend →
    `unimplemented` "multipart uploads are not supported by this storage backend".
  - After admission and before the batch, call `begin_multipart`, store the session in
    `TicketSpec.upload_session`, and mint the token with it (replacing `upload_session: vec![]` at
    `pipeline/begin.rs:~347` and `None` at `~291`).
  - On a batch failure, or on the `Existing` race, abort the new session best-effort.
  - Session creation failing under an admission-supplied reservation → retryable `unavailable`, with
    `TODO(WP-3.3)`, as the existing race path does.
- A live-ticket re-mint carries the stored session.
- A single-part ticket keeps an empty session.

### B.6 CompleteUpload order

1. `verify_ticket(...)`.
2. `PartPlan::new`, then `receipts.len() == plan.count()`; otherwise `invalid_argument`.
3. **For each receipt:**
   - check the MAC (B.4);
   - its ticket id must equal the claims' ticket id → `permission_denied` "upload ticket binding mismatch";
   - its index must equal its position, and `len == expected_len(i)` → `invalid_argument`.
4. The length sum must equal `bytes`, then `merge_to_root == pack_id`; otherwise `invalid_argument`
   "merged part root does not match the ticket".
5. **Only then call the store:**
   - `head(pack)` present with length `bytes` → abort the session best-effort and succeed;
   - otherwise `complete`;
   - session gone with the blob absent → `failed_precondition` "invalid or expired upload ticket".
6. **On success,** including the already-present case, `write_upload_marker(ticket_id, pack_id)`. The client proved
   it streamed every part: each receipt is server-authenticated.

The pure checks come first, so a repeat with the same inputs gives the same answer.

### B.7 STC and SPEC edits

- **STC §7.6:** "aborts the storage session" becomes "**MAY** abort the storage session". The M1 server does not
  abort on a root mismatch. Reclaim is WP-1.14's and the backend's lifecycle rule's, so the ticket isn't stuck until
  it expires.
- **STC §5:** add a row: an invalid part receipt → `invalid_argument`.
- **STC §7.6:** add the key-retirement sentence (B.4).

### B.8 Plan

- **Add row R-114:**

  > WP-1.11 split along the storage seam.
  > - **1.11a:** the protocol, receipts, trait plus memory, and the BeginUpload session.
  > - **1.11b:** FS, native wiring, the storage multipart suite, and the conf-native wire cases under
  >   `Feature::Multipart`.
  >
  > - 1.12 and 1.13 depend on 1.11b; 1.18 depends on 1.11a.
  > - Completion writes the upload marker (R-113).
  > - M4 note: stateless completion writes no row, so indexed-mode verification scheduling (SPEC-SERVER §9.5) moves
  >   to the first AdvanceRefs that consumes the ticket.
  > - The R2 multipart tag is an MD5 ETag: WP-1.12 must verify the completed object's BLAKE3, or escalate.
  > - G18 is corrected: `mkit-transport-s3`'s multipart helpers are private and blocking; only `sigv4` is reusable
  >   (1.13).
- **Registry:**
  - split 1.11 into 1.11a (depends on 1.9a) and 1.11b (depends on 1.11a);
  - 1.12 and 1.13 depend on 1.11b;
  - 1.18 depends on 1.11a.
- **Native router:** add UploadPart to `STREAMING` (`router.rs:~80`), so it doesn't get the 30 s unary deadline.
  This is a one-line native change allowed here.

## C. Your decisions

- The trait names and exact signatures, within B.3's shape.
- The memory implementation's internals.
- Test organisation.

## D. Escalate (stop and report) if

- The diff exceeds ~1,500 changed lines (excluding goldens).
- `BeginUpload`'s session creation can't be made safe under the existing race paths.
- Any B item contradicts merged normative text that you can't reconcile by citation.

## Tests (required; pipeline tests use the memory backend and a spy `NamespaceStore` that fails any call)

1. **Receipts:** the golden; a round trip under key rotation; an unknown key id is invalid.
2. **Auth:** `Commitment::Part` parsing and `PartStream` selection.
3. **UploadPart:**
   - out-of-order parts, then completion;
   - a duplicate part is idempotent;
   - a wrong subtree;
   - a short or long length;
   - a short non-last part in the commitment;
   - index out of range;
   - a header/commitment index or ticket mismatch (`permission_denied`);
   - a foreign signer or repository (`permission_denied`);
   - an expired or garbage token (`failed_precondition`);
   - a chunk before the header;
   - an empty chunk.
4. **CompleteUpload:**
   - a wrong count, a wrong order, a forged receipt, and a receipt from another ticket;
   - a root mismatch never becomes visible (`head` is `None`);
   - a total mismatch;
   - completing twice succeeds twice;
   - an already-present pack succeeds and aborts the session;
   - the marker is written in both success cases.
5. **Resume:** upload parts 0 and 1, drop the process state, send the rest using only the held receipts, then
   complete.
6. **Memory bound:** a chunk-counting sink never holds a whole part.
7. **BeginUpload:**
   - a multipart ticket carries a non-empty session;
   - a live re-mint carries the same session;
   - a single-part ticket has an empty session;
   - an unsupported backend → `unimplemented` before admission (admission spy count is 0);
   - an injected batch failure aborts the created session.
8. **Unchanged:** every existing test.

## Gates

- `just ci-server`
- `cargo nextest run --locked -p mkit-core -p mkit-server -p mkit-server-native -p mkit-server-worker --all-features`
- the wasm32 check and the worker build
- `buf lint` (no proto change is expected)
