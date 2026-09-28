## Purpose

A client that uploads a pack first calls `BeginUpload(ref, pack_id, bytes)`. The server admits the upload once, records
a reservation and a ticket in the target ref's shard, and returns a **stateless, server-authenticated ticket token**.
Uploads (1.9b), parts (1.11) and the consuming advance (1.10) then verify that token without strongly consistent
metadata.

This WP implements `BeginUpload` end to end in core, plus the token key configuration in both adapters.

## A. Fixed by the plan and specs (do not change)

1. **STC** (read it all):
   - §7.6: BeginUpload, the ticket, the token binding (ticket id, audience, repository, signer, pack_id, bytes,
     part_size, expires, key id), expiry under 7 days, "same signer, ref and pack returns the same ticket", errors,
     threshold, membership, retries;
   - §7.7: lifecycle, including "a live ticket is returned after authorization and before admission: no admission,
     no reservation, never challenged", and `AlreadyPresent` only for members;
   - §7.1: signed-write order and replay (every signed write outside the part path persists a replay record);
   - §5: the error table;
   - §2.1.
   SPEC-SERVER §3 rule a and §5.
2. **WP-1.7 planners (merged):**
   - `store/tickets.rs`: `TicketSpec`, `TicketReads`, `TicketCaps`, `plan_ticket_open`, `keys`, `ticket_id`;
   - `store/outbox.rs`: `OutboxBuilder::reserve`, `synthetic_reservation_id`;
   - `TicketV1`, validated in `codec.rs` (TTL under 7 days; `part_size` a power of two ≥ `MIN_PART_SIZE`);
   - `kinds::TICKET_EXPIRY = 2`. Its handler is WP-1.14; until then expired tickets keep their cap slots.
3. **WP-1.25 (#1150, merged before you start):**
   - under D34, `observe_lease` runs before `authorize`, and `admit_lease` runs after `admit`;
   - the `el` guard goes in `plan_write`, and `plan_clock` caps the deadline.

   `BeginUpload`'s ref-shard batch MUST carry the same lease handling as any D34 write.
4. **WP-1.6:** `PipelineConfig.part_size` and `max_parts` exist; use `part_size` for tickets.
5. **R-101:** 1.9 needs only 1.23a. Membership reads (`is_member`) are 1.23b's.

## B. Decided by the orchestrator (do not change)

### B.1 Procedure and auth

- Add `Procedure::BeginUpload` (`is_write = true`, not streaming, path `/mkit.transport.v1.TransportService/BeginUpload`),
  plus `OpKind::BeginUpload { ref_name, key: PackKey, bytes }`.
- Update the tables in `op.rs` tests and the conformance `Rpc` enum.
- Replace the stub's SECURITY comment with real authentication (`authenticated(&ctx)?`). Flip the relevant assertion
  in `m1_stub_paths_are_not_authenticated_procedures_yet`: BeginUpload is now a Procedure. UploadPart and
  CompleteUpload remain pending (1.11).
- **`AuthMode::AuthV2` only.** Other modes have no signer to bind, so they answer `unimplemented`, with message
  "BeginUpload requires auth v2". ssh implicit tickets are WP-1.15.
- Rename the internal legacy `Pipeline::begin_upload` (the UploadPack session) to `open_upload`, so the RPC can be
  `Pipeline::begin_upload`. Mechanical: update all callers.

### B.2 The token (`rust/crates/mkit-server/src/upload/token.rs`)

**MAC:**
- BLAKE3 keyed hash, with key `blake3::derive_key("mkit-server ticket token v1", secret)`.
- 1.11 derives its part-receipt key from the **same secret**, with the context `"mkit-server part receipt v1"`.
  Reserve that constant now, unused.

**Encoding** (little-endian lengths are not used; everything is fixed-order):
- the byte `0x01`;
- `key_id` (u8 length, then 1–32 ASCII bytes of `[A-Za-z0-9._-]`);
- `ticket_id` (32 bytes);
- `audience` and `repository`, each as a u16 BE length followed by the bytes;
- `signer` (32) and `pack_id` (32);
- `bytes`, `part_size` and `expires_at_ms`, each u64 BE;
- `upload_session` (u16 BE length, then bytes; empty in 1.9a);
- `tag` (32 bytes): BLAKE3-keyed over everything before it.

**Verification:**
- MAC first (constant-time compare), against the key named by `key_id` among the accepted keys;
- then decode;
- then expiry against the business clock.

**Errors** (per STC §7.6, since the fields travel in clear, the server can tell these apart):
- a bad MAC, an unknown key id, a truncated or garbage token, or expiry → `failed_precondition`;
- a binding mismatch → `permission_denied` (this check is used by 1.9b, 1.10 and 1.11).

**API:**
```rust
pub struct TicketClaims { pub ticket_id: [u8;32], pub audience: String, pub repository: String, pub signer: [u8;32],
    pub pack_id: [u8;32], pub bytes: u64, pub part_size: u64, pub expires_at_ms: u64, pub upload_session: Vec<u8> }
pub struct TicketKeys { /* current (id, secret), accepted Vec<(id, secret)> */ }
impl TicketKeys { pub fn mint(&self, c: &TicketClaims) -> Vec<u8>; pub fn verify(&self, token: &[u8], now_ms: u64) -> Result<TicketClaims, ServerError>; }
```

- Add a golden, `rust/tests/golden/uploads/ticket-token-v1.json`, with a fixed test secret and claims: the bytes, and
  one verify failure per error class. Add it to that directory's MANIFEST.

### B.3 Key configuration

- **Core:** `PipelineConfig.ticket_keys: Option<TicketKeys>`. With `None`, `BeginUpload` answers `unimplemented`
  "upload tickets are not configured".
- **Native:** `--ticket-key-file <PATH>`, read with the existing `read_secret_file` and `ReadRule::SECRET`, and an
  alternative env var `MKIT_TICKET_KEYS`.
  - Format: one key per line, `<key-id> <64 hex>`. The first line is the signing key, and every line is accepted.
    Blank lines and `#` comments are allowed.
  - An invalid file is a `USAGE` error.
- **Worker:** the secret `TICKET_KEYS`, in the same format, parsed in `WorkerConfig::from_vars`.
  - Add a clearly fake dev value to `wrangler.dev.jsonc` vars, so conformance can run.
  - `wrangler.jsonc` gets a comment saying it's installed with `wrangler secret put TICKET_KEYS` (WP-1.19).
- Add row **R-104** to `00-plan.md`:

  > One deployment secret for the M1 upload MACs. WP-1.9a derives the ticket-token key from it, and WP-1.11 derives
  > the part-receipt key (context "mkit-server part receipt v1"). It's rotated by key id: the first key signs and all
  > listed keys verify. This supersedes the breakdown's assignment of key config to WP-1.11.

### B.4 The `BeginUpload` flow (a unary write through the existing `write()`, not a parallel path)

1. **Validate before anything else:**
   - `check_ref_name`;
   - refuse `refs/mkit/packmap/*` with `invalid_argument` "BeginUpload names a branch or tag, not its packmap";
   - under D34, require `refs/heads/` (only heads pair with packmaps in AdvanceRefs);
   - `pack_id` is 32 bytes;
   - `1 ≤ bytes ≤ max_pack_bytes`.
2. **authenticate → replay lookup.** A committed record returns the stored result (B.5). An in-flight one is not
   possible for a unary write.
3. **Under D34, `observe_lease`, then authorize.** This runs WP-1.5's policy.
4. **Pre-admission reads,** folded into the existing read-ahead `get_many` in the target ref shard: `ti`, `tc`, `tu`,
   and the local membership row `m 00 <repo> 00 <pack>`. The indexed `t` is read by id after `ti` if needed; that is
   one extra `get` only when `ti` exists.
5. **Decide before admission:**
   - **(a) A live ticket** (`ti` names a `t` whose `expires_at_ms > now`, with the same signer, ref and pack):
     answer that ticket (re-mint its token from the row) with **no admission and no reservation**. Still commit a
     replay record, plus the D34 lease handling, as for every signed write.
   - **(b) The pack is already a member:**
     - Multi: a local `m` row in the target ref shard;
     - Single: `BlobStore` presence;

     answer `AlreadyPresent` with no admission, and commit the replay record.
   - **(c) A cap is reached** (`tc ≥ per_ref` or `tu ≥ per_signer`): `failed_precondition` with the public message
     `"too many open upload tickets"`. Nothing is stored.
6. **Otherwise:**
   - Admission, with `declared_bytes = bytes`, `pack_id`, and `new_to_repo_bytes = Some(bytes)`.
   - **Capture `Allow.reservation`,** which today's `admit()` drops. Change it to return the reservation too.
   - The rid is the admission's reservation if any, else `synthetic_reservation_id(replay_scope)`.
   - Then creation or the lease grant (existing), then **one ref-shard batch:**
     - the replay record, with `Committed(BeginUploadTicket …)`;
     - the quota charge;
     - `plan_ticket_open` (ticket, index, counters, the kind-2 timer, and `o` Ticketed via `OutboxBuilder`);
     - the lease guard.
7. **Races after admission** (`plan_ticket_open` returns `Existing` or `CapExceeded` because of a concurrent open):
   - with a synthetic rid: answer the existing ticket (or the cap error), committing only replay plus charge;
   - with an admission-supplied rid: fail with retryable `aborted` "upload ticket race", commit nothing, and add
     `// TODO(WP-3.3): record Aborted via Pending`.
8. **The ticket:**
   - `expires_at_ms = now + ticket_ttl_ms`;
   - `part_size = cfg.part_size`;
   - `upload_session = None` (1.11 fills it);
   - the token is minted with the claims.

### B.5 The stored replay result

- `StoredResult::BeginUpload(BeginUploadResult)`, where `BeginUploadResult` is
  `AlreadyPresent | Ticket { id, part_size, expires_at_ms, token }`.
- The codec gains `ResultV1::BeginUploadAlreadyPresent` and `ResultV1::BeginUploadTicket { id, part_size,
  expires_at_ms, token_hex }`, with goldens.
- Store the token itself: a retry must get byte-identical bytes even after the ticket row is consumed.

### B.6 Config (`PipelineConfig`, validated in `Pipeline::new`)

- `ticket_ttl_ms: u64` (86,400,000 = 24 h), which must be under 604,800,000;
- `ticket_caps: TicketCaps` (per_ref 1024, per_signer 64), both ≥ 1.

### B.7 Client-loop guard (STC edit)

STC §5 maps `failed_precondition` on BeginUpload to a ticket failure resolved "by calling `BeginUpload` again". With
the cap error, that loops. Make exactly these edits:
- Add a §5 Condition row: "Too many open upload tickets for the ref or the signer (§7.6)" → `failed_precondition`,
  with the message `too many open upload tickets`.
- In the §5 client-mapping paragraph, alongside the existing indexed delta-base carve-out: on `BeginUpload`,
  `failed_precondition` with exactly that message is **not** a ticket failure. The client fails the operation with a
  user-visible error and does not retry BeginUpload.
- Add a §7.6 sentence: "`AlreadyPresent` and a returned live ticket run no admission."

Add the version-2 history note to the existing row.

### B.8 Out of this WP (1.9b and later)

- ticketed `UploadPack`;
- threshold enforcement;
- legacy UploadPack resume (R-85; add a line to R-85 that it is decided in 1.9b);
- `is_member` over index shards (1.23b);
- expiry handling (1.14);
- consumption (1.10);
- parts (1.11).

## C. Your decisions

- The module layout under `upload/`.
- How `admit()` returns the reservation (tuple or struct).
- How the pre-admission reads thread through `read_ahead`.
- The token golden's fixed values.
- Test organisation.

## Tests (required)

1. **Token:** golden bytes; mint/verify round trip; a wrong key, an unknown key id, a flipped tag byte, truncation and
   expiry each give `failed_precondition`; rotation (an old accepted key verifies, and the new key signs).
2. **Flow,** in-process, memory and SQLite, both Single and D34:
   - a new ticket;
   - the same (signer, ref, pack) returns **the same** ticket, with no admission call (spy Admission counts 0) and a
     replay record committed;
   - a different signer gets its own ticket;
   - `AlreadyPresent` with a planted `m` row (Multi) or a stored blob (Single);
   - both caps return the message, with nothing stored;
   - a retry with the same nonce returns byte-identical bytes, even after the ticket row is deleted;
   - a packmap ref and a non-heads ref under D34 give `invalid_argument`;
   - a non-AuthV2 mode and `None` keys give `unimplemented`;
   - under D34 the lease guard is present, and denial or challenge write nothing.
3. **The race of B.4.7,** via a store barrier, for both rid kinds.
4. **Wire:** `Feature::Tickets` cases `tickets.begin_upload_new`, `tickets.begin_upload_idempotent`,
   `tickets.begin_upload_caps` and `tickets.begin_upload_packmap_refused`, on the in-process baselines and the native
   binary (`--ticket-key-file`). Also the vcs-worker `--test-faults` phase, using the dev `TICKET_KEYS`.
5. **Unchanged:** all existing tests, with the legacy UploadPack still working as today.

## D. Escalate (stop and report) if

- #1150 hasn't merged.
- `write()` can't carry BeginUpload without a parallel path, or it breaks WP-1.25's stage order.
- The token binding needs a field not in `TicketV1`.
- The B.7 STC edit conflicts with other §5 text.

## Gates

- `just ci-server`
- `cargo nextest run --locked -p mkit-server -p mkit-server-native -p mkit-server-conformance -p mkit-server-worker --all-features`
- the wasm32 check and the worker build
- `scripts/vcs-worker-conformance.sh --test-faults`
- goldens: only the new token and codec entries change
