## Purpose

`mkit push` over `mkit+https` uses the M1 ticketed upload lifecycle end to end:
- BeginUpload per pack;
- a ticketed `UploadPack` for packs of at most `part_size`, and resumable `UploadPart`/`CompleteUpload` above it;
- AdvanceRefs consuming the tickets.

It recovers from ticket failures, membership lag and lost delta bases without user action. It resumes interrupted part
uploads from locally persisted receipts. Legacy and unknown servers keep today's ticketless path.

## A. Fixed (do not change)

1. **STC §7.6 and §7.7:**
   - BeginUpload semantics: `AlreadyPresent`, the live-ticket return, and the open-ticket cap with no retry (§5);
   - the part path records no replay and carries no grant;
   - `bytes > part_size` uploads in parts;
   - the receipt MAC and invalid receipt → `invalid_argument`;
   - key retirement after at least 7 days;
   - at most **7 tickets per advance** (STC §4, SPEC-SERVER §15.2).
   - **STC §7.6:** a ticketed advance pairs `refs/heads/<x>` with `refs/mkit/packmap/<x>`.
2. **R-122 / WP-1.10:**
   - a re-signed retry after a real commit gets a ticket failure, resolved through BeginUpload `AlreadyPresent` and
     ReadRef (B.5);
   - "upload not complete for ticket";
   - `Aborted(PACK_MISSING)` gives a new ticket on the next BeginUpload.
3. **SPEC-SERVER §9.4:** exact messages may be matched only where §5 or §9.4 name them (STC §11).
4. **The 4.9 re-sign rule for AdvanceRefs:** re-sign only at poll start, or when the envelope has actually lapsed.
5. **WP-1.3's core part primitives** (`PartPlan`, `PartHasher`, the `part:` commitment) and their goldens.
6. **The CLI stays server-free.**

## B. Decided (do not change)

### Part 1: WP-1.17

- **B1. Plumbing.** Add defaulted, behavior-neutral methods to core `Transport`:
  - `upload_pack_via_ref(bytes, key, ref)` and `upload_blob_via_ref(bytes, key, ref)`;
  - `advance_refs_committing(head…, packmap…, commit: &[PackKey]) -> TransportResult<CommitOutcome>`;
  - `upload_limits() -> UploadLimits { max_pack_bytes: Option<u64>, tickets_per_advance: Option<usize> }`.

  Details:
  - `CommitOutcome` is a new `#[non_exhaustive]` enum: `Advanced(AdvanceOutcome)`, `TicketRejected`,
    `DeltaBaseUnavailable` and `PacklistNotInRepository`. **No** new `TransportError` variants for these, and no string
    sentinels.
  - `ConnectTransport` keeps a per-instance ticket cache keyed by `(head_ref, PackKey)`, in memory only.
- **B2. BeginUpload** is signed and unary, with its own nonce and the normal ladder.
  - **`AlreadyPresent`:** skip the upload.
  - **`Ticket`:** cache it, then upload.
  - **A ticket failure on the upload side:** the bytes are in hand, so call BeginUpload again once, re-upload, then fail.
  - **"Too many open upload tickets":** a non-retryable error, with no second BeginUpload.
  - **Grant (2.10):** BeginUpload needs `write` plus a ref-scope match with any flag. Add the needed `GrantOperation`
    in `grant.rs`. The part path uses `GrantOperation::Part`.
- **B3. Advance.** Map `commit` keys to cached tickets; keys without a ticket contribute nothing.
  - Before sending, assert locally: at most 7 ids, no duplicates, and the canonical pairing whenever ids are non-empty
    (`InvalidRef`).
  - Pass `ticket_ids`, and `deadline = min(expires)`, through the merged 4.9 advance path.
  - Evict consumed tickets on `Committed`. Keep them on typed conflicts.
  - When `ticket_ids` is non-empty, classify these before `map_connect_error`:
    - `failed_precondition` + "delta base not available in this repository" → `DeltaBaseUnavailable`;
    - any other `failed_precondition` → `TicketRejected`;
    - `invalid_argument` + "packlist lists a pack that is not in this repository" → `PacklistNotInRepository`;
    - `unavailable` + "repository membership not yet visible" → the lag loop: same nonce, about 2 s fixed interval,
      up to 60 s after the first lag answer, observer and Ctrl-C honored.
- **B4. The re-sign rule.**
  - One helper, `renew_if_lapsing(now, 30 s)`, runs at attempt start for UploadPack, UploadPart, BeginUpload,
    UpdateRef and CompleteUpload.
  - AdvanceRefs keeps 4.9's rule, with one tightening (from the WP-4.9 review):
    - At poll start, renew when the remaining validity is less than the worst-case ladder time: every attempt's
      timeout plus the ladder sleeps, about 5 × `unary_timeout` plus the sleeps, which still fits in 300 s.
    - The purpose is to avoid a mid-ladder lapse. A lapse would force a re-sign after an ambiguous failure, and a
      write that already landed would then be replayed under a new nonce.
  - Test with the injected clock.
- **B5. Server fallback matrix,** decided per instance:

  | Server info | Signer | Path |
  |---|---|---|
  | V2, below `begin_upload_threshold_bytes` | any | ticketless |
  | V2, at or above the threshold | yes | BeginUpload |
  | V2, at or above the threshold | no | fail fast: "server requires signed uploads; set `transport_auth = envelope`" |
  | Legacy | any | ticketless; `advance_refs_committing` falls back to `advance_refs` |
  | Unknown | yes | try BeginUpload; on `unimplemented`, latch ticketless for the instance and never re-probe |
  | Unknown | no | ticketless |

  A V2 server answering BeginUpload `unimplemented` gets a clear non-retryable error.
- **B6. The planner.**
  - Honor `max_pack_bytes`: payload cap = `min(MAX_TOTAL_PAYLOAD, max_pack_bytes)` minus a documented overhead margin.
  - When tickets are in play, allow at most **6 data packs** plus the MKPL node:
    - stop before the 7th data pack's BeginUpload with
      `PushTooLarge { packs, limit: 6 }`, whose message says: push an ancestor commit first, or ask the operator to
      raise `max_pack_bytes`;
    - the re-baseline stays `Append` when its estimate exceeds 6;
    - a self-contained re-plan that exceeds 6 fails with the same error.
  - Automatic first-parent history splitting is a **follow-up WP, 1.17b**. Add it to the registry: deps 1.17, M1, no
    gate.
- **B7. Recovery in the CLI.**
  - **`TicketRejected`:**
    1. ReadRef the head. If it is at the tip, the push succeeded.
    2. Otherwise restart `push_branch` once, re-planning deterministically. A second rejection is an error.
  - **`PacklistNotInRepository`:** the same restart-once.
  - **`DeltaBaseUnavailable`:** restart once with a forced self-contained plan.
  - The 4.9 interrupt hint gains its BeginUpload clause, resolving its `TODO(WP-1.17)`.
- **B8. Orphan tickets.** Accept that repeated PackmapConflict retries leave orphan MKPL-node tickets, which expire.
  Reuse the node ticket when the node bytes are identical.

### Part 2: WP-1.18

- **B9. Part planning.**
  - With a ticket and `bytes <= ticket.part_size`: a single-part ticketed `UploadPack`.
  - Otherwise: `PartPlan::new(bytes, ticket.part_size, max_parts)`. The ticket's `part_size` is authoritative;
    `max_parts` comes from V2 server info, and is `u32::MAX` when the info is Unknown.
  - Map `PartError`: a bad size → `ProtocolError`; `TooManyParts` → a clear error.
  - `valid_server_info` requires `max_parts >= 1`.
  - There is **no oversize single-part fallback.**
- **B10. UploadPart.** Parts go sequentially, in index order, skipping stored receipts.
  - Hash the slice, then build the `part:` commitment.
  - Stream **lazily** from the borrowed pack, one chunk at a time, with no whole-pack copy and no clone per attempt.
  - Each part gets its own identity (B4).
  - **Persist the receipt before starting the next part.**
  - Error handling:

    | Answer | Action |
    |---|---|
    | `unavailable`, `resource_exhausted`, `aborted`, connection failure | the ladder, re-streaming this part only |
    | `unauthenticated` | renew once |
    | `failed_precondition` | B2's one-shot re-ticket |
    | `permission_denied`, `invalid_argument` | non-retryable |
- **B11. Receipt store.**
  - A `PartReceiptStore` trait in `mkit-transport-connect`, with `load`, `put`, `forget` and `sweep`, and an in-memory
    default.
  - The CLI's file implementation lives at `<common>/upload-parts/<ticket-hex>/`: `ticket` metadata written first,
    then one `<index>.part` file per part.
  - Writes are atomic: temp, fsync, rename, then a parent-directory fsync.
  - On load, ignore records whose metadata or plan doesn't match.
  - It is installed in `open_with_config`.
  - Add `upload_parts_dir()` to core `layout.rs`, and a row to the SPEC-WORKTREE common-dir table. It is a cache,
    never a GC root, and **not** `.mkit/receipts/`, which is reserved for M5.
- **B12. Cleanup and resume.**
  - `forget` on `Committed`. `sweep` once per process: expired tickets, unreadable metadata older than 7 days, and stray
    `*.tmp` files.
  - Keep receipts after `CompleteUpload` until the advance commits.
  - Resume relies on deterministic regeneration; document that it only works while the plan is identical.
  - **`CompleteUpload` `invalid_argument`:**
    - if any receipt came from disk: `forget`, resend every part, and complete once more;
    - otherwise it is an error.
  - The client asserts it has exactly `count` receipts, in index order, before `CompleteUpload`.
  - `CompleteUpload` uses the long (pack-transfer) client timeout, not the unary one. A completion of several GiB
    re-hashes or copies server side, and the native server gives it the streaming deadline (WP-1.13 B9).
- **B13. Progress and cancel.** An `UploadEvent` observer: `PartsPlanned`, `PartSent`, `Completing` and `Finished`,
  with a continue flag.
  - tty: `Uploading pack: part 5/12 (40/96 MiB), 4 resumed`.
  - Piped: one start line and one end line.
  - Ctrl-C between parts prints: "upload interrupted; N of M parts saved, run `mkit push` again to resume".
- **B14. Also make the single-part `UploadPack` request lazy,** removing the per-attempt clone.
- **B15. Server G-A.**
  - `server_info()` advertises `max_pack_bytes = min(max_total, part_size)` when the blob store can't do multipart.
  - Add the STC §2.1 sentence and a test.
  - The client maps BeginUpload `unimplemented` for `bytes > part_size` on a V2 server to "server storage cannot
    accept packs over part_size", never to the ticketless latch.
- **B16. Docs and plan.**
  - **R-142 (1.17):** B1–B8, the 1.17b follow-up, and the orphan-ticket note.
  - **R-143 (1.18):** B9–B15, plus follow-ups for parallel parts and spooling for constant-memory upload.
  - CHANGELOG lines. `docs/CLI.md`: push behavior and the resume hint.

## C. Your decisions

- The shape of `UploadLimits`, and where the ticket cache lives inside `ConnectTransport`.
- The overhead margin under `max_pack_bytes`, documented.
- The file-store record encoding: JSON or a fixed binary layout, versioned.
- The test harness shapes.

## D. Escalate (stop and report) if

- Ticket threading requires a breaking change to the merged 4.9 or 2.10 public API.
- The CLI would need a server dependency.
- Production code passes 3,000 lines. Then open the PR with the finished steps, and list the rest as not done.

## Tests (required)

**Part 1:**
1. **Default trait methods:** behavior-neutral for every other transport (memory, file, ssh, enc, http).
2. **BeginUpload:**
   - `AlreadyPresent` skips the upload;
   - a ticket leads to a ticketed `UploadPack` with the token;
   - a live-ticket return reuses the ticket;
   - "too many open upload tickets" is non-retryable, with a single call;
   - an upload-side ticket failure re-tickets once.
3. **Advance:**
   - the commit-set mapping, including stale MKPL-node tickets that stay off the wire;
   - the local asserts: more than 7, duplicates, non-canonical pairing;
   - the deadline is the minimum expiry;
   - eviction on `Committed` and retention on conflict;
   - each classification;
   - the lag loop: same nonce, interval, 60 s bound, Ctrl-C;
   - with a grant source and a non-owner signer, **every** AdvanceRefs attempt carries `x-write-grant`, including
     pending polls and re-signed attempts. BeginUpload carries it too; the part path doesn't. There is no end-to-end
     test of this yet: the merged 2.10+4.9 code covers it only by unit tests.
4. **Re-sign:** with the injected clock, each RPC renews at attempt start past the margin; AdvanceRefs follows 4.9.
5. **The fallback matrix:** every row, including the Unknown latch without a re-probe, and the V2 misconfiguration
   error.
6. **Planner:**
   - `max_pack_bytes` honored;
   - the 7th data pack gives `PushTooLarge` before any BeginUpload;
   - the re-baseline estimate over 6 stays `Append`.
7. **Recovery:**
   - `TicketRejected` with the head already at the tip succeeds;
   - otherwise one restart succeeds, and a second rejection errors;
   - `PacklistNotInRepository` restarts;
   - `DeltaBaseUnavailable` restarts self-contained.

**Part 2:**
8. **Part plan:** boundaries (`bytes == part_size`, `+1`), and `max_parts` exceeded.
9. **The `part:` commitment:** matches the `auth-v2/part.json` golden.
10. **Lazy streaming:** a counting allocator or a byte count shows no whole-pack copy.
11. **Resume:**
    - a fault after part 2 (the registry case), then resume sends only parts 3..n;
    - crash-restart from the file store;
    - an expired ticket sends every part;
    - a new ticket id forgets the old one.
12. **Invalid receipt:** a stored one leads to forget, resend all, and complete; a fresh one is an error.
13. **Store:**
    - atomic writes (a torn temp file is ignored);
    - a metadata mismatch is ignored;
    - `sweep` behavior;
    - concurrent pushes write valid receipts.
14. **Progress and cancel:** the tty and piped output, and Ctrl-C between parts leaves resumable state.
15. **G-A:** the clamp test, and the client's error mapping.
16. **Native end-to-end:**
    - a push of a pack over `part_size` through parts;
    - an interrupted-then-resumed push;
    - a 3-pack push through tickets;
    - a legacy (ticketless) server push still works.

## Gates

- `just ci-scripts` (including `check-cli-baseline.sh`), `just ci-security` and `just ci-server`
- `cargo nextest run --locked -p mkit-core -p mkit-transport-connect -p mkit-cli -p mkit-server -p mkit-server-native --all-features`
- workspace clippy, rustdoc and doctests; the wasm32 check for `mkit-core` and `mkit-server`
