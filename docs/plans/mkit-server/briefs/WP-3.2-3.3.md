## Purpose

A deployment can plug arbitrary business logic, such as payments, quotas or verification, into writes. It does that
through a generic, protocol-neutral admission hook that can allow, challenge (HTTP 402 with opaque challenges) or deny.
Every reservation admission grants gets exactly one durable outcome: `Committed`, `Aborted`, `Expired` or
`ReadServed`. The outcome is delivered at least once to an `OutcomeSink`, with bounded backlog and safe backpressure.
A billing layer, for example MPP or x402 on Cloudflare Workers through hooks.v1, settles on `Committed` and releases on
`Aborted` or `Expired`.

## A. Fixed (do not change)

1. **STC §5.1:**
   - a challenge is 402 with `permission_denied` and an `AdmissionChallenge` detail, sent on unary RPCs only;
   - the bounds: 1–8 challenges; scheme `^[a-z0-9][a-z0-9.-]{0,63}$`; value ≤ 8,192 bytes; description ≤ 512 bytes.
   - The 3.1 goldens pin the encoding, the public message "admission required", and the type name.
2. **STC §7.7:** admission runs only on a new UpdateRef, a ticketless AdvanceRefs, BeginUpload, and a ticketless
   UploadPack (ssh and enc). It never runs on replays, ticket consumption, live-ticket or `AlreadyPresent` answers,
   the part path, GetServerInfo or reads. One outcome per reservation.
3. **SPEC-SERVER:**
   - §5: the pending record comes before any apply; a separate `Aborted`; reconcile; backpressure over the combined
     backlog.
   - §6.2: sanitation.
   - §6.3: credential headers; R-92.
   - §6.5: outcomes.
   - §6.6: the pass-through header sets, and reservation-id uniqueness.
   - §8: an invalid hook response is `unavailable` with nothing written.
4. **R-99:** synthetic `s:` ids for default quota. **R-119:** `external_ref` is carried now and stored by 5.8.
   **R-122:** the placeholders 3.3 removes.
5. **Timer kinds:** 1–5 used, 6 reserved, 7 is 4.8's. **This bundle takes 8 (`OUTCOME_DELIVERY`) and 9
   (`RESERVATION_RECONCILE`).**
6. **The op budget.** The ticketed advance runs no admission. At most one kick op is added: D34 at n = 7 goes from 88
   to **89**, and Single from 77 to **78**.

## B. Decided (do not change)

### Part 1: WP-3.2

- **B1. The trait, extended additively.**
  - `AdmissionDecision::Allow { charges, reservation, response_headers, external_ref }`.
  - `Challenge { challenges, description, response_headers }`, now `#[non_exhaustive]`.
  - `Deny(ServerError)`.
  - Builders: `allow`, `.with_reservation`, `.with_response_header`, `.with_external_ref`, `challenge` and `deny`.
  - `AdmissionInput` gains `audience: Option<&str>` and `credential_headers: &[CredentialHeader]` (`Redacted`).
  - Migrate the literal sites. Stage 3 moves into a new `pipeline/admission.rs`; `mod.rs` keeps only the call site.
- **B2. The core seam.** A new pure `mkit-core/src/admission.rs`, wasm-clean with no dependencies:
  - the constants;
  - `is_valid_scheme`, and `validate_challenges`;
  - a hand-written `encode_admission_challenge`, pinned byte for byte to the 3.1 golden, with a `connect`-feature test
    that decodes it with buffa.
- **B3. The validator** applies to every decision, in-process or remote. Any violation is retryable `unavailable`
  "admission unavailable", with the reason logged redacted and **nothing written**. Rules:
  - the STC bounds;
  - no control characters except HTAB in values or the description;
  - Challenge pass-through names only `WWW-Authenticate` (repeatable) and `PAYMENT-REQUIRED`;
  - Allow pass-through names only `Payment-Receipt` and `PAYMENT-RESPONSE`;
  - pass-through headers: at most 8, values ≤ 8,192 bytes in `0x20–0x7e`;
  - `reservation` passes `validate_reservation_id` and **does not start with `s:`**;
  - `external_ref` ≤ 256 bytes in `0x21–0x7e`.
- **B4. The challenge path writes nothing.**
  - Validate, encode, then `ServerError::admission_challenge(bytes)`, which carries `Cache-Control: no-store`.
  - Attach the pass-through headers.
  - Return before any session, lease, creation or quota work.
  - **Streaming** (ticketless UploadPack): a Challenge is a plain `permission_denied("admission required")`, with no
    402.
- **B5. Only stage 3 can produce a 402.**
  - `Deny` becomes a 403 `permission_denied`, with details and headers stripped. Its message is kept if it is at most
    512 bytes with no control characters; otherwise "admission denied".
  - Authorizer, PreReceive and `admit()` errors go through a strip that removes any `AdmissionChallenge` detail and
    turns a 402 into a 403.
  - Flip the tests that relied on smuggling.
- **B6. Credential headers (R-92, §6.3).**
  - Captured at authenticate through a multi-value `RequestMeta` accessor. They are excluded from `Debug` and from the
    fingerprint.
  - The defaults are `Payment-Authorization` and `PAYMENT-SIGNATURE`.
  - `Authorization` is used only if it is exactly one line matching `Payment<SP+>token68`, with no comma.
  - Extras come from `PipelineConfig.admission_credential_headers`. They can never add `Authorization` or an STC §5.1
    hard-reserved name, and they are fed to the redactor.
  - Bounds: at most 8, one line per name, visible ASCII, SP or HTAB, each ≤ 8,192 bytes. A violation is a 403
    admission denial without calling `admit()`.
  - Unsigned, ssh and enc requests get an empty list.
- **B7. Receipt pass-through.**
  - `*_with_meta` entry points return `(T, ResponseMeta)`. The old ones delegate to them.
  - Connect attaches Allow `response_headers` **only on a committed success**, plus `Cache-Control: private`.
  - Receipts are not stored in, or replayed from, the replay record. Document that they are best-effort.
- **B8. GetServerInfo.** One wire test with a non-default admission: `admission = true`, threshold 0.

### Part 2: WP-3.3

- **B9. Codec.**
  - `ReservationV1` gains `Pending{repository, created_at_ms, reconcile_at_ms, op: Write|Read}` and
    `ReadServed{repository, occurred_at_ms, object, bytes_served}`.
  - `AbortReason::Unspecified` is added.
  - Goldens for each new state.
- **B10. Builder.**
  - `pending(rid, prior, record)` is `Absent(o)` + `Put(Pending)` + a kind-9 timer. A `Some` prior is an invalid hook
    response (B3 semantics).
  - `reserve` accepts a Pending prior (`Equals`).
  - `outcome` enforces the transition table:
    - `Ticketed` → `Committed` | `Aborted` | `Expired`;
    - `Pending(Write)` → `Committed` | `Aborted`;
    - `Pending(Read)` → `ReadServed` | `Aborted`.
  - `try_finish` adds one kind-8 kick only when `oc` was absent or zero before the batch. Invariant: `oc > 0` ⇒
    exactly one kind-8 row.
- **B11. The pending lifecycle** (new `pipeline/reservation.rs`).
  1. **The pending unit.** Once `Allowance.reservation` is `Some`, after backpressure and before any lease, creation,
     multipart session or apply, write one unit in the op's partition: `Absent(o rid)`, `Put(Pending)` and the
     reconcile timer.
     - `reconcile_at_ms` = `apply_deadline_ms + MAX_CLOCK_LEAD_MS` + margin.
     - Every apply batch of the op uses `NotAfter(min(clock.deadline(), apply_deadline_ms))`.
  2. **The guard through planning.** A `PendingGuard` goes into `WriteRequest`, and `plan_write` emits:
     - on commit: `Committed{0,0,0, refs}` (upper-bound byte fields, see B16);
     - for BeginUpload: `reserve(…, Some(Pending))`;
     - on a typed conflict or CAS loss: `Aborted(REF_CONFLICT)` **in the same batch that records the conflict**
       (orchestrator decision: atomic, no crash window).
  3. **Resolve on exit.** Every exit after the pending unit that didn't commit its own replacement writes
     `Aborted(reason)` in a separate unit guarded by `Equals(Pending)`. This includes the multipart failure and the
     BeginUpload race or cap. A failed guard is a no-op, and a failed write is logged (reconcile covers it). Reasons:

     | Cause | Reason |
     |---|---|
     | CAS loss | `REF_CONFLICT` |
     | Grant or lease epoch | `EPOCH_MISMATCH` |
     | Lost a replay or ticket race | `REPLAY_RACE` |
     | Store error, deadline, multipart failure | `INTERNAL` |
     | Pre-receive, quota, open-ticket cap | `UNSPECIFIED` + a ≤ 512-byte operator detail |
  4. **Guard loss.** A guarded apply whose `Equals(Pending)` fails commits nothing, does not re-plan, and answers
     `unavailable`. `apply_loop` tells this guard's index apart from the others.
- **B12. Kind 9, reconcile.**
  - `Pending(Write)` → `Aborted(ABANDONED)`.
  - `Pending(Read)`, due at deadline + read grace → `Aborted(ABANDONED)`.
  - Anything else is `Done`.
  - It is guarded through the builder.
- **B13. Kind 8, delivery,** generic over `O: OutcomeSink`.
  - It scans `oq` from a rotating cursor kept in the timer value. A non-terminal or undecodable row is logged and
    skipped, never deleted.
  - It delivers up to 16 rows sequentially. Each successful delivery is acked with `plan_ack` in the returned
    `oc`-guarded batch.
  - `Done` when the backlog reaches 0. Otherwise `Reschedule` at `now` if progress was made, else at backoff: 1 s
    doubling to 15 min, with deterministic jitter from `BLAKE3(partition ‖ attempt)`.
  - **Synthetic `s:` rows are acked locally with a metric, never sent to the sink.**
  - The gauge `mkit_server_outbox_backlog{shard_kind}` tracks rows and bytes.
- **B14. Public API.**
  - `#[non_exhaustive] Outcome { reservation_id, audience, repository, occurred_unix_ms, kind }`.
  - `OutcomeKind { Committed{…refs}, Aborted{reason, detail}, Expired, ReadServed{object, bytes_served} }`, mirroring
    hooks.v1 field for field.
  - `OutcomeSink::deliver(&Outcome) -> Result<(), DeliveryError>`, with a defaulted
    `deliver_batch(&[Outcome]) -> Vec<Result<…>>`.
  - `DeliveryError { reason (redacted), retry_after }`. Every `Err` means retry.
  - A blanket `Arc<T>` impl. `NoOutcomes` acks.
  - The trait docs state: at-least-once, duplicates possible even after `Ok`, any order across rids, and the sink
    dedupes on rid.
  - `OutboxRow` is removed.
- **B15. Backpressure.**
  - It runs after `begin_decision` and **before `admit()`**, and only for ops that will run admission.
  - Read `oc` from the snapshot, adding it to `read_ahead` where it is missing.
  - Over the cap: retryable `unavailable` "outbox backlog; retry", `Retry-After: 30`, and a counter.
  - The cap is `PipelineConfig.outbox_backlog_cap`, default `Some({rows: 100_000, bytes: 64 MiB})` per shard; `None`
    disables it.
  - It is a soft, unguarded bound. Document the overshoot bound.
- **B16. Ticketless UploadPack with a reservation (ssh/enc).**
  - Fail closed **and** record `Aborted(UNSPECIFIED, "reservations unsupported on this transport")` in one guarded
    `Absent(o)` unit in the op's partition, plus `oq` and the kick.
  - The client gets `failed_precondition`.
  - Note for WP-3.5: the Worker registers kind 8 on `NsCoordinator` too.
  - **`new_to_store`:** keep the upper bound. Add a SPEC-SERVER §6.5 sentence: "in opaque mode, an upper bound: the
    declared pack bytes". The exact value arrives in M4.
- **B17. Ownership with 1.14.**
  - 3.3 owns the kind-8 driver: `NoOutcomes` plus the driver realizes P-9.
  - **WP-1.14 keeps only the kind-2 expiry handler** (`Expired` through the builder, multipart abort, ticket deletion,
    replay bounds), and drops "pre-M3 outbox retention".
  - State this in R-139.
- **B18. Read outcomes.** The codec, builder, `Pending(Read)` and the reconcile grace ship with pure planner tests
  only. There is no HTTP read path (4.13 owns it).
- **B19. Spec and plan.**
  - SPEC-SERVER §6.6: `s:` is reserved for server synthetic ids. Uniqueness holds while the row exists, which extends
    R-99.
  - §6.5: the `new_to_store` sentence.
  - **R-138 (3.2):** B1–B8, the §3.9 note that in-process admission on Workers needs a generic `HookSet`, and
    `ADMISSION_EXPOSE_HEADERS` for CORS in 3.4 and 3.5.
  - **R-139 (3.3):**
    - B9–B18;
    - the op budget, 89 on D34 and 78 on Single;
    - the carry-forwards: 3.4/3.5 register kinds 8 and 9 and a shutdown drain; events (5.2) and purges (5.10) add to
      `oc` and reuse kind 8; restore seeds kind 8 when `oc > 0` and keeps kind-9 rows.
  - A CHANGELOG line per WP.
  - Rename or avoid the name clash with `pipeline/outcome.rs`, which is request telemetry.

## C. Your decisions

- Module layout inside `pipeline/`, and the `ResponseMeta` shape.
- How `PendingGuard` threads through `WriteRequest` and `apply_loop`.
- The read reconcile grace value (document it).
- Conformance storage cases for memory and SQLite.

## D. Escalate (stop and report) if

- The ticketed advance at n = 7 exceeds 89 ops on D34, or 78 on Single.
- The pending unit can't precede every apply without an extra round trip on the hot path of **unadmitted** writes.
  Unadmitted writes must stay at their current call count.
- Production code passes 3,000 lines. Cut in this order:
  1. B6 credential headers → 3.2b;
  2. B18 read outcomes → 4.13.

  Then open the PR, listing what was cut.

## Tests (required)

**Part 1:**
1. **Core encoder:** byte-identical to the golden; the buffa decode round trip; validator boundaries (scheme grammar,
   8/9 challenges, 8,192/8,193, 512/513, control characters).
2. **Challenge:**
   - 402 with the detail and `no-store`, and pass-through headers attached;
   - nothing written (spy store);
   - streaming gives a plain 403.
3. **Sanitation:**
   - Deny → 403 stripped, with a long or control-character message → "admission denied";
   - Authorizer, PreReceive and `admit()` 402s are downgraded.
4. **Invalid decision matrix:** each bound violation, the `s:` prefix, a bad `external_ref` → `unavailable`, with
   nothing written.
5. **Credential headers:**
   - selection (defaults, the `Authorization` Payment form, extras, reserved names refused);
   - bounds;
   - redaction in `Debug` and in logs;
   - the fingerprint is unchanged by them;
   - "retry with credential, same nonce" works.
6. **Receipts:**
   - on committed success only, with `private`;
   - not on conflict or error;
   - not replayed.
7. **GetServerInfo wire test.**

**Part 2:**
8. **Transition table:** every legal and illegal transition, and the duplicate `pending` refusal.
9. **Exactly one outcome,** for each exit path: commit, CAS conflict (in-batch Aborted), epoch, replay race, store
   error, deadline, pre-receive, quota, multipart failure, BeginUpload race or cap. Each gets exactly one terminal row.
10. **Crash windows:**
    - a crash after the pending unit ends in `Aborted(ABANDONED)` through reconcile;
    - the apply's `NotAfter` never races reconcile (injected clock);
    - guard loss answers `unavailable` without re-planning.
11. **Delivery:**
    - rows delivered in order, acked and deleted;
    - a sink `Err` backs off with jitter;
    - a poison row is skipped, not deleted, and the rows behind it are delivered;
    - `s:` rows are acked locally without the sink;
    - redelivery is byte-identical;
    - the invariant `oc > 0` ⇒ exactly one kind-8 row.
12. **Backpressure:**
    - over the cap: `unavailable` + `Retry-After`, and `admit()` is never called;
    - reads, ticketed advances and parts are unaffected;
    - recovery once the backlog drains.
13. **Budget:** exactly 89 (D34, n = 7) and 78 (Single).
14. **Ticketless UploadPack with a reservation:** fail closed with one `Aborted` row.
15. **Read planners:** Pending(Read) → ReadServed or Aborted, and reconcile after the grace.
16. **wasm32 builds** of `mkit-server` and `mkit-server-worker`.

## Gates

- `just ci-server`, `just ci-scripts` and `just ci-security`
- `cargo nextest run --locked -p mkit-core -p mkit-server -p mkit-server-native -p mkit-server-conformance -p mkit-server-worker --all-features`
- the wasm32 check and the worker build
- `scripts/vcs-worker-conformance.sh` (the default phase stays green)
