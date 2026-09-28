## Purpose

This WP makes the ticketed upload path end to end on the server. An AdvanceRefs that carries `ticket_ids`:
- verifies each ticket and the upload marker;
- consumes the tickets;
- records exactly one terminal outcome per reservation;
- writes membership, relayed to the index shards.

It also adds ref deletion (STC §7.8). It closes R-111(3) and fulfils R-113.

## A. Fixed (do not change)

1. **STC §7.6, §7.7 and §7.8.**
   - A ticket-consuming AdvanceRefs runs **no admission**.
   - Tickets bind the audience, repository, signer, pack and bytes. The ref binding comes from the ticket **row**.
   - A head-only UpdateRef consumes no tickets.
   - Typed conflicts are successful RPCs.
   - Deletion requires `MATCH` and an empty `new_id`.
2. **R-99:** exactly one outcome row per reservation. Tickets without an admission reservation use `s:` rids.
3. **R-113:** consuming a ticket requires its **upload marker and the pack blob** (PRD D15).
4. **R-111(3):** the live-ticket answer in BeginUpload must guard the ticket row.
5. **SPEC-SERVER.**
   - §9.1: the packlist (MKPL) and membership-dependent checks of §9.2–9.6 are **indexed mode only**. M1 is opaque.
   - §13.2: unexpired tickets' packs are GC roots, so no hold or GC precondition is needed (R-64).
6. **Existing fragments:** `plan_ticket_close` (`CloseReason::Consumed` keeps the kind-2 timer on purpose),
   `plan_membership`, `OutboxBuilder::outcome` and `relay_at`, and `MAX_TICKETS_PER_ADVANCE = 7`.

## B. Decided (do not change)

### B.1 Wire decoding

| Condition | Code | Message |
|---|---|---|
| A `ticket_ids` entry is not 32 bytes | `invalid_argument` | "ticket id must be 32 bytes" |
| Duplicate ticket ids | `invalid_argument` | "duplicate ticket id" |
| More than 7 ticket ids | `invalid_argument` | "too many tickets in one advance" |

Add an STC §7.6 sentence: "a server MAY limit `ticket_ids` per advance; over the limit is `invalid_argument`".

### B.2 Types

- `RefUpdate.new` becomes `Option<Hash>` (`None` means delete).
- `OpKind::AdvanceRefs` becomes `{ head, packmap, tickets: Vec<Hash> }`.
- ssh and enc pass empty tickets.
- The fingerprint remains the auth-v2 signing digest.

### B.3 Stage placement

Add a `ticket_decision` stage in a new `pipeline/advance.rs`, next to `begin_decision`.
- It runs after authorize, **instead of admission**, and before the lease grant (R-97).
- It reads the `t` rows and then the `ti`, `o` and `m` rows.
- It validates tickets and runs the blob heads concurrently: at most 2n R2 subrequests, n ≤ 7.
- It writes nothing. A failure leaves no replay row.

### B.4 Per-ticket validation

Tickets are validated in request order, and the first failure wins.

| Condition | Code | Message |
|---|---|---|
| No `t` row in this shard | `failed_precondition` | "invalid or expired upload ticket" |
| `repo` ≠ this repository | `failed_precondition` | "invalid or expired upload ticket" |
| `ref_name` ≠ `head_ref` | `failed_precondition` | "invalid or expired upload ticket" |
| `expires_at_ms` ≤ business now | `failed_precondition` | "invalid or expired upload ticket" |
| Signer ≠ request signer | `permission_denied` | "upload ticket binding mismatch" |
| Marker absent, or marker present but pack absent | `failed_precondition` | "upload not complete for ticket" |

Check the marker **first**, and check the pack only when the marker exists. The answer then never depends on whether
the pack exists globally.

### B.5 Planner order: replay → tickets → CAS

- Generalize `replayed_begin_upload` to ticketed AdvanceRefs, and add the replay key to `read_keys`. A same-nonce twin
  that committed first then returns the stored result.
- The planner re-validates the tickets from its own snapshot.
- On a CAS conflict:
  - the typed outcome is stored in replay;
  - **no ticket is touched and no outcome row is written**, so the tickets stay usable for a corrected advance.
- Document the accepted cost: a re-signed retry after a real commit gets a ticket failure. The client resolves it
  through BeginUpload's `AlreadyPresent` and ReadRef.

### B.6 Marker present, pack missing

Amendment 1 replaces this section: a missing marker leaves the ticket open and returns `failed_precondition`.
A present marker with a missing pack closes that ticket in a separate guarded transaction and writes
`Aborted(PACK_MISSING)` before returning `failed_precondition`. On a lost guard race, re-plan the request.
In a mixed request, abort only tickets whose marker exists but whose pack is missing.

### B.7 The consumption batch

Use one `OutboxBuilder` with `try_finish` only.

**For each ticket:**
- Run `plan_ticket_close(.., Consumed)`, which keeps the timer.
- Verify that the `o` row's `Ticketed.ticket_id` matches.
- Write the outcome:

  ```
  outcome(rid, Committed{
      repository: a.repo().identity,
      occurred_at_ms: business now,
      bytes_stored: ticket.bytes,
      new_to_repo: ticket.bytes, or 0 when the local `m` row already exists,
      new_to_store: ticket.bytes,
      refs: [packmap, head] in decision order,
  })
  ```

  `new_to_store` is a documented **upper bound** in opaque M1; WP-3.3 refines it.
- Run `plan_membership`.

**Once per batch:** `relay_at(plan_time_ms)`.

**Op accounting:** rewrite the `outbox.rs` accounting to the real shape. A ticketed advance runs no admission, so there
is no quota charge, and there is a single signer, so one `tu` counter. The cost is `9n + 21`, which is 84 at n=7.
Keep the const assert, and add a planner test on the real maximal batch.

### B.8 Deletion (STC §7.8)

| Condition | Code | Message |
|---|---|---|
| A deletion that is not `MATCH` with an empty `new_id` | `invalid_argument` | "delete requires MATCH and an empty new_id" |
| Delete together with tickets | `invalid_argument` | "delete consumes no tickets" |

Add an STC sentence for the second rule.

- **An absent ref:** `Conflict(Missing)`. That is `failed_precondition` on UpdateRef and a typed conflict on
  AdvanceRefs.
- **Admission** runs on deletions.
- **Only the `r` rows are removed.** Open tickets and `m` rows stay. Ref-index tombstones belong to WP-1.28. There is
  no published-pointer row, because published equals live when no inspector is configured.
- Head and packmap are deleted together in AdvanceRefs.

### B.9 R-111(3)

Both the `Return(Ticket)` path and the `Existing` path in `begin.rs` push `Equals(t, value)`. Add the `t` key to
`read_keys`. If the ticket is gone at plan time, answer `aborted_retryable` "upload ticket race".

### B.10 Reservations on direct writes

If admission returns a reservation on a non-BeginUpload write, fail closed with `unimplemented` "admission reservations
on ref writes land with WP-3.3". Do not drop it silently.

### B.11 Seams only (no code)

- `TODO(WP-5.3a)` for R-115 (unmark GC marks at the ticket stage).
- `TODO(WP-4.x)` for R-114 (verification scheduling) and the §9.2 packlist rule.

### B.12 Plan

Add row **R-122**:

> WP-1.10.
> - The packlist rule and the lag-window `unavailable` are indexed-only (§9.1) and are not in 1.10.
> - A marker without a pack records `Aborted(PACK_MISSING)` in a separate transaction per STC §7.7.
> - Direct-write reservations fail closed until 3.3.
> - Ticketed advances write uncharged replay rows, and a live ticket can be reused across conflicting advances;
>   WP-1.14 and WP-1.27 bound this (extends R-111(2)).
> - The Committed `new_to_store` is an upper bound in opaque mode; WP-3.3 refines it.
> - The advance-batch op budget is `9n + 21` (84 at n=7), which corrects R-119's headroom note.
> - UpdateRef carries no `ticket_ids`.

Also:
- fix `repo.rs:~137`: Multi is not deployable until WP-1.14 (R-111(1));
- update INVARIANTS and CHANGELOG.

## C. Your decisions

- The module layout.
- Test organisation.
- Exact batch-golden format.

## D. Escalate (stop and report) if

- Production changes exceed 1,500 lines.
- The real maximal batch doesn't fit `MAX_BATCH_OPS`.
- Any B item contradicts merged normative text.

## Tests (required)

**Flow** (pipeline and native; memory and SQLite; Single and D34):
- BeginUpload → ticketed UploadPack → AdvanceRefs consuming 2 tickets (a pack and an MKPL node). Then:
  - `m` rows exist, relay delivers them to RepoIndex, and `is_member` works with and without `X-Mkit-Ref`;
  - exactly 2 `o` Committed and 2 `oq` rows, `oc` = 2, `tc`/`tu` back to 0, `t` and `ti` gone, kind-2 timers
    present;
  - repo B: PackExists is false and DownloadPack is `not_found`;
  - a later BeginUpload answers `AlreadyPresent`.
- A ticket without a reservation (the `s:` rid).
- Admission is never called on a ticketed advance (spy).
- 8 tickets are rejected; 7 tickets commit and pass `Batch::validate`.
- Deletion:
  - head and packmap together;
  - UpdateRef deletion of an absent ref → `failed_precondition`;
  - the `invalid_argument` rules;
  - delete with tickets is rejected.

**Race** (the `BeforeFinalApply` barrier):
- A same-nonce twin returns the stored Committed, with no second outcome row.
- Two different advances consuming one ticket: exactly one commits.
- R-111(3): a live-ticket BeginUpload racing a consume, on both the `Return` and `Existing` paths.
- A simulated `Expired` close racing a consume: exactly one terminal outcome.

**Wire** (conformance under `Feature::Tickets`, native and wrangler):
- every B.4 and B.8 code and message;
- HeadConflict and PackmapConflict leave the tickets usable, and a later corrected advance consumes them;
- marker missing → `failed_precondition`, then upload, then retry succeeds.

**Golden:**
- the existing codec and marker goldens are unchanged;
- add a golden of the planned batch (keys and op count) for a 2-ticket advance.

## Gates

- `just ci-server`
- `cargo nextest run --locked -p mkit-server -p mkit-server-native -p mkit-server-conformance -p mkit-server-worker --all-features`
- the wasm32 check and the worker build
- `scripts/vcs-worker-conformance.sh` (default, and `--sharding d34 --test-faults`)
