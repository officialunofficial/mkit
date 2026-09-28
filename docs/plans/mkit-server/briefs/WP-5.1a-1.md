## Purpose

This WP specifies how storage leases govern a repository's lifecycle, how the server reports lease transitions to
the embedding business, and how server-side GC decides, safely and fail-closed, which repository data and bytes can
be removed.

It sits on the critical path to WP-5.2 (leases) and WP-5.3a (GC mark).

## A. Fixed (do not change)

1. **PRD §6.7** (lines ~398–445) and §5.3 (the coordinator holds "lease defaults"; ref shards hold per-ref leases), and
   PRD §7: lease terms, prices and renewal endpoints belong to the implementer.
2. **`00-plan.md`:**
   - **P-15:** a relay-lag bound of 60 s.
   - **P-20:** a GC grace of 7 days; no default lease periods (policy must set them).
   - **P-22:** `config_version`.
   - **P-23:** watermarks.
   - **R-64**, the GC protocol, verbatim in substance: mark → wait → re-check → guarded delete. Planners unmark
     first. `deleting` → retryable `unavailable`.
   - **R-75:** the lag holes.
   - **R-106:** the coordinator watermark is WP-1.23c. Cite the watermark abstractly.
3. **SPEC-WRITE-GRANTS:**
   - §1.1 (`MAX_APPLY_WINDOW` 10 s, `margin` 5 s, the 30 s epoch lease) and §5.5 (`NotAfter` on every write batch).
     **Cite these; don't restate them.**
   - §9.4: URL tokens resolve only in the published view.
4. **SPEC-GC** (client-local): mirror its fail-closed rule. Any unreadable root source, a missing object, or a
   truncated walk aborts the run.
5. **Proto rules** (00-plan lines ~72, R-79):
   - additive only, and `buf breaking` must stay green;
   - never change the label or oneof membership of an existing field.
   - 5.1a owns hooks.v1 and transport.v1 additions for M5 leases.
6. **SPEC-SERVER today:**
   - §10–§14 are one-line reserved M5 headings, §15 is version history and §16 is test anchors;
   - §16 is cited by `rust/crates/mkit-server/tests/golden_server_hooks.rs`,
     `rust/crates/mkit-server/tests/golden_pending_verification.rs` and `scripts/check-server-hooks-goldens.sh`.

## B. Decided by the orchestrator (do not change)

### B.1 Section layout

Renumber once. You own this.

| § | Title | Owner |
|---|---|---|
| §10 | Published view | 5.1a-2 |
| §11 | Quarantine and inspection | 5.1a-2 |
| **§12** | **Storage leases and lifecycle events** | this WP |
| **§13** | **Server garbage collection** | this WP |
| §14 | Takedown and redaction notices | reserved, 5.1b |
| §15 | Storage receipts | reserved, 5.1c |
| §16 | Admin API and audit log | reserved, 5.1b |
| §17 | Custom backends, backup and migrations | reserved |
| §18 | Conformance scope | reserved |
| §19 | Version history | |
| §20 | Test anchors | |

- For §10 and §11, leave the existing one-line headings in place (5.1a-2 fills them).
- Fix the §1 sentence ("Sections 10–14 reserve …"), the §2 stage 9 text, and the three files that cite §16.
- Add a **named-parameters table** in §12 or §13:
  - `gc_grace` = 7 d;
  - `relay_lag_bound` = 60 s;
  - `already_present_pin_window` ≥ the ticket lifetime;
  - cite WRITE-GRANTS §1.1 for `MAX_APPLY_WINDOW` and `margin`.

### B.2 §12 Storage leases

- **Terminology:** call them "storage leases", and state that they are unrelated to epoch leases
  (SPEC-WRITE-GRANTS §5.4).
- **Terms:** `{expires_at_ms, grace_ms, suspension_ms}`, all set explicitly by policy. mkit defines no default
  durations. **No lease means permanent.**
- **Scope:**
  - per ref, with a repository-level default held by the namespace coordinator and carried by `config_version`;
  - opaque-mode deployments support repository-level leases only.
- **States** are a pure function of the terms and backend time, **evaluated on every request**, so enforcement
  never waits for a timer:

  | State | Effect |
  |---|---|
  | `active` | normal |
  | `grace` | writes blocked, reads allowed |
  | `suspended` | reads blocked |
  | `deleted` | terminal: the ref is removed (head and packmap together), and so is its published pointer; objects wait for GC |

  - Renewal during `grace` or `suspended` restores `active`.
  - A new lease after `deleted` allows new writes only.
  - Timers perform the side effects and emit the events.
  - Repository-level changes take effect within the §9.1 visibility completion rule: at most one epoch lease plus
    the cache TTL.
- **Admin suspension** is a separate override. The effective state is the more severe of the two, and a payment
  renewal never lifts an admin or takedown suspension.
- **Errors:**
  - a write during `grace` → `permission_denied`, with the fixed message `repository lease expired; writes blocked`;
  - a read while `suspended` or `deleted` → `not_found` for readers (no existence oracle, cache-safe); for authorized
    writers → `permission_denied` with `lease suspended`;
  - never `failed_precondition`, which would make clients loop on `BeginUpload`.
- **Setting leases:**
  - §12 defines the semantics of SetLease: scope, terms, the right to shorten, and that it is audited;
  - the wire belongs to 5.1b's admin API, so reserve the cross-reference;
  - a deployment policy hook sets the initial lease when a ref is created (normative behaviour, no wire).
  - `AdmitAllow.lease` is deferred (say so).

### B.3 §12 Lifecycle events

- **A new hooks.v1 RPC:** `HooksService/Event(EventRequest) → EventResponse{}`.
  - `EventRequest{ Event event = 1; }`
  - `Event`:
    - `event_id = 1`: 1–128 bytes of `[A-Za-z0-9._:-]`, an idempotency key;
    - `audience = 2`;
    - `repository = 3`;
    - `occurred_unix_ms = 4`;
    - `sequence = 5`: monotonic per (repository, ref-or-repository) scope;
    - `oneof kind { LeaseTransition lease = 6; }`. Reserve `7` for 5.1a-2's `PublicationTransition` by comment only;
      do not add it.
  - `LeaseTransition{ string ref = 1 (empty = repository level); LeaseState from = 2; LeaseState to = 3; int64 lease_expires_unix_ms = 4; LeaseCause cause = 5; }`
  - `LeaseState`: `LEASE_STATE_UNSPECIFIED = 0`, `ACTIVE`, `GRACE`, `SUSPENDED`, `DELETED`.
  - `LeaseCause`: `UNSPECIFIED = 0`, `EXPIRY`, `RENEWAL`, `POLICY`, `ADMIN`.
- **Delivery:**
  - events go through the same durable outbox as outcomes;
  - at least once, retained until acknowledged, with **no ordering guarantee**; receivers order by `sequence`;
  - signed under §7.1 and retried under §8;
  - events count toward the §5 backlog bound.
- Update §5 (the outbox is no longer outcome-only), §6.1 ("any subset of the five RPCs") and §8.
- **Remote `CachePurge`:** deferred to 5.1b. WP-5.10 is Rust-trait-only; record this in R-108.

### B.4 §13 Server GC

- **Per-repository roots:**
  - every live ref value, including each branch's packmap chain;
  - every published pointer;
  - every unexpired ticket's pack or packlist node;
  - every unexpired hold.
- **Pins:** an `AlreadyPresent` answer pins the pack for `already_present_pin_window`.
- **Pending advances:** "pending advances" in R-64 means planned, unapplied writes, which the wait phase covers.
  Advances awaiting clearance are live refs.
- **Liveness:**
  - every pack or node on a root's packmap chain is live **in both modes**, because clients hard-fail on a missing
    packmap pack;
  - indexed mode adds object-closure liveness for index rows and extracted objects;
  - opaque mode: a repository with any live non-branch ref keeps all its member packs (fail-closed).
- **Phases:**
  1. **Per repository, mark:** mark `gc_pending(since)`.
  2. **Wait until all three hold:**
     - `now > mark + MAX_APPLY_WINDOW + margin`;
     - the namespace relay watermark has passed that point;
     - `since + gc_grace ≤ now`.
  3. **Re-check roots from the strongly consistent ref shards.** The shard list is the ref index read *after* the
     watermark, ∪ the coordinator's active-shard table.
  4. **Drop:** remove membership and index rows, and this repository's holder.
- **Global byte deletion:**
  - only at zero holders and zero live holds;
  - through a per-object step guarded on the mark and the change sequence: `deleting` → delete → clear;
  - no cross-namespace watermark is needed, because holds cover holders still in flight.
- **Pack holders:** content-index holders and holds are a normative obligation for packs as well as extracted
  objects. Without them GC can drop membership but never pack bytes. Record the implementation gap in R-108 (owner:
  5.3a, with 4.10).
- **Planner obligations:** a planner that relies on a `gc_pending` member unmarks it first. `deleting` answers
  retryable `unavailable` (or a re-upload), never a permanent error.
- **Fail closed:** abort the run on any of:
  - an unreadable root source;
  - an undecodable packlist node;
  - a missing object;
  - a truncated walk.
- **Not roots:** a lease-deleted ref. Preservation-store bytes and blocklist rows are never collected; cross-reference
  the 5.1b details.
- **STC §7.7:** reword "a ticket's pack is collected before an advance consumes it" as a defensive case, since
  unexpired tickets are roots.

### B.5 transport.v1

- Add `GetServerInfoResponse.leases = 17` (bool: storage leases are enforced).
- Add an STC §2.1 row and a version-history row. **Field 18 belongs to 5.1a-2; do not use it.**

### B.6 Goldens (`rust/tests/golden/server-hooks/`)

- `event-lease-grace.request.json`, `event-lease-deleted.request.json` and `event.response.json`;
- an Event webhook vector in `signature.json`;
- updates to the `check-server-hooks-goldens.sh` table, `MANIFEST.txt` and `golden_server_hooks.rs`.

### B.7 Plan edits (you own these)

- **Registry:**
  - replace the 5.1a row with **5.1a-1** (this WP) and **5.1a-2** (the published view and quarantine);
  - 5.2 and 5.1c depend on 5.1a-1;
  - 5.4, 5.5 and 5.1b depend on 5.1a-2.
- **Add row R-108:**

  > WP-5.1a split into 5.1a-1 (§12 leases and events, §13 GC, the `Event` RPC, `GetServerInfo.leases`, the
  > renumbering) and 5.1a-2 (§10 published view, §11 quarantine).
  > - Remote `CachePurge` is deferred to 5.1b, and WP-5.10 is a Rust trait only.
  > - Pack holders and holds are normative; the implementation gap is owned by 5.3a with 4.10.
  > - The `gc_pending` and `AlreadyPresent` pin fields are implementation state for 5.3a.

## C. Your decisions

- Prose structure inside §12 and §13, and diagrams (if any).
- The exact field comments.
- Whether the parameters table lives in §12 or §13.

## D. Escalate (stop and report) if

- Any B item contradicts a merged normative rule you can't reconcile by citation.
- The proto additions fail `buf breaking`.
- The spec text exceeds ~1,500 changed lines (excluding goldens).

## Gates

- `buf lint`, and `buf breaking --against '.git#branch=origin/feat/mkit-server'`, from the repo root
- `bash scripts/check-generated-fresh.sh`
- `bash scripts/check-spec-status.sh`
- `bash scripts/check-server-hooks-goldens.sh`
- `just ci-server`
- the wasm32 check of `mkit-server`
