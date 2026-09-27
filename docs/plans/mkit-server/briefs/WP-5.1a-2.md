## Purpose

Content a writer pushes must not reach readers, URL tokens, HTTP or caches until every configured inspection has
cleared it. This WP specifies:
- **the published view:** the value each reader sees;
- **the per-advance clearance state machine;**
- **the sync and async inspector contract.**

It also corrects today's §6.4 and §8 text, which contradicts D18/D28.

## A. Fixed (do not change)

1. **PRD §6.7**, the published view, quarantine and published pointer: pending content is never served to
   non-writers.
2. **The user's decisions** (2026-09-27):
   - **(a) Inspected set:** every file object newly reachable in the advance, i.e. plain blobs of any size, chunked
     files (the manifest and its chunks) and extracted objects. **No option narrows it.** This deliberately deviates
     from PRD line 415 ("extracted blobs"), which would let small plain blobs publish without inspection. State the
     deviation in the PR body.
   - **(b) Writer classification is per repository**, not per ref.
3. **STC §7.9:** `X-Mkit-Ref` is always subject to the caller's view.
4. **SPEC-WRITE-GRANTS:**
   - §3.2 and §6: the capabilities are `read`, `read,write` or `write`;
   - §9.2: a client with a signer MUST sign reads to be seen as a writer;
   - §9.4: URL tokens resolve in the published view.
5. **WP-2.9** (plan): `caller_view ∈ {writer, reader, anonymous}`.
6. **Proto rules:**
   - additive only; `buf breaking` must stay green;
   - never change the label or oneof membership of an existing field (R-79).
   - hooks.v1 today: `InspectRequest{operation=1, objects=2}`, `InspectObject{id=1, size=2}`, and
     `InspectResponse` oneof `pass` / `quarantine{reason}` / `reject` (a `Deny`). Read the file for the exact
     numbers.

## B. Decided by the orchestrator (do not change)

### B.1 §10 Published view

- **Writer:** a caller whose signed request presents any of these for the **repository** (any ref scope):
  - an owner key;
  - a grant with a `write`-capable capability covering the repository;
  - an ssh/enc principal authorized to write;
  - an authority source whose `Authorize` answer sets `writer_view` (B.4).

  Everyone else is a reader, including unsigned requests. A writer that doesn't sign is a reader; document this.
- **Per-ref state:**
  - an advance sequence per ref, which `UpdateRef` writes increment too;
  - each advance has a clearance state: `pending | cleared | held | hit → resolved`.
- **Published value:** the value at the largest *k* such that every advance ≤ *k* is `cleared` or `resolved`.
- **Clearance:** advance *k* clears only when **both** hold:
  - its own inspection passes;
  - every pack its packmap chain lists is in **published membership**, meaning membership added by a cleared
    advance. For a non-branch ref, use its target's containing packs.

  This closes the cross-ref leak: branch B advancing onto a pack that pending branch A added (via `AlreadyPresent`),
  and a tag pointing at a pending commit.
- **Deletions** publish immediately.
- **With no async inspector configured,** the published pointer is written in the same apply, so the published view
  equals the live view.
- **An async inspector in opaque mode is refused at startup.**
- **Reader answers:** pending refs and packs read exactly like absent ones (`exists = false`, `not_found`), on every
  read surface: `ListRefs`, `ReadRef`, `PackExists`, `DownloadPack`, `X-Mkit-Ref`, snapshots, URL tokens and HTTP.
- **"Caller's view":** define it abstractly (visible ref values plus visible membership), so SPEC-HTTP-OBJECTS can
  cite it.

### B.2 §11 Quarantine and inspection

- **Configuration:** each inspector has a phase, `sync | async`, and an `on_unavailable` setting,
  `fail_closed | publish`.
- **Sync (§2 stage 5):**
  - pass → continue;
  - reject → `permission_denied` (403);
  - quarantine → the push commits, but the advance starts `held`;
  - unavailable + `fail_closed` → retryable `unavailable`.
- **Async (§2 stage 9):**
  - The call is scheduled from the outbox or a timer, is idempotent by `inspection_id`, and is retried with backoff.
  - pass → `cleared`.
  - quarantine → `held`, until re-inspection or an admin release (the wire is 5.1b).
  - reject → a **hit**: takedown of `flagged_objects` (5.1b/5.6); the advance becomes `resolved` once the takedown
    completes.
  - `defer{retry_after_ms}` → re-poll. Clamp `retry_after_ms` like PendingVerification: 1000–60000.
  - unavailable + `fail_closed` → the advance stays `pending`.
  - unavailable + `publish` → the advance clears after a configured deadline. A later hit becomes a takedown,
    **never** a retroactive un-publish.
- `AdvanceRefs` itself succeeds and records `Committed`; only readers' view lags.
- **The inspected set** is A.2(a).
- **Rewrite §6.4's fetch note:** inspectors fetch bytes through a deployment-private channel, never the public
  serving path, which would serve only published content.
- **Fix the §6.4/§8 contradictions:**
  - `publish` / `fail_closed` govern only inspector **unavailability**;
  - an async check can never reject an already-committed push.

### B.3 hooks.v1 additions (additive)

- `InspectRequest`:
  - `InspectPhase phase = 3`, with values `UNSPECIFIED = 0`, `PRE_RECEIVE`, `QUARANTINE`;
  - `string inspection_id = 4`, an idempotency key.
- `InspectObject.kind = 3`: `InspectObjectKind`, with values `UNSPECIFIED = 0`, `BLOB`, `CHUNKED_FILE`, `CHUNK`.
- `InspectResponse`:
  - a new oneof member, `InspectDefer defer = 4` (`{ uint32 retry_after_ms = 1; }`);
  - a new top-level field, `repeated bytes flagged_objects = 5`, with 32-byte ids, meaningful with `reject` or
    `quarantine`.
  - Verify the free numbers first. If 4 or 5 is taken, use the next free ones and record them.
- `AuthorizeAllow.writer_view`: a bool, on the next free field number. When set, an authority-source caller is a
  writer for the published view.

### B.4 transport.v1

- `GetServerInfoResponse.async_inspection = 18` (bool). When true, writers must sign reads to see their own pending
  content.
- Add an STC §2.1 row and a version-history row. **Field 17 belongs to 5.1a-1.**

### B.5 Goldens (`rust/tests/golden/server-hooks/`)

- `inspect-quarantine-phase.request.json`, `inspect-quarantine.response.json`,
  `inspect-reject-flagged.response.json`, `inspect-defer.response.json` and `authorize-writer-view.response.json`;
- update the `check-server-hooks-goldens.sh` table, `MANIFEST.txt` and `golden_server_hooks.rs`.

## C. Your decisions

- The prose structure, and a state diagram of clearance if it helps.
- The configured clear deadline's parameter name, and whether it is listed in the parameters table (coordinate by
  name with 5.1a-1's table).
- The exact field comments.

## D. Escalate (stop and report) if

- The B.1 clearance rule leaves any read surface that can observe pending content.
- The proto numbers conflict in a way the "next free" rule can't resolve.
- The spec text exceeds ~1,500 changed lines (excluding goldens).

## Gates

- `buf lint`, and `buf breaking --against '.git#branch=origin/feat/mkit-server'`
- `bash scripts/check-generated-fresh.sh`
- `bash scripts/check-spec-status.sh`
- `bash scripts/check-server-hooks-goldens.sh`
- `just ci-server`
- the wasm32 check of `mkit-server`
