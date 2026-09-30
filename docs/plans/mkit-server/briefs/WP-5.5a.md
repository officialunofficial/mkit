## Purpose

Uno's scanner decides at push time. Before apply, mkit calls each synchronous inspector with the complete inspected
set, rejects on `reject`, and fails closed when an inspector is unavailable.

## A. Fixed

- **The §11.1 inspected set.** It is the union of:
  - every newly reachable file object not in published membership;
  - every file entry of every added pack, including surplus, manifests, chunks and extracted objects.

  Duplicates are reported once; a blob used as both a file and a chunk is reported once as `BLOB`. No configuration
  narrows the set.
- **Batching:** at most `inspect_batch_max_objects` (default 10,000) per call, within §6.6 limits. Every inspector
  gets every batch.
- **Configuration refusals:**
  - an inspection deployment requires ticketed uploads and `begin_upload_threshold_bytes = 0`, including in Single;
  - startup refuses opaque mode or `write_policy = open` combined with an inspector.
- **Replay:** a sync `fail_closed` `unavailable` is excluded from replay storage (STC §7.1).
- **The 100-op seven-ticket apply budget.**
- **B4:** without an inspector, behavior is byte-identical.

## B. Decided (R-200)

1. **The launch-profile amendment**, in SPEC §11.1/§11.2 and §18, with a version-history row:
   - the launch profile accepts only `sync` inspectors with `on_unavailable = fail_closed`, and startup refuses
     anything else;
   - a PRE_RECEIVE `quarantine` is treated as `reject`: `permission_denied`, nothing committed;
   - `defer` is invalid at PRE_RECEIVE, as now;
   - the full profile's async, hold and quarantine semantics are unchanged and marked "deferred (WP-5.5c)".
2. **PRE_RECEIVE at stage 5, before apply:**
   - `pass`: continue;
   - `reject` (or `quarantine`): 403, no commit;
   - `unavailable`: a retryable `unavailable`, no commit, no replay;
   - a reject from any inspector dominates.

   Each call has a stable `inspection_id` per inspector, advance, phase and batch, and a fresh signing nonce.
   Metadata only; bytes are never inlined.
3. **The remote Inspect call** goes over the existing signed hook channels (3.9c: native `HttpChannel`, Worker
   `BindingChannel`/`FetchChannel`) using the public `mkit.server.hooks.v1` types. Byte retrieval for the scanner is
   R-193, the next PR, so only leave a documented seam here.
4. **No durable inspection-mode marker at launch.** Sync-only inspection leaves no outstanding obligations or holds,
   so turning inspection off only stops scanning future pushes. The marker arrives with 5.5a-0 and 5.5c (follow-ups).
5. **Docs:**
   - add row **R-200** to `00-plan.md` (the launch cuts);
   - update `registry.json`: remove 5.15 from REL-1's deps; add registry rows for 5.5c (deferred) and for 5.15 and
     4.14b-2 as post-launch;
   - add a CHANGELOG line.

## C. Your decisions

Module layout, inspected-set enumeration (bounded and resumable), id derivation and metrics. Record them in the PR
body.

## D. Escalate (stop, commit, report)

- The inspected set can't be enumerated within the call and budget bounds.
- The Worker hook call can't fit the request's subrequest budget.
- You'd pass 2,000 production lines.

## Tests

- **The complete inspected set:**
  - an extraneous pack entry;
  - mixed manifests and chunks;
  - a dual file/chunk blob;
  - duplicates.
- **Multi-batch and multi-inspector.**
- **Every verdict:**
  - reject dominance;
  - quarantine becomes reject;
  - defer is invalid;
  - unavailable fails closed with no replay.
- **Startup refusals:** async, publish-on-unavailable, open writes and opaque mode.
- **Stable ids across retries.**
- **The Worker path, conformance included.**
- **B4 identity without an inspector.**

## Gates

- the common gates;
- `just ci-server`;
- nextest across the server crates with `--all-features`;
- wasm32 clippy;
- the vcs-worker conformance default phase on a free port.

Do the self-review, then open the PR.
