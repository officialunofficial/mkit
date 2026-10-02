## Purpose

the embedding host's scanner decides at push time. Before apply, mkit calls each synchronous inspector with the complete inspected
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

## R-200 input-limit ruling (supersedes launch multi-batch requirement)

The original batching and multi-batch test requirements above are historical;
the ruling below replaces them with one-batch launch limits and boundary tests.

Ruling: explicit launch-profile input limits. No durable inspection continuation.
1. The launch profile caps the inspected set per advance at inspect_batch_max_objects (default 10,000), so there is exactly
   one batch per inspector.
   - Advertise the limit in server info.
   - Check it before enumerating, from the pack entry counts already recorded in the header or verify job. The sum of
   entries across the advance's added packs is an upper bound on the added-pack part of the set. Add the newly reachable
   objects to it.
   - An oversize advance is rejected before any Inspect call and before apply, using the same error and replay behavior as
   the existing pack-size and entry-count limits. It is never unavailable.
   - The rule applies to the whole set's count regardless of reachability. It does not single out surplus entries, so
   §11.1's "not rejected merely for surplus entries" still holds.
2. At most 4 inspectors in the launch profile. Refuse startup above that.
3. Put both limits in the R-200 launch-profile amendment (§11/§18, plus a version-history row). The full profile keeps
   unbounded multi-batch inspection, noted as deferred to 5.5c.
4. Budget: re-derive the advance's worst case: enumeration scans at 1,000 rows per call for 10,000 objects or fewer, plus
   at most 4 Inspect calls. Assert it in a test, and document it against the repository's 1,000-call accounting contract.
   Don't rely on raising the Paid platform limit.

Tests to add: over-limit rejection before any hook call, exactly-at-limit acceptance, and the 5-inspector startup refusal.

Then continue with the pipeline integration, gates and PR. No new tag, timer or durable state.

## Revised R-200 added-pack ruling (supersedes role classification and selection-fact dependency)

The following revised ruling supersedes the original launch inspected-set
classification and the earlier selection-fact dependency. The original prompt
above is retained as the first-commit brief. The input cap and four-inspector
limit remain; their preflight now uses added-pack entry counts only.

Revised ruling: drop role classification and the dependency on #1238's selection facts.
1. The inspected set in the launch profile. With sync-only inspection, every advance clears at apply, so all earlier
   membership was already inspected. The only newly reachable objects outside published membership are those in the advance's
   added packs. The inspected set is therefore exactly the file-typed entries of the added packs: every Blob and ChunkedBlob
   entry, surplus included. Enumerate it from the frame/checkpoint rows, at up to 1,000 rows per scan against the
   10,000-object cap. No tree walk, no reference pages, no R2 reads.
2. Kinds by object type.
   - A Blob is reported as BLOB, and a ChunkedBlob as CHUNKED_FILE.
   - CHUNK isn't used in the launch profile.
   - The scanner gets chunk membership from the manifests. R-193 retrieval will give it the raw pack bytes to decode.
3. The spec amendment (inside your R-200 launch-profile text):
   - the reduced inspected set, and why it's complete;
   - chunk-only blobs MAY be reported as BLOB, with CHUNK unused;
   - enabling inspection over existing, unscanned content is unsupported in the launch profile: start from an empty store.
   The durable mode marker arrives with 5.5a-0 and 5.5c.

   The full profile keeps the complete §11.1 classification, deferred to 5.5c.
4. Your branch. Remove the #1238 merge if nothing else of yours needs it: rebuild the branch from your last pre-merge
   commit and cherry-pick your later work. That keeps #1238's diff out of your PR.
5. Tests. Turn the 400-entry case into an acceptance test on the Worker with native parity, add a worst case at the cap,
   and assert the call count.

Keep the timer-failure check as ruled. Then finish the gates and open the PR.

The retained timer ruling requires rerunning `timers.redelivery_is_idempotent`
alone and on a clean `origin/feat/mkit-server`: record a reproduced base failure
as pre-existing and continue; fix a branch-only failure. No new tag, timer or
durable state is authorized.
