# WP-5.6a-3 restricted administration contract (R-190)

Status: implemented and independently source-reviewed; runtime gates are
running after restoration of the unrestricted executor profile. The fifteen
restricted admin regressions pass. This does not yet claim launch readiness.
Activation remains false. The assigned branch is
`mkit-server/wp-5-6a-3-admin-reads`, based on PR #1249 head `c8bae135`.
Do not open its PR until #1249 merges; then merge `origin/feat/mkit-server`.

## Implementation and brief checklist

- Signed moderation-role GetTakedown/ListTakedowns/SetLegalHold/ReadPreserved:
  `takedown/admin.rs` implements AdminOperations for the existing Work runtime;
  `admin/ledger.rs` uses the existing authentication, replay and audit lifecycle.
- Status: additive fields on the existing v1 TakedownRecord separately report
  acquisition pending, historical canonical verification, discovery status,
  legal hold and purged copies. Real completion remains false. Any never reports
  discovery complete. Get/List include no canonical payload. Missing state uses
  the existing preservation defaults and checked explicit retention.
- List: absent or empty scope lists all requests. Repository and namespace
  selectors filter a bounded root scan. Tokens bind the normalized scope and
  last processed request key; foreign/malformed tokens fail closed. Page size
  is 1–100; filtered pages can be empty with a continuation.
- Hold: uses PR2 plan_legal_hold, including its purge ownership guard, state CAS
  and deadline. The core effects, signed operator audit and terminal nonce
  result commit in one batch. No second retention/ownership arbiter is added.
- Read replay: only a bounded action/object/offset descriptor or terminal error
  is persisted. Each byte-reading retry freshly verifies the current key and
  role, rechecks retention and availability metadata and appends acceptance
  audit before returning a fresh stream. Ordinary-operation replay preserves
  SPEC-SERVER §16.4 behavior; the §18 fresh-read exception applies to ReadPreserved.
- Streaming: each poll checks live request/state/object ownership and retention,
  verifies the bounded piece intent and immutable action/object/offset header
  and content hash, then checks live retention/ownership again after blob I/O.
  Offsets are exact and ordered. Successful streams emit one last response,
  including an empty last at size. Above-size offsets fail. Piece/backend or
  retention failures append a backend-clock operator audit and terminate with
  a Connect error, without a last message. Audit failure aborts the transport.
- Confidentiality: no preserved response enters replay, public caches, audit,
  logs or errors. Public stream/piece Debug representations omit payload.
- Foundations: no new tag, timer, storage primitive, catalog, protocol or wire
  version. The five additive status fields remain in AdminService v1 and are
  documented by a separate SPEC-SERVER version-history entry and golden vector.
  §14.7 configuration/signing/public-key-list and full-profile rules remain.

## Adapter handoff to 4.18

Attach the configured Work runtime to Engine::with_operations (it delegates
Takedown acceptance/resume to the existing Service). On the protected Worker
admin mount, invoke Arc<Engine>::handle_streamed, supplying separately decoded
bytes when appropriate while signing the exact wire body. Reply::Unary uses the
existing response adapter. Reply::Stream is an application/connect+json HTTP 200
body stream, containing its own success/error end envelope. Apply
Cache-Control: no-store to every response and do not collect the stream.
Engine::handle/handle_decoded reject preserved reads because those methods
return replayable buffered responses. All catalog exposure/activation remains
4.18 work, as specified by the executor prompt.

## Bounds

List scans at most 100 existing root request rows, retains at most 256 KiB of
record JSON plus framing, and bounds page tokens at 2 KiB. Under the generic
512 KiB value limit its scanned raw rows are at most 50 MiB; actual current
producer rows are smaller. A status lookup uses two metadata reads; a full
100-row matching list uses at most 201 calls within one plan, plus the existing
ledger transaction/retry calls. The shared operation budget remains 9,000.

A successful nonempty stream piece uses eight logical calls: request/state/
object before I/O, piece intent, blob GET, then request/state/object again.
An empty final response uses six. Each poll has a 16-call allowance and retains
one at-most-1 MiB owner-framed piece (payload at most 1 MiB minus 72 bytes),
plus bounded base64/JSON/framing buffers. No whole-copy preflight, whole-object
accumulation or piece-count-sized collection is used. These are source-derived
bounds, not allocator/RSS measurements. Adapters retain their actual Worker
request/R2/DO call budgets; exhausting them terminates the stream with error.

Production Rust delta against c8bae135: 705 added and nine deleted physical
lines (714 conservatively counting test-module declarations); below 1,500.
Fifteen focused regression tests are implemented and pass: roles/replay/audit
continuity, separate status, current-role/key/retention/ownership retry checks,
byte-free nonce storage, offsets and last-message rules, midstream failures,
actual hold-blocked purge, all/scoped pagination, stale hold CAS and audit failure.

## Verification evidence (2026-09-30)

Passed locally with DEV/TEST_DEBUG=0, owned worktree target and the prescribed
TMPDIR environment:

- cargo check --locked -p mkit-server --all-features;
- cargo check --locked -p mkit-server --tests --all-features;
- cargo clippy --locked -p mkit-server --all-targets --all-features -- -D warnings;
- cargo clippy --locked -p mkit-server --no-deps --target wasm32-unknown-unknown
  --all-features -- -D warnings;
- RUSTDOCFLAGS=-D warnings cargo doc --locked --no-deps -p mkit-server --all-features;
- cargo fmt --all --check; git diff --check;
- buf lint; buf breaking against origin/feat/mkit-server;
- new GetTakedownResponse golden v1 JSON round-trip and all admin manifest hashes.

Initial restricted-profile attempts (historical; unrestricted reruns follow):

- Focused nextest: linker cannot create temporary files in the mandatory
  ~/.cache/mkit-test-tmp/wp-5-6a-3 directory (Operation not permitted).
- Workspace all-target/all-feature clippy: aws-lc C compilation encounters the
  same temporary-file denial; no workspace lint pass is claimed.
- Server doctests: rustdoc cannot create its prescribed temporary directory.
- just ci-server, ci-scripts and ci-security: just itself cannot create its
  temporary recipe directory, so none of the recipes executes.
- Default vcs-worker conformance on port 52983 (no listener observed): mktemp
  cannot create its prescribed state directory; no Worker process starts.
- GitHub reads: gh pr view 1249 fails connecting to api.github.com after the
  network restriction. Its latest observed state before that change was OPEN.
  Merge-base refresh, push and new PR publication remain outstanding.

Reverse dependencies requiring complete nextest/doctest checks on resume are
mkit-cli, mkit-server-native, mkit-server-worker and mkit-server-conformance.
No dependency manifests or lockfiles changed. Required scratch paths are fixed
by executor-common-external.md; execution does not relocate them to evade the
permission profile. Restore access, run the full gates on the final integrated
base, and open the requested PR without merging.

## Independent self-review

Two independent read-only reviewers checked correctness/security and spec/brief
conformance. The conformance reviewer found missing all-scope List support;
it is fixed and has a pagination regression. Payload Debug was hardened, Any
status was defended, buffered read replay rejects descriptor exposure, and
invalid descriptor/offset errors receive audits. The final reviewers reported
no remaining actionable source defects. They did not execute runtime gates.

## Restored-profile gate progress

The orchestrator saved and pushed checkpoint 4f8bf232 while Git writes were
restricted. On resumption, scratch writes and GitHub access succeeded. The
focused 13-test nextest suite passed (0.479 seconds). Workspace all-target/all-
feature clippy passed (2m20s), and just ci-security passed. Remaining gates are
in progress. PR #1249 is still open at the latest checked state; final base
integration and publication await its merge. Scratch logs are under
~/.cache/mkit-test-tmp/wp-5-6a-3/. No prior permission-failed gate is counted as
passing merely because permissions were restored.

A final spec pass also tightened SetLegalHold's UTF-8 byte bounds to the existing
§16.5 limits (512-byte reason, 128-byte label) and aligned List parsing with
ProtoJSON null scope/quoted page sizes. Both new regressions failed before the
fix; all fifteen admin tests and native server clippy pass after it.
The first broad CLI run timed out in the unchanged pack-count property test;
its isolated nextest rerun passes in 12.186 seconds. An unchanged-parent check
is compiling. The first Worker run passed cold health 30/30 but failed
refs.many_refs_one_repository with a local Miniflare Network connection lost
HTTP 500. Final integrated-base reruns and isolation are required.
