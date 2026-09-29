# M3 exit report (WP-3.7b, WP-3.12, WP-3.13; incomplete)

Evidence from base `85c4adf3`, the earlier bundle commits through `70138d7f`,
and the resumed local commit recorded by git, on 2026-09-29. Machine:
macOS aarch64, Rust 1.95.0. Builds used `CARGO_PROFILE_DEV_DEBUG=0`,
`CARGO_PROFILE_TEST_DEBUG=0`, the worktree's own target directory, and
`$HOME/.cache/mkit-test-tmp/3-12-3-13` as a nonsymlinked TMPDIR.
Other executors were active. Worker runs used `VCS_CONFORMANCE_PORT=8931`.
No staging, deploy, fault proxy, pipeline, proto or golden change occurred.
The only spec edit is the explicitly authorized STC §7.1 note/version row.

**Verdict: M3 remains incomplete under a new Section D escalation.**
The original concurrent-admission escalation is resolved by the ruling
below. Two Worker runs now expose repeated challenge fields coalescing on
the wire, which violates the accepted separate-field assertion. A minimal
Worker reproduces that behavior without mkit. The adapter already appends
the values; an inline one-line adapter fix has not been identified.
The case has an explicit Section D skip for this observed shape. The
Worker script rejects skips, so it cannot report a green M3 exit.
Work is committed locally, without pushing or opening a PR under the
common executor rules' Section D exception.

## 1. Native lanes

The resumed native M3 run after correcting fixture CORS configuration
and removing the single-repository flag from Multi produced:

```text
S3+SQLite: admission 9/9 and CORS 2/2 passed; isolated rerun passed in 1.430 s.
FS+SQLite: admission 9/9 and CORS 2/2 passed;
  outcomes.aborted_on_cas_loss and outcomes.expired_ticket passed;
  backpressure and eventual completeness failed in the fixture.
Binary: admission 9/9 and CORS 2/2 passed;
  CAS-loss stage exceeded nextest's 60-second ceiling.
Multi: admission requests returned 400 before reaching Admit.
Summary: 1 passed, 2 failed, 1 timed out (four lane tests).
```

The remaining native harness corrections are not server-bug claims:
Multi must sign and read a namespaced owner repository rather than the
profile's literal `default`; the backlog guard checks strictly greater
than the cap, so setup must exceed it before expecting rejection.
The subsequent eventual-completeness failure followed the undrained
backpressure fixture. Binary CAS-loss delivery/teardown needs diagnosis;
its timeout is not classified as machine load without an isolated pass.

FS-layout/bearer now declares M3 and explicitly expects hook-case skips
under R-165, while its CORS case remains independent. This updated lane
has not completed its final run.

## 2. Worker lane and the orchestrator ruling

Leg W now uses a Rust `stub-hook --unsigned` process on numeric loopback,
an isolated JS raw-byte forwarder, and one wrangler multi-worker session
with `wrangler.hooks.jsonc`. The script configures test-only row cap 16
and ticket TTL 10,000 ms. The main conformance script accepts `--hooks`.
The Free-plan completeness case prepares nine outcomes, exceeding the
eight-row per-alarm sink budget, and polls for acknowledged completion;
that Worker case has not run because the admission filter stops first.

The 2026-09-29 ruling resolves the earlier held-Admit expectation:
STC §7.1 reserves the replay record after admission. Concurrent duplicates
that both pass replay lookup may each call Admit. Single-use payment
credentials prevent double charging. Unary reserve/apply/result commit
atomically; holding Admit creates no observable in-flight replay window.
`admission.concurrent_duplicate_during_admit` replaces the former case
and checks one committed operation, one reservation and one distinct
Committed outcome. It accepts either duplicate denial or the saved
committed result and rejects another principal receiving that result.
The obsolete Section D skip and ignored diagnostic are removed.
Committed replay without another Admit remains the lost-response evidence.

Two runs of `bash scripts/vcs-worker-hooks.sh` produced the same result:

```text
not ok 1 - admission.challenge_402_typed_detail
  # WWW-Authenticate lines coalesced
ok 2 - admission.deny_403_no_detail
ok 3 - admission.no_state_on_challenge
ok 4 - admission.replay_skips_admission
ok 5 - admission.challenge_exhausted
ok 6 - admission.hook_down_unavailable
ok 7 - admission.ticketless_upload_refused
ok 8 - admission.concurrent_duplicate_during_admit
ok 9 - admission.helper_flow_commit
# pass 8 fail 1 skip 0
```

A separate minimal local Worker, with no Rust or mkit dependency, appends
`Basic realm=one` and `Bearer realm=two` independently and returns 402.
Curl observes:

```http
HTTP/1.1 402 Payment Required
WWW-Authenticate: Basic realm=one, Bearer realm=two
```

The unchanged Worker adapter's `response_header_plan` and
`copy_response_headers` already set the first value and append the second.
The installed worker 0.8.6 delegates append to Web Headers. Cloudflare's
[Headers documentation](https://developers.cloudflare.com/workers/runtime-apis/headers/)
identifies Set-Cookie as the special nonfolded response header.
The minimal reproduction establishes that adjusting this adapter's
append loop cannot alone satisfy the separate-field requirement.
A runtime/proxy solution or a new orchestrator ruling is needed; neither
is silently implemented here. The committed case reports a reasoned skip
for exactly the observed one-field shape, never success. The script's
no-skip guard keeps the milestone blocked.

## 3. Admission end to end and public hooks

WP-3.7b publishes JSON-enabled hooks.v1 messages, HookSigner and HookVerifier
under `mkit_rpc::hooks`, with server re-exports. Public-only integration
tests decode all request goldens, build all response goldens and verify
every signature vector. Freshness, wasm dependency graph and focused
RPC/server tests, doctests and clippy passed in the earlier run.
Generated Debug prints credential fields; prominent module and
AdmitRequest warnings document this. Buffa redaction needs a proto option,
which the brief forbids. Server redacting wrappers remain intact.

WP-3.12's MPP fixture binds credentials server-side with a fresh HMAC
secret and enforces single use. Its redacted ledger deduplicates complete
terminal bodies per reservation; delivery may repeat, settlement may not.
Loopback controls expose counts and outcome summaries, not credentials.
Leg N uses the existing public `remote_dispatch::open_trusted` Config entry
and `push_branch_steps`; no ExecResponder re-export was needed. The
POSIX helper uses an absolute temporary executable path and explicit trust.

Earlier native e2e evidence: six tests passed in 33.84 seconds, covering
commit/SIGTERM drain, no helper, reserved header rejection, second 402,
hook down, and the isolated child entry. The resumed test adds an exact
receipt-value leak assertion; its final rerun remains pending.
Earlier conformance/native focused nextest passed 39 tests, with only
the now-removed escalation diagnostic ignored; that is historical
evidence, not a final gate pass for this tree.

## 4. Wire conformance and deviations

Fifteen M3 cases are registered and documented: nine admission, two CORS
and four outcome cases. Shared native fixtures, Worker profile knobs and
strict lane judging are implemented. Backlog and TTL Worker vars exist
only under `test-faults`; tests cover bounded injection and release
configuration never looking them up.

The missing-ticket case follows STC §5's contract: `failed_precondition`
at Connect stream end, no challenge detail and no 402. The research
brief's plain-403 expectation was stale. No pipeline status was changed.
The duplicate case follows the explicit ruling in §2. Existing M1 rows
and TODOs are retained; the resolved M3 TODO block is removed.

## 5. Release and server-free CLI checks

The release feature guard rejects `stubs` and scans for `/__stub/`,
`TEST_OUTBOX_BACKLOG_ROWS` and `TEST_TICKET_TTL_MS`, alongside the
existing test-fault markers. Synthetic release-guard tests passed earlier.

A real production server was built with the guard's release feature set:

```text
Finished release profile [optimized] in 8m 22s
mkit-server: 323 packages compiled
mkit-server-native=['enc','http','s3','sqlite']
mkit-server=['connect','fs','sql','ssh']
check-release-artifact-features: OK (server): mkit-server
```

The Worker test-faults wasm release build completed in both hook runs.
A final default Worker build, compiled-marker check and both configuration
unit-test runs remain pending. The CLI baseline gate ran as part of
ci-scripts but that overall recipe failed on the root lock refresh after
adding the native e2e's base64 dev dependency; metadata refreshed it.
No successful final ci-scripts pass is claimed.
cargo-semver-checks 0.50.0 is now installed privately; its comparison
against the base remains pending.

## 6. Gate results

- Final workspace all-target/all-feature clippy passed (17.56 seconds)
  before the explicit coalescing skip; final conformance/native/Worker
  all-target/all-feature clippy also passed (29.99 seconds). The final
  conformance all-target/all-feature recheck after narrowing the skip
  to the observed combined value passed (1m 28s).
- `just ci-security` passed.
- Native production release build and artifact feature/marker guard passed.
- Two Worker hook runs built wasm and passed eight admission cases each;
  the repeated-field case failed and prevented later filters.
- Native S3 M3 admission/CORS passed; FS CAS-loss and expiry passed.
- Formatting and whitespace checks run before the continuation commit.

Not completed: full workspace/reverse-dependency nextest and doctests,
warnings-as-errors docs, wasm32 clippy, semver comparison, `just ci-server`,
final `just ci-scripts`, Worker wasm without test-faults, default Worker
conformance, and `vcs-worker-conformance.sh --test-faults --hooks`.
No `just ci` or complete M3 gate pass is claimed.

The earlier fs multipart heap test failed under parallel cargo test and
passed alone. Its parent comparison remains pending; it is unrelated
to the deterministic repeated-header blocker.

## 7. PRD M3 exit criteria mapped to evidence

| PRD §8 exit bullet | Test/evidence | Status |
|---|---|---|
| Challenge → helper → credential → commit → one distinct Committed outcome, delivered at least once | Leg N `helper_push_commits_and_sigterm_drains`; `admission.helper_flow_commit` native/Worker | Earlier native e2e and both adapter wire flows pass; final whole bundle pending |
| Aborted work settles nothing | `outcomes.aborted_on_cas_loss`; unused upload `outcomes.expired_ticket` | FS cases pass; Worker pending |
| Lost-response retry returns saved result without another challenge | `admission.replay_skips_admission`; 3.11 credential-retention ladder tests | Both adapter wire cases pass; final CLI suite pending |
| Simulated old client fails fast | `no_helper_fails_after_one_attempt`; 3.10 regression | Earlier native e2e passes; final rerun pending |
| Hard-reserved headers cannot be set through config | `reserved_helper_header_is_named_without_retry`; 3.11 filtering tests | Earlier native e2e passes; final rerun pending |

## 8. Decisions, risks and follow-ups

Executor choices: FakeHook's additive behavior/gate API; numeric-loopback
`/__stub/{mode,calls,outcomes,release}`; canonical length-delimited protobuf
HMAC binding; Rust-owned MPP semantics behind a raw-byte JS forwarder;
runner spellings `--hook-stub`, `--backlog-cap`, `stub-hook`, and `--hooks`.
Native knobs remain in-process and Worker knobs remain test-faults-only.

The required two-pass final PR review has not completed because publication
stops under Section D. Earlier review fixed reply Debug, credential leak
assertions and normal hook-down retry behavior. Resumed review corrected
CORS fixture setup, single-repository flags on Multi and clippy findings.
Outstanding native harness corrections are listed in §1.

Carry forward the repeated-field runtime ruling/fix, remaining native
harness checks, Worker CORS/outcomes/backpressure/Free-budget cases, lane
allowlists, final release-only Worker checks, full gates and final review.
Before publication, merge any moved `origin/feat/mkit-server`, preserving
M1's additive table, TODO and lane/script edits.

The diff adds 1,842 handwritten non-test source/script/JS lines (including
relocated signer additions conservatively; generated messages, test files
and cfg(test) modules excluded), below the production cap.

Existing scope carry-forwards remain staging after REL-1 (R-154), the
3.9b Queue sink, RemoteError sanitization (R-140), platform invocation-log
capture at staging (R-166 B13), and an optional real-mkit-binary script lane.
