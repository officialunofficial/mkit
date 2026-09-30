# M3 exit report (WP-3.7b, WP-3.12, WP-3.13; incomplete)

Evidence from merged base `b0bbbba2` and bundle commits through `49c7affd`,
on 2026-09-29. Machine: macOS aarch64, Rust 1.95.0. Builds used
`CARGO_PROFILE_DEV_DEBUG=0`, `CARGO_PROFILE_TEST_DEBUG=0`, this worktree's
own target directory, and `$HOME/.cache/mkit-test-tmp/3-12-3-13` as a
nonsymlinked TMPDIR. Other executors were active. Worker runs used
`VCS_CONFORMANCE_PORT=8931`. No staging, deploy, fault proxy, proto or golden
change occurred. Spec edits and the core timer correction are explicitly
authorized by the three continuation rulings.

**Verdict: implementation complete; final verification and publication pending.**
All three Section D escalations are resolved. The kind-8 correction is a
separate commit, and the CAS-loss wire case runs without its former skip.
The full Worker test-faults/hooks script passes, including all 15 M3 cases.
Final native/full gates remain incomplete: two unchanged baseline lanes
failed and need isolated reruns and parent comparison. The current managed
permissions prevent writes to the mandatory TMPDIR, so the remaining
gates cannot run and publication remains pending.
This report does not claim an M3 exit or an open PR.

## 1. Core outcome completion correction and native lanes

The third ruling authorizes correcting #1219's B1 acknowledgment window.
The original handler awaited the sink, planned acknowledgments using fresh
`oc`, but decided completion against the initial backlog count. An append
during that await could leave one outcome without a timer. Completion now
uses the decoded fresh backlog, and the acknowledgment batch guards that
same `oc`. It returns Done only when all rows in that guarded backlog were
acknowledged; otherwise it preserves one kind-8 timer and reschedules now.
An append after the fresh read fails the guard, retaining the original
timer for the next fire to re-plan. Empty acknowledgments continue to use
and guard the initial `oc`.

Commit `49c7affd` is `fix(server): kind-8 completion uses the guarded fresh
backlog`. R-165 records the correction to #1219 B1. INVARIANTS.md records
that a nonempty outbox retains exactly one kind-8 row. The old ignored
diagnostic is now the regular regression
`append_during_ack_keeps_a_timer_and_delivers_on_the_next_fire`.
Additional regular tests cover an append after the fresh read, guarded
completion of all acknowledgments, and empty acknowledgments. The first
regression failed on the old handler (expected one timer, observed zero);
all 13 focused outcome-delivery tests pass on the correction, with no
ignored tests. Core all-target/all-feature clippy also passes.

Historical native focused evidence covers S3 admission/CORS, binary
admission/CORS/CAS-loss, FS-layout/bearer, and seven exec-helper/e2e tests.
Multi initially assumed an unallocated repository existed; signing the
owner repository and expecting not_found until allocation corrected the
fixture, and its isolated rerun passed in 1.248 seconds. FS admission/CORS
passed before exposing the now-corrected race. Final native M3 runs on the
corrected handler remain pending; older passing runs are not substituted
for them.

Final review replaced broad admission/outcomes/CORS skip prefixes with an
explicit 15-case M3 allowlist, made FS-layout/bearer check every unsupported
M3 case, and added nine-outcome eventual completion to the binary lane.
These last test changes pass formatting, but their behavioral verification
is pending because of the permission blocker. FS and S3 baseline lanes retain their additive M1
allowlists. The backlog fixture exceeds the strictly-greater-than cap
before expecting rejection.

## 2. Worker lane and the three orchestrator rulings

Leg W runs a Rust `stub-hook --unsigned` on numeric loopback behind a
raw-byte JS forwarder and one wrangler multi-worker session using
`wrangler.hooks.jsonc`. Test-only knobs set backlog rows to 16 and ticket
TTL to 10,000 ms. The runner declares `combined-challenge-fields` on this
lane; native lanes continue to require two response field lines.

The first ruling preserves STC §7.1's ordering: replay reservation follows
Admit. Concurrent duplicates that both pass replay lookup may each call
Admit; payment credentials must be single-use. Unary reserve/apply/result
commit atomically, so holding Admit creates no observable in-flight window.
`admission.concurrent_duplicate_during_admit` checks one committed operation,
one reservation and one distinct Committed outcome. It allows denial or the
saved committed result and rejects another caller receiving that result.
Committed replay without another Admit remains the lost-response evidence.
The former skip and ignored held-Admit diagnostic are removed.

The second ruling accepts Workers' platform combination of repeated
WWW-Authenticate fields under RFC 9110 §5.3 when challenge order is
preserved. STC §5.1 and SPEC-SERVER §6.3 now say servers SHOULD emit separate
lines, and clients/helpers MUST parse values as RFC 9110 §11.6.1 challenge
lists. PAYMENT-REQUIRED is unaffected. The wire case compares semantics and
order using a bounded parser; unit tests cover quoted commas, escaped
quotes, token68, empty list members, whitespace and malformed input.
R-166 and R-173 record this platform limitation and ruling. The old header
skip and escalation text are removed.

The third ruling fixes the shared outcome completion defect described in
§1. The CAS-loss case is active, and the full Worker run after that
correction passes:

```text
main M1:   88 passed, 0 failed, 115 skipped
quotas:     4 passed, 0 failed,   1 skipped
admission:  9 passed, 0 failed,   0 skipped
cors:       2 passed, 0 failed,   0 skipped
outcomes:   4 passed, 0 failed,   0 skipped
```

The quota skip is the undeclared multi-namespace capability. The planted
D34 relay passes with target member=true and source queued=false. Upload
and download peak buffering is 864,011 bytes, below 1,048,576. M3 includes
Committed/Aborted/Expired ledger behavior, backpressure recovery and
Free-plan eventual completion of nine outcomes, exceeding the eight-row
per-alarm sink budget. These are actual wrangler runs, not mocks.

The separate default Worker phase builds successfully and passes cold
start (30/30), but ends with 80 passed, two failed and 121 skipped.
`multipart.three_parts` receives HTTP 500 Network connection lost in
Miniflare; `refs.concurrent_missing_one_winner` receives an aborted
coordinator lease-grant contention response in round two. Both cases are
unchanged M1 cases. Isolated retries and comparison on the unchanged parent
remain pending; neither failure is classified as load-related without
that evidence. The main script's --hooks double-shift was corrected, and
all additive M1 case rows remain.

## 3. Public hooks and admission end to end

WP-3.7b publishes JSON-enabled hooks.v1 types, HookSigner and HookVerifier
under `mkit_rpc::hooks`, with server re-exports. Public-only integration
tests decode all request goldens, build all response goldens and verify
every signature vector. Earlier focused RPC/server tests, doctests,
freshness and wasm dependency checks passed. `cargo-semver-checks` 0.50.0
against `origin/feat/mkit-server` with all features now passes: 196 checks
passed, 58 skipped; no semver update required.

Generated Debug prints credential fields. Module and AdmitRequest warnings
explain this; buffa redaction requires a proto option, outside the brief's
allowed scope. The server keeps its redacting wrappers. Implementers are
instructed to use Default or constructors for additive evolution.

WP-3.12's Rust fixture binds credentials server-side with a fresh HMAC secret
and enforces single use. The redacted ledger deduplicates complete terminal
bodies per reservation; delivery may repeat, settlement may not. Loopback
controls return counts and outcome summaries, never payment credentials.

Leg N uses existing public `remote_dispatch::open_trusted` and
`push_branch_steps` with Config; no ExecResponder re-export was needed.
All seven native integration tests pass, including actual server binary
commit/SIGTERM drain, no helper, reserved-header rejection, second-402
termination, normal hook-down retries, the child entry and the new combined
challenge helper check. Exact credential/receipt leak assertions pass.

Transport/CLI inspection found raw WWW-Authenticate values forwarded by
`filter_headers` into helper stdin, without challenge splitting. CLI.md
now documents that each value may carry multiple challenges; typed details
remain separately available. No client production behavior changed. The
Rust MPP helper uses the challenge-list parser. The POSIX sh fixture selects
the first Payment id/expiry without splitting commas; its test combines
multiple schemes, later Payment credentials and a quoted comma. The
existing CLI stdin test also now checks a combined raw field value and passed
in the interrupted workspace run (0.847 seconds). The CLI helper trust/filter
integration test passed there too (10.831 seconds).

## 4. Wire conformance and deviations

Fifteen M3 cases are registered/documented: nine admission, two CORS and
four outcome cases. Shared native fixtures use real hook configuration and
the real timer driver; knobs are set in-process. Worker vars
TEST_OUTBOX_BACKLOG_ROWS and TEST_TICKET_TTL_MS are test-faults-only.

The missing-ticket case follows STC §5: failed_precondition at Connect
stream end, no challenge detail and no 402. The research's plain-403
expectation was stale. Both adapter cases pass without changing status code
implementation. Duplicate behavior and combined headers follow the fixed
rulings in §2. M1 TODOs/table rows and lane additions remain intact.

All former Section D skips and ignored diagnostics are removed. Strict
native/Worker no-skip checks remain. The final allowlist edits described
in §1 still require their gate run.

## 5. Release guards

Release guards reject `stubs` and scan for `/__stub/`,
TEST_OUTBOX_BACKLOG_ROWS and TEST_TICKET_TTL_MS, alongside existing markers.
Synthetic guard tests pass. The real native production release build and
artifact feature/marker guard passed (8m 22s; 323 packages; production
native features enc/http/s3/sqlite and core connect/fs/sql/ssh).

Both Worker wasm release builds pass, with and without test-faults. A
read-only scan of the actual default build/index_bg.wasm finds none of
the three new test markers. The app host/wasm clippy, formatting and host
lib test command pass. Final root Worker configuration tests in both
feature modes remain pending. Earlier RPC hooks wasm and server
remote-hooks wasm checks passed; final root wasm32 clippy remains pending.
The native release artifact guard predates the core correction and needs
a final rebuild.

## 6. Gates and evidence files

Logs live under `$HOME/.cache/mkit-test-tmp/3-12-3-13`; they contain no
expected payment credential or receipt values.

| Check | Latest result/evidence |
|---|---|
| Core kind-8 regression | Old handler fails; corrected handler passes all 13 outcome tests; kind8-regression-red.log, kind8-final.log |
| Core all-target/all-feature clippy | Passed; kind8-final.log |
| Final formatting / shell and JS syntax / diff check | Passed on the final review edits |
| Full Worker test-faults/hooks | Passed, including all 15 M3 cases without skips; worker-full-kind8.log |
| Default Worker | Build/cold-start pass; two unchanged M1 cases fail, isolated reruns/parent comparison pending; worker-default-kind8.log |
| just ci-server | 1,940 passed, one failed, seven skipped, 286 not run; ci-server-kind8.log |
| RPC semver against merged b0bbbba2 | 196 checks pass, 58 skip; semver-rpc-kind8.log |
| Worker app host/wasm clippy, fmt and lib test command | Passed; worker-app-host-wasm.log |
| Default Worker compiled-marker scan | Passed on actual build/index_bg.wasm; no /__stub/ or either new TEST_* marker |
| Native focused lanes/e2e, before core fix | Historical coverage only; native-m3-fixed2.log, multi-final.log |
| Conformance unit tests | Historical 34 passed; escalation-conformance-unit.log |
| Workspace all-target/all-feature clippy | Historical pass; workspace-clippy-fixed2.log |
| ci-scripts / CLI baseline / wasm graph | Historical pass; ci-scripts-continue2.log |
| ci-security | Historical pass; ci-security-continue2.log |
| Native production artifact guard | Historical pass; server-release-guard.log |
| Locked apps metadata | Merged published-view-probe lock refreshed offline and locked metadata passes; final repeat pending |
| Full just ci | Historical run interrupted at the former Section D stop; no final run/pass claimed |

The ci-server failure is binary_fs_sqlite_auth_v2_d34's unchanged
`timers.redelivery_is_idempotent` case: ListRefs returns 503 with a test
timer tick reporting failed=1. The case's other timer checks pass. Its
isolated retries (up to three) and unchanged-parent comparison must run
before attributing the failure. The new core kind-8 tests pass in this
same server gate.

No full-gate pass is claimed. Pending: isolated baseline reruns and parent
comparison; complete ci-server; required four-crate nextest including CLI;
full just ci/workspace/reverse-dependency nextest; doctests and warnings-as-
errors docs; final root wasm32 checks and configuration tests in both
Worker feature modes; default Worker rerun; freshness; final native release
artifact guard; and verification of the last native allowlist/binary edits.
The historical FS multipart heap failure passed alone; its parent
comparison also remains pending.

The current managed permission profile excludes
`$HOME/.cache/mkit-test-tmp/3-12-3-13` from writable roots. The isolated
native rerun cannot even create its log there: Operation not permitted.
The common rules require that exact scratch location. Git staging, which
initially also failed, now succeeds; the remaining review edits can be
committed. Restored scratch access is needed for final tests and their
logs before publication. Scratch is not relocated to bypass the rules.

## 7. PRD M3 exit criteria mapped to evidence

| PRD §8 exit bullet | Test/evidence | Status |
|---|---|---|
| Challenge → helper → credential → commit → one distinct Committed outcome delivered at least once | Leg N helper_push_commits_and_sigterm_drains; admission.helper_flow_commit native/Worker | Native e2e and both adapter helper-flow evidence pass; final native gates pending |
| Aborted work settles nothing | outcomes.aborted_on_cas_loss; unused upload outcomes.expired_ticket | Worker passes after core fix; final native FS/binary reruns pending |
| Lost-response retry returns saved result without another challenge | admission.replay_skips_admission; client credential-retention ladder | Both adapter wire cases pass; full CLI gate incomplete |
| Simulated old client fails fast | no_helper_fails_after_one_attempt | Native e2e passes |
| Hard-reserved headers cannot be set through config | reserved_helper_header_is_named_without_retry; client filtering tests | Native e2e passes; full CLI gate incomplete |

## 8. Decisions, review and carry-forwards

Executor choices: additive FakeHook behavior/gate API; numeric-loopback
`/__stub/{mode,calls,outcomes,release}`; canonical length-delimited protobuf
HMAC binding; Rust-owned MPP semantics behind a JS raw-byte forwarder;
runner spellings `--hook-stub`, `--backlog-cap`, `stub-hook`, and `--hooks`.
The combined-challenge capability is declared only by the Worker profile.
Native knobs remain in-process and Worker vars remain test-faults-only.

Local review corrected parser boundaries, quoted-comma handling and
parameter whitespace; preserved raw CLI values; tested helper challenge
selection; fixed Multi owner-repository allocation expectations; corrected
backlog setup and the script double-shift; and found the shared outcome
race. Temporary native debug tracing used during diagnosis was removed.
Two review passes are recorded below; verification of their last edits
and the final publication gate remain pending.

The diff adds 2,077 handwritten non-test source/build-script/shell/JS lines,
including relocated signer additions conservatively, excluding generated
messages, tests and cfg(test) modules. This remains below the cap.

The correctness/security pass checked credential binding and single use,
raw-body signature verification, loopback/unsigned controls, bounded
reads, redaction, storage guards and kind-8 completion/retry paths. The
conformance pass checked each brief item, the three rulings, all 15 case
names, lane capabilities and release gating. It found broad skip prefixes
that could hide future cases and absent binary eventual-completion
coverage; both are corrected in the pending test edits. No further core
change is proposed. Gates are not waived by this review.

| Brief item | Implementation or verification status |
|---|---|
| A1 | Bound credentials; one distinct terminal outcome with at-least-once delivery; CAS Aborted and ticket Expired; no staging/fault proxy |
| A2 | No pipeline/proto/golden changes; only explicitly authorized spec notes and separate core completion fix |
| A3 | Additive FakeHook behavior, hold gate and ledger API |
| A4 | stubs feature, test-faults-only vars and release feature/marker guards |
| B0.1 | RPC hooks feature, buffa JSON vendored generation, regen/freshness scripts and server re-export |
| B0.2 | Public runtime-free signer/verifier, clock injection and optional nonce replay |
| B0.3 | Module/type credential Debug warnings; schema unchanged; server redaction retained |
| B0.4 | Default-based additive message construction documented |
| B0.5 | Public integration test for every golden request/response/signature vector |
| B0.6 | RPC semver passes against merged base; historical wasm graph/build pass; final repeat pending |
| B0.7 | Registry 3.7b, Stage 1/M3/deps 3.7 and 3.8; R-174/Linear MKIT-67 |
| B0.8 | MPP uses public RPC types and shared verifier |
| B1 | stubs/mpp.rs, loopback controls and stub-hook command |
| B2 | Actual native binary and trusted Config/public CLI transport entry with POSIX sh helper |
| B3 | wrangler.hooks.jsonc and unsigned JS raw-byte forwarder to Rust fixture |
| B4 | Fifteen cases, HookStub/backlog/ShortTickets profile; native in-process knobs and Worker test-faults vars |
| B5 | Native lane matrix/explicit allowlists; full Worker --hooks pass; nine-outcome Free case; last native edits need gates |
| B6 | Guard rejects stubs/markers; actual default wasm marker scan pass; feature-mode unit tests/final native artifact rerun pending |
| B7 | Report and PRD mapping, README and registry; final exit remains pending |
| B8 | R-172/R-173 and separate CHANGELOG lines for all three WPs |

Execution remaining: restore required scratch access; rerun failed baseline
cases alone and on the unchanged parent; run all final gates and verify
the last native test edits; refresh and merge any moved
origin/feat/mkit-server while keeping both sides; push and open the
single authorized bundle PR. Base b0bbbba2 has already been merged, with
both CHANGELOG additions preserved. None of the three resolved
escalations remains a scope carry-forward.

Scope carry-forwards remain staging after REL-1 (R-154), the 3.9b Queue
sink, RemoteError sanitization (R-140), platform invocation-log capture at
staging (R-166 B13), and an optional real-mkit-binary helper lane.
