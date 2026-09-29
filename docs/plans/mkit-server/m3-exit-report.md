# M3 exit report (WP-3.7b, WP-3.12, WP-3.13; incomplete)

Evidence from base `85c4adf3`, bundle commits through `c77f3883`, and the
continuation commit recorded by git, on 2026-09-29. Machine: macOS aarch64,
Rust 1.95.0. Builds used `CARGO_PROFILE_DEV_DEBUG=0`,
`CARGO_PROFILE_TEST_DEBUG=0`, this worktree's own target directory, and
`$HOME/.cache/mkit-test-tmp/3-12-3-13` as a nonsymlinked TMPDIR. Other
executors were active. Worker runs used `VCS_CONFORMANCE_PORT=8931`.
No staging, deploy, fault proxy, production pipeline, proto or golden
change occurred. Spec edits are the two explicitly authorized rulings.

**Verdict: M3 remains incomplete under a new Section D escalation.**
Both earlier escalations are resolved. The Worker M3 lane passes all 15
cases, but native FS exposes a shared outcome-delivery race. A second
terminal outcome appended while the first is acknowledged can remain
queued without a delivery timer. A deterministic store diagnostic proves
this independently of runtime timing or machine load. Section D forbids
fixing this shared handler inline; the CAS-loss case now reports a reasoned
skip, and strict M3 lane guards reject that skip. Work is committed locally,
without pushing or opening a PR, as the common rules' Section D exception
requires.

## 1. Native lanes and the new blocker

The latest twelve-test focused native run completed ten tests successfully:
S3 admission/CORS, binary admission/CORS/CAS-loss, FS-layout/bearer, and
seven exec-helper/e2e tests. Multi initially failed because the fixture
read a fresh, unallocated repository as if it existed; after signing an
owner repository and expecting `not_found` until allocation, its isolated
rerun passed in 1.248 seconds. FS passes all nine admission and both CORS
cases, but its CAS-loss outcome stage times out. Two isolated FS reruns
fail after about 60 seconds with the same redacted diagnostic:

```text
not ok 1 - outcomes.aborted_on_cas_loss
  # outcome delivery deadline: needed 2, saw 1 rows, acknowledged 1
```

Both competing requests finish: one succeeds, the other returns the stored
ref-conflict result. The repository has exactly one winning value. The
missing second terminal delivery is not an assertion about the duplicate
request's status or the earlier held-Admit ruling.

The ignored diagnostic
`timers::outcome_delivery::tests::diagnostic_append_during_ack_strands_an_outcome`
in `mkit-server/src/timers/outcome_delivery.rs` uses the unchanged production
handler and MemoryKv with an injectable clock. It seeds one Committed
outcome, appends an Aborted outcome inside the first sink's `deliver`, and
then lets that first acknowledgment complete. It proves:

```text
First tick: fired = 1; backlog = 1; pending index rows = 1; timer rows = 0.
After advancing time to 1,000,000: fired = 0; backlog remains 1.
Diagnostic: 1 passed, 959 filtered out, 0.04 seconds.
```

Reproduce from `rust/`, with the build environment above:

```sh
cargo test --locked -p mkit-server --all-features \
  diagnostic_append_during_ack_strands_an_outcome -- --ignored --nocapture
```

The diagnostic asserts the observed defect, rather than claiming the
milestone passed. It remains ignored in ordinary gates pending a core fix.

Root cause: `OutcomeDelivery::deliver` reads the initial backlog before
awaiting the sink, then reads a fresh backlog for acknowledgment planning.
Its `delivered == backlog.rows` completion check uses the initial count.
With one original row and one concurrent append, it plans acknowledgment
against fresh count two but returns `Fired::Done`, deleting the timer while
one row remains. The concurrent append sees a nonempty backlog and does
not create another kick timer. A fix must base completion on the guarded
current backlog or preserve a wake for concurrent appends, with regression
coverage for the acknowledgment races. This is a shared handler change,
not a one-line adapter correction; it requires an orchestrator ruling or
a prerequisite fix. No production correction is made here.

The wire case is retained in full behind an explicit Section D skip.
Earlier passing binary/Worker runs show that the race is schedule dependent;
the deterministic diagnostic establishes that it is not merely a slow test.
FS expiry passed historically, but FS backpressure/eventual-completeness
have not completed a final run because the preceding CAS-loss stage fails.
The backlog fixture now exceeds the strictly-greater-than cap before
expecting rejection. FS-layout/bearer explicitly lists unsupported hook
cases under R-165 while exercising its independent CORS case.

## 2. Worker lane and both orchestrator rulings

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

The standalone Worker hook phase, before the new CAS-loss skip, passed:

```text
admission: 9 passed, 0 failed, 0 skipped
cors:      2 passed, 0 failed, 0 skipped
outcomes:  4 passed, 0 failed, 0 skipped
```

This includes Committed/Aborted/Expired ledger behavior, backpressure
recovery and Free-plan eventual completion of nine outcomes, exceeding the
eight-row per-alarm sink budget. These are actual wrangler runs, not mocks.

The full `vcs-worker-conformance.sh --test-faults --hooks` run stopped in
its unchanged M1 phase: 86 passed, two multipart cases returned HTTP 500
`Network connection lost`, and 115 skipped. A second full run passed cold
start (30/30) but was stopped after the new Section D defect was proved.
Neither full run reached its hooks phase. This does not replace the green
standalone M3 evidence or establish a complete Worker gate pass. The main
script's `--hooks` double-shift was corrected; all additive M1 rows remain.

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

The sole remaining Section D skip is the CAS-loss delivery case described
in §1. Strict native/Worker no-skip checks prevent a false M3 exit.

## 5. Release guards

Release guards reject `stubs` and scan for `/__stub/`,
TEST_OUTBOX_BACKLOG_ROWS and TEST_TICKET_TTL_MS, alongside existing markers.
Synthetic guard tests pass. The real native production release build and
artifact feature/marker guard passed (8m 22s; 323 packages; production
native features enc/http/s3/sqlite and core connect/fs/sql/ssh).

The Worker test-faults wasm release build passes. Default Worker wasm,
its compiled-marker check and final configuration tests in both feature
modes remain pending. Earlier RPC hooks wasm and server remote-hooks
wasm checks passed; final wasm32 clippy remains pending.

## 6. Gates and evidence files

Logs live under `$HOME/.cache/mkit-test-tmp/3-12-3-13`; they contain no
expected payment credential or receipt values.

| Check | Latest result/evidence |
|---|---|
| Conformance unit tests | Final 34 passed (0.02 s); escalation-conformance-unit.log |
| Native focused lanes/e2e | Ten passed, Multi fixture failed then isolated pass, FS timed out; native-m3-fixed2.log, multi-final.log |
| FS isolated | Two failures, exactly one of two outcomes delivered; native-fs-isolated.log, native-fs-diagnostic.log |
| Deterministic shared-handler diagnostic | Defect reproduced twice (0.04 / 0.07 s); outcome-race-diagnostic-final.log, outcome-race-diagnostic-confirmed.log |
| Worker standalone M3 | 15/15 passed before the new skip; worker-hooks-continue2.log |
| Full Worker test-faults/hooks | M1 multipart network failures; retry stopped under Section D; worker-full-hooks-final.log, worker-full-hooks-retry.log |
| RPC semver | Passed; semver-rpc-final.log |
| Workspace all-target/all-feature clippy | Passed before diagnostic/skip; workspace-clippy-fixed2.log |
| Final touched-crate clippy | Passed (13.23 s); escalation-final-clippy-fixed2.log |
| ci-scripts / CLI baseline / wasm graph | Passed; ci-scripts-continue2.log |
| ci-security | Passed; ci-security-continue2.log |
| Native production artifact guard | Passed; server-release-guard.log |
| Locked apps metadata / shell / JS syntax | Passed |
| Full just ci | Formatting, clippy, workspace and signer builds passed; nextest interrupted under Section D: 1,685 passed, ten interrupted, 4,272 not run; just-ci-final.log |

No full-gate pass is claimed. Pending: just ci-server; required four-crate
nextest (including CLI); complete workspace/reverse-dependency nextest,
doctests and warnings-as-errors docs; final wasm32 clippy/builds in both
Worker feature modes; default/full Worker phases; and final gate reruns
once the shared handler is fixed. The unrelated historical FS multipart
heap failure passed alone; parent comparison remains pending.

## 7. PRD M3 exit criteria mapped to evidence

| PRD §8 exit bullet | Test/evidence | Status |
|---|---|---|
| Challenge → helper → credential → commit → one distinct Committed outcome delivered at least once | Leg N helper_push_commits_and_sigterm_drains; admission.helper_flow_commit native/Worker | Pass; complete milestone blocked by §1 |
| Aborted work settles nothing | outcomes.aborted_on_cas_loss; unused upload outcomes.expired_ticket | Worker/binary historical pass; FS exposes stranded delivery; not complete |
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
A final publication review/checklist and full gates remain pending.

The diff adds 2,074 handwritten non-test source/build-script/shell/JS lines,
including relocated signer additions conservatively, excluding generated
messages, tests and cfg(test) modules. This remains below the cap.

Carry forward: fix the shared append/acknowledgment race with regression
coverage, remove only that Section D skip/diagnostic ignore, rerun native
FS and all gates, complete both Worker phases and final review, fetch/merge
any moved origin/feat/mkit-server preserving additive M1 changes, then push
and open the authorized bundle PR. Both earlier rulings are complete.
Existing scope carry-forwards remain staging after REL-1 (R-154), the 3.9b
Queue sink, RemoteError sanitization (R-140), platform invocation-log capture
at staging (R-166 B13), and an optional real-mkit-binary script lane.
