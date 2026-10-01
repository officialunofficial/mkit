# M3 exit report (WP-3.7b, WP-3.12, WP-3.13)

Historical evidence from merged base `d9ff5f96` (including WP-1.27, WP-4.13/4.15,
WP-4.16 and the R-185 launch plan), on 2026-09-29–30. Machine: macOS aarch64, Rust 1.95.0. Builds used
`CARGO_PROFILE_DEV_DEBUG=0`, `CARGO_PROFILE_TEST_DEBUG=0`, this worktree's
own target directory, and `$HOME/.cache/mkit-test-tmp/3-12-3-13` as a
nonsymlinked TMPDIR. Other executors were active. Worker runs used
`VCS_CONFORMANCE_PORT=8931`. No staging, deploy, fault proxy, proto or golden
change occurred. Spec edits and the core timer correction are explicitly
authorized by the three continuation rulings.

**Verdict: both adapters prove the M3 exit behavior.** All three Section D
escalations are resolved. The kind-8 correction is a separate commit, and
all 15 M3 wire cases run without Section D skips. Native helper e2e and
Worker admission, CORS, outcomes and Free-plan eventual delivery pass.
The verification table below distinguishes complete runs, isolated reruns
and unchanged-parent comparisons. Full just ci passes before the final WP-4.16/R-185 merge;
Worker M1 network-loss failures are recorded with isolated and parent evidence.
After the final adapter merge, strict workspace clippy/docs and the
complete 15-case Worker M3 phase pass; the server gate and wasm checks repeat.
Latest-base `45616828` verification in §6 passes all affected gates and
both complete Worker scripts without reruns.

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

The complete serial native/server gate after the correction passes 2,227
tests, including all 15 FS M3 cases, binary admission/CORS/CAS-loss and
nine-outcome completion, Multi admission, S3 admission/CORS and all seven
native admission e2e tests. The hook-down e2e exercises normal retry timing;
the successful push uses a real binary and actual SIGTERM drain.

Final review replaced broad admission/outcomes/CORS skip prefixes with an
explicit 15-case M3 allowlist, made FS-layout/bearer check every unsupported
M3 case, and added nine-outcome eventual completion to the binary lane.
That case uses production defaults and does not require the backlog-cap
knob. Its unnecessary capability requirement was removed; the binary
rerun and the complete serial server gate pass. FS/S3 retain additive M1
allowlists, and the moved-base merge preserves the new ticket, lease and
lag cases. Multi signs its owner repository and expects not_found until
allocation. The backlog fixture exceeds the strictly-greater-than cap
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

The separate default Worker phase passes after isolated reruns: 82 passed,
zero failed, 121 skipped; cold start is 30/30. An earlier run failed the
unchanged multipart.three_parts and refs.concurrent_missing_one_winner
cases with Miniflare network loss and coordinator contention. Both pass
alone. The unchanged parent reproduces multipart network loss in two
cases and passes the ref race. This is recorded as transient baseline
behavior, not hidden by changing assertions. The main script's --hooks
double-shift was corrected. Merged-base Worker results are recorded in §6.

## 3. Public hooks and admission end to end

WP-3.7b publishes JSON-enabled hooks.v1 types, HookSigner and HookVerifier
under `mkit_rpc::hooks`, with server re-exports. Public-only integration
tests decode all request goldens, build all response goldens and verify
every signature vector. Public integration tests, all-feature doctests, generation freshness and
wasm dependency/build checks pass. `cargo-semver-checks` 0.50.0
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
in the complete four-crate run before its unrelated S3 timer failure.
The CLI helper trust/filter integration test also passed in that run.

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
in §1 pass the complete serial server gate.

## 5. Release guards

Release guards reject stubs and scan for /__stub/,
TEST_OUTBOX_BACKLOG_ROWS and TEST_TICKET_TTL_MS alongside existing markers.
Synthetic guard tests pass. Actual native release builds and feature/marker
guards pass for both the pinned minimal production features and the same
feature set with hooks enabled. The latter exposes --hook-admit-url.
Both builds compile 323 packages and exclude test-only surfaces.

The current release feature pin still lists enc/http/s3/sqlite and omits
hooks. REL-1 must include hooks when enabling the shipping payment server.
Changing release configuration is outside this bundle's fixed scope; this
is a release activation carry-forward, not absent hook implementation.

Both Worker wasm release builds pass, with and without test-faults.
The actual default build/index_bg.wasm contains none of the three test
markers. Root default-feature release_never_reads_m3_test_vars passes;
the test-faults suite tests bounds/injection and preserves WP-1.27's
ticket-lifetime test. The shared test-only TTL parser remains positive,
trimmed and capped at 60,000 ms; both runners use shorter lifetimes.
RPC hooks, server remote-hooks, and Worker default/test-faults strict
wasm32 clippy pass; RPC hooks and Worker test-faults builds also pass.
The app host/wasm clippy, formatting and host library tests pass.

## 6. Gates and evidence files

Logs live under `$HOME/.cache/mkit-test-tmp/3-12-3-13`; they contain no
expected payment credential or receipt values.

| Check | Latest result/evidence |
|---|---|
| Core kind-8 regression | Old handler fails; all 13 corrected outcome tests pass; kind8-regression-red.log, kind8-final.log |
| Complete serial just ci-server | Passed: 2,227 passed, seven skipped; wasm/core/Worker/CLI-baseline checks pass; ci-server-kind8-serial.log |
| Four-crate nextest | Passed: 2,734 passed, 16 skipped, no retries (CI profile, four threads); four-crate-kind8-ci-final.log |
| Full just ci | Before final adapter/plan merge, passed with repository default profile/four threads: signers 57, workspace 6,021, pure-Rust decoder 1,108 and ignored-lane 16; fuzz/doctests/version/enc/security/docs/geiger/scripts/interop pass; just-ci-merged-default-final.log |
| Full merged-tree server gate | Passed: 2,258 passed, eight skipped; wasm checks and CLI baseline pass; ci-server-merged-final.log |
| Full Worker test-faults/hooks | All 15 M3 cases pass without skips; worker-full-kind8.log; Merged full script stops on 11 inherited M1 network-loss failures; all 15 M3 cases pass separately without skips; worker-full-merged-final.log, worker-hooks-final-base.log |
| Default Worker | 82 passed, zero failed, 121 skipped, cold-start 30/30; worker-default-kind8-restored.log; Merged build/cold-start pass; 80 passed, four inherited Miniflare network-loss failures, 130 skips; all four pass alone; worker-default-merged-final.log, worker-default-merged-isolated.log, worker-default-three-parts-isolated.log |
| Workspace strict all-target/all-feature clippy | Passed; clippy-final-base.log |
| All-feature workspace doctests / warnings-as-errors docs | Passed; doctests-merged-final.log; warnings-as-errors docs pass again after final merge; docs-final-base.log |
| Root strict wasm32 clippy/builds | Passed for RPC hooks, server remote-hooks, Worker default and test-faults; wasm-final-base.log; actual builds in wasm-clippy-build-kind8.log and merged ci-scripts |
| RPC semver | 196 checks pass, 58 skip against merged b0bbbba2; semver-rpc-kind8.log |
| Generation freshness | Passed; generated-fresh-merged-final.log |
| All apps and new HTTP probe locked metadata | Passed, including refreshed published-view-probe lock; metadata-final-base.log, http-probe-metadata-final.log |
| Actual native release guards | Minimal and hook-enabled builds pass; server-release-kind8-guard.log, server-release-hooks-merged-guard.log |
| Default Worker compiled-marker scan / default config test | No new markers; config test passes; worker-release-vars-merged-final.log |
| Worker app host/wasm clippy, fmt and tests | Passed; worker-app-host-wasm.log |
| Final formatting / syntax / diff check | Passed: cargo fmt, shell/JS syntax and git diff --check |
| ci-scripts / ci-security | Passed on merged tree; ci-security-merged-final.log, ci-scripts-merged-final.log |

Initial parallel native D34 timer-redelivery failures pass alone on this
branch and on the unchanged parent. A later serial four-crate run stops
at 2,443 passes on the S3 binary lane's unchanged timer-redelivery case:
ListRefs returns 503 with a test timer tick reporting failed=1. The
S3 lane passes alone in 5.073 seconds on this branch, and the unchanged
parent reproduces the same failure in 10.017 seconds. Logs:
native-s3-timer-isolated-kind8.log and parent-native-s3-timer-kind8.log.
The historical FS multipart heap case passes alone on this branch and
on the parent (1.398 seconds); parent-fs-heap-kind8.log. Worker baseline
reruns and parent reproduction are described in §2. The merged full Worker script later reports 11 inherited M1 cases with
the same Miniflare network-loss response (82 passed, 11 failed, 121 skipped).
Every affected case passes individually against a fresh instance with
the original 1,000-ref setting, concurrency and assertions:
worker-baseline-merged-isolated.log. The separate merged M3 hooks phase
passes all 15 cases without skips. The unchanged merged parent bf27f6fc reproduces network loss in multipart.three_parts and tickets.expiry_timer_frees_cap_slot; its other nine isolated cases pass (worker-parent-merged-isolated.log).
No assertion,
pipeline or CI configuration was weakened. The complete serial server
gate passes without retries; subsequent complete runs use the existing
CI profile and record any retries rather than concealing them.

### Final latest-base integration (2026-09-30)

Base `45616828` (WP-4.8) is merged at `6599393d`. The two additive
conflicts retain `IndexedAsync` alongside all M3 capabilities, and retain
both `--indexed` and `--hooks` runner phases. Source was clean during these
runs. Fresh evidence is under `$HOME/.cache/mkit-test-tmp/wp-3-12-3-13`,
with a nonsymlinked TMPDIR and the same debug-profile settings. Worker
hooks used port 8931; the serialized default run uses 8933.

| Integration check | Result and log |
|---|---|
| Complete `just ci-server` | 2,340 passed, 8 declared skips, no retries; wasm checks and CLI baseline pass; ci-server-integration.log |
| RPC and CLI all-feature nextest | 1,559 passed, 9 declared skips, no retries, including public hooks goldens/signatures and helper tests; rpc-cli-integration.log |
| Strict workspace all-target/all-feature Clippy | Pass; clippy-integration.log |
| Formatting, all-feature touched-crate doctests and warning-strict docs | Pass; docs-wasm-integration.log |
| Strict wasm32 Clippy | RPC hooks, server remote-hooks, Worker default/test-faults pass; docs-wasm-integration.log |
| `just ci-scripts` / `just ci-security` | Pass; scripts-security-integration.log |
| Six app/probe lockfiles | Locked offline metadata passes; metadata-integration.log |
| Default Worker configuration regression | release_never_reads_m3_test_vars passes; release-config-integration.log |
| Full Worker `--test-faults --hooks` | M1 93/0/122; growth 2/0/0; quotas 4/0/1; all 15 M3 cases pass with no skips; worker-integration.log |
| Default Worker / production artifact | 84 passed, zero failures, 131 declared skips; cold-start 30/30; all three M3 markers absent from default wasm; worker-default-integration.log |

The full Worker run also passes both 30-request cold-start probes and the
planted relay. Peak upload/download buffering is 863,989 bytes, below
1,048,576. The quota skip remains the undeclared multi-namespace capability.
No isolated reruns or baseline comparisons were needed for these latest
integration runs. The earlier full `just ci` remains historical evidence;
it was not rerun on base `45616828`. The fresh affected gates above cover
the integrated server, RPC, CLI, wasm, scripts/security and real Worker
surfaces. No staging or deployment was run.

## 7. PRD M3 exit criteria mapped to evidence

| PRD §8 exit bullet | Test/evidence | Status |
|---|---|---|
| Challenge → helper → credential → commit → one distinct Committed outcome delivered at least once | Leg N helper_push_commits_and_sigterm_drains; admission.helper_flow_commit native/Worker | Pass: native e2e and both adapter helper-flow cases |
| Aborted work settles nothing | outcomes.aborted_on_cas_loss; unused upload outcomes.expired_ticket | Pass: FS/Worker Aborted and Expired; binary CAS-loss |
| Lost-response retry returns saved result without another challenge | admission.replay_skips_admission; client credential-retention ladder | Pass: both adapter wire cases and CLI retry ladder |
| Simulated old client fails fast | no_helper_fails_after_one_attempt | Native e2e passes |
| Hard-reserved headers cannot be set through config | reserved_helper_header_is_named_without_retry; client filtering tests | Pass: native e2e and CLI filtering tests |

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
Two local review passes are recorded below. Two independent read-only reviews
at `6599393d` additionally found no actionable correctness/security or
spec/brief/crypto findings. The final status-table audit corrected stale
planned labels for merged WP-3.1–3.11 using their merged PR references. Their last fixture edits pass the
complete serial server gate; merged-tree runs are recorded in §6.

The diff adds 2,075 handwritten non-test source/build-script/shell/JS lines,
including relocated signer additions conservatively, excluding generated
messages, tests and cfg(test) modules. This remains below the cap.

The correctness/security pass checked credential binding and single use,
raw-body signature verification, loopback/unsigned controls, bounded
reads, redaction, storage guards and kind-8 completion/retry paths. The
conformance pass checked each brief item, the three rulings, all 15 case
names, lane capabilities and release gating. It found broad skip prefixes
that could hide future cases and absent binary eventual-completion
coverage; both are corrected and tested. No further core
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
| B0.6 | RPC semver passes against merged base; wasm graph/build/clippy pass |
| B0.7 | Registry 3.7b, Stage 1/M3/deps 3.7 and 3.8; R-174/authentication re-exports |
| B0.8 | MPP uses public RPC types and shared verifier |
| B1 | stubs/mpp.rs, loopback controls and stub-hook command |
| B2 | Actual native binary and trusted Config/public CLI transport entry with POSIX sh helper |
| B3 | wrangler.hooks.jsonc and unsigned JS raw-byte forwarder to Rust fixture |
| B4 | Fifteen cases, HookStub/backlog/ShortTickets profile; native in-process knobs and Worker test-faults vars |
| B5 | Native lane matrix/explicit allowlists; full Worker --hooks pass; nine-outcome Free case; last native edits pass the full serial server gate |
| B6 | Guard rejects stubs/markers; actual default wasm marker scan pass; both feature-mode unit tests and native artifact rebuilds pass |
| B7 | Report and PRD mapping, README and registry; both adapter behavior demonstrated; §6 records full gates |
| B8 | R-172/R-173 and separate CHANGELOG lines for all three WPs |

Base 45616828 is merged, including WP-1.27, paid/private HTTP reads,
the WP-4.16 adapter mounts, WP-4.8 scheduled verification and R-185. This local M3 exit is distinct
from the new single launch gate; the brief still authorizes no staging.
Both sides of adjacent CHANGELOG, wire-table, configuration, registry
and runner changes are retained. The six Worker/probe lockfiles pass
locked metadata after refreshing the new HTTP mount probe offline. All three resolved escalations are implemented;
none is a scope carry-forward.

Scope carry-forwards: real staging delegated to 1.19/1.20 as a pre-launch
gate under R-185 (none in this bundle), enabling hooks in the
REL-1 native release feature pin, Queue sink 3.9b, RemoteError sanitization
(R-140), platform invocation-log capture at staging (R-166 B13), and an
optional actual-mkit-process helper lane. There is no staging evidence.
