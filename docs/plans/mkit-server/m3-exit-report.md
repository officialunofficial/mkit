# M3 exit report (WP-3.7b, WP-3.12, WP-3.13; incomplete)

Evidence from `85c4adf3` plus this bundle's local commits, on 2026-09-29,
macOS aarch64, Rust 1.95.0. Builds used `CARGO_PROFILE_DEV_DEBUG=0`,
`CARGO_PROFILE_TEST_DEBUG=0` and `$HOME/.cache/mkit-test-tmp/3-12-3-13`
as `TMPDIR`, with the worktree's own target directory. Other executors
were active on the shared machine.

**Verdict: M3 is blocked, not complete.** The required held-admission
case reproduces behavior contrary to the accepted brief. Section D
requires escalation because the correction belongs in the shared
pipeline, beyond a one-line adapter fix. Work is committed locally;
there is no push or PR. No pipeline, spec, proto, golden, or CI workflow
was changed to resolve the gap. No staging was used (R-154).

## 1. Implemented work

WP-3.7b moves JSON-enabled hooks.v1 types, HookSigner and HookVerifier to
`mkit-rpc/hooks`, preserving server re-exports and generated freshness.
Public-only acceptance tests cover every request and response golden and
signature vector. Generated Debug can expose credentials; the public
module and AdmitRequest document that prominently. Buffa's redaction
requires a proto option, prohibited by this brief, so server wrappers
retain their existing redaction.

WP-3.12 adds the test-only Rust MPP fixture, loopback controls and gated
`stub-hook` command, server-side HMAC binding, single-use credentials,
redacted outcome ledger, unsigned binding mode and JS forwarder. Leg N
uses the existing public `remote_dispatch::open_trusted` Config entry;
no CLI re-export was needed. Its POSIX helper and the real server binary
exercise commit and SIGTERM drain, no helper, hard-reserved headers,
second challenge and hook failure. The shared FS/SQLite commit case passes.

WP-3.13 has a held-admission diagnostic and explicit known-gap skip.
Remaining conformance and Worker work is not complete.

## 2. Section D escalation: duplicate during held Admit

The fixture's `hold` mode blocks a credentialed Admit's Allow response.
After an initial 402, the test sends the credentialed request, waits for
that Admit call, then resends the exact same signed body and headers.
It releases the gate and awaits the first response before asserting.
The original request succeeds; the duplicate produces:

```text
not ok 1 - admission.in_flight_aborted
  # held admission duplicate: HTTP 403, code "permission_denied", paid Admit calls 2; expected aborted and 1 paid Admit
# pass 0 fail 1 skip 0
```

Reproduced twice on FS/SQLite through the production native router and
hook configuration: 0.16 s and 0.44 s. No test fault was injected into
the pipeline. Reproduction command from `rust/` (prepend the environment
above):

```bash
cargo test --locked -p mkit-server-native --all-features --test wire_fs_sqlite \
  wire_held_admission_duplicate_fs_sqlite -- --exact --ignored --nocapture
```

The registered case now explicitly skips this exact observed divergence
with a Section D reason. The ignored diagnostic forbids skips, so it
remains red until the behavior meets the expected assertion. Other
unexpected results still fail. The diagnostic never reports success
for the observed 403.

`Pipeline::write_inner` reads the replay record before admission, then
calls `admit`, then records the pending reservation and applies the
write. While Admit is held, the duplicate has no replay entry and also
reaches admission. Its already-spent credential is denied by the stub.
Both adapters share this ordering; changing the HTTP status alone would
leave the duplicate hook call and spent-credential problem intact.

There is a design tension to resolve: STC §7.1 explicitly reserves the
replay record **after** admission and commits unary reserve/apply/result
together, while the accepted research §2 requires `aborted` and one Admit
when the hook itself is held. An orchestrator ruling or a separate
pipeline correction is needed; this bundle must not silently change
that ordering or reinterpret the required case.

## 3. Passing checks

- RPC hooks public acceptance, existing RPC tests and doctests.
- Server remote-hooks tests and doctests, including signature/golden coverage.
- Focused RPC/server clippy with all features and targets.
- RPC hooks wasm32 build, hook regeneration, and wasm dependency graph.
- Part 1 conformance/native clippy with all features and targets.
- Native admission e2e: 6 tests passed, 33.84 s.
- Native FS/SQLite: helper commit and baseline wire suite passed, 3.21 s.
- Conformance unit/stub tests: 30 tests passed; release guard passed earlier.
- JS forwarder syntax check, Rust formatting and diff whitespace checks.
- Final focused nextest: 39 passed, one ignored escalation diagnostic,
  35.240 s; final conformance/native all-feature, all-target clippy passed.

```bash
cargo nextest run --locked -p mkit-server-conformance -p mkit-server-native --all-features \
  -E 'binary(admission_e2e) | binary(wire_fs_sqlite) | binary(release_guard) | (package(mkit-server-conformance) & kind(lib))'
# Summary [35.240s] 39 tests run: 39 passed, 1 skipped
```

## 4. Broader test run limitation

`cargo test -p mkit-server-conformance --all-features` passed its initial
unit and baseline stages, then stopped in `fs_backends` with 107 passed
and one failure: `fs_multipart::multipart_bounded_heap` measured
8,834,063 completion bytes against 2,097,152. The isolated rerun passed
in 1.71 s. This is separate from the deterministic admission gap.
Parent comparison and the remaining full suite are pending; no full
conformance gate pass is claimed.

## 5. Pending gates and work

No completed M3 exit, semver, full workspace lint/nextest, common gate
set, `ci-server`, `ci-scripts`, `ci-security`, native reverse-dependency
suite, Worker wasm builds with/without test-faults, or Worker conformance
phase is claimed. `cargo semver-checks` is not installed on this machine.

Carry forward Leg W validation; the `--hooks` runner phase; the remaining
admission/CORS/replay/outcome/backpressure cases; native S3 and multi-repo
lanes; Worker test-only backlog/TTL vars and their compiled-out test;
short-ticket expiry and at least nine Free-plan outcomes; actual release
artifact marker scans; full exit evidence and final reviews. The old
`vcs-worker-hooks.sh` script must be adapted to the Rust fixture and new
forwarder before running it; its former JS control endpoints were removed.

## 6. Executor decisions and local review

- Extend FakeHook with optional behavior and a semaphore gate; keep its
  existing signed recorder and scripted replies.
- Use `/__stub/{mode,calls,outcomes,release}` on numeric loopback only;
  expose counts and redacted outcome digests, never credentials.
- Use a length-delimited protobuf HMAC fingerprint to avoid ambiguous
  concatenation; include exactly the accepted binding inputs and expiry.
- The isolated Worker binding forwards raw protocol bytes with redirect
  refusal and a timeout to `STUB_UPSTREAM`; Rust owns MPP semantics.
- Runner spellings are `--hook-stub`, `--backlog-cap`, and `stub-hook`.
- Review corrected Debug on fixture replies to expose body length only,
  tightened the native leak assertion to distinguish public Payment
  challenges from credentials, and retained the normal transport retry
  ladder for hook-down failures. No two-pass final PR review is claimed.

The diff adds approximately 1,200 non-test code/script lines (excluding
relocated/generated files and test modules), below the production cap.
Registry rows stay additive and the incomplete state is recorded here
and in the README. Existing M1 TODO rows are retained.

## 7. PRD M3 exit criteria mapped to evidence

| PRD §8 exit bullet | Test/evidence | Status |
|---|---|---|
| Challenge → helper → credential → commit → one distinct Committed outcome, delivered at least once | `helper_push_commits_and_sigterm_drains`, `wire_helper_flow_commit_fs_sqlite`; Worker counterpart pending | Native passes; both-adapter exit pending |
| Aborted work settles nothing | Admitted UpdateRef CAS-loss case and unused-ticket Expired case per accepted override | Not implemented |
| Lost-response retry returns saved result without a new challenge | `admission.replay_skips_admission` pending; held-admission duplicate exposes separate gap (§2) | Not proven |
| Simulated old client fails fast | `no_helper_fails_after_one_attempt` | Native passes |
| Hard-reserved headers cannot be set through config | `reserved_helper_header_is_named_without_retry` | Native passes |
