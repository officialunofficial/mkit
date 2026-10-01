# WP-5.6a-2 local verification

Activation remains fixed false; the approved WP-5.6a-3 admin catalog and
streaming work is required before launch. ReadPreserved is unexposed.

The measured production count is **3,298 additions / 3,300 cap**, 64 removals,
against `cd680351` (#1246), the merged feature base. Tests, generated Rust,
docs and proto are excluded. The original estimate was 2,333 + 1,050–1,280 = 3,383–3,613;
that estimate triggered the authorized admin split.

## Checks

| Check | Result |
|---|---|
| Rust format | Pass. |
| Workspace/all-targets/all-features clippy, warnings denied | Pass on the final content-header merged tree. |
| Four server packages, all-feature nextest | Full run: 2,739 passed, one failed and two timed out; all three passed isolated retries. Earlier pipeline/relay timeouts also passed isolated retries. No failed assertion was weakened. |
| CLI reverse dependency, all-feature nextest | 1,462 passed before an SSH handshake timeout. All 72 remaining cases, including the timeout, passed; coverage union is 1,534/1,534 selected cases. |
| Affected runtime tests after timer-12 merge | 231/231 passed. |
| Pure-Rust acquisition-bound integration suite | 8/8 passed, including both dense old-resolver reproductions and allocator fixtures. |
| Doc tests and rustdoc with warnings denied | Pass for the five touched/reverse-dependency packages. |
| wasm32 clippy | Core and Worker pass with default and all features, warnings denied. |
| ci-scripts | Pass after timer-12 merge, including goldens, dependency graph, CLI baselines and wasm builds/fixtures. |
| ci-security | Pass (advisories, bans, licenses and sources). |
| Default vcs-worker on owned free ports | Final full run: 80 pass / 4 fail / 131 skip, same Miniflare HTTP 500 category. All four failures pass individually on fresh servers/ports; selected-case coverage union is 84/84. |
| Unchanged-parent baseline checks | At unchanged d89c37fb: SSH, relay, pipeline and native FS pass; D34 redelivery and S3 timer-directive cases fail with HTTP 503 timer RunReport.failed=1. The D34 failure reproduces the full-run failure; all three native cases passed isolated retries on this branch. |
| Content-header merge checks | 358/358 affected HTTP/runtime tests pass after merging cd680351 (#1246), including denial/proof/header paths. Strict workspace and both wasm clippy checks, formatting, doc tests, rustdoc and ci-scripts pass on that tree. |

Full server and CLI suites were run before the timer-12 merge; affected runtime
checks were rerun after it. Subsequent content-header integration checks are
recorded separately. This does not claim that the literal initial ci-server
invocation passed: its untouched pipeline timeout aborted the first run, and
its untouched relay timeout aborted the second. A no-fail-fast complete run
provided full server coverage, and isolated retries resolved its three failures.

## Commands and environment

Every Rust check uses `CARGO_PROFILE_DEV_DEBUG=0`, `CARGO_PROFILE_TEST_DEBUG=0`
and the non-symlink `TMPDIR=$HOME/.cache/mkit-test-tmp/wp-5-6a-2`. Final checks
also use `CARGO_BUILD_JOBS=2`. The owned worktree's `rust/target` is used;
CARGO_TARGET_DIR is never set.

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo nextest run --locked -p mkit-server -p mkit-server-native -p mkit-server-worker -p mkit-server-conformance --all-features --no-fail-fast --test-threads 2
cargo nextest run --locked -p mkit-cli --all-features
cargo test --locked --doc -p mkit-server -p mkit-server-native -p mkit-server-worker -p mkit-server-conformance -p mkit-cli --all-features
RUSTDOCFLAGS='-D warnings' cargo doc --locked --no-deps -p mkit-server -p mkit-server-native -p mkit-server-worker -p mkit-server-conformance -p mkit-cli --all-features
cargo clippy --locked -p mkit-server -p mkit-server-worker --no-deps --target wasm32-unknown-unknown -- -D warnings
cargo clippy --locked -p mkit-server -p mkit-server-worker --all-features --no-deps --target wasm32-unknown-unknown -- -D warnings
cargo nextest run --locked -p mkit-server --no-default-features --features memory,pack-ruzstd,remote-hooks --test takedown_acquisition_bounds --test-threads 1
just ci-server
just ci-scripts
just ci-security
bash scripts/vcs-worker-conformance.sh
```

Worker runs set WRANGLER_SEND_METRICS=false and select a free owned
VCS_CONFORMANCE_PORT. The isolated Worker retry appends
`-- --filter multipart.resume_receipts`. Merged runtime subsets use
`-E 'test(takedown) | test(publication) | test(timer) | test(receipt) | test(admin::)'`;
the final content-header subset also includes `test(http)`.

## Failure and retry evidence

| Untouched case | Full-run failure | Isolated result |
|---|---|---|
| pipeline_d34_multi_namespace_cap_after_rollup | 60.024 s timeout | Pass, 0.098 s. |
| relay::tests::random_relay_schedules_preserve_order_and_healthy_liveness | 60.024 s timeout | Pass, 8.834 s. |
| binary_fs_sqlite_auth_v2 | 60.218 s timeout | Pass, 19.882 s. |
| binary_fs_sqlite_auth_v2_d34 | 104.255 s timer/redelivery failure | Pass, 29.322 s. |
| binary_s3_sqlite_auth_v2 | 60.282 s timeout | Pass, 6.991 s. |
| ssh_root_mode_without_principal_reads_but_cannot_write | 32.282 s SSH hello timeout | Pass, 4.560 s. |

The final full run on the cd680351 merge again hit multipart.three_parts,
multipart.resume_receipts, multipart.root_mismatch_invisible and
refs.many_refs_one_repository with the same Miniflare HTTP 500 category
(80 pass / 4 fail / 131 skip). Each passed alone on a fresh server/free port;
all four isolated script runs exited zero (1 pass / 0 fail each).

The first default Worker run had 79 pass / 5 fail / 131 skip, with Miniflare
HTTP 500 `Network connection lost` in three multipart cases and two ref cases.
The fresh full run had 83 pass / 1 fail / 131 skip: the other four passed;
`multipart.resume_receipts` still hit that HTTP 500. It passed alone on another
fresh server/port (1 pass / 0 fail). No conformance assertion or server setting
was weakened. The unchanged d89c37fb parent also failed with the same
Miniflare HTTP 500 category (82 pass / 2 fail / 131 skip):
refs.many_refs_one_repository and replay.concurrent_duplicates_all_succeed.
The multipart resume case passed on that parent run.

All scratch logs and retained failing Wrangler state are under
`~/.cache/mkit-test-tmp/wp-5-6a-2/`. The relevant logs are
`final-server-no-fail-fast.log`, `final-cli-nextest.log`,
`final-cli-remaining.log`, `merged-runtime-tests.log`,
`final-ruzstd-bounds.log`, `merged-workspace-clippy.log`,
`merged-default-wasm.log`, `final-all-feature-wasm.log`,
`merged-ci-scripts.log`, `final-ci-security.log`,
`final-vcs-worker-default.log`, `merged-vcs-worker-default.log`,
`isolated-worker-resume.log`, `parent-baseline.log`, and
`parent-vcs-worker-default.log`, `content-merged-affected-tests.log`,
`content-merged-workspace-clippy.log`, `content-merged-ci-scripts.log`,
`content-merged-vcs-worker-default.log` and the four
`final-worker-isolated-<case>.log` files.

## Review and limits

Independent correctness/security and spec/conformance reviews found no
confirmed defect in the merged preservation tree. Review fixes include
checkpoint CAS against stale continuations, durable bounded source selection,
manifest ordering/duplicate validation and fresh selected-frame/membership
refusal. Timer 12 retains the shared alarm counter and bounded publication
rechecks. Timer 13 and timer 15 remain behind the fixed activation guard.

The [core contract](WP-5.6a-2-contract.md) records asserted operation counts,
copy/closure geometry and the distinction between historical acquisition
verification and fresh streaming verification required in PR3. The original
96 MiB allowance was superseded by FIX-preservation-memory's 48 MiB scheduled
acquisition bound and latest-base retention. Per-phase allocator fixtures do
not prove whole-Worker RSS; R-203 supplies the bounded corrupt-zstd decoder. External cloud/staging readiness was not run;
preservation storage is user-provisioned.
