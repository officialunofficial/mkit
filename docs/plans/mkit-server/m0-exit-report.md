# M0 exit report (WP-M0-20)

The M0 exit gate of [MKIT-29](https://linear.app/officialunofficial/issue/MKIT-29): PRD §8, "M0 Exit", all four bullets,
run on `feat/mkit-server` at `75fdaa22` plus this WP's changes, on 2026-09-26. The machine was **quiet**: no other executor
or build ran; the only other load came from macOS services, with a load average of about 5 at rest. It is a 10-core Apple M1 Pro on macOS 26.3, with Rust 1.95.0 (`rust/rust-toolchain.toml`), cargo-nextest 0.9.133
and Node 24.13.0. Unless a step says otherwise, every command ran from the repo root with
`CARGO_PROFILE_{DEV,TEST}_DEBUG=0`, a non-symlinked `TMPDIR` and the worktree's own `rust/target`.

**Verdict.** Three of the four PRD §8 M0 exit criteria are met outright: conformance natively and on `wrangler dev`,
the existing CLI e2e tests, and the server-free CLI. The fourth, "nothing changes on the wire", is **met except for the
16 spec-mandated or bug-fix wire changes listed in §4, which require the user's acceptance**. The ssh goldens and the
Connect wire suite pass unchanged, and `buf breaking` is clean. M0 is complete once the user accepts those changes. The
one CI hazard the run found (pre-existing timeouts under the suite's own load, the same on `main`) is fixed by
exact-name nextest overrides (§6). §9 lists the risks for the final PR to `main`.

## 1. Conformance natively: FS + SQLite and S3 + SQLite (PRD §5.1)

```bash
( cd rust && cargo nextest run --locked -p mkit-server-native -p mkit-server-conformance -p mkit-server-worker --all-features \
    -E 'binary(wire_fs_sqlite) | binary(wire_s3_sqlite) | binary(wire_fs_layout_bearer) | binary(wire_binary)
        | binary(baseline_pipeline_memory) | binary(memory_backends) | binary(fs_backends) | binary(sqlite_backends)
        | binary(s3_backends) | (package(mkit-server-worker) & binary(conformance)) | binary(suite_selftest)' )
#   Summary [  80.502s] 456 tests run: 456 passed (2 slow), 0 skipped
```

(The brief's filter used `test(wire_fs_sqlite)`, which matches no test: the tests are named `wire_suite_fs_sqlite_auth_v2`
and so on. `binary(...)` selects them.)

**Wire suite** (black-box, raw Connect, no divergence declared on any target):

| Target | Test | Result |
|---|---|---|
| FS packs + `.mkit`-layout refs, bearer, in-process | `wire_fs_layout_bearer` | pass |
| FS packs + SQLite, auth v2, in-process | `wire_fs_sqlite` | pass |
| S3 (in-repo fake) + SQLite, auth v2, in-process | `wire_s3_sqlite` | pass |
| The spawned `mkit-server` binary: FS layout bearer, FS + SQLite, S3 + SQLite | `wire_binary` (3 tests) | pass |
| The pipeline over memory stores, plus store mutants each case must catch | `baseline_pipeline_memory` | pass |

**Storage-contract suite**, per backend (cases passed; the `dur.*` and `kv.not_after_*` cases are counted separately):

| Backend | Cases | `dur.*` + `kv.not_after_*` |
|---|---|---|
| memory, full capabilities (kv + `MemoryBlobStore`) | 75 | 11 |
| memory, `RefsOnly` single-key (kv) | 59 | 11 |
| FS: `FsLayoutStore` (refs class) + `FsBlobStore` | 75 | 11 |
| SQLite file (`SqlKvStore` over `RusqliteConn`) | 59 | 11 |
| SQLite in-memory | 59 | 11 (crash/restart is its one declared skip: a `:memory:` database cannot be reopened) |
| S3 blobs (`S3BlobStore` against the fake) | 16 | n/a (blob cases) |
| Workers: `DoNamespaceStore` over simulated DO SQLite + `R2BlobStore` | 75 | 11 |
| Workers: R2 answering failed conditions and 429s before reading the body | 16 | n/a |

The 11 are `dur_cancelled_apply_is_all_or_nothing`, `dur_crash_restart_atomic_at_last_commit`,
`dur_export_import_roundtrip`, `dur_import_newer_layout_rejected` and the seven `kv_not_after_*` cases (review 01, R-61).
`wrangler dev` runs Durable Object bindings locally, so placement, Cloudflare's limits and point-in-time recovery are
first exercised by the M1 staging runs (WP-1.20, the orchestrator's local runs against staging during the epic).

**New in this WP:** `refs.non_refs_prefix_rejected` now also lists each rejected name's own parent prefix (`{ns}`,
`heads/{ns}`, `refsx/{ns}`), each of which must list nothing, so a server that stores `{ns}/main` and still answers
`invalid_argument` fails the case. Those listings are bounded by the case itself. A whole-server `ListRefs("")` runs as
well, but only when the profile declares a fresh target (the new `Profile::fresh_target` / `--fresh-target`, set by the
native test harnesses and `scripts/vcs-worker-conformance.sh`, whose servers all start empty). A long-lived server
accumulates refs from earlier runs, and an unpaged listing could outgrow its limits before WP-1.27. A
`resource_exhausted` answer skips that sub-check with a note. The case passes on every target above and on vcs-worker
(§2).

## 2. Conformance against `wrangler dev` (vcs-worker)

`bash scripts/vcs-worker-conformance.sh` (wrangler 4.134.0, local `wrangler dev`, release features):

```text
ok 9 - refs.non_refs_prefix_rejected
...
ok 71 - list.large_response_within_limit # 10000 refs: 450000 bytes in one response
# pass 61 fail 0 skip 10
>> vcs-worker conformance passed          (161 s)
```

The 10 skips are the feature-gated cases this build does not enable (bearer auth; the non-atomic advance profile;
`test-faults`; quota). `bash scripts/vcs-worker-conformance.sh --test-faults` covers the fault and quota cases:

```text
# pass 62 fail 0 skip 9      (phase 1: the whole suite, test-faults build)
# pass 1 fail 0 skip 0       (phase 2: growth.replay_and_quota_pruned)
# pass 4 fail 0 skip 0       (phase 2: quota.*)
>> adapter peak buffered UploadPack/DownloadPack body bytes: 864075 (bound 1048576)
>> vcs-worker conformance passed          (263 s)
```

## 3. Existing CLI e2e tests

```bash
( cd rust && cargo nextest run --locked -p mkit-cli --all-features -E 'binary(ssh_e2e) | binary(ssh_retry_e2e)
    | binary(remote_dispatch_ssh) | binary(remote_dispatch_connect) | binary(serve_containment) | binary(serve_guard)
    | binary(serve_golden) | binary(roundtrip) | binary(push_pull_includes_pack) | binary(fetch_pull_all)' )
#   Summary [   7.675s] 57 tests run: 57 passed, 2 skipped      (the 2 are `#[ignore]`d real-timing tests that the ignored lane runs)
( cd rust && cargo nextest run --locked -p mkit-server-native --all-features -E 'binary(client_e2e)' )
#   Summary [   0.188s] 6 tests run: 6 passed, 0 skipped        (the mkit+http:// client against mkit-server)
( cd rust && cargo nextest run --locked --workspace --all-features --profile ignored-lane --run-ignored ignored-only )
#   Summary [  15.673s] 14 tests run: 14 passed, 4344 skipped  (in `just ci`)
```

## 4. Nothing changes on the wire

- **ssh goldens:** `serve_golden`'s `session_1_is_byte_identical_through_the_binary` and
  `session_2_is_byte_identical_through_the_binary` pass: the two sessions captured from `mkit serve` 0.4.2
  (`rust/tests/golden/ssh-serve/`) replay byte for byte through the ported `mkit serve`.
- **Connect wire suite:** §1 and §2, with no divergence declared on any target.
- **Proto:** `buf lint` and `buf breaking --against '.git#branch=origin/main'` both pass. The proto diff against `main` is
  comments only: `transport.proto`'s header now names `mkit-server` as the implementation (M0-15), and `ssh.proto`'s
  `ListRefs.prefix` comment gives the 512-byte cap (M0-12). No field, type or service changed. (The brief asked for an
  empty diff; these two comment edits are deliberate.)

**Wire changes made during M0.** Each entry of the CHANGELOG's Unreleased section was checked for an observable wire
or protocol effect; the table lists every one found. Each follows a spec or fixes a bug; none is a silent regression.
They need the user's acceptance.

| # | Where | Change | Basis |
|---|---|---|---|
| 1 | every binding (`mkit serve` ssh, `mkit-server`, vcs-worker) | a grammar-valid ref name outside `refs/` is refused (`invalid_argument` / `INVALID_REQUEST`) instead of stored | SPEC-REFS v3 §2, SPEC-TRANSPORT §4.2.1, SPEC-TRANSPORT-CONNECT §5 (R-86) |
| 2 | every binding, and the ssh/enc clients | a ref name or `ListRefs` prefix over 512 bytes is refused (was 4096 on ssh/enc, unbounded on `--http` and the worker); the clients refuse one before sending | SPEC-REFS v2 §3 |
| 3 | ssh and enc clients | a listed ref whose name is over 512 bytes is skipped instead of failing the listing (as the file, memory, s3 and http clients already did) | SPEC-REFS v2 §3 |
| 4 | `mkit-server` (was `mkit serve --http`), vcs-worker | `ListRefs` matches its prefix at a `/` boundary and strips the prefix plus its `/` | SPEC-REFS §4 |
| 5 | `.mkit`-layout `ListRefs` (`mkit serve`, `mkit-server` FS refs) | a legacy ref file that is undecodable, or whose name is over 512 bytes, is skipped with a server-side warning instead of failing the whole listing | SPEC-REFS §3–§4; bug fix |
| 6 | `mkit-server` (was `mkit serve --http`) | `AdvanceRefs` validates both ref names before any write (`--http` wrote the packmap, then rejected an invalid head) | SPEC-TRANSPORT-CONNECT §5 (all-or-nothing validation); bug fix |
| 7 | `mkit serve` (ssh) | a session idle for `--idle-timeout-secs` (default 60) gets `Error{INVALID_REQUEST, "idle timeout"}` and exit 76 | SSH-SECURITY §4, §7 (Q12) |
| 8 | enc listener (moved from `mkit serve --listen-enc` to `mkit-server`) | error replies follow the ssh session: a non-`Hello` first frame, a wrong version, an unserved frame and a parse error each get their specific `Error` reply ("pack chunk read failed" inside an upload, "ref name too long" for a long name), where the old listener closed silently or said "unexpected frame" | SPEC-TRANSPORT §4.2 via SPEC-TRANSPORT-ENC §3 |
| 9 | enc listener | the handshake timeout default is 10 s (was 60 s); `0` for the handshake or idle timeout is refused at startup (idle `0` used to mean "none") | SPEC-TRANSPORT-ENC §2.1 |
| 10 | vcs-worker | nonce reuse for another operation is `invalid_argument` (was an uncaught 500) | SPEC-TRANSPORT-CONNECT §5 error table, §7.1 |
| 11 | vcs-worker | a 33-byte `expected_id` is `invalid_argument` (was `failed_precondition`) | transport.proto: `expected_id` MUST be 32 bytes (naming the code is an open spec-pass item) |
| 12 | vcs-worker | an upload stream past its declared size and past 64 MiB is `invalid_argument` (was `resource_exhausted`) | SPEC-TRANSPORT-CONNECT §5 (`ProtocolError`: declared and received byte counts disagree) |
| 13 | vcs-worker | storage failures are `internal`/`unavailable` (were `invalid_argument` "refstore …"); a missing `AUTH_AUDIENCE`/`AUTH_REPOSITORY` makes every RPC `unavailable` (was writes only) | SPEC-TRANSPORT-CONNECT §5 (`ServerError` → `unavailable`) |
| 14 | vcs-worker | a gzip-compressed unary response is no longer compressed a second time by the runtime | bug fix |
| 15 | vcs-worker, `mkit-server` | `DownloadPack` streams 800 KiB chunks (vcs-worker sent one message); the suite checks contiguity and `last` | SPEC-TRANSPORT-CONNECT streaming (no whole-pack buffering) |
| 16 | pack readers (CLI fetch/clone/pull, `mkit-wasm`'s `verify_closure_packs`) | a `0x03`/`0x04` entry holding concatenated or skippable zstd frames, or trailing bytes, is refused (`PackError::ZstdDecompress`); the C path used to accept it | SPEC-PACKFILE §3.3 |

On #16: in M0 no server parses an uploaded pack (`UploadPack` checks only the declared length and BLAKE3 id, before
and after this branch), so `UploadPack` itself accepts the same packs as before. A pack with such an entry, pushed by a
third-party writer, is now refused by the reading side: a client's fetch, clone or pull. mkit's `PackWriter` never
produced one. (The review note said `UploadPack` rejects these; it does not in M0. Server-side verification comes with
indexed mode, WP-4.7.)

Checked and **not** wire changes: `--max-session-secs` (new, off by default); the upload temp-file sweep; refusing a
root marked for `mkit-server --meta sqlite:` (`mkit serve` exits 78, `FileTransport` ref writes get `MetaElsewhere`),
since the marker is new and no existing root carries it; the operator-side flag moves of WP-M0-15 (the bearer token
from a file or the environment, enc allowlist and key file checks); the storage-contract change that makes a `scan`
cursor from another range `Invalid` (M0's `ListRefs` has no page token on the wire); and `mkit_rpc`'s `MAX_REF_NAME`
constant, which is #2.

## 5. Server-free CLI

```bash
bash scripts/check-cli-baseline.sh
#   check-cli-baseline: OK (no axum/SQLite/mkit-server-native, no server features; mkit-server: ssh, fs)
( cd rust && cargo build --locked -p mkit-cli && cargo build --locked -p mkit-cli --no-default-features )   # both ok
( cd rust && cargo build --release --locked -p mkit-cli --bin mkit --message-format=json-render-diagnostics > "$TMPDIR/mkit-build.jsonl" \
    && bash ../scripts/check-release-artifact-features.sh "$TMPDIR/mkit-build.jsonl" target/release/mkit )
#   check-release-artifact-features: mkit: 239 packages compiled (golden: 286); ...
#   check-release-artifact-features: OK (cli): mkit
```

## 6. Full local CI (`just ci`) on the quiet machine

**Final run: `just ci` exit 0 in 1,102 s** (fmt, clippy, builds, signers, workspace nextest, the `pack-ruzstd` lane, the
ignored lane, fuzz and doc tests, the version contract, the enc build and e2e, `ci-security`, `ci-docs`, `ci-geiger`,
`ci-scripts`, `interop-enc`):

```text
Summary [   1.420s] 57 tests run: 57 passed, 1 skipped                  (contrib/signers)
Summary [ 576.308s] 4332 tests run: 4332 passed (36 slow), 26 skipped  (workspace)
Summary [  68.862s] 1033 tests run: 1033 passed (11 slow), 0 skipped   (mkit-core pack-ruzstd)
Summary [  15.673s] 14 tests run: 14 passed, 4344 skipped              (ignored lane)
stdout:   [mkit 0.4.2] / expected: [mkit 0.4.2]                        (version contract)
advisories ok, bans ok, licenses ok, sources ok                        (cargo deny, both manifests)
geiger baseline OK: mkit-cli mkit-attest mkit-core mkit-rpc mkit-git-bridge mkit-keystore mkit-server
  mkit-transport-file mkit-transport-connect mkit-transport-enc mkit-transport-http mkit-transport-s3 mkit-transport-ssh
check-spec-status / wasm dep-graph / check-cli-baseline: ok
ok: pack-ruzstd decodes every v2 fixture, and pack framing is overflow-free, on wasm32-unknown-unknown
test published_enc_client_talks_to_mkit_server ... ok                  (interop-enc)
```

**The first two `just ci` runs failed, and the cause is a CI hazard for the final PR to `main`.** With nothing else
running, the workspace nextest still timed out tests under their ceilings, because the suite's own parallelism starves
them. Run 1 stopped at the first TIMEOUT. A `--no-fail-fast` rerun of the workspace nextest had 7 TIMEOUTs, and each of
them passed when rerun alone. Run 2, with the first version of the overrides below, timed out `branch_rename_commit_race`
at 300 s. Durations:

| Test | Alone | In the suite, 600 s ceiling (branch) | Same, on `main` `db0b826b` |
|---|---|---|---|
| mkit-cli `branch_rename_commit_race` | 32.7 s | 526 s (TIMEOUT at 150 s, then at 300 s) | 505 s |
| mkit-core `history::ancestry` scrub/full-walk (4 tests) | 20–23 s | 118–122 s | 117–123 s |
| mkit-core `batch_write_hash_equals_store_write_hash` | 8.1 s | 90 s | 89 s |
| mkit-cli packmap `verify_new_object_signatures_mixed_with_unsigned_object_kinds` | 11.5 s | 60 s | 56 s |
| mkit-core `refs::cas_match_race_never_loses_an_update_across_uncoordinated_callers` | — | 62 s | 73 s |

`main` shows the same numbers, so the branch introduced none of this. `main`'s own CI config would kill the same tests.
The fix is in `rust/.config/nextest.toml`, for both the `default` and `ci` profiles:

- `branch_rename_commit_race` runs with no other test beside it (`threads-required = "num-test-threads"`), under its
  existing 150 s ceiling. It calibrates its race delays from one `commit` it times at the start, so a loaded start
  inflates every round. Run exclusively in the final run, it took 39.6 s.
- Twelve tests, each named exactly (`test(=…)`), get a 300 s ceiling: every test that took 40 s or more in a quiet full
  run on the branch or on `main`. They are the seven `history::ancestry` scrub/full-walk tests, `refs::tests::cas_match_race_…`
  and `cas_delete_vs_match_advance_race_…`, `batch_write_hash_equals_store_write_hash`,
  `write_parts_equals_concatenated_write`, and mkit-cli's `verify_new_object_signatures_mixed_with_unsigned_object_kinds`.
  300 s is about 2.4× the worst time measured (123 s). Every other test, including the rest of those modules, keeps its
  existing ceiling (60 s, `ci` 120 s, or its own override), so it keeps hang detection. The final `just ci` run above
  used an earlier, module-wide version of this filter; the exact-name filter selects a subset of it (checked with
  `cargo nextest list`), and each of the twelve took at most 99 s in that run.

## 7. Pack benches (main vs this branch, quiet machine)

`cargo bench -p mkit-benches --bench pack_unpack_fanout --bench closure_verify_fanout`, in four alternating rounds
(main `db0b826b`, then the branch). The harness reports the mean of 10 timed iterations, with no confidence interval, and
`pack_unpack_fanout` writes every object to a fresh store on disk, so it is noisy. During round 3 the load average
climbed to about 30 from macOS services (Spotlight indexing, storage management), and main's round-3 numbers are 2–4×
its others. The table gives the best of the four rounds (ms) and all four rounds per side:

| Bench | main best | branch best | Δ best | main rounds 1–4 | branch rounds 1–4 |
|---|---|---|---|---|---|
| pack_unpack 16 entries | 40.05 | 32.50 | −19 % | 44.1 / 43.0 / 117.9 / 40.1 | 39.9 / 45.0 / 32.5 / 40.3 |
| pack_unpack 64 | 107.6 | 98.6 | −8 % | 107.6 / 114.5 / 366.4 / 133.9 | 109.3 / 120.4 / 98.6 / 100.7 |
| pack_unpack 256 | 311.7 | 298.0 | −4 % | 326.0 / 311.6 / 493.2 / 351.1 | 362.3 / 320.2 / 318.2 / 298.0 |
| pack_unpack 1024 | 589.4 | 607.7 | +3 % | 589.4 / 632.9 / 1777.2 / 709.5 | 716.9 / 607.7 / 610.6 / 692.5 |
| pack_unpack 4096 | 1258.3 | 1232.0 | −2 % | 1258.3 / 1304.3 / 2785.5 / 1797.6 | 1255.7 / 2232.8 / 1296.1 / 1232.0 |
| closure_verify 16 objects | 0.052 | 0.053 | +2 % | 0.124 / 0.079 / 0.052 / 0.060 | 0.065 / 0.059 / 0.061 / 0.053 |
| closure_verify 64 | 0.186 | 0.193 | +4 % | 0.328 / 0.322 / 0.186 / 0.240 | 0.284 / 0.196 / 0.193 / 0.203 |
| closure_verify 256 | 0.743 | 0.724 | −2 % | 0.748 / 0.743 / 0.747 / 0.751 | 0.770 / 0.724 / 1.059 / 0.757 |
| closure_verify 1024 | 2.944 | 3.017 | +2.5 % | 3.010 / 2.944 / 12.918 / 2.960 | 3.117 / 3.017 / 3.145 / 3.074 |
| closure_verify 4096 | 11.77 | 11.83 | +0.5 % | 11.77 / 12.12 / 36.09 / 13.07 | 12.04 / 11.83 / 12.41 / 11.91 |
| closure_verify 16384 | 39.99 | 40.15 | +0.4 % | 39.99 / 40.85 / 90.78 / 42.95 | 40.15 / 40.97 / 41.39 / 41.80 |

**No regression.** `closure_verify_fanout` is within ±4 % at every size, and within ±0.5 % at the sizes large enough to
time reliably. `pack_unpack_fanout`'s best-of-four times are within +3 % / −19 %. Its single-round swings, up to ±75 % on
either side, are disk noise. Both benches use raw entries only, so neither exercises WP-4.2's delta-base seam. A
delta-heavy pack bench remains the open suggestion from 4.2.

## 8. CI wiring (main-only)

- `just ci-server`: the M0 gate in one command (`mkit-server*` nextest, the wasm32 check of `mkit-server` and build of
  `mkit-server-worker`, `check-cli-baseline.sh`). Its local run: `Summary [83.167s] 912 tests run: 912 passed, 6
  skipped`, then both wasm32 steps `Finished`, then `check-cli-baseline: OK`, exit 0 in 122 s. `just ci` already covers every step (the workspace nextest and
  `ci-scripts`, which now also builds `mkit-server-worker` for wasm32), so `ci` does not call it and doesn't run the
  server suites twice.
- `cloudbuild/ci.yaml` gains a `mkit-server` block: `cargo check --locked -p mkit-server` and `cargo build --locked -p
  mkit-server-worker` for wasm32, `check-wasm-dep-graph.sh` and `check-cli-baseline.sh`. The two scripts and the
  `mkit-server` check ran in no CI config before. `mkit-server-worker` was already compiled for wasm32 by `workers.yml`,
  as a dependency of `apps/vcs-worker` (its wasm32 clippy step and the conformance job's `worker-build`), against
  `apps/vcs-worker/Cargo.lock`; the new step builds it against `rust/Cargo.lock` with `--locked`. The Cloud Build
  triggers (`mkit-ci-main`, `mkit-ci-pr`) are on `^main$` only (cloudbuild/README.md), so they first run on the final PR
  to `main`. `workers.yml` (including the `vcs-worker-conformance` job of M0-17) triggers on `main` only.
- `scripts/check-geiger-baseline.sh` now fails closed. It used to discard `cargo geiger`'s stderr and ignore its exit
  status, and it only warned about a missing crate, so a geiger that could not build reported nothing and passed. geiger
  exits 1 on every normal run ("error: Found N warnings"), so the script now requires the report table and the
  `mkit-cli` root row. A missing or unknown first-party crate, or an unreadable count, is an error. A missing
  `cargo-geiger` is an error, unless `MKIT_SKIP_GEIGER=1` skips the check with a visible warning. geiger now builds in
  `<target>/geiger`, so it cannot clobber a concurrent nextest run. The ceilings did not change: every crate is at its
  ceiling (mkit-cli 23, mkit-core 3, the rest 0), `mkit-server` included. Any `error:` line other than the warning
  count fails the check, even when a table was printed. Failure injection fails each case as intended: a failing
  `cargo`, no geiger, a lowered ceiling, an absent expected crate, and a complete in-ceiling report beside a compile
  `error:` line. The control, a complete report with only the warning count, passes.

## 9. Risks for the final PR to `main`

- **Unmeasured on the CI machines.** Cloud Build's `ci.yaml` has a 2400 s timeout on an E2_HIGHCPU_8. The new cold
  wasm32 builds of `mkit-server` and `mkit-server-worker`, and `branch_rename_commit_race` now running alone (about
  40 s here, with the rest of the suite waiting), add time that nobody has measured there. The 300 s ceilings were
  calibrated on a 10-core M1 Pro, and an 8-vCPU Linux runner, or GitHub's macOS runner, may be slower. The first CI run
  of the final PR is where these numbers get checked.

## 10. Open follow-ups (not M0 blockers)

Carried to later WPs or to the user; the orchestrator notes have the detail.

- **WP-REL:** wire `wasm-ruzstd-check.sh` (needs wasm-pack 0.13.1), the `pack-ruzstd` nextest lane and `just
  interop-enc` into the CI configs; add `mkit-server` to the crates-publish semver-checks list; the 0.5.0 breaking
  release of the lockstep crates (`mkit-transport-connect` lost its `server` feature; `mkit-cli` lost `http-transport`);
  publish `mkit-server` (`mkit-cli` depends on it); `release-smoke.sh` for the server archives and the container image.
- **M1:** `ListRefs` paging (WP-1.27; a unary listing over about 25k refs exceeds 1 MiB); S3 multipart and the S3
  follow-ups (#1090, WP-1.13); staging runs for placement, limits and PITR (WP-1.20).
- **M2:** grants for enc peers (TransportIdentity principals bypass HTTP auth); M0's auth v2 with the default hooks lets
  any signer write any ref, and per-signer quota can be bypassed by minting keys.
- **Operations:** `mkit-server-native` does not sweep legacy ref files or crashed upload temp files yet; a header-read
  timeout against slow-header clients; a separate WAL read connection.
- **For the user:** GLIBC floor of the published Linux CLI (2.39) and server (2.38); the release job's `id-token`
  supply-chain exposure; the pre-existing `PackReader` delta-memory OOM on `main`; Workers Paid confirmation for
  `WORKERS_PLAN=paid`; the container `latest` tag (Q9); STS/IAM support for the S3 store; a CLI warning when fetch
  skips over-long remote ref names; the enc listener's `/tmp` panic; the demo repo-worker's connectrpc 0.9.0.
