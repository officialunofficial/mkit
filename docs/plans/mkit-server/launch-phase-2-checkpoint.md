# WP-4.18 phase 2 implementation checkpoint

## October 1 continuation

The branch incorporates #1254 extra native CA trust at
`b90f74a3725467c827b554e8ac20c4d0a29bee90` and #1255 inherited fixture/timer
repair at `acd179233aad12d841e2ea09938ab31ec0e4b1b9`. The four previously
reported deterministic timer failures now pass together, with 865 unrelated
tests skipped. No timer exemption is used.

D-N2-010 applies the existing dedicated-role requirements in SPEC-SERVER
§§7.1, 14.7 and 16.3 and SPEC-HTTP-OBJECTS §3.1. Reproduction sets ticket MAC
material to the public bytes of an otherwise distinct active/retired URL key,
or to configured admin/hook public bytes. The prior derived-public-only test
accepted that exposed MAC material. The common predicate now rejects both raw
secret/public equality and derived-public equality. Worker/native startup also
reject token, hook and receipt seeds published under another configured role;
runtime embedding checks revalidate the final programmatic configuration
against zeroized environment hook/receipt secrets. Default-off profiles and
distinct active/retained role keys remain accepted. No key type or wire format
is introduced. Mounted HTTP startup errors pass through the existing
no-store/CORS/HEAD response wrapper.

Focused checks on this continuation source: Worker library 179/179 PASS,
native launch profile 9/9 PASS, the four timer regressions 4/4 PASS, and host
clippy for core/native/Worker all-targets/all-features with warnings denied
PASS. These are component checks on the dirty implementation before its
checkpoint; final integrated gates must use the eventual immutable candidate.
The source currently has a conservative 3,154 added Rust line upper bound
against the merged base after excluding explicit test files. It includes inline
tests and the conformance harness, and is below the 3,500 production-line cap.

| Owned `night2/` log | SHA-256 |
|---|---|
| `key-material-red.log` | `1d3a155149ae3edb24ca250aecf9e88a019ea9139ee12f9ff3569c59da06add3` |
| `token-seed-material-red.log` | `0d7356a945f5b23619665dadea9c6d89898a7060ec4e0d6812bc69de76a8475f` |
| `worker-role-final-targeted-2.log` | `ebada47cc5d700d7ae540adaaf6c23175139c7a13a4ffcb3a6e8e64f9abd2e52` |
| `native-role-final-targeted.log` | `0dc416a64b0999c1f51c3558a87ccfea60ce0c43937f81618fe4c5db8e08267f` |
| `four-timers-1255-2.log` | `daa3142d631a039b1f1f90bd0afe810bf2d280c96be017a395b9e9f0194b9160` |
| `role-clippy-4.log` | `55d3bfd067aaf7d2de3fd81a9e026aa6afc318bf45bacb503b124077d00349cc` |

The decoder-enabled five-variant size runner and independently signed
seven-operation release admin/preservation probe are implemented. Their
runtime result remains UNRUN until execution; the full 28-case matrix remains
UNRUN. Fix A/B/decoder merge notifications are still prerequisites to final
integrated gates and PR. D-N2-012 and D16 require activation wiring to charge
immediate local invalidation against the same physical alarm purse and to
register/drain existing audit relay kind 1 on ContentIndexShard. Automatic
purge source work belongs to Fix A. The `many_refs` Medium diagnosis remains
part of matrix diagnosis and is not waived.

Status: **implementation checkpoint; sandbox access restored;
complete launch matrix UNRUN; no PR opened**. This is a retained work record,
not a passing gate or permission waiver.

Embedding implementation commit: `62e87a56e16c5c7cadc1162cfed0fb0b0554198e`
(committed and pushed). The preceding base merge is
`7a2d1bf039e0853fb53d5e8e78d4d449782196ca`.
It merges `origin/feat/mkit-server` with physical timer-alarm repair #1247 at
`e45def2fe1855a531d0149727bf6678fc8145c3c` and native timer-conformance repair
#1248 at `12e4ce4998145a959c4fc400e02b6ad546812090`.
No old native timer flake exception applies. The completed native timer
integration and wire rerun passed all 22 tests.

## Implemented in the worktree

- Combined `NsObjectBuilder` configuration, published snapshots, custom
  Outcome factory and actual `PurgeSink`/`LocalInvalidation` registration.
  Verification uses the same explicit configuration and blob binding.
- Programmatic ref-policy validation, takedown denial, custom-purge parsing
  before startup validation, host-only admin placement and authenticated
  `serve_admin_with`. Custom purge delivery requires Paid alarm capacity.
- `durable_objects!` exports all five classes with a scoped workers-rs
  wasm-bindgen import. The reference Worker and embedded example use it.
- Streamed in-process example with custom service-binding hooks, a local
  release Wrangler probe, its lockfile and explicit wasm CI check.
- Supported 0.x embedding documentation, reserved prefixes, audience/resource
  contracts, #1246 ref-file headers and updated timer prerequisite records.
  The size table remains unmeasured. The current platform limit is linked
  to official Cloudflare documentation; gzip is informational.

Preservation core and the configured 5.6a-3 admin catalog are wired. Complete preservation/admin/takedown
integration, the integrated native/release runtime matrix, measured wasm/bundle
sizes, final full gates and two independent final reviews remain required.

## Checks at the dirty source checkpoint (2026-09-30)

All Cargo invocations use debug level zero, the worktree's own target and
`TMPDIR=$HOME/.cache/mkit-test-tmp/wp-4-18`, as mandated by the executor rules.
`ulimit -n 4096` applies to compilation commands. These are targeted checks,
not the final workspace gates.

| Directory | Exact command | Result |
|---|---|---|
| `rust/` | `cargo fmt --all --check` | PASS |
| `rust/` | `cargo clippy --locked --offline -p mkit-server-worker -p mkit-server --all-targets --all-features --no-deps -- -D warnings` | PASS; includes compilation of new host regression tests |
| `rust/` | `cargo clippy --locked --offline -p mkit-server-worker --features http-objects,published-view,signed-http-hooks --no-deps --target wasm32-unknown-unknown -- -D warnings` | PASS |
| `apps/vcs-worker/` | `cargo clippy --locked --offline --target wasm32-unknown-unknown --features launch -- -D warnings` | PASS; generated DO classes expand across crates |
| `apps/embedded-worker/` | `cargo metadata --offline --format-version 1` | PASS; generated dedicated lockfile |
| `apps/embedded-worker/` | `cargo fmt --check` | PASS |
| `apps/embedded-worker/` | `cargo clippy --locked --offline --target wasm32-unknown-unknown -- -D warnings` | PASS; custom factory macro expansion |
| Repository | `git diff --check` | PASS |
| Repository | `python3 scripts/vcs-worker-launch.py validate` | PASS; 24-case inventory after the R-203 addition, no runtime PASS implied |
| Repository | `bash -n scripts/embedded-worker-conformance.sh` | PASS |
| Repository | Python AST parse of `scripts/embedded-worker-conformance.py` | PASS |
| Repository | `node --check apps/embedded-worker/tests/hook/worker.mjs` | PASS |

The new owned Rust diff has a conservative upper bound of 2,065 added tracked
Rust lines including tests, plus the small new embedded app. This is below the
3,500 non-test production-line cap; finalize the exact production count at
the final candidate.

## Historical blocked execution, without flake classification

The requested focused rerun was attempted from `rust/`:

```sh
cargo nextest run --locked --offline \
  -p mkit-server -p mkit-server-native -p mkit-server-worker \
  --all-features --lib \
  -E 'test(timers::) | test(alarm::) | test(publication_recheck) | test(timer_window)' \
  --test-threads 1
```

It exited 101 while linking core/native/Worker test binaries. No tests ran.
The linker reported `clang: error: unable to make temporary file: Operation
not permitted`. A separate release-feature embedding test attempt also exited
101 with the same linker denial. No timer assertion failure was observed and
no failure is classified as a flake. Native timer integration and wire timer
checks still require execution, followed by actual release Worker alarm checks.

The sandbox also denied Git staging with:

```text
fatal: Unable to create '.../mkit/.git/worktrees/wp-4-18/index.lock': Operation not permitted
```

This denial was resolved when unrestricted access was restored. The retained
embedding implementation was subsequently committed and pushed; mandated
scratch logs can now be written. The historical denial grants no exception
to runtime checks or the complete local matrix.

## Permission restoration

The user restored unrestricted filesystem/network access. A real scratch-file
write/delete and Git staging succeeded. The previously blocked timer/alarm
rerun and native embedding tests are being repeated at the saved implementation
checkpoint. Historical linker failures above are environment failures, not
accepted timer exceptions. Fresh results must replace the UNRUN matrix slots
only after actual execution.

## Completed focused reruns after access restoration

At embedding source `62e87a56e16c5c7cadc1162cfed0fb0b0554198e`, the complete
focused core/native/Worker timer, publication, alarm, launch and embedding
selection ran 152 tests: 151 passed and one failed. All native cases passed.
The Worker snapshot test
`published_view::tests::etag_conflict_crash_and_relay_during_upload_preserve_dirty_work`
fails deterministically because its old 5,000 ms expectation precedes the
retained row's correct 9,000 ms backoff wake. It failed again in isolation and
on the clean unchanged base `e45def2fe1855a531d0149727bf6678fc8145c3c`.
The user assigned its repair to the base conformance lane; WP-4.18 does not
change or waive it. Timer internals and this fixture have no launch-owned diff.

The native `timers` integration binary and three `wire_binary` timer profiles
then passed all 22 selected tests, including Single, D34 and local fake-S3.
The new release-only indexed-verification wire registration regression first
failed (missing case), then the complete conformance library selection passed
all 36 tests after implementation. This is host harness evidence, not a real
release Worker pass.

`worker-build --release` for `apps/embedded-worker` succeeded with optimized
wasm. Harness artifact capture now requires the actual `build/index_bg.wasm`,
JavaScript, compatibility shim and package metadata; shim-only hashes are
insufficient. Actual local Wrangler assertions still require execution.

Logs live below `$HOME/.cache/mkit-test-tmp/wp-4-18/`.

| Log | SHA-256 |
|---|---|
| `phase2-timer-modules-complete.log` | `8ac036bab7db8a8d9bf3d7e5fc785f1cfcd88e7c1116d45932c6b969854812d7` |
| `phase2-snapshot-isolated.log` | `c1f3488e1773b28a68af033a98fdc17e56f698b8b26f1844d0139742c7089b81` |
| `phase2-snapshot-unchanged-base.log` | `6e4b11280c8d8c0ad603281207999ff6ba4819ba9e00c5a376274efd8a9e22dd` |
| `phase2-release-case-red.log` | `3ab298c2fa6490ac91c5bf797010c1d02537b7183a22a9350479c22977f1ea5b` |
| `phase2-embedded-release-build.log` | `75ec5c90de6da107ad65c293b36a312404bcccd48eca41c3b86d16526f468fdc` |

R-203 is an additional pending prerequisite: the decoder remains off until
bounded ruzstd merges. Native CLI push/clone and decode CPU/resident-memory
evidence are mandatory after that merge. No integrated row is marked PASS
from these focused host checks alone.

## Preservation core merge and catalog ruling

Preservation core #1249 merged at
`a3966d84d05449d164d0ba4365eb30181a1c7ce7`. Its contract records a required
5.6a-3 admin-catalog split. The user ruled to wait for that part and retain
takedown refusal. Integration uses the actual `PRESERVATION` binding, explicit
`PRESERVATION_RETENTION_MS`, secret `RECEIPT_NOTICE_KEY` and `RECEIPT_KEYS`
publication grammar; obsolete phase-1 placeholder names are removed. Receipt
key publication remains required with takedown, while launch publication
Events remain excluded. The merged core handlers retain their activation gate.

## Latest integration steering and regression evidence

Merged 4.16c object reader #1250 at
`1edfc3065e3e22c869c8b3913f2ab77fb97ef272`; the embedding README now mentions
its bounded in-process prefetch API. The latest user ruling removes the
preservation startup refusal and wires configured preservation core work while
keeping admin catalog exposure unavailable until 5.6a-3. The decoder remains
off until R-203.

The first real release build attempts at source
`21ffd9d4b48c26960ccb30b71ba71154e1084def` failed before Wrangler startup: the
preservation merge omitted a wasm-only `enabled` local in the admin mount.
The compile diagnostic is retained in `launch-runtime-xrb77bbi/minimal-build.log`
and `embedding-example/runtime-oubmmrgn/build.log`. It is a branch integration
defect, not a baseline exception or runtime PASS. The fix is followed by wasm
clippy and rebuilt release runs.

Independent pre-review found programmatic startup checks could be bypassed.
Three focused regressions failed on the pre-fix source: an HTTP launch audience,
admin/URL-token key reuse, and remote inspection without scanner retrieval.
`phase2-programmatic-validation-red.log` records 0 passed / 3 failed. A separate
runtime-plan regression records 0 passed / 1 failed in
`phase2-runtime-plan-red.log`: a parsed Paid launch configuration was accepted
with a Free runtime. Fixes revalidate programmatic policy/key roles and actual
runtime plan/bindings before requests or DO construction. Admin operations use
one retained request counter through guards and engine calls.

The merged 55-test focused run passed 54 and failed one fixture that reused the
ticket seed for the new receipt role. Configuration correctly refused it; the
fixture now uses a distinct receipt seed. The expanded focused rerun passed
59/59 (`phase2-programmatic-validation-green.log`), covering launch, embedding,
admin configuration and conformance inventory checks.

The paid-read wrapper class-entrypoint regression was reproduced with a mock
class export before correction and then passed ordinary/zero/partial cancellation
paths. This checks fixture interface only, not actual workerd behavior. The
root-owned release runs still must execute before any corresponding matrix PASS.

## Restricted admin integration and CA prerequisite checkpoint (2026-09-30)

Merged #1251 (`e8164870170ac0dcedd1512fde25d3c0063ee6d0`) in
`d5beb551`. Native and Worker adapters attach the complete preservation Work
runtime and dispatch through `Arc<Engine>::handle_streamed`. The five
restricted operations require configured preservation, enabled admin keys,
indexed storage, global denial and purge delivery. Hold review and Reinstate
remain absent. Preserved reads stream bounded freshly verified pieces without
buffering replay bytes; Worker metadata and both R2 stores share the retained
request allowance. Responses, including admin startup failures, use no-store.
The inventory adds distinct GetTakedown, ListTakedowns, ReadPreserved and
SetLegalHold cases (28 total), all integrated runtime slots still UNRUN.

Regression RED logs demonstrate the former fixed 404 catalog gate, denial
being disabled while preservation remains selected, empty admin keys being
accepted, and missing native purge delivery. These are targeted source fixes,
not launch runtime PASS claims. Logs remain under the mandated WP scratch
path as `phase2-{admin-denial,admin-empty-keys,native-admin-catalog,native-admin-purge}-red.log`.

The native CLI HTTPS round trip additionally needs an explicit local CA trust
option. The user ruled that `MKIT_SSL_CA_FILE` and git-parity `http.sslCAInfo`
will be implemented in a separate prerequisite PR, adding certificates to the
compiled Mozilla roots with certificate and hostname verification intact.
Worker zstd decoding remains disabled until #1252 / R-203 merges.

Actual release probes remain incomplete. Minimal R1 allowlist runs at
`be09f81d` and `4e936489` hit Miniflare proxy `Network connection lost` before
publication; an intervening `25e96a79` run committed, then exposed an unsigned
fixture repository-header bug fixed in `4e936489`. No whole-case PASS or
platform-resource claim follows. The embedded example at `4e936489` verifies
multipart transfer and audience rejection, then fails its Outcome assertion:
persisted reservation is still Ticketed, with no kind-8 obligation. The fixture
must consume a ticket through AdvanceRefs before expecting Committed; this
requires a fixture correction and rerun. Neither failure is waived.

Targeted checkpoint checks pass: 33/33 Worker/native admin, embedding and launch
regressions; strict host all-target/all-feature clippy for both adapters;
Worker wasm32 HTTP/signed-hooks/published-view clippy; formatting, whitespace
and the 28-case inventory validator. These do not replace final workspace gates.

| Log (WP scratch) | SHA-256 |
|---|---|
| `phase2-admin-activation-final-tests.log` | `a93639a6a81f40024f28401416a6f8cc1879f711962ef4873a6a2c84ec105e56` |
| `phase2-admin-activation-final-host-clippy.log` | `9725bd4965783e5589355b689386850d3d91d508cb5cb9f846508a6e750a7955` |
| `phase2-admin-activation-final-wasm-clippy.log` | `450ebead2af05f97c1005bc6e6839988a30864caee2886dbf4152c7a9ab4ea1b` |

## Bounded zstd merge and renewed conformance checkpoint

Merged #1252 / R-203 and #1253 into `4db831f2`. Only adjacent CHANGELOG
entries conflicted; both intents were retained. The app's explicit `launch`
feature now enables `mkit-core/pack-ruzstd` through the Worker adapter.
The default Worker graph keeps decoding off. Launch locked metadata selects
the vendored bounded decoder; the app lock adds ruzstd and twox-hash.
Strict Worker wasm32 clippy with HTTP, signed hooks, published view and
pure-Rust decoding passes. This is compilation evidence, not a push PASS.

The CA-file prerequisite is open in [#1254](https://github.com/officialunofficial/mkit/pull/1254),
at `66f596cc5ce001d677bd784c67bcaa7ebcc7a7eb`. Its 1,540 CLI tests,
131 transport tests, six CA CLI cases, 16 protocol cases, workspace clippy,
scripts/security/wasm/docs checks and two independent reviews pass. It remains
unmerged. A new local HTTPS compressed push/clone harness accepts that separate
CLI pin and records exact artifacts; its runtime remains UNRUN.

The embedding fixture now consumes a separate ticket through the existing
`AdvanceRefs` conformance case before checking Committed. Completing the
multipart staging upload alone does not create that terminal outcome.
The fixture correction is source-only until its release rerun.

Renewed timer/alarm checks run 163 cases: 159 PASS, four FAIL. All four fail
again in isolation on unchanged base `841ff1105730b2bc29fbd2147c84e370096276f4`:

- Native `relay::sqlite_full_source_relay_timer_reschedules_immediately_after_progress`.
- Native `relay_capacity::sql_soft_limit_reserves_space_for_guarded_relay_timer_reschedule`.
- Worker `quota_rollup::rollup_config_failure_retries_the_stored_timer`.
- Worker `relay::relay_config_failure_retries_the_stored_timer`.

These are deterministic base failures; neither native failure is classified as
a timer flake or waived. The existing published-view fixture remains owned by
the base conformance lane.

A focused signed core probe reproduces another prerequisite gap: configured
`Engine.with_operations(Work).with_purge(true)` accepts Takedown with HTTP 200
and `complete=false`, but creates no automatic purge generation. Manual
PurgeCache activation is separate. SPEC-SERVER §§14.3, 14.9 and 16.7 require
takedown cache invalidation and shared purge. Source tracing finds no producer
of `Trigger::Takedown` in this path. A complete repair must cover both signed
after-commit and timer-15 recovery, enqueue after denial activation, and retain
deduplication after timer 11 removes a delivered purge. Existing purge/audit
rows can support this without a new tag, timer or protocol; no repair is
implemented here pending the section-D ruling. The probe is retained in private
scratch, not left as a failing test in the launch tree.

Decoder scratch is additional to owned payloads. The new budget audit records
R-203's 28 MiB working allowance and the scheduled driver's missing debit in
its existing 48 MiB calculation. Actual overlapping allocations and CPU remain
unmeasured; no total resident ceiling is claimed from source arithmetic.

| Log (WP scratch) | SHA-256 |
|---|---|
| `phase2-r203-timer-tests.log` | `2b0643aa7cd6c3181492cd5b29fce93b3b7e43334114fd445fc0eb343b04210e` |
| `base-control-r203/four-timer-base-tests.log` | `c564dcbf878ccf5420449a807c2c8826aefc20ae1d7e7d3371d2f86da4f5562f` |
| `automatic-takedown-purge-red.log` | `7e96125e85a05c0d24a65f69b466c7c533aa0efff1e561eb9cedcf940f634ecf` |
| `phase2-r203-worker-wasm-clippy.log` | `7a8186c59ff0467732bd6d47c67b8432aeabf59d1afba26c7f219aa7b4a02e12` |

## Decoder scratch ruling checkpoint

The real pure-Rust `VerifyTimer` allocator probe reaches eight decoded objects
and the legal-block malformed zstd frame, commits one terminal rejection, and
records 51,418,822 additional live requested bytes against the unchanged
50,331,648-byte allowance. The strict 48 MiB assertion fails. This is requested
heap above a seeded fixture baseline, not process RSS. The standalone regression
requires explicit execution in a pure-Rust graph; the all-feature graph also
enables C and cannot substitute for it.

Log: `phase2-r203-slice-heap.log`, SHA-256
`ff2025188682565c59d099a6590d1a350dd76f7d42c6e6963d97f84672054411`.

The user ruled both automatic takedown purge and decoder scratch accounting
will be repaired in separate prerequisite PRs. The decoder PR reserves derived
scratch without increasing 48 MiB, preserves the 1 MiB entry/pack limits, and
must retain bounded-call progress, 50-deep deltas and extraction parity.
Neither newly identified launch intersection is certified.
