# Specification remediation execution

Baseline: `abaf6f21`, 2026-09-05. This records execution of
[all ten audit findings](2026-09-05-spec-architecture-audit.md) under the
[approved implementation plan](2026-09-05-spec-remediation-plan.md) and the
repository's plan-and-execute workflow. Verification preceded PR preparation;
no deployment was performed. The pre-existing Windows installer file was
preserved outside the change.

Status: all ten remediation packages are implemented in PR #965. A subsequent
user decision removes backwards compatibility from the pre-production design.
Current contracts below reflect that cleanup; initial and cleanup verification
are recorded separately.

## Coverage and evidence

| Package | Result | Regression evidence |
|---|---|---|
| 1A Requested pack identity | Requested PackKeys and metadata keys checked before effects; shard manifest binding checked before download | Valid substituted packs, mismatched manifests and map nodes rejected; HTTP/S3 shard suites and CLI recovery tests pass |
| 1B Ref mutation serialization | Local Any/Missing/Match/deletion, tags and remotes share full-ref guards; file transport serializes every condition within its separate lock domain; lock order documented | Core guard/contention tests, 35 file-transport tests and 13 ref integration tests pass |
| 1C Git correspondence audit | Pure translation derives unsigned fields and graph edges from retained Git bytes; exact signed provenance claims verified | Swapped intermediate twins and unrelated head attestations reproduced red then pass rejection tests; all 45 Git-import integration tests pass, including audit after private-key removal |
| 2A Destination-bound authorization | Auth v2 binds audience/repository/procedure/commitment/time/nonce; user-only signing mode and destination trust; transactional Worker replay/quota/effects | Core and Connect context/retry tests; web/spammer tests; actual local Worker tests for captured replay, concurrent effects, wrong destination, expiry, legacy rejection and interrupted publication |
| 2B Sparse metadata witnesses | v2 carries canonical Tree witnesses and verifies independently expected Tree IDs; selection and recursive completeness derived locally | Substituted hashes and unauthenticated legacy proof acceptance reproduced red; core witness/recursive/golden tests, witness cache tests and 13 sparse transport/CLI tests pass |
| 2C Bounded fetch staging | Packs stage to temporary files; retained payload does not grow with chain length; bounded chain/disk and process-wide shard budgets | Prior 32 MiB retained-payload regression now retains at most one 1 MiB pack; measured process peak RSS 13,680,640 bytes; cleanup, disk budget, GC/ref/recovery tests pass |
| 2D Signer handshake | Compatible capabilities validated before SignRequest; frame/time/PIN bounds retained | No-sign-on-incompatible-response regression; all 28 external-signer tests and bundled file-signer end-to-end test pass |
| 3A Durable staged state | Checksummed index v3 only; no old readers or migration API; staged entries remain authoritative | Zero-length/checksum and unsupported-version rejection; current staged selections/modes/deletions and GC no-sweep tests; 42 current index tests pass |
| 3B Content equality | Bounded verified byte comparison; staged identity retained; diff/rename/merge/dirty checks honor content plus modes | Different chunk-layout cleanliness reproduced red; large inline/fixed/CDC equality and malformed chunk tests; five CLI integration tests cover staging, overwrite protection, mode/type changes and status renames |
| 3C First-parent history | Canonical ancestry snapshots, generations and contextual descriptors; durable intent recovery and GC roots | Eight core contract tests cover chain/reset/recreate/ABA/context and six persistence boundaries; CLI lifecycle, no-op, amend/rebase tests; canonical ancestry tests and focused CLI history suites pass |

The implementation keeps object encoding, object IDs and signed object bytes
unchanged. New pure import helpers are checked against the existing Git-import
golden suite. Auxiliary formats change explicitly: sparse wire/cache v2, index
v3, auth v2 and a separate ancestry snapshot format.

## Current contracts and limits

The project is not live in production. Only current formats and APIs are
supported; no production migration, downgrade path, or compatibility reader is
required. This policy is recorded in CONTRIBUTING.md.

- Sparse wire v2 carries canonical Tree witnesses. Verification returns entries
  derived locally against the requested Tree ID and filter. `.witness` caches
  have no old-path lookup or conversion. Complete metadata trades bandwidth for
  authenticated selection/completeness; file payloads remain sparse. Oversized
  witnesses require verified local metadata fallback.
- Only checksummed index v3 is accepted. Unsupported or corrupt data fails
  without conversion or reconstruction from HEAD/working files.
- Auth v2 is the sole request contract. Names use per-key SQLite exclusively;
  repository Workers use the shared replay ledger with no obsolete idempotency
  tables. Wrangler class declarations provision Durable Objects on first deploy.
- Canonical ancestry snapshots are the only history representation. Descriptors
  currently establish local trust; remote descriptor authentication is not
  claimed. Snapshot/MMR reconstruction is O(chain length), capped at one million
  leaves. Event-journal APIs, executors and compatibility state are removed.
- Fetch staging caps temporary pack bytes at 64 GiB, pack count at one million
  and metadata-chain nodes at 100,000. Shard downloads share a process-wide
  encoded-buffer budget of 4 GiB + 1 MiB and at most 32 workers. These are explicit
  bounds, not a promise of small total process RSS under all workloads.

## Independent review

Separate agents reviewed Git/equality, transport/signing, storage publication,
and Worker mutation adapters. Confirmed findings were fixed:

- Mode/type-only changes now block `rm`/`restore` without force (new red/green test).
- Retained Git audit bytes use a bounded descriptor read, closing a metadata/read
  race; worktree safety snapshots use ephemeral objects.
- NameStore normalizes uppercase pubkey paths consistently with its router
  (real Worker regression reproduced and fixed).
- Worker quota cleanup, indexed replay expiry and malformed stored-ref handling
  passed actual local Worker tests, including injected corrupt state and stale records.

No actionable issue was found in the canonical sparse witness, universal ref
lock participation, ancestry intent GC roots, streamed content comparison or
external signer sequencing during those reviews.

## Initial implementation verification (before compatibility cleanup)

| Check | Status |
|---|---|
| Focused regressions and package suites above | Passed |
| Web repo-client Wasm rebuild | Passed |
| Web full Vitest suite | 252 tests passed |
| Web TypeScript | Passed |
| Spammer unit suite and TypeScript | 191 tests passed; typecheck passed |
| Keys host unit/clippy/Wasm build | 11 tests passed; strict clippy and build passed |
| Keys actual local Worker | Replay after later rename, nonce conflict, audience/repository isolation, v1 rejection, uppercase paths, single/batch reads passed |
| Keys transaction failure injection | Errors after name write and after saved-result write roll back; identical retry succeeds |
| Keys full Worker restart | Saved old response survives; newer name remains current |
| Repo/VCS actual local Workers | Concurrent replay/effect, publication faults, malformed-ref rejection, quota pruning and expiry-index tests passed |
| Formatting, all-feature strict lint and workspace/signer builds | Passed |
| Signer workspace | 57 tests passed; one hardware-dependent test skipped |
| Normal all-feature workspace tests | All 3,031 tests have passing results across the full run and focused completion/reruns; see execution detail below |
| Serial ignored-test lane | All 11 configured tests passed; other native-keystore/real-SSH tests remain outside this lane |
| Fuzz harness | 16 tests passed (not a long-duration fuzz campaign) |
| Workspace doctests | Passed |
| Release version contract | Passed: exact stdout `mkit 0.4.2` |
| Encrypted-transport CLI build | Passed |
| Encrypted-transport TCP suite | 36 tests passed; its three ignored TCP cases passed in the serial lane above |
| `git diff --check` | Passed |

The first all-feature run exposed four legacy `advance_head` fixtures using
nonexistent hashes. Fixtures now persist real commit graphs; production ancestry
validation was unchanged. Layout fixtures recognize the new ancestry files, and
shard retry fixtures make the retried shard necessary for quorum so early
cancellation cannot invalidate request counts. The linked-worktree stash path
now reads its authoritative index through the resolved repository layout.

The final `NEXTEST_TEST_THREADS=8 just ci-macos` invocation passed formatting,
strict lint, builds and signer tests, then stopped after 2,673 workspace passes
on two Connect tests with local TCP connection failures. The remaining transport
run passed 328 tests and encountered one HTTP error-response assertion after a
23-second request. All 40 Connect tests and the HTTP test passed unchanged when
run serially; concurrent failures moved between RPCs. No timeout or assertion was
weakened. The completion run also passed all 22 in-memory transport tests.
Deduplicating the passing normal-test results accounts for all 3,031 tests.
Thus the single `just ci-macos` invocation did not exit successfully, but every
constituent check was completed separately, with the transient network failures
retained here rather than described as a clean full run.

Verification was local on macOS, including real local Workers. Linux-specific
CI, native hardware/credential backends, production deployment and sustained
fuzzing were not run. No live service was changed.

## PR integration verification

Rebased onto `a446864f` before opening the PR, preserving upstream shared serve
diagnostics and bounded parallel signature verification. The concurrency
specification conflict was resolved with separate local and file-transport lock
domains explicit; release notes and invariants use that same scope.

Post-rebase formatting, strict all-feature workspace clippy and diff whitespace
checks passed. All 142 focused tests passed, covering ref/repository locks,
packmap staging and parallel signature verification, serve diagnostics, config
aliases, content representation, fetch signature checks and history lifecycle.
The original 3,031-test record above applies to the pre-rebase implementation;
the complete workspace suite was not repeated after integration.

## Pre-production simplification verification

The cleanup removes compatibility readers/APIs/state, not validation of current
formats. It also removes the hash-only rename API; the remaining status caller
now uses content-aware detection. A new regression first reported delete/add for
equal content with different representations, then passed with a rename. An
unset-key runtime regression first returned 500 without KV, then passed with 404
and an empty batch result after removing the fallback.

Focused checks passed: 42 index tests (feature-on and no-default), canonical
ancestry and CLI history tests, all 13 sparse integrations, five CLI content tests,
11 Keys unit tests, 59 Repo unit tests, and 19 VCS unit tests. Actual local Workers
passed replay/read/fault checks from fresh storage; inspected SQLite contains only
the current replay tables. Strict Worker host/Wasm checks passed. Independent
review caught a test-only runtime dependency, now scoped to dev-dependencies.

Final all-feature workspace execution ran all 3,005 tests: 3,000 passed,
three Connect timing tests failed under concurrent load, the branch race hit its
150-second limit, and the help snapshot used a binary compiled before the final
wording edit. A fresh serial nextest run passed all 49 selected checks: all 40
Connect tests, the branch race, six help tests and two exact layout tests. No
assertion or timeout was weakened. Together the runs account for passing results
for all 3,005 current tests; the full concurrent invocation itself was not clean.
Strict all-feature workspace clippy, formatting, rustdoc with warnings denied,
and diff whitespace checks passed. No service was deployed.
