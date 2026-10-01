# WP-4.18 phase 1 checkpoint

Status: phase 1 checkpoint; both separate budget repair rulings implemented.
Timer-12 #1245, physical alarm #1247 and native conformance #1248 are merged.
The phase 2 input merge is `7a2d1bf039e0853fb53d5e8e78d4d449782196ca`.
This checkpoint does not complete launch activation or the integrated matrix.

Production source: `d46af16bf9ced385b1a5eacc6449595bdd10ab7a`, based on origin feature
`d691d32eb20967e4d45576aa0fb9bdd844272c9b`. Branch:
`mkit-server/wp-4-18-launch-activation`.

Implemented startup grammar and Paid indexed selection, active capability
honesty, configured Worker admin catalog, real merged extraction and R-193
retrieval, six-response bounds, shared alarm headroom, README/launch docs and
the 23-case conformance/evidence skeleton. The remaining startup prerequisite
refusal is WP-5.6a-2 preservation. Both embedding addenda are assigned to phase
2; the binding cap is 3,500 non-test production Rust lines. All added Rust
lines including tests total 1,355, a conservative upper bound below that cap.

## Verification

All Rust commands used debug=0 and the private nonsymlinked
`~/.cache/mkit-test-tmp/wp-4-18` scratch directory, with the worktree's own
target. The logs are local evidence, not deployed measurements.

| Check | Result | Local log / SHA-256 |
|---|---|---|
| Focused core/Worker launch, admin, retrieval, budgets and concurrency | 80 passed | `phase1-focused.log` / `382d04d5255dc00540d369e6f186f36af630089d9fb3a1407f31c738191f6630` |
| Worker library without test-faults | 141 passed | `phase1-worker-release-config.log` / `f8264745647f887f82fc7ab4fd23287fc2f0681163e60c3ed613f1b19076c822` |
| Native launch configuration and real HTTP retrieval | 6 + 4 passed | `phase1-native-launch-retrieval.log` / `92b3c120432b0a168d8365d16f950f3ad63117b71af834197698fa651a518e3e` |
| Native binary wire suite | 8 passed | `phase1-native-wire.log` / `b0815cf9cbbfe7555af5c61c27c02c634e2751ad93d92bacbce2889fff18e1b0` |
| Touched-crate native all-target/all-feature clippy | PASS | `phase1-clippy-native.log` / `58b1b1c734d13806f10300d8b1d65d2a4cbcd1eb93b4317de0d2d3b8f23f563a` |
| Core/Worker all-feature wasm32 clippy | PASS | `phase1-clippy-wasm.log` / `32bc65fedb150fd42519f7635aea15b0824ae65f1a0363bfd14801aa77504230` |
| vcs-worker launch-feature wasm32 clippy | PASS | `phase1-clippy-app-wasm.log` / `aab689f483aa90e51bed2fd0a3912fea3ce5d7ed83191b4929a06c14e5a9bbd5` |
| just ci-scripts | PASS | `phase1-ci-scripts.log` / `41328ceaaf2be2cea6cd5a6616f896502cd87ac372fd2976087737b0a50d248d` |

`cargo fmt --all --check`, `git diff --check`, harness validation (23 cases),
and shell/Python syntax also passed. Commands for reproducible runtime lanes
are in [launch-conformance.md](launch-conformance.md); no runtime lane was run
for this checkpoint. Native timer-conformance remains unrun, with no new flake
classification.

Two independent read-only reviews found no blocking implementation defect.
They identified and corrected a launch doc overclaim: synchronous inspection
does not make D34 dependency publication immediate; Committed means Sent,
never Delivered. Checks also corrected a hook-signing test fixture to reflect
the new startup requirement and retained test-faults scanner configuration.

## Separate repairs and phase 2

The user ruled a bounded in-memory cursor with persisted backoff for cold
fairness. [PR #1247](https://github.com/officialunofficial/mkit/pull/1247)
implements it at `f07195914af704aa255f7430b5d93427f4d0c619` and merged as
`e45def2fe1855a531d0149727bf6678fc8145c3c`. Native timer repair #1248 merged as
`12e4ce4998145a959c4fc400e02b6ad546812090`; prior flake exceptions do not apply
to phase 2 reruns. The component gates passed 242 targeted tests and
18 native timer integration tests, native/wasm32 clippy and fmt; both independent
reviews closed without blocking findings. Its internal retry metadata preserves
original due times and payloads, with guarded moves and bounded indexed scans.
These results belong to that separate repair, not the integrated launch matrix.

Refreshed phase-1 source: `fbefda7964e82a010dee68f428d47c121e79b8fa`, based on
`cd680351bb499538c287b2197fcabd89c7783a95`; extraction, retrieval and publication
recheck now use their merged implementations. Only preservation remains a
startup prerequisite refusal. Refreshed component checks are recorded below.

At this historical checkpoint the user had authorized phase 2 for available
prerequisites while preservation awaited 5.6a-2. See the
[phase 2 checkpoint](launch-phase-2-checkpoint.md) for current preservation
wiring and the remaining 5.6a-3 endpoint gate. Phase 2 includes
preservation/admin runtime integration, both embedding addenda, complete native
and actual opted-in release Worker probes, final full gates and fresh reviews,
then an open PR into feat/mkit-server. External review, Cloudflare staging,
CPU/memory/subrequest/cost and multicolo gates remain user-owned and UNRUN.

The separately ruled bounded resumable publication recheck is
[PR #1245](https://github.com/officialunofficial/mkit/pull/1245), merged at
`d89c37fb968d39c180228678bc09c77a12002fc9`. It does not fix or classify native
timer flakes.

## Refreshed-base component verification

Source `fbefda7964e82a010dee68f428d47c121e79b8fa`. Private TMPDIR and debug=0
settings match the earlier component runs.

| Check | Result | Local log / SHA-256 |
|---|---|---|
| Focused refreshed-base component tests | 82 passed | `phase1-base-refresh-tests.log` / `74116601c2efad6cb04b32304eef2dbf453bedc48456d92ed1dfef2c81cce3bd` |
| Native all-target/all-feature clippy | PASS | `phase1-base-refresh-clippy-native.log` / `b70cde84dfcfab02cff4ae361ad2bed504961f63b6c2bf51d6108d46e02bcd77` |
| Core/Worker all-feature wasm32 clippy | PASS | `phase1-base-refresh-clippy-wasm.log` / `c5009813b8fa58d0f7dd8cf9f98d07944cf28222ccadb0730bd9fdbec7a1d2b6` |
| Rust formatting | PASS | `phase1-base-refresh-fmt.log` / `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |

The focused run covers launch configuration, admin, private retrieval,
publication recheck, content headers and shared budget/connection regressions.
Harness validation (23 cases) and `git diff --check` also pass. Complete matrix,
full gates and native timer-conformance remain phase 2 work.

## Resolved header policy

The user ruled that launch adopts merged #1246's extension allowlist and safe
filename headers. Ordinary successful ref-path file responses select media
type and inline/attachment disposition from the final decoded extension;
object-id Blob/ChunkedBlob responses remain `application/octet-stream`.
HEAD and 206 follow the same file policy. A sanitized ASCII filename and an
octet-preserving encoded `filename*` prevent header injection. No content
sniffing occurs. Nosniff and the sandbox CSP remain mandatory. Non-file,
proof, 304, and error representations retain their specified behavior.
The ruling resolves the documentation question; actual launch runtime header
evidence remains UNRUN in [launch-evidence.md](launch-evidence.md).
