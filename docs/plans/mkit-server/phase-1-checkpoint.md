# WP-4.18 phase 1 checkpoint

Status: independent phase-1 work committed; cold-alarm escalation still open.
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

## Outstanding ruling and phase 2

[The cold-alarm finding](launch-budgets.md#unresolved-deterministic-findings)
requires a user ruling under brief section D. SQL timer_heads aggregates all
timer rows and materializes all logical heads, while the local TickBudget resets
per head. A bounded indexed scan plus an in-memory cursor needs no new durable
state, but repeated isolate restarts can starve later timers behind retained
unknown/failing rows. A persistent cursor requires a separate authorized design
and repair. Neither option has been inferred from elapsed time or implemented.

Phase 2 awaits the user's signal after preservation merges. It includes
preservation/admin runtime integration, both embedding addenda, complete native
and actual opted-in release Worker probes, final full gates and fresh reviews,
then an open PR into feat/mkit-server. External review, Cloudflare staging,
CPU/memory/subrequest/cost and multicolo gates remain user-owned and UNRUN.

The separately ruled bounded resumable publication recheck is
[PR #1245](https://github.com/officialunofficial/mkit/pull/1245), source
`3038c158`, open and unmerged. Its targeted 87 tests, fmt and native/wasm clippy
passed; it must merge before phase 2. It does not fix or classify native timer
flakes.
