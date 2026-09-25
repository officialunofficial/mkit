# WP-P1: Create `feat/mkit-server` and land the plan

> Superseded in part by the CI policy in conventions.md: no CI runs on the branch, and the CI-check steps below are dropped.

- **Milestone/track:** Prep
- **Run by:** the orchestrator (not an executor agent)
- **Depends on:** WP-P0 merged to `main`, so the new branch inherits the CI trigger changes
- **Size:** S (docs only)

## Goal

Cut the integration branch from `main` and commit the plan and briefs where every later executor can read them from
its worktree.

## Steps

1. `git fetch origin && git switch -c feat/mkit-server origin/main` (after P0 is merged).
2. Create `docs/plans/mkit-server/` containing the files below.
3. Commit with the message `docs(plans): mkit-server epic plan and work-package briefs (MKIT-29)` and the trailer
   `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>`.
4. `git push -u origin feat/mkit-server`.
5. Confirm the GitHub ruleset and Cloud Build trigger changes from WP-P0's "User actions" are applied. Open a
   throwaway docs PR against the branch and check that `ci-gate`, `workers-gate`, `proto-gate` and the Cloud Build
   `mkit-ci-pr` check all appear. Close it.

## Contents of `docs/plans/mkit-server/`

| File | Content |
|---|---|
| `README.md` | Index: link to Linear MKIT-29 (canonical PRD), the branch and PR conventions, and a status table of WPs (id, title, PR link, state), with the orchestrator updating it as WPs merge |
| `prd-snapshot.md` | Verbatim copy of the approved PRD (Linear MKIT-29, as held in the orchestrator's working copy), headed "Snapshot of Linear MKIT-29 taken <date>. Linear is canonical; decisions D1–D36 are settled (D21 superseded by D34; D35 staging; D36 `X-Mkit-Ref`)." |
| `00-plan.md` | `docs/plans/mkit-server/00-plan.md` (pipeline, registry, DAG, defaults, reconciliation log) |
| `registry.json` | `docs/plans/mkit-server/registry.json` (the WP registry used for Linear sub-issues) |
| `m0-overview.md` | `docs/plans/mkit-server/m0-overview.md` |
| `m1-m2-breakdown.md`, `m3-m5-breakdown.md` | the coarse breakdowns for later milestones (rolling wave) |
| `conventions.md` | The shared executor rules: base branch, branch naming, TMPDIR, commit trailer, no CI polling or comments, size target, per-PR gate (below), pre-production policy, credit rule for spec PRs |
| `briefs/WP-*.md` | Every brief from the orchestrator's working copy of the plan, including P0 and P1 for the record |

Per-PR gate text for `conventions.md`:

```bash
export TMPDIR="$HOME/.cache/mkit-test-tmp"; mkdir -p "$TMPDIR"   # never macOS /tmp (symlink breaks sign/attest tests)
cd rust
cargo fmt --check
cargo clippy --all-targets --all-features --workspace -- -D warnings
cargo nextest run -p <touched crates> -p <their reverse deps>        # reverse deps: cargo tree -i <crate> -e normal --workspace --depth 1
cargo test --doc -p <touched crates>
# Area gates when touched:
#   proto:   buf lint && buf breaking --against '.git#branch=origin/feat/mkit-server'
#   specs / wasm:  just ci-scripts
#   apps/* workers: (cd apps/<w> && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test --lib && cargo build --target wasm32-unknown-unknown)
#   deps (Cargo.toml/Cargo.lock): just ci-security
#   web (rust/Cargo.lock wasm-bindgen moves, mkit-wasm): (cd apps/web && bun install --frozen-lockfile && bun run wasm:build && bun run test && bun run build)
# Full `just ci` when touching mkit-core public API or rust/Cargo.lock.
# From M0-17 on: any change to mkit-server*/mkit-worker-common dependencies also refreshes and commits
# apps/vcs-worker/Cargo.lock (workers.yml builds without --locked): (cd apps/vcs-worker && cargo check --target wasm32-unknown-unknown)
```

## Acceptance criteria

- [ ] `origin/feat/mkit-server` exists and matches `origin/main` plus the one docs commit.
- [ ] Only `docs/plans/mkit-server/` is added (no other untracked plan directories).
- [ ] The docs render on GitHub (tables, relative links from README to briefs).
- [ ] A test PR against the branch shows the required checks (step 5).
