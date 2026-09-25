# mkit-server executor conventions

Shared rules for every work package (WP) of the mkit-server epic ([Linear MKIT-29](https://linear.app/officialunofficial/issue/MKIT-29)).
Your brief (`briefs/WP-<id>.md`) is the spec for your WP. Where a brief and [`00-plan.md`](00-plan.md) disagree, `00-plan.md`
wins. The PRD snapshot is [`prd-snapshot.md`](prd-snapshot.md); Linear is canonical.

## CI policy (authoritative; supersedes any CI-on-branch wording in this plan)

- **No CI runs for `feat/mkit-server`.** Nothing changes GitHub workflow triggers, Cloud Build triggers or rulesets to cover the branch. WP-P0 (CI enablement) is **dropped**: PR #1094 was closed unmerged.
- In place of CI, the evidence is the executor's local gate run (output in the PR body) and a clean adversarial review; all other merge rules are unchanged. The orchestrator re-runs the gate after rebasing and before squash-merging.
- **CI runs once**, on the final PR that merges `feat/mkit-server` into `main` (WP-REL). All normal `main` gates apply there.
- `workflow_dispatch` runs are never dispatched against `feat/mkit-server`.
- A WP that adds CI wiring (new jobs, `server-staging.yml`, workflow changes) may add it, but it must trigger only on `main`, `schedule` or dispatch against `main`, never on the feature branch; it runs for the first time on the final PR to `main`. During the epic the same checks run **locally or against staging from the orchestrator's machine**, at the WP and at every milestone boundary, and the results go in the PR or the milestone report.

## Base branch

- Every WP branches from and targets **`feat/mkit-server`**.
- Start from a fresh fetch: `git fetch origin && git switch -c <branch> origin/feat/mkit-server`.
- Stacked spec PRs (S2 on S1, S3 on S2) retarget to `feat/mkit-server` once their parent merges.
- Nothing is released from `feat/mkit-server`. Crates publish and the workspace version moves to 0.5 only at WP-REL.

## Branch naming

`mkit-server/wp-<id>-<slug>`, with the WP id lowercased and dots written as dashes:

- `mkit-server/wp-m0-02a-storage-contract`
- `mkit-server/wp-1-22-shard-model`
- `mkit-server/wp-4-10a-content-index-shards`
- `mkit-server/wp-rel-0-5-release`

## TMPDIR

Never run the test suite under macOS `/tmp` or `/var`: they are symlinks, and about 20 sign/attest tests fail spuriously on
the resolved path. Always export a non-symlinked `TMPDIR` first:

```bash
export TMPDIR="$HOME/.cache/mkit-test-tmp"; mkdir -p "$TMPDIR"   # never macOS /tmp (symlink breaks sign/attest tests)
# Run from the repo root. Rust steps run in a subshell under rust/, like the justfile recipes.
( cd rust && cargo fmt --check )
( cd rust && cargo clippy --all-targets --all-features --workspace -- -D warnings )
( cd rust && cargo nextest run -p <touched crates> -p <their reverse deps> )   # reverse deps: cargo tree -i <crate> -e normal --workspace --depth 1
( cd rust && cargo test --doc -p <touched crates> )
# Area gates when touched (all from the repo root):
#   proto:   buf lint && buf breaking --against '.git#branch=origin/feat/mkit-server'
#   specs / wasm:  just ci-scripts
#   apps/* workers: (cd apps/<w> && cargo fmt --check && cargo clippy --all-targets -- -D warnings \
#                    && cargo clippy --target wasm32-unknown-unknown -- -D warnings \
#                    && cargo test --lib && cargo build --target wasm32-unknown-unknown)
#   deps (Cargo.toml/Cargo.lock): just ci-security
#   web (rust/Cargo.lock wasm-bindgen moves, mkit-wasm):
#       (cd apps/web && bun install --frozen-lockfile && bun run wasm:build) && ./scripts/check-generated-fresh-ts.sh \
#       && (cd apps/web && bun run typecheck && bun run test && bun run lint && bun run fmt:check && bun run build)
# Full `just ci` when touching mkit-core public API or rust/Cargo.lock.
# From M0-17 on: any change to mkit-server*/mkit-worker-common dependencies also refreshes and commits
# apps/vcs-worker/Cargo.lock (workers.yml builds without --locked): (cd apps/vcs-worker && cargo check --target wasm32-unknown-unknown)
```

**Working directory rule:** every gate command in this plan (here, in `00-plan.md`, and in each brief) is run from the **repo root**. A line that starts with `cd rust && …` or `cd apps/<w> && …` means "in a fresh subshell from the repo root", i.e. `( cd rust && … )`. Never chain a bare `cd` into later root-relative commands. `buf` must run from the root, where `buf.yaml` lives.

Each WP's `area_gates` in [`registry.json`](registry.json) name the extra gates it needs; [`00-plan.md`](00-plan.md) §1
defines the codes.

## Pre-production policy

mkit is not live in production (CONTRIBUTING, "Pre-production compatibility policy"). Replace unshipped APIs and formats
directly: no older readers, aliases, migration helpers, fallback state or v1 compatibility machinery unless a brief
explicitly asks for it. Keep format identifiers, strict validation, corruption checks and tests for current behavior, and
record breaking changes in the changelog.

## Credit rule for spec PRs

S1, S2 and S3 are rebuilt from PR [mkit#1087](https://github.com/officialunofficial/mkit/pull/1087) by Christopher Wallace
(@christopherwxyz), split per PRD D26. Every commit in those PRs carries both trailers:

```text
Co-authored-by: Christopher Wallace <362387+christopherwxyz@users.noreply.github.com>
Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
```

The PR body opens with "Rebuilt from #1087 by @christopherwxyz (split per PRD D26: addressing / grants / admission)."
Don't close or comment on #1087; the user does that once S1–S3 have merged.

## Review and merge

An adversarial Opus reviewer checks each diff against the brief, the PRD, the specs and the invariants. Every finding is
verified against the code before it is applied. The orchestrator squash-merges into `feat/mkit-server` after the
reviewer's APPROVE and its own local gate re-run on the rebased branch. There is no CI on the branch; CI runs only on
the final PR to `main`, which the user merges. Spec PRs (S1–S3, 3.6, 4.4, 4.11, 5.1a–c) also need the user's approval
of the normative text. See [`00-plan.md`](00-plan.md) §1
for the full merge rules (proto changes, file-overlap ordering, milestone boundaries).
