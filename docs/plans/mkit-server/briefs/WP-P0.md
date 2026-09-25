# WP-P0: Enable CI on `feat/mkit-server`

- **Milestone/track:** Prep
- **Base branch:** `main` (this is the only mkit-server WP that targets main)
- **Branch:** `mkit-server/wp-p0-ci-feature-branch`
- **Depends on:** none
- **Size:** S (~60 changed lines of YAML/shell)

## Goal

Make every PR opened against `feat/mkit-server` run the same GitHub Actions gates a PR against `main` runs. List the
Cloud Build trigger changes the user must apply in GCP, because Cloud Build triggers live in GCP and not in the repo.

## PRD refs

§8 "How each milestone lands"; pipeline P4=A per-PR gate (orchestrator context).

## Conventions

- Commit trailer: `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>`.
- Do not poll CI and do not comment on GitHub or Linear. Report the PR URL and your local validation output.
- Never trigger deploys. Don't add the feature branch to any `push:` filter whose jobs deploy.

## Scope

**IN**
- Add `feat/mkit-server` to the `pull_request.branches` filter of every workflow whose filter is main-only.
- Make `proto.yml`'s `buf breaking` compare against the PR's base branch, not a hardcoded `origin/main`.
- Update `scripts/setup-cloud-build.sh` so a fresh setup creates the triggers with the feature branch included.
  This doesn't change existing triggers; see "User actions".
- Change `cloudbuild/codegen.yaml` to compare against the PR base (adopted Q15 default: do it in P0).

**OUT**
- `push:` filters on workflows that deploy or that cost 10x (see the table).
- Branch protection and rulesets. These are GitHub settings; list them for the user.
- Any change to jobs' logic beyond the base-branch comparison.

## Files and exact edits

Audit of every `on:` block at `main@db0b826b`:

| Workflow | `pull_request` today | Action | `push` today | Action |
|---|---|---|---|---|
| `.github/workflows/buf.yml` | `branches: [main]` | add `feat/mkit-server` | `[main]` | add `feat/mkit-server` (cheap; buf-action defaults to the PR base for breaking) |
| `.github/workflows/proto.yml` | `branches: [main]` | add | `[main]` + paths | add `feat/mkit-server` |
| `.github/workflows/rust.yml` | `branches: [main]` | add | `[main]` (runs **macOS** build, 10x cost) | **do not add** |
| `.github/workflows/workers.yml` | `branches: [main]` | add | `[main]` + paths | add (path-gated; no deploy) |
| `.github/workflows/web.yml` | `branches: [main]` | add | `[main]` + paths | leave as is (web deploy is handled by Workers Builds on main) |
| `.github/workflows/mcp.yml` | `branches: [main]` | add | `[main]` + paths ("Worker-code deploy on merge to main", header line 4) | **do not add** |
| `.github/workflows/og.yml` | `branches: [main]` | add | `[main]` | leave |
| `.github/workflows/spammer-worker.yml` | `branches: [main]` | add | `[main]` | leave |
| `.github/workflows/third-party-notices.yml` | `branches: [main]` | add | `[main]` + paths | add |
| `.github/workflows/mutants.yml` | `branches: - main` | add (diff base uses `pull_request.base.sha`, so it is branch-agnostic) | n/a | n/a |
| `actionlint.yml`, `crypto-stack-version.yml`, `docs-lint.yml` | no `branches` filter (paths only) | none; they already run on any PR | `[main]` | leave |
| `bench-freshness`, `fuzz`, `rust-security`, `release*`, `crates-publish`, `mcp-release`, `release-plz`, `release-verify` | schedule/tag/dispatch only | none | | |

`proto.yml` edit (lines ~87-137): replace the hardcoded `origin/main` with the base ref.

```yaml
      - name: Ensure base branch is fetched
        env:
          BASE_REF: ${{ github.base_ref || 'main' }}
        run: git fetch --no-tags origin "${BASE_REF}:refs/remotes/origin/${BASE_REF}" || true
```

Then use `origin/${BASE_REF}` in the `git cat-file -e`, `git diff --quiet` and `buf breaking --against
".git#branch=origin/${BASE_REF},subdir=$dir"` lines. Export `BASE_REF` into that step's `env:` too. Keep every
existing comment and adjust wording from "origin/main" to "the PR base branch (origin/main on push)".

`scripts/setup-cloud-build.sh:99-100`: parameterize the pattern.

```bash
PR_BASE_PATTERN="${PR_BASE_PATTERN:-^(main|feat/mkit-server)$}"
mk_pr()   { local n="$1"; shift; mk "$n" --pull-request-pattern="$PR_BASE_PATTERN" "$@"; }
```

Leave `mk_push` on `^main$`. Update the comment block and `cloudbuild/README.md` "Triggers" section ("All on branch
`^main$`") to describe the PR pattern.

`cloudbuild/codegen.yaml:74-80` (adopted Q15 default: required in this WP): Cloud Build PR triggers expose `$_BASE_BRANCH`. Use
`BASE="${_BASE_BRANCH:-main}"` and `git fetch origin "$BASE"` before `buf breaking --against ".git#branch=origin/$BASE"`.
Keep the "module is new" skip. If `_BASE_BRANCH` isn't substituted on push triggers, the `:-main` fallback applies.
Declare `_BASE_BRANCH` in `substitutions:` with an empty default, because Cloud Build rejects undeclared user
substitutions when the trigger doesn't set them. Add `options: substitution_option: ALLOW_LOOSE` if it's not already
present. If you can't verify this statically, keep the change and add a "verify on the first feature-branch PR"
item to "User actions" rather than dropping it.

## User actions (GCP / GitHub console), which go in the PR description verbatim

Existing Cloud Build triggers aren't updated by the setup script (it skips any trigger that exists). The user runs
these commands, with `PROJECT` and `REGION=us-east4` as in `scripts/setup-cloud-build.sh`:

```bash
for t in mkit-ci-pr mkit-codegen-pr mkit-security-pr mkit-docs-pr mkit-geiger-pr; do
  gcloud builds triggers describe "$t" --project="$PROJECT" --region="$REGION" --format=json > "/tmp/$t.json"
  # edit .github.pullRequest.branch from "^main$" to "^(main|feat/mkit-server)$", then:
  gcloud builds triggers import --project="$PROJECT" --region="$REGION" --source="/tmp/$t.json"
done
```

The Cloud Console works too: Cloud Build → Triggers → each `*-pr` trigger → Source → Base branch regex.

Optional, recommended: post-merge Linux CI on the feature branch. Create push triggers `mkit-ci-feat`,
`mkit-codegen-feat` and `mkit-security-feat`, cloned from the `*-main` triggers with
`--branch-pattern='^feat/mkit-server$'`.

Also in GitHub, add a ruleset for `feat/mkit-server` that requires the same status checks as `main`: `ci-gate`,
`workers-gate`, `proto-gate`, `web-gate`, `third-party-notices-gate`, the buf check and the Cloud Build checks. Block
force-push and require squash merge.

## Tests to write first

None (CI config). Validate statically.

## Gate commands

```bash
actionlint .github/workflows/*.yml          # or: docker run --rm -v "$PWD":/repo -w /repo rhysd/actionlint:latest
bash -n scripts/setup-cloud-build.sh
shellcheck scripts/setup-cloud-build.sh || true   # report findings, don't block on pre-existing ones
yq '.on' .github/workflows/*.yml            # eyeball: every edited pull_request filter lists both branches
```

## Acceptance criteria

- [ ] All 10 main-only `pull_request` filters also list `feat/mkit-server`.
- [ ] No deploying workflow gained a `push` trigger on the feature branch (mcp.yml, web.yml, og.yml, spammer-worker.yml unchanged on `push`).
- [ ] `rust.yml` `push` unchanged (no 10x macOS runs on feature-branch merges).
- [ ] `proto.yml` breaking check compares against `github.base_ref` with a `main` fallback. Behavior on `main` PRs is unchanged.
- [ ] `setup-cloud-build.sh` PR pattern includes the feature branch. README updated.
- [ ] The PR description carries the "User actions" block.
- [ ] actionlint is clean.

## Risks / gotchas

- `workers.yml` path filter (`changes` job) doesn't yet list `rust/crates/mkit-server*/**`. M0-17 adds it, not this WP.
- Required-check names: the always-on `*-gate` jobs only run on `pull_request`. Adding the branch to `pull_request`
  is what makes them appear on feature-branch PRs.
- Don't use `github.base_ref` on `push` events, where it's empty; keep the `|| 'main'` fallback.
