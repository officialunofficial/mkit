# mkit ↔ Git parity matrix

> **Authoritative scope gate for git-parity (umbrella #246, Phase -1 #247).**
> This file defines *exactly* what "usable like git" means for mkit v1. A row
> is in scope only if it appears here. If schedule pressure appears, the lever
> is **renegotiating this matrix — never the safety principles.**

## Scope statement

mkit targets **CLI/UX parity** with Git: every *in-matrix* command and flag a
human or AI agent would type behaves like Git's, while mkit keeps its own
improvements — **BLAKE3 content addressing, native attestation, and data-loss
safety guards.** This is *not* on-disk or wire interop with real `.git`
repositories; mkit's object/wire formats remain native (a BLAKE3 object store
cannot share bytes with Git's SHA-1/SHA-256 store).

### Inherent, documented-only divergences (cannot change without dropping BLAKE3)

- **Hash length** — mkit object IDs are 64-hex BLAKE3, Git's are 40-hex SHA-1.
  A literal Git SHA pasted into mkit will never resolve. We match the UX
  *shape* (short prefixes, abbreviated display) but not the length.
- **Repo marker** — mkit uses `.mkit/`, not `.git/`. Repo detection by `.git/`
  is **not** added to core; the opt-in `git` alias shim (Phase 6, #254) is the
  only bridge.

## v1 non-goals (explicit)

These are out of scope for v1 parity. Listing them here keeps scope from
creeping; revisit post-v1 if demand warrants.

- Submodules / subtrees
- Hooks (`.git/hooks`, `core.hooksPath`)
- Multiple working trees (`git worktree`)
- Full refspec grammar (`+a:b`, wildcard push/fetch maps beyond current remotes)
- Wire protocol v2 / smart-HTTP negotiation flags
- `git notes`
- Partial / shallow clone beyond what `clone` already exposes
- `.git/`-format on-disk interop, SHA-1/SHA-256 objects, `git fsck`-compat
- Shadowing the real `git` binary on `PATH` by default

## Status legend

| Status | Meaning |
|--------|---------|
| ✅ shipped | Behaves like Git's in-matrix subset today |
| ⚠️ shipped, divergent | Works, but with a known divergence to reconcile (noted + tracked) |
| 📝 docs-only gap | Implemented; docs/tests need alignment (no code) |
| 🔨 to implement | In scope, not yet built — owned by the listed phase/issue |
| 🚫 non-goal | Explicitly out of scope for v1 |

---

## Porcelain commands

| Command | Git-compatible subset (in scope) | mkit current state | Status | Phase | Issue | Notes |
|---------|----------------------------------|--------------------|--------|-------|-------|-------|
| `init` | create repo | `.mkit/` repo | ✅ | — | — | marker differs (`.mkit/`) |
| `add` | pathspecs, `-A`, `-u` | same | ✅ | — | — | `-p` is separate (#258) |
| `rm` | `--cached`, `-r`, `-f` + dirty guard | same | ✅ | — | — | guard is an mkit safety divergence |
| `mv` | rename, `-f` | absent (by-design, being reversed) | 🔨 | 2 | #250 | guarded: refuses to clobber w/o `-f` |
| `status` | `--porcelain[=v1]`, `-s` — **simple paths only** | v1, no path quoting | ✅ | — | — | C-style quoting of special paths / `-z` / v2 → Phase 1 (next row) |
| `status` | `--porcelain=v2`, `-z`, path quoting | not present | 🔨 | 1 | #249 | agent-parsed machine output |
| `diff` | HEAD/worktree, `--staged`, pathspecs | same | ✅ | — | — | |
| `diff` | `<rev>`, `<a>..<b>` ranges | implemented (`split_range`/`rev_to_tree`) | ✅ | 0 | #248 | docs reconciled (stale CLI.md divergence removed) |
| `diff` | `--name-only`, `--name-status`, `--stat`, `-z` | absent | 🔨 | 1 | #249 | `-z` applies to name-only/name-status only |
| `diff` | byte-exact hunks (Myers/histogram) | LCS unified diff | 🔨 | 4 | #257 | header is `diff --mkit`, not `diff --git` |
| `commit` | `-m`, `-a`, `--amend`, `--author` | same | ✅ | — | — | signed; amend leaves unreachable obj until gc |
| `log` | history, `-n`, `--format=json`, `--oneline`, `--abbrev-commit`, `--abbrev[=N]` | same | ✅ | 0 | #248 | `--oneline`/`--abbrev-commit` abbreviate (default 7); abbreviated id is a BLAKE3 prefix |
| `log` | `--graph`, `<a>..<b>` range walk | `--graph` is a no-op | 🔨 | 1 | #249 | real ASCII graph + commit-range walking |
| `branch` | create, list, `-d`/`-D`/`-m` | same (see notes) | ⚠️ | 1 | #249 | **known divergences to reconcile:** default list prints a short id (Git omits it); `-D <missing>` no-ops (Git errors). Tracked in Phase 1. |
| `checkout` | switch branch, restore files | same | ✅ | — | — | guarded against clobber |
| `tag` | lightweight/`-a`/`-s`/`-m`/`-d` | same | ✅ | — | — | |
| `merge` / `cherry-pick` / `rebase` | merge, pick, replay + conflict workflow | same | ✅ | — | — | `rebase -i` separate (#259) |
| `rebase -i` | interactive todo list | absent | 🔨 | 4 | #259 | promoted everyday-safe only after Phase 5 |
| `restore` / `reset` | `--staged`/`--worktree`/`--soft`/`--mixed` | same | ✅ | — | — | |
| `reset --hard` | reset worktree | absent (by-design, being reversed) | 🔨 | 2 | #250 | guarded; `-f` override is an mkit divergence |
| `revert` | inverse-commit, conflict-aware | absent (by-design, being reversed) | 🔨 | 2 | #255 | forward commit; not gated on gc |
| `clean` | `-n`/`-f`/`-d`/`-x`/`-X`, pathspecs | absent (by-design, being reversed) | 🔨 | 2 | #250 | refuses unless `-f` (Git semantics) |
| `stash` | save/list/pop/apply/drop/clear/show | same | ✅ | — | — | |
| `gc` | prune unreachable objects | mark-and-sweep, recovery-aware | ✅ | — | #233 | `-n`/`--grace-secs`; fail-closed; see SPEC-GC.md |
| `add -p` | interactive hunk staging | absent | 🔨 | 4 | #258 | partial staging / synthetic index blobs |

## Plumbing commands (read-only first, mutating later)

| Command | Git-compatible subset (in scope) | mkit current state | Status | Phase | Issue | Notes |
|---------|----------------------------------|--------------------|--------|-------|-------|-------|
| `rev-parse` | `--verify`, `--short`, `--abbrev-ref`, `--show-toplevel` | absent | 🔨 | 3 | #251 | whole command lands in Phase 3 (not split) |
| `cat-file` | `-p`, `-t`, `-s`, `--batch` | `cat <hash>` exists | 🔨 | 3 | #251 | extends existing `cat` |
| `ls-files` | `-s`, `-z`, `--others`, `--ignored`, `--exclude-standard` | absent | 🔨 | 3 | #251 | |
| `ls-tree` | `-r`, `-z` | `tree` (native) exists | 🔨 | 3 | #251 | |
| `show-ref` | `--heads`, `--tags` | absent | 🔨 | 3 | #251 | |
| `for-each-ref` | `--format` | absent | 🔨 | 3 | #251 | |
| `show` | object/commit display | partial via `cat`/`log` | 🔨 | 3 | #251 | |
| `symbolic-ref` | read | partial (HEAD handling) | 🔨 | 3 | #251 | read in Phase 3 |
| `symbolic-ref` / `update-ref` | write | absent | 🔨 | 4 | #252 | mutating — guarded, later phase |

## Config & format conventions

| Convention | Git-compatible subset (in scope) | mkit current state | Status | Phase | Issue | Notes |
|------------|----------------------------------|--------------------|--------|-------|-------|-------|
| `config user.name` / `user.email` | accept + map | flat `user.identity` only | 🔨 | 2 | #250 | **user-scope / non-authoritative only**; never feeds signed `Identity` (keeps `REPO_FORBIDDEN_KEYS` guard) |
| `config core.*` | accept honored subset | absent | 🔨 | 2 | #250 | display/no-op where not meaningful |
| `.gitignore` | nested, `**`, anchored `/`, dir-relative, negation order | `.mkitignore`, basename/root-only | 🔨 | 3 | #256 | matcher upgrade; v1 glob subset decided in #256 |
| abbreviated hashes | short prefix resolution + display | resolve + `log --abbrev[=N]`/`--oneline` | ✅ | 0 | #248 | display side shipped; `rev-parse --short` is Phase 3 |
| `--version` / `-V` | top-level flag | `mkit --version`/`-V` alias `version` | ✅ | 0 | #248 | emits `mkit <X.Y.Z>` (not git's `git version …`) |
| `.git/` repo detection | — | — | 🚫 | — | #254 | non-goal in core; opt-in alias shim only |

---

## Safety divergences (mkit improvements, documented as intentional)

mkit deliberately refuses Git's silent data-loss defaults. These are
**features, not gaps**, and stay even when the command reaches parity:

- `rm` / `restore` / `reset --hard` / `clean` / `stash pop` — refuse to destroy
  locally-modified or untracked content without an explicit `-f`/`--force`.
- `checkout` — refuses to clobber dirty/untracked files.
- Repo-local config — `user.identity` and other security-sensitive keys are in
  `REPO_FORBIDDEN_KEYS` so a hostile clone cannot spoof the signed author or
  redirect signing/transport trust. Git-style `user.name`/`user.email` aliases
  must respect this (user-scope / non-authoritative only).
- History-rewriting commands (`commit --amend`, `reset`, `rebase`) record the
  superseded commit in the recovery log so `gc` keeps it recoverable within the
  retention window (#260 + #233, shipped).

## Machine-output contract (for agents & scripts)

Outputs that tools parse must be **stable and Git-shaped**, normalized only by
hash length:

- `status --porcelain=v1` — `XY <path>`, newline-delimited, **simple paths only**
  (no C-style quoting of special paths and no `-z` yet — Phase 1, #249). mkit
  adds `T` for mode-change as the sole extension.
- `status --porcelain=v2` / `-z` / C-quoting — Phase 1 (#249).
- Plumbing (`rev-parse`, `cat-file`, `ls-files`, `ls-tree`, `show-ref`,
  `for-each-ref`) — exact flag contracts defined in Phase 3 (#251); output
  matches Git modulo 64-hex vs 40-hex hashes.

The **differential parity harness** (`rust/crates/mkit-cli/tests/git_parity_harness.rs`)
runs the same script under real `git` and `mkit` and asserts these contracts
modulo hash length. Cases for not-yet-implemented rows are `#[ignore]`d with
their phase/issue so CI stays green until the feature lands; each phase
un-ignores its rows as it implements them.
