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
  is **not** added to core; the opt-in `git` alias shim (Phase 6, #254 —
  shipped at `contrib/git-shim/mkit-git`, never installed by default) is the
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
- `log --graph` ASCII commit-graph rendering (the flag is accepted as a
  no-op for script compatibility). Full byte-parity is unachievable because
  mkit's default `log` body already diverges from git's `commit/Author/Date`
  (mkit `Identity` + 64-hex ids); an `--oneline --graph` renderer for the
  linear/DAG case is an optional post-v1 follow-up, not a v1 blocker.

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
| `add` | pathspecs, `-A`, `-u` | same | ✅ | — | — | `-p` interactive hunk staging shipped (#258, row below) |
| `rm` | `--cached`, `-r`, `-f` + dirty guard | same | ✅ | — | — | guard is an mkit safety divergence |
| `mv` | rename single file, `-f`, into-dir | same | ✅ | 2 | #250 | guarded: refuses to clobber w/o `-f` (incl. dangling symlink); rejects missing/untracked source; keeps writes inside the repo. No rename detection → `status` shows delete+add not `R`. **Directory moves (`mv dir newdir`) not yet supported** (refused with a clear error; follow-up). |
| `status` | `--porcelain[=v1]`, `-s`, `-z`, C-style path quoting | same | ✅ | 1 | #249 | tracked changes combine into one `XY` record per path (e.g. `MM`); untracked stays its own `??` record, so a staged-delete-plus-untracked path emits both `D ` and `??` like git; quoting matches git `core.quotePath`; `-z` = raw NUL-terminated |
| `status` | `--porcelain=v2` | same | ✅ | 1 | #249 | `1 <XY> N... <mH> <mI> <mW> <hH> <hI> <path>` (octal modes; full 64-hex BLAKE3 ids modulo length) + `? <path>` for untracked; no rename `2` lines (no rename detection); `--branch` header lines not emitted. A tracked path shadowed on disk by a directory is suppressed like git — only the tracked-side deletion is reported (#288) |
| `diff` | HEAD/worktree, `--staged`, pathspecs | same | ✅ | — | — | |
| `diff` | `<rev>`, `<a>..<b>` ranges | implemented (`split_range`/`rev_to_tree`) | ✅ | 0 | #248 | docs reconciled (stale CLI.md divergence removed) |
| `diff` | `--name-only`, `--name-status`, `-z` | same | ✅ | 1 | #249 | `A`/`D`/`M` (`T` = mkit mode change); special-byte paths C-quoted, `-z` = raw NUL (status letter + path each NUL-terminated); `-z` only with name-only/-status |
| `diff` | `--stat` | same | ✅ | 1 | #249 | byte-exact diffstat: padded name column, `+`/`-` graph scaled to width via git's `scale_linear` (honors `COLUMNS`, default 80), summary line with git pluralization; binary → `Bin … bytes` |
| `diff` | byte-exact hunks (Myers) | same | ✅ | 4 | #257 | Myers diff + git change-compaction; full `diff --git` header (`new file`/`deleted file`/`index`/`--- a/p`/`+++ b/p`, `/dev/null`); byte-matches `git diff` modulo the abbreviated `index` ids (BLAKE3 vs SHA-1). git's optional indent heuristic not applied |
| `commit` | `-m`, `-a`, `--amend`, `--author` | same | ✅ | — | — | signed; amend leaves unreachable obj until gc |
| `log` | history, `-n`, `--format=json`, `--oneline`, `--abbrev-commit`, `--abbrev[=N]` | same | ✅ | 0 | #248 | `--oneline`/`--abbrev-commit` abbreviate (default 7); abbreviated id is a BLAKE3 prefix |
| `log` | `<rev>`, `<a>..<b>`, `<a>...<b>` ranges | same | ✅ | 1 | #249, #252 | `<rev>` start (annotated tags peeled), `A..B`/`A..`/`..B` ranges, `A...B` symmetric difference (excludes the merge base's ancestors); reverse-chrono + topological order = git `--date-order` (matches git default for linear/monotonic-timestamp history) |
| `diff` | `<a>...<b>` symmetric range | same | ✅ | 4 | #252 | diffs `merge-base(a,b)` against `b` (git semantics); single merge base (criss-cross multi-base is a documented edge) |
| `log` | `--graph` | `--graph` is a no-op | 🚫 | 1 | #249 | **v1 non-goal** — flag accepted as a no-op; full graph parity unachievable (mkit's default `log` body diverges); optional `--oneline --graph` renderer is a post-v1 follow-up |
| `branch` | create, list, `-v`, `-d`/`-D`/`-m` | same | ✅ | 1 | #249 | default list is `<marker> <name>` (no id, like git); `-v` adds abbreviated id + subject; `-D <missing>` errors like git (no silent no-op). Prior Phase-1 divergences reconciled. |
| `checkout` | switch branch, restore files | same | ✅ | — | — | guarded against clobber |
| `tag` | lightweight/`-a`/`-s`/`-m`/`-d` | same | ✅ | — | — | |
| `merge` / `cherry-pick` / `rebase` | merge, pick, replay + conflict workflow | same | ✅ | — | — | `rebase -i` row below (#259) |
| `rebase -i` | interactive todo list | same | ✅ | 4 | #259, #291 | reorder / `drop` / `reword` / `squash` / `fixup` via `$EDITOR` (squash combines messages, fixup keeps the prior; a leading squash/fixup is rejected); conflict pause/resume + `--continue`/`--skip`/`--abort` carry over. `edit` (stop-to-amend) not yet supported |
| `restore` / `reset` | `--staged`/`--worktree`/`--soft`/`--mixed` | same | ✅ | — | — | |
| `reset --hard` | reset worktree | same | ✅ | 2 | #250 | resets HEAD+index+worktree to target; removes dropped tracked files, keeps untracked (like git) except a target-colliding untracked path; refuses to discard dirty/staged or overwrite a colliding untracked path without `-f` (mkit divergence — git discards silently); guard re-checks each dropped path directly, so it also covers a tracked file matching an ignore rule (`.gitignore`/`.mkitignore`) |
| `revert` | inverse-commit, `--no-commit`, conflict-aware | same; merge `-m` not yet supported | ✅ | 2 | #255 | forward commit (not gated on gc); reuses the conflict workflow; reverting a merge is refused pending mainline selection |
| `clean` | `-n`/`-f`/`-d`/`-x`/`-X`, pathspecs | same | ✅ | 2 | #250 | refuses unless `-f` (git `clean.requireForce`); `-n` previews `Would remove …`; `-d` removes untracked dirs but keeps ignored files + protects nested repos (no `-ff`); `-x`/`-X` mutually exclusive, use the shared path-aware ignore matcher (#256); pathspecs select top-level entries / whole dirs (`.` = all under cwd; naming a file inside a removable untracked dir is a known limitation) |
| `stash` | save/list/pop/apply/drop/clear/show | same | ✅ | — | — | |
| `gc` | prune unreachable objects | mark-and-sweep, recovery-aware | ✅ | — | #233 | `-n`/`--grace-secs`; fail-closed; see SPEC-GC.md |
| `add -p` | interactive hunk staging | same | ✅ | 4 | #258 | per-hunk `y/n/q/a/d`; regular text files only (binary skipped with a message, symlink/dir refused); explicit paths required; ignored paths need `-f`; symlinked-parent escapes refused; `s` (split) / `e` (manual edit) are follow-ups |

## Plumbing commands (read-only first, mutating later)

| Command | Git-compatible subset (in scope) | mkit current state | Status | Phase | Issue | Notes |
|---------|----------------------------------|--------------------|--------|-------|-------|-------|
| `rev-parse` | `--verify`, `--short`, `--abbrev-ref`, `--show-toplevel` | same | ✅ | 3 | #251 | id is 64-hex BLAKE3 (vs 40-hex SHA-1); `--short` = BLAKE3 prefix |
| `cat-file` | `-t`, `-s`, `-p`, `--batch` | same | ✅ | 3 | #251 | `-s`/`-p` byte-exact for blobs; tree `-p` is `<mode> <type> <hash>\t<name>` (modulo hash); commit/tag `-p` and `remix` type are mkit-shaped. `--batch` header is `<hash> <type> <size>`; `<size>` matches the emitted content (byte-exact for blobs, mkit-shaped otherwise); unknown → `<name> missing` |
| `ls-files` | `-s`, `-z`, `--others`, `--ignored`, `--exclude-standard` | same | ✅ | 3 | #251 | `-s` is `<mode> <hash> 0\t<path>` (modulo hash; stage always 0 — no merge stages); tracked/others paths sorted; `-z` raw NUL |
| `ls-tree` | `-r`, `-z` | same | ✅ | 3 | #251 | `<mode> <type> <hash>\t<name>` modulo hash length; `-r` omits tree lines like git; `-z` raw NUL |
| `show-ref` | `--heads`, `--tags` | same | ✅ | 3 | #251 | `<hash> <refname>` sorted, modulo hash length |
| `for-each-ref` | `--format` | same | ✅ | 3 | #251 | default `<objectname> <objecttype>\t<refname>`; `%(atom)` subset: refname[:short], objectname[:short], objecttype (modulo hash length) |
| `show` | object/commit display | same | ✅ | 3 | #251 | commit/remix = header + first-parent diff (diff body byte-matches `git show`); tag peels to target; tree listing; blob contents; defaults to HEAD. Commit/tag *header* diverges (mkit `Identity` + 64-hex), same as `log` |
| `symbolic-ref` | read | same (HEAD) | ✅ | 3 | #251 | reads HEAD only; full target or `--short`; detached → error |
| `symbolic-ref` | write (HEAD → refs/heads/<b>) | same | ✅ | 4 | #254 | repoints HEAD without touching the worktree; target need not exist yet |
| `update-ref` | `[-d] <ref> [<new> [<old>]]` | same | ✅ | 4 | #254 | refs/heads/* + refs/tags/* only; CAS via `<old>` (all-zero = must be absent, update mode only; `-d`'s `<old>` must be concrete); branch moves go through the history-MMR ref-write path; `-d` refuses the current branch (mkit safety divergence) |

## Config & format conventions

| Convention | Git-compatible subset (in scope) | mkit current state | Status | Phase | Issue | Notes |
|------------|----------------------------------|--------------------|--------|-------|-------|-------|
| `config user.name` / `user.email` | accept + round-trip | same | ✅ | 2 | #250 | **non-authoritative**: stored/round-tripped but never feed the signed `Identity` (that stays `user.identity`, still in `REPO_FORBIDDEN_KEYS`). Repo-safe precisely because inert — proven by a no-spoof test |
| `config core.*` | accept inert subset, reject dangerous | same | ✅ | 2 | #254 | inert allowlist (autocrlf/bare/filemode/ignorecase/quotepath/symlinks) stored & round-tripped but **not honored**; dangerous keys (sshCommand/pager/editor/hooksPath/fsmonitor) **rejected**; case-insensitive, lowercased like git |
| `.gitignore` | `**`, anchored `/`, dir-relative, negation, char classes | path-relative; reads `.gitignore` + `.mkitignore` (root) | ✅ | 3 | #256 | v1 subset: path-relative matching, anchored leading `/`, multi-segment patterns, `**` (leading/middle/trailing), `[...]` classes, `\` escapes, negation (last-match-wins), trailing-space trim. Reads both files at the repo **root**; `.mkitignore` applied last (wins). **Deferred:** nested per-directory ignore files, `core.excludesFile` global excludes, escaped trailing spaces |
| abbreviated hashes | short prefix resolution + display | resolve + `log --abbrev[=N]`/`--oneline` | ✅ | 0 | #248 | display side shipped; `rev-parse --short` is Phase 3 |
| `--version` / `-V` | top-level flag | `mkit --version`/`-V` alias `version` | ✅ | 0 | #248 | emits `mkit <X.Y.Z>` (not git's `git version …`) |
| `.git/` repo detection | — | — | 🚫 | — | #254 | non-goal in core; opt-in alias shim only |

---

## Safety divergences (mkit improvements, documented as intentional)

mkit deliberately refuses Git's silent data-loss defaults. These are
**features, not gaps**, and stay even when the command reaches parity:

- `rm` / `restore` / `reset --hard` / `clean` / `stash pop` — refuse to destroy
  locally-modified or untracked content without an explicit `-f`/`--force`.
- `mv` — refuses to overwrite an existing destination without `-f` (matches
  git's `mv` clobber guard).
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

- `status --porcelain=v1` — `XY <path>`, newline-delimited; special-byte
  paths are C-style quoted (git `core.quotePath`), and `-z` emits raw,
  NUL-terminated records. mkit adds `T` for mode-change as the sole
  extension.
- `status --porcelain=v2` — git's richer per-path format: `1 <XY> <sub>
  <mH> <mI> <mW> <hH> <hI> <path>` for tracked changes (octal modes; full
  64-hex BLAKE3 object ids, masked to git's length in the differential
  harness; `<sub>` always `N...`) and `? <path>` for untracked. `-z` raw
  NUL-terminated. No rename `2` lines (mkit has no rename detection); no
  `--branch` header lines. The tracked-side columns match git, including
  `mW = 000000` when a tracked file is shadowed by a directory.
- **Untracked-walk collision (#288, resolved)** — when a tracked path is
  shadowed on disk by a directory (e.g. a tracked file replaced by a
  directory), `status` (v1 and v2) and `clean` now match git: they report
  only the tracked-side deletion and suppress the directory's contents as
  untracked. Note the behavior is **not** uniform across consumers — git's
  `ls-files --others` is raw plumbing and still *lists* the shadowed
  directory's contents; mkit matches that too.
- Plumbing (`rev-parse`, `cat-file`, `ls-files`, `ls-tree`, `show-ref`,
  `for-each-ref`) — exact flag contracts defined in Phase 3 (#251); output
  matches Git modulo 64-hex vs 40-hex hashes.

The **differential parity harness** (`rust/crates/mkit-cli/tests/git_parity_harness.rs`)
runs the same script under real `git` and `mkit` and asserts these contracts
modulo hash length. Cases for not-yet-implemented rows are `#[ignore]`d with
their phase/issue so CI stays green until the feature lands; each phase
un-ignores its rows as it implements them.
