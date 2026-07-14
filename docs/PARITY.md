# mkit ↔ Git parity matrix

> **Authoritative scope gate for git-parity (umbrella #246, scope-definition milestone #247).**
> This file defines *exactly* what "usable like git" means for mkit v1 &mdash; the
> **scope statement, non-goals, machine-output contract, and tracked
> divergences**. The live, per-command status matrix now lives on the web
> **`/parity`** page (see the pointer below). A command is in scope only if it
> is covered by this scope gate. If schedule pressure appears, the lever is
> **renegotiating scope here &mdash; never the safety principles.**

## Scope statement

mkit targets **CLI/UX parity** with Git: every *in-matrix* command and flag a
human or AI agent would type behaves like Git's, while mkit keeps its own
improvements &mdash; **BLAKE3 content addressing, native attestation, and data-loss
safety guards.** This is *not* on-disk or wire interop with real `.git`
repositories; mkit's object/wire formats remain native (a BLAKE3 object store
cannot share bytes with Git's SHA-1/SHA-256 store).

**Scope amendment (git-bridge):** one deliberate, renegotiated exception to
the paragraph above &mdash; the translation bridge: a deterministic **export** to
git mirrors (`mkit git export`, [`SPEC-GIT-BRIDGE`](specs/SPEC-GIT-BRIDGE.md)) and
an **importer-signed import** from git remotes (`mkit git import`,
[`SPEC-GIT-IMPORT`](specs/SPEC-GIT-IMPORT.md)). Neither shares bytes between the
stores (every object is translated, never aliased); bidirectional *sync*
remains a permanent non-goal. Safety principles are untouched.

### Inherent, documented-only divergences (cannot change without dropping BLAKE3)

- **Hash length** &mdash; mkit object IDs are 64-hex BLAKE3, Git's are 40-hex SHA-1.
  A literal Git SHA pasted into mkit will never resolve. mkit matches the UX
  *shape* (short prefixes, abbreviated display) but not the length.
- **Repo marker** &mdash; mkit uses `.mkit/`, not `.git/`. Repo detection by `.git/`
  is **not** added to core; the opt-in `git` alias shim (issue #254 &mdash;
  shipped at `contrib/git-shim/mkit-git`, never installed by default) is the
  only bridge.

## v1 non-goals (explicit)

These are out of scope for v1 parity. Listing them here keeps scope from
creeping; revisit post-v1 if demand warrants.

- Submodules / subtrees
- Hooks (`.git/hooks`, `core.hooksPath`)
- Full refspec grammar (`+a:b`, wildcard push/fetch maps beyond current remotes)
- Wire protocol v2 / smart-HTTP negotiation flags
- `git notes`
- Partial / shallow clone beyond what `clone` already exposes
- `.git/`-format on-disk interop, SHA-1/SHA-256 objects, `git fsck`-compat
  *(exception: the translation bridge, see the scope amendment above &mdash;
  export mirroring and importer-signed import, never byte-sharing or
  bidirectional sync)*
- Shadowing the real `git` binary on `PATH` by default
- `log --graph` ASCII commit-graph rendering (the flag is accepted as a
  no-op for script compatibility). Full byte-parity is unachievable because
  mkit's default `log` body already diverges from git's `commit/Author/Date`
  (mkit `Identity` plus 64-hex ids); an `--oneline --graph` renderer for the
  linear/DAG case is an optional post-v1 follow-up, not a v1 blocker.

---

**Scope amendment (worktrees, #493):** multiple working trees left the
non-goals list &mdash; `mkit worktree add/list/remove/prune` ships with git's
core semantics (linked trees share one object store and the shared
refs; each tree has its own `HEAD`/index/op-state; a branch can be
checked out in at most one tree; gc never prunes objects reachable
from a sibling tree's state). Documented divergences: the **stash is
per-worktree** (git shares `refs/stash` across trees) &mdash; a deliberate
consequence of mkit's worktree-state stash manifest; and
`worktree move`/`lock`/`repair` remain follow-ups outside the minimal
set. On-disk format and discovery are specified in
[`SPEC-WORKTREE.md`](specs/SPEC-WORKTREE.md).

## Per-command status matrix

The live, per-command git-parity matrix &mdash; every porcelain, plumbing, remote,
and config-convention row with its shipped / divergent / non-goal status &mdash; is
rendered on the web **[`/parity`](../apps/web/src/pages/parity.tsx)** page from
[`apps/web/src/lib/parity-data.ts`](../apps/web/src/lib/parity-data.ts). That
page is the single source of truth for *which commands and flags* behave like
git today; keep it current when a command's behavior changes.
[`apps/web/src/lib/parity-sync.test.ts`](../apps/web/src/lib/parity-sync.test.ts)
parses the "Deferred flags" list below and fails CI if a command listed there
is rendered with an unqualified `'parity'` status on the web page.

This document keeps the surrounding **contract** that the web page distills out
(it carries user-facing notes only): the scope gate above, and the
machine-output / safety / divergence sections below.

---

## Safety divergences (mkit improvements, documented as intentional)

mkit deliberately refuses Git's silent data-loss defaults. These are
**features, not gaps**, and stay even when the command reaches parity:

- `rm` / `restore` / `reset --hard` / `clean` / `stash pop` &mdash; refuse to destroy
  locally-modified or untracked content without an explicit `-f`/`--force`.
- `mv` &mdash; refuses to overwrite an existing destination without `-f` (matches
  git's `mv` clobber guard).
- `worktree remove` &mdash; refuses to delete a tree holding local changes,
  untracked files, or an in-progress operation without `--force`, and never
  removes the main tree or the tree the caller stands in.
- `checkout` &mdash; refuses to clobber dirty tracked files or colliding untracked
  files; non-colliding untracked files are preserved (git semantics).
- Repo-local config &mdash; `user.identity` and other security-sensitive keys are in
  `REPO_FORBIDDEN_KEYS` so a hostile clone cannot spoof the signed author or
  redirect signing/transport trust. Git-style `user.name`/`user.email` aliases
  must respect this (user-scope / non-authoritative only).
- History-rewriting commands (`commit --amend`, `reset`, `rebase`) record the
  superseded commit in the recovery log so `gc` keeps it recoverable within the
  retention window (#260 plus #233, shipped).

## Machine-output contract (for agents and scripts)

Outputs that tools parse must be **stable and Git-shaped**, normalized only by
hash length:

- `status --porcelain=v1` &mdash; `XY <path>`, newline-delimited; special-byte
  paths are C-style quoted (git `core.quotePath`), and `-z` emits raw,
  NUL-terminated records. mkit adds `T` for mode-change as the sole
  extension.
- `status --porcelain=v2` &mdash; git's richer per-path format: `1 <XY> <sub>
  <mH> <mI> <mW> <hH> <hI> <path>` for tracked changes (octal modes; full
  64-hex BLAKE3 object ids, masked to git's length in the differential
  harness; `<sub>` always `N...`) and `? <path>` for untracked. `-z` raw
  NUL-terminated. Exact renames emit a `2` `R100` record; no
  `--branch` header lines. The tracked-side columns match git, including
  `mW = 000000` when a tracked file is shadowed by a directory.
- **Untracked-walk collision (#288, resolved)** &mdash; when a tracked path is
  shadowed on disk by a directory (for example, a tracked file replaced by a
  directory), `status` (v1 and v2) and `clean` now match git: they report
  only the tracked-side deletion and suppress the directory's contents as
  untracked. Note the behavior is **not** uniform across consumers &mdash; git's
  `ls-files --others` is raw plumbing and still *lists* the shadowed
  directory's contents; mkit matches that too.
- Plumbing (`rev-parse`, `cat-file`, `ls-files`, `ls-tree`, `show-ref`,
  `for-each-ref`) &mdash; exact flag contracts defined by the plumbing-commands milestone (#251); output
  matches Git modulo 64-hex vs 40-hex hashes.

The **differential parity harness** (`rust/crates/mkit-cli/tests/git_parity_harness.rs`)
runs the same script under real `git` and `mkit` and asserts these contracts
modulo hash length. Cases for not-yet-implemented rows are `#[ignore]`d with
their phase/issue so CI stays green until the feature lands; each phase
un-ignores its rows as it implements them.

## Human-facing output parity

Beyond the machine contract, mkit's **human** output is shaped like git's so
people and agents who learned git's surface aren't surprised:

- **Sync** &mdash; `push`: `Everything up-to-date` / `To <url>` plus ref-update summary
  (`* [new branch]`, `<old>..<new>`, `+ …(forced update)`, `! [rejected] …`);
  `pull`: `Already up to date.` / `Updating <a>..<b>` plus `Fast-forward` plus
  diffstat; `fetch`: `From <url>` plus per-ref summary (silent on no-op);
  `clone`: `Cloning into '<dir>'...`. `fetch --all` / `pull --all` repeat the
  same per-remote summary once per configured remote rather than inventing a
  combined format. `clone`/`push`/`pull`/`fetch` also stream a live,
  **honest** transfer-progress line on stderr while the network transfer
  runs (`Writing objects: N objects, B bytes` / `Unpacking objects: N
  objects`, #711) &mdash; real counts derived from objects actually staged into
  the outgoing pack / unpacked from a downloaded one, shown only when
  stderr is a tty (`--quiet`/`-q` or `MKIT_PROGRESS=never` suppress it;
  `MKIT_PROGRESS=always` forces it). mkit deliberately does **not**
  fabricate git's object-count / delta-compression progress lines
  (`Enumerating/Counting/Compressing objects`, `Total N (delta D)`) &mdash; mkit's
  transport is one-object-per-pack and computes no cross-branch delta
  graph, so those specific numbers would be invented.
- **Local mutation** &mdash; `commit`/`cherry-pick`/`revert`: `[<branch> <hash>]
  <subject>` + diffstat + `create/delete mode`; `merge`: `Merge made by the
  'ort' strategy.` / `CONFLICT (content): …` + `Automatic merge failed; …`;
  `checkout`/`switch`: `Switched to (a new) branch '<n>'` / `Already on '<n>'`;
  `reset --hard`: `HEAD is now at …`; `branch`/`tag` delete confirmations;
  `stash` `Saved working directory …` / `Dropped …`; `rebase` `Successfully
  rebased …`.
- **status** (long format) &mdash; `On branch`, `No commits yet`, word labels
  (`new file:`/`modified:`/`deleted:`/`typechange:`), a separate `Untracked
  files:` section, and `(use "mkit …")` hints.
- **color** &mdash; `diff --color[=always|auto|never]` / `--no-color` colorizes the
  patch with git's palette (bold meta, cyan hunk, green/red lines); default
  `auto` (tty-only, honoring `NO_COLOR`/`CLICOLOR_FORCE`). Color for
  `status`/`log`/`branch` is a tracked **follow-up** (the `term::ColorChoice`
  gating is in place).

**Channel divergence (intentional):** all of the above goes to **stderr** &mdash;
mkit reserves stdout for porcelain/data so `mkit status` stays empty-on-clean
in a pipeline. git puts some of these on stdout; mkit keeps its stderr
convention (documented in `docs/CLI.md`). Object ids stay 64-hex BLAKE3
prefixes (the inherent hash-length divergence).

### Deferred flags (tracked follow-ups, not silently dropped)

These commonly-typed flags are recognized as in-scope for full parity but are
**not yet implemented**; they are larger feature additions best done as their
own change, and are listed here so the gap is explicit:

- `log -p` / `--stat` / `--decorate` / `--all` &mdash; needs the log renderer
  plus walk extensions. (`--author` / `--grep` / `--since` / `--until` /
  `--no-merges` / `--first-parent` shipped: #712 &mdash; `--author`/`--grep`
  are substring matches rather than regexes, and `--since`/`--until`
  use a small explicit date grammar rather than git's `approxidate`;
  both are documented divergences, not gaps.)
- `branch -r` / `-a` / `-u` / `--unset-upstream` &mdash; remote-tracking listing and
  upstream config.
- `add -n` / `--dry-run` &mdash; needs the path-selection pass without the index
  write (a no-op flag would incorrectly stage, so it is deferred rather than
  faked).
- `reset --mixed` "Unstaged changes after reset:" file list &mdash; needs a
  worktree-vs-target-tree diff; `--hard`'s `HEAD is now at …` ships, `--mixed`
  is otherwise silent.
- color for `status` / `log` / `branch` (see above).

### Behavior kept by decision (documented divergences)

- **Empty commit** &mdash; when the index is populated but identical to HEAD (no
  change to record), `mkit commit` silently creates an empty commit, whereas
  git refuses without `--allow-empty`. (A *truly empty* index &mdash; nothing ever
  staged &mdash; still errors, like git.) Left unchanged this PR to avoid surprising
  existing mkit workflows; revisit with `--allow-empty`.
- **Default remote name `default`** &mdash; mkit's flat default remote is `default`,
  not git's `origin` (tracking refs live under `refs/remotes/default/`).
  Renaming is a load-bearing migration, deferred.
- **`mkit blame --ignore-rev-precise`** &mdash; opt-in, content-addressed
  refinement of `--ignore-rev` fall-through (#496). git's `--ignore-rev`
  decides which parent line a fallen-through line should inherit blame from
  by *position*: within a changed hunk it pairs the k-th added line with
  the k-th removed line, purely by offset, because a textual diff is all it
  has. mkit hashes line content, so for a reformat/reorder commit it can
  often identify the line's true surviving origin directly &mdash; including
  cases where the positional pass finds no in-hunk counterpart at all and
  git would credit the noise commit itself. This is the same shape as
  mkit's content-addressed rename detection giving a more reliable `R` than
  git's similarity heuristic in `status`/`diff`. The **default**
  `--ignore-rev` fall-through is git's exact positional guess, byte-for-byte
  &mdash; parity is the contract there; `--ignore-rev-precise` is a conscious,
  documented better-than-git mode, not a changed default.
- **`mkit remote rename` and prefix-nested remote names (#660/#789)** —
  with prefix-nested remote names configured (`a` and `a/b` both exist),
  mkit's rename moves only the named remote's own tracking refs and
  bridge state, leaving a nested sibling's exactly where they are; git's
  own rename (verified on 2.50.1) silently drags the sibling's refs to
  the new name while its config still points at the old one. `remote
  remove` was already per-ref-filtered the same way in git, so mkit only
  reaches parity there. This protection is keyed on the *source* name,
  not the destination: a rename whose destination nests under an
  unrelated configured sibling (`rename a/b a` while `a/x` is configured,
  or `rename a a/b` while `a/b/c` is configured) is outside what the
  source-side check can see, so it fails closed with the standard
  warning rather than merging into the sibling or dragging it along —
  nothing moves, nothing is lost, the sibling is untouched. Deliberate
  boundary, not a bug; see `move_state_dir`'s doc in
  `mkit-cli/src/commands/remote.rs`.
