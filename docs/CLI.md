# mkit &mdash; CLI reference

Short user-facing reference for the `mkit` command. For wire-format
details see the spec docs in this directory (SPEC-OBJECTS, SPEC-INDEX,
SPEC-REFS, SPEC-PACKFILE, SPEC-TRANSPORT, SPEC-SIGNING, SPEC-FASTCDC,
SSH-SECURITY).

## Quick start

```sh
mkit init                          # create .mkit/ in the current directory
mkit keygen                        # generate an Ed25519 signing key
echo hello > README.md
mkit add README.md
mkit commit -m "first commit"
mkit log
```

Commits are signed with your Ed25519 key and stored locally. Your author
Identity is automatically derived from your signing key's public key &mdash;
no config needed.

## Global flags

These are parsed **before** the subcommand (so they apply to repo
discovery too), like git:

- `mkit -C <path> <command>` &mdash; run as if `mkit` were started in `<path>`.
  Repeatable; relative paths resolve against the prior `-C` (git semantics).
- `mkit -c <key>=<value> <command>` &mdash; set a config value for this one
  invocation. It is applied to the **effective** config only (never written
  to disk) and flows through the same enforcement as a per-repo config
  file: security-sensitive keys (`user.identity`, signing/transport trust &mdash;
  the `REPO_FORBIDDEN_KEYS` set) are **refused** with a warning, and
  dangerous `core.*` keys are dropped. So `-c` cannot spoof the signed
  author or redirect trust; use it for inert/allowlisted keys (for example,
  `-c user.email=ci@example.com`).
- `mkit --no-pager` / `-P` / `--paginate` &mdash; accepted **no-ops**. mkit never
  paginates (better for agents and scripts); the flags exist so defensive
  invocations like `mkit --no-pager log` don't error.

`--git-dir`, `--work-tree`, and `--exec-path` are **non-goals** &mdash; mkit uses
the `.mkit/` marker and has no split work-tree / exec-path model.

## Subcommand reference

Working-tree commands:

- `mkit init` &mdash; create a new repository in `.mkit/`.
- `mkit add [-A|-u] [-f] [-p] <path>...` / `mkit add .` &mdash; stage files for the
  next commit. Multiple pathspecs may be given. `.` stages every non-ignored
  file under the current directory. `-A`/`--all` stages every change in
  the worktree including deletions of tracked files (takes no path
  arguments). `-u`/`--update` restages only already-tracked files &mdash;
  updating modified ones and recording deletions &mdash; without adding
  untracked paths (takes no path arguments). `-A` and `-u` are mutually
  exclusive. An explicitly-named path that is ignored (by
  `.gitignore`/`.mkitignore`) is refused unless `-f`/`--force` is given
  (git parity); already-tracked paths are never subject to ignore.
  `-p`/`--patch` interactively presents each hunk between the staged (or
  HEAD) blob and the worktree file and stages only the accepted ones &mdash;
  per hunk: `y` stage, `n` skip, `a` stage this and all later hunks, `d`
  skip this and all later hunks, `q` quit (keeping hunks already chosen).
  It requires explicit path arguments, is incompatible with `-A`/`-u`,
  and operates on regular text files only: a binary file is **skipped**
  with a message (the command still succeeds), and symlinks/directories
  are **refused**. An explicitly-named ignored path is refused unless
  `-f`/`--force` (like plain `add`); a path that escapes the repo through
  a symlinked parent is refused. The hunk view and prompts go to stderr;
  `s` (split) and `e` (manual edit) are follow-ups.
- `mkit rm [--cached] [-r|--recursive] [-f|--force] <path>...` &mdash; remove
  paths and stage the deletion for the next commit. By default this
  **deletes the worktree file(s)** and stages the removal; now-empty
  parent directories are pruned. Multiple pathspecs are accepted.
  - `--cached` &mdash; stage the removal only, leaving the worktree file(s)
    on disk (the historical mkit behavior).
  - `-r`/`--recursive` &mdash; required to remove a directory and everything
    under it; without it, a directory pathspec is refused.
  - `-f`/`--force` &mdash; remove worktree files even when their content has
    diverged from the staged blob. Without `--force`, `rm` refuses to
    destroy a locally-modified tracked file (a dirty-worktree guard in
    the spirit of the #176 restore guards); use `--cached` to keep the
    file or `--force` to discard the local changes.
- `mkit mv [-f|--force] <source>... <dest>` &mdash; move or rename a tracked
  path and stage the change. `mv <src> <dst>` renames `src` to `dst`, or
  moves it into `dst` when `dst` is an existing directory; with more than
  one source, `<dest>` must be an existing directory. The worktree file is
  moved and the index updated (the source staged as removed, the
  destination staged with the source's blob and mode &mdash; content is
  unchanged, so the existing object is reused). Because the blob keeps the
  same content id at the new path, `mkit status` / `mkit diff` detect the
  move as an exact rename and report git's `R` by default; `--no-renames`
  shows the underlying deletion plus addition instead.
  - `-f`/`--force` &mdash; overwrite an existing destination. Without it, `mv`
    refuses to clobber an existing path (matching git's `mv` guard) &mdash; an
    mkit data-loss guard; a dangling symlink at the destination counts as
    existing (git refuses that too). A missing or untracked source is
    refused. All sources are validated before any move, so a bad source in
    a batch never leaves the worktree half-moved. As an mkit safety
    divergence, a destination that escapes the repository through a
    symlinked parent directory is refused (git would silently follow it).
  - **Directory sources** are supported: `mv dir newdir` renames the
    directory, and `mv dir existing-dir/` moves it *into* the target
    (becoming `existing-dir/dir`). The directory is renamed in a single
    filesystem operation, so untracked files inside it travel with it
    (exactly like `git mv`), and every tracked file beneath it is restaged
    at its new path (each a delete plus add, per the no-rename-detection note
    above). The repo-escape and validate-before-move guards all apply.
    A directory move **refuses a pre-existing destination even with `-f`**
    (recursively removing it would strand its tracked files in the index and
    delete untracked ones &mdash; git won't clobber a directory with `mv` either),
    rejects **overlapping sources** up front (`mv dir dir/file <dest>`), and
    refuses moving a directory into itself.
- `mkit status [--porcelain[=v1|v2]] [-s|--short] [-z]` &mdash; show staged and
  unstaged changes. Default-mode prose (banner plus section headers plus per-file
  lines) goes to **stderr**; stdout is reserved for machine output.
  `-s`/`--short` is an alias for `--porcelain=v1`; both select the same
  renderer. Porcelain emits one entry per line in `git status --porcelain=v1`
  format (`XY <path>`, with mkit's `T` for `ModeChanged` as the only
  non-git extension). `--porcelain=v2` selects git's richer per-path
  format &mdash; `1 <XY> <sub> <mH> <mI> <mW> <hH> <hI> <path>` for tracked
  changes (octal modes; full 64-hex BLAKE3 object ids; `<sub>` always
  `N...`) and `? <path>` for untracked &mdash; with no rename (`2`) records and
  no `--branch` header lines. Paths with special bytes are **C-style quoted**
  (matching git's default `core.quotePath`). `-z` (which implies
  porcelain) NUL-terminates records and emits **raw, unquoted** paths &mdash;
  the round-trip-safe form for paths containing newlines or other special
  bytes. Empty stdout means clean.
- `mkit diff [--staged|--cached] [--name-only|--name-status|--stat] [--merge-base] [-w|-b] [-U<n>] [-z] [<rev> [<rev>] | <a>..<b> | <a>...<b>] [<path>...]`
  &mdash; show changes as a unified patch. With no arguments, compares the HEAD
  tree to a fresh worktree snapshot. `--staged` (alias `--cached`) compares
  the HEAD tree to the staged index tree &mdash; the change `mkit commit`
  would record. A single revision compares that revision against the
  worktree; two revisions (or an `<a>..<b>` range) diff the two
  resolved trees directly; a symmetric `<a>...<b>` range diffs the
  **merge base** of `a` and `b` against `b` (git semantics). `--merge-base`
  is the flag spelling of that symmetric range: with two revisions it
  diffs `merge-base(a, b)` against `b`, and with one revision it diffs
  `merge-base(<rev>, HEAD)` against the worktree (like `git diff
  --merge-base`). Revisions may be refs, commit hashes, short
  hashes, or `HEAD~n` (a raw 64-hex tree hash also works, since it
  resolves to itself). Any remaining positional arguments are pathspecs
  that limit the output to entries at or below them. The default output is a
  git-shaped unified diff: a `diff --git a/<path> b/<path>` header per changed
  path (with `new file mode`/`deleted file mode`/`old mode`/`new mode` lines,
  an `index <old>..<new> <mode>` line, and `--- a/<p>`/`+++ b/<p>` using
  `/dev/null` for adds/deletes) followed by `@@`-delimited hunks (or
  `Binary files … differ` for non-text blobs). The hunk algorithm is the
  Myers diff with git's change-compaction, so the output **byte-matches
  `git diff`** apart from the abbreviated `index` ids, which are BLAKE3
  prefixes rather than SHA-1 (git's optional indent heuristic is not
  applied).
  `--name-only` instead lists one changed path per line; `--name-status`
  prefixes each with a status letter (`A`/`D`/`M`; `T` marks an mkit mode
  change). `--stat` shows a diffstat: one `<name> | <count> <graph>` row
  per file (name column padded, `+`/`-` graph scaled to the terminal
  width like `git diff --stat`, honoring `COLUMNS`; default 80) followed
  by a ` N files changed, … insertions(+), … deletions(-)` summary; binary
  files render `Bin <old> -> <new> bytes`. In `--name-only`/`--name-status`
  /`--stat` modes special-byte paths are C-style quoted (git
  `core.quotePath`); `-z` instead NUL-terminates records and emits raw
  paths (in `--name-status -z` the status letter and path are each their
  own NUL-terminated field). `-z` is only valid with `--name-only` /
  `--name-status`.
  `--exit-code` exits 1 when there are differences (0 when none), still
  printing the patch; `--quiet` is the same but prints nothing &mdash; the CI
  idiom for "fail if the tree changed". `--color[=always|auto|never]`
  colorizes the patch (git's palette: bold metadata, cyan hunk headers,
  green additions, red deletions); the default `auto` colorizes only on a
  tty (honoring `NO_COLOR`/`CLICOLOR_FORCE`), and `--no-color` forces it
  off. (Color for `status`/`log`/`branch` is a tracked follow-up.)
  `-w`/`--ignore-all-space` ignores whitespace when comparing lines (a
  line that differs from its counterpart only in whitespace shows as
  unchanged context &mdash; like git); `-b`/`--ignore-space-change` is the
  weaker form, where differing *amounts* of whitespace compare equal but a
  line with whitespace where the other side has none still differs. `-w`
  wins if both are given. Either way the printed hunk lines show their own
  real (unmodified) bytes &mdash; only line *comparison* changes. `-U<n>` /
  `--unified=<n>` sets the number of unchanged context lines around each
  hunk (default 3, matching git's `-U3`).
- `mkit worktree add <path> [<commit-ish>]` / `list [--porcelain]` /
  `remove [--force] <path>` / `prune [--dry-run]` &mdash; manage linked working
  trees (git-worktree parity, #493). Linked trees share the one object
  store and the shared refs; each tree keeps its own `HEAD`, index,
  in-progress-operation state, and stash (note: git shares the stash
  across worktrees; mkit's stash is deliberately per-tree). `add` with no
  `<commit-ish>` creates a new branch named after the path's basename
  (refusing if it already exists); with a branch name it checks that
  branch out, and with any other revision the new tree starts on a
  detached HEAD. A branch may be checked out in at most one tree at a
  time &mdash; `worktree add`, `checkout`/`switch`, `branch -d`, and
  `branch -m` all refuse with `already checked out at '<path>'`, naming
  the holding tree (branch moves are single-writer by design; see
  SPEC-HISTORY-PROOF). `remove` refuses when the tree has local changes,
  untracked files, or an operation in progress unless `--force` is
  given, and never removes the main tree or the tree you are standing
  in. `prune` deletes registry entries whose tree has vanished
  (`--dry-run` previews). On-disk: a linked tree's `.mkit` is a pointer
  *file* (`mkitdir: <path>`) into the main repository's
  `.mkit/worktrees/<id>/`. Interim limit: `mkit gc` refuses to run while
  linked worktrees exist (cross-tree root collection is a tracked
  follow-up phase of #493) &mdash; remove or prune them first.
- `mkit stash [save|list|pop|apply|drop|clear|show] [--format=json]` &mdash;
  save/restore WIP
  changes. `apply` restores an entry without removing it; `clear` drops
  every entry. `pop`/`apply`/`drop`/`show` select an entry by index
  (default `0`), accepting either a bare `N` or the `stash@{N}` form
  printed by `stash list`. `pop`/`apply` accept `--index`, which also
  restores the **staged** state recorded when the stash was created (like
  `git stash pop --index`), not just the worktree changes. `save` records
  that staged snapshot as the stash commit's second parent (git-style
  `[HEAD, index]`) &mdash; no on-disk manifest change, and it stays gc-reachable
  through the stash commit. The snapshot is the **serialized index** (a blob
  in the index commit's wrapper tree, paired with a content subtree that
  keeps staged blobs gc-reachable), so `--index` restores the index exactly,
  **including staged deletions** (`mkit rm`-staged) &mdash; which a tree could not
  encode. Stashes created before this feature carry no index snapshot, so
  `--index` is a no-op for them (with a note).
  `--format=json` (a global flag, valid after any subcommand) emits a
  machine-readable result to stdout: on `list`, JSONL with keys `index`,
  `hash`, `message` (mirroring `branch --format=json`); on
  `save`/`pop`/`apply`/`drop`/`clear`, a single `{"ok":true,"kind":"…",
  ...}` object; on failure, `{"ok":false,"error":"…"}`.
- `mkit sparse-checkout` &mdash; manage sparse checkout patterns.

History / commits:

- `mkit commit [-a|--all] [--amend] [--author <spec>] [-m <msg> | -F <file>]
  [--format=json]`
  &mdash; create
  a signed commit from the staging index. The index is built by `mkit
  add` / `mkit rm`; `commit` with an empty index is an error. Use `mkit
  add .` to snapshot the whole worktree before committing. `-m` supplies
  the message inline; `-F`/`--file` reads it from `<file>` (like `git
  commit -F`), with `-` meaning standard input &mdash; `-m` and `-F` are
  mutually exclusive, and omitting both launches `$EDITOR`. `-a` / `--all`
  follows Git's tracked-only shortcut: it stages modified tracked files
  and tracked deletions before committing, but does not add untracked
  files. `mkit commit -am <msg>` is accepted as shorthand for `-a -m
  <msg>`. `--author <spec>` overrides the recorded author Identity for
  this commit (highest precedence &mdash; above `user.identity` config and the
  signing-key-derived default). The `<spec>` grammar is `ed25519:<hex>`
  (32-byte public key), `did:key:<multibase>` (the multibase payload after
  `did:key:`, for example `did:key:z6Mk…`, stored verbatim &mdash; must be a non-empty
  printable-ASCII multibase string), or `opaque:<bytes>` (raw UTF-8); note
  this differs from the `user.identity` *config* grammar (which also accepts
  `mid:<N>` and raw encoded hex).
  The signature is always produced by your signing key regardless of the
  recorded author.
  `--amend` **replaces HEAD** instead of adding a new commit: the new
  commit re-uses HEAD's parent(s) as its own parent(s), takes its tree
  from the index, and is re-signed; the branch is moved to it and the
  move is recorded in the ref-history journal. Without `-m` the previous
  commit's message is reused (no editor is launched). The superseded
  commit is recorded in the recovery log so it stays recoverable, and is
  reclaimed by `mkit gc` once it falls out of the retention window.
  After `mkit merge --no-commit` (or a merge you have just resolved),
  `commit` notices the recorded `MERGE_HEAD` and records a **two-parent
  merge commit** rather than an ordinary single-parent one.
  On success `commit` prints git's summary on stderr: `[<branch> <hash>]
  <subject>` (with `(root-commit)` for the first commit, `detached HEAD`
  when detached) followed by a diffstat and `create/delete mode` lines;
  `-q`/`--quiet` suppresses it. `-S`/`--gpg-sign[=<keyid>]` and
  `--no-verify` are accepted **no-ops** (mkit always signs and has no
  hooks); `--no-edit` matches mkit's default amend behavior.
  `--format=json` additionally emits one JSON object to stdout on success:
  `{"ok":true,"hash":"<64-hex>","branch":"<name>|null",
  "parents":["<64-hex>",...],"tree":"<64-hex>","subject":"...",
  "is_merge":<bool>,"is_root":<bool>}`.
- `mkit log [--oneline] [--abbrev-commit] [--abbrev[=N]] [--format=json] [--graph] [--author <pattern>] [--grep <pattern>] [--since <date>] [--until <date>] [--no-merges] [--first-parent] [-n N] [<rev> | <A>..<B> | <A>...<B>]` &mdash; show
  commit history. With no argument the walk starts at `HEAD`; an optional
  `<rev>` starts it there instead, a range `<A>..<B>` shows commits
  reachable from `B` but not from `A` (an empty side means `HEAD`, so `A..`
  is `A..HEAD` and `..B` is `HEAD..B`), and a symmetric range `<A>...<B>`
  shows commits reachable from `A` or `B` but not their common ancestors
  (the merge base). Commits are ordered
  reverse-chronologically with a topological tie-break (a parent never
  precedes a child) &mdash; git's `--date-order`, which matches git's default for
  linear and monotonic-timestamp history (it can differ only on merge DAGs
  with skewed/imported timestamps). The default format prints the **full commit message
  body**, indented by four spaces, and renders the timestamp as a stable
  UTC date in the form `YYYY-MM-DD HH:MM:SS +0000`. `--oneline` condenses
  each commit to `<abbrev-hex> <title>`. `--abbrev-commit` abbreviates the
  commit id in the default format too, and `--abbrev[=N]` sets the
  abbreviation length (bare `--abbrev` and `--oneline` default to 7; the
  length is clamped to `[4, 64]`). Note the abbreviated id is a BLAKE3
  prefix, so it is longer than a Git SHA-1 prefix of the same `N`.
  `--format=json` emits JSONL (one JSON
  object per commit, newest first) with keys `hash`, `parents`, `tree`,
  `author`, `timestamp`, `title`, `message`; the `timestamp` stays a raw
  Unix-seconds integer for machine consumption. **`--graph` is accepted
  for compatibility but is currently a no-op** (no ASCII graph is drawn);
  see "Divergences from Git" below.
  `--author <pattern>` and `--grep <pattern>` filter the walk by a plain
  **substring** match &mdash; `--author` against both the short display form
  (the `Author:` line) and the full `kind:hex`/`mid:N` form
  (`--format=json`'s `author` field); `--grep` against the full commit
  message (title plus body). This is intentionally not a regex: unlike git,
  mkit identities are opaque (Ed25519 keys, `mid:N` numbers, DID keys),
  not free-text `Name <email>`. `--since <date>`/`--until <date>` bound
  the commit timestamp; accepted forms are `@<unix-seconds>`,
  `now`/`today`/`yesterday`, `<N> <unit> ago`
  (second/minute/hour/day/week/month/year), `YYYY-MM-DD` (midnight UTC),
  and `YYYY-MM-DD HH:MM:SS` / `YYYY-MM-DDTHH:MM:SS[Z]` &mdash; a small, explicit
  grammar, not git's full natural-language `approxidate`. `--no-merges`
  hides merge commits (more than one parent) from the output without
  changing the walk; `--first-parent` is stronger &mdash; it follows only each
  commit's first parent, so a merged side branch never enters the walk at
  all. All of these filters apply **before** `-n <limit>`, so `-n` caps
  the filtered result, matching git.
- `mkit reflog [<ref>] [--format=json] [-n N]` &mdash; **read-only** view of a
  branch's recorded movement history. Defaults to the branch `HEAD`
  points at (a detached `HEAD` needs an explicit `<ref>`, since the
  ref-history journal is keyed per-branch). Walks the branch tip's
  first-parent chain newest-first, addressing each entry `<ref>@{N}`
  (`@{0}` is the current tip). The underlying journal (the per-branch
  commit-history MMR written on every branch advance) stores a count of
  advances and a tamper-evident root, but its leaf digests cannot be
  decoded back to commit hashes &mdash; so the listed hashes are reconstructed
  from the reachable chain. On a build with `--features history-mmr`
  each entry is additionally cross-checked against the journaled MMR root
  via an inclusion proof, and the recorded-advance count is printed.
  `--format=json` emits JSONL with keys `ref`, `selector`, `index`,
  `hash`, `title`, `journaled` (`true`/`false`/`null`). **This is not a
  full Git reflog:** `@{N}` indexes the reachable first-parent chain, so
  commits superseded by `commit --amend` or a reset are not listed; see
  "Divergences from Git" below.
- `mkit blame [--format=json | --porcelain | --line-porcelain] [-w] [-M] [-C]
  [--ignore-rev <rev>] [--ignore-revs-file <file>] [--ignore-rev-precise]
  [--first-parent] [--reverse] [-L <start>,<end>] [<rev>] <file>` &mdash;
  show line-level commit attribution. `--porcelain` emits git's grouped
  machine format &mdash; a per-line header (`<id> <orig> <final> [<group-len>]`)
  followed by a metadata block (author/committer, `author-time`/`-tz`,
  `summary`, a `boundary` marker on a file-history root, and `filename`) once
  per commit, with each content line tab-prefixed; `--line-porcelain` repeats
  the full block for every line. mkit's documented divergences (consistent
  with `--format=json` and the `log` precedent): object ids are 64-hex;
  `author`/`committer` carry mkit's Identity string, not `Name <email>`
  (`author-mail`/`committer-mail` are empty and both `*-tz` are `+0000`,
  since mkit commits store a single UTC author plus timestamp); `filename` is
  the `-C` copy source on a cross-file copy; git's out-of-scope `previous`
  line is not emitted. `-w` ignores whitespace when
  matching lines across revisions (like `git blame -w`, ignoring *all*
  whitespace), so a whitespace-only edit &mdash; reindent, tab↔space, spacing
  tweak &mdash; doesn't reattribute the line; output still shows the file's
  current bytes. `-M` detects lines moved *within* the file and `-C` lines
  copied *from other files* (like `git blame -M`/`-C`; `-C` implies `-M`,
  and repeating it widens the search: `-C` covers files changed in the
  commit, `-C -C` every file in the commit that creates the blamed file,
  and `-C -C -C` every file in any commit &mdash; a whole-tree search at each
  walk step, so a block copied from an unmodified source is still found).
  Detection is block-based: the
  longest contiguous moved/copied block above git's default thresholds (20
  alphanumeric characters for `-M`, 40 for `-C`) is credited to its origin,
  so a moved block next to genuinely-new lines is still split out, and
  combined with `-w` a block copied with a whitespace change is still
  detected. The inline numeric forms override the default threshold, like
  git: `-M<num>`/`-C<num>` (glued, no space) set the minimum alphanumeric
  character count, and a numeric `-C<num>` still counts toward the `-C`
  level (so `-C40 -C` is level 2 with threshold 40). The percent form
  `-M<num>%`/`-C<num>%` is accepted for git-surface compatibility, but
  because mkit's block detector has no similarity-ratio model the number is
  treated as the same char-count threshold &mdash; a deliberate, `log`-consistent
  divergence. Remaining divergence from git: a single unmatched run over
  10,000 lines is matched only as a whole, not by sub-block. Move/copy
  detection is merge-aware and
  implements git's per-parent mechanism (pinned against git 2.50.1): at a
  merge, every **real** parent is offered the unexplained lines in commit
  order, first-found-wins. A parent that contains the blamed file (and
  whose copy of it isn't byte-identical to an earlier parent's) supplies
  the within-file `-M` source, and its `-C` copy candidates are the files
  *modified between that parent and the merge*; a parent without that &mdash;
  because it deleted the file, holds a duplicate of an earlier parent's
  copy, or the file is newly added by the merge &mdash; has no `-M` source, and
  with `-C -C` its **entire tree** is searched instead. Everyday
  consequences (each pinned by a test with its git recipe): a block copied
  in from a side branch is credited to that side; an *unchanged* source
  file on the first parent is invisible (the block stays on the merge)
  while the same source *modified* in the merge does credit the first
  parent; a parent that deleted the blamed file can still supply the copy
  source; and for a file newly added by the merge every real parent is
  searched, first included. `-M` and `--ignore-rev` treat every relevant
  parent uniformly (first-parent-wins); under `--first-parent` all of the
  above runs against the first parent only.
  `--ignore-rev <rev>` (repeatable) and `--ignore-revs-file <file>` skip
  "noise" commits &mdash; mass reformats, license-header sweeps, renames &mdash; during
  attribution, like `git blame --ignore-rev`: a line that would be credited
  to an ignored commit falls through to the commit that previously changed
  it, while a line the ignored commit genuinely inserted stays put.
  `--ignore-rev` accepts any revision (short hash, ref, `HEAD~2`);
  `--ignore-revs-file` entries must be full hex object names, one per line,
  with blank lines and `#` comments (including inline) skipped &mdash; both
  matching git. (mkit does not auto-read a `.git-blame-ignore-revs` file or
  a `blame.ignoreRevsFile` config key; pass the file explicitly.)
  `--ignore-rev-precise` (mkit-only; requires `--ignore-rev` or
  `--ignore-revs-file` &mdash; a usage error otherwise) refines that fall-through
  with content matching instead of git's positional per-hunk guess: git
  pairs the k-th added line of a changed hunk with the k-th removed line
  purely by position, so a reformat/reorder can land a line on the wrong
  parent counterpart (or leave it credited to the noise commit as a
  "genuine insertion" when the hunk has no local counterpart at all); mkit
  hashes line content, so it searches the **whole parent file** &mdash; not just
  the enclosing hunk &mdash; for the line's true surviving origin, and only
  overrides the positional guess when content evidence disagrees with it.
  Composes with `-w` (matching is over `-w`-normalized keys, same as
  `-M`/`-C`) and with merges (the search runs per relevant parent,
  first-parent-wins, same as the positional default). This is a
  **documented divergence** &mdash; the default `--ignore-rev` fall-through stays
  byte-identical to git; see "Divergences from Git" below. Blame is
  **merge-aware by default** (like `git blame`): at a merge, a line is
  credited to whichever parent's side actually wrote it, so a line merged in
  from a side branch is attributed to its authoring commit rather than the
  merge. `--first-parent` (like `git blame --first-parent`) follows only
  each commit's first parent, so such a line is instead credited to the
  merge commit &mdash; the older linear-history behavior; it composes with
  `-w`/`-M`/`-C`/`--ignore-rev`. `-L`
  restricts output to a line range &mdash;
  `<start>,<end>`, `<start>,+<n>` (n lines forward), `<start>,-<n>` (n
  lines back, ending at `<start>`), `<start>,` (to EOF), `,<end>` (from
  start of file), or a bare `<start>` (to EOF); bounds are 1-based and
  inclusive, an inverted range is swapped, and an over-long end is
  clamped to EOF, matching `git blame -L`. An optional
  `<rev>` (a ref, hash, or `HEAD~2`-style spec) blames the file as of
  that revision instead of `HEAD`. `--reverse <start>..<end>` walks
  history *forward* instead of backward (like `git blame --reverse`):
  it blames the `<start>` version of the file and attributes each line to
  the **last** commit in the range in which it still existed &mdash; useful for
  "which commit removed or last touched this line." `<start>..` defaults
  `<end>` to `HEAD`; an explicit `<start>` is required (mkit reports a
  clear error for a missing range or open start, where `git` prints a
  cryptic "dig up from" message &mdash; a deliberate divergence, like the `-L`
  diagnostics). A line that never survives a step stays on `<start>`
  (git marks such lines with a leading `^`; mkit's tab format carries no
  `^`, consistent with its existing boundary-marker omission). `-w` and
  `-L` compose with `--reverse`. Default emits
  `<short12>\t<line_num>\t<text>` per line; `--format=json` emits JSONL
  with keys `hash`, `line_num`, `author`, `timestamp`, `text`.
- `mkit verify <rev> [--trusted] [--trust-roots <path>]` &mdash; verify the
  signature on a commit, remix, or signed tag. `<rev>` is an object
  hash, a branch/tag name, or `HEAD`; a tag name resolves to its
  annotated-tag object when one exists. By itself this only proves the
  object's own embedded `signer` produced the signature &mdash; it does NOT
  check `signer` against any allow-list, so a signature from an
  unrecognized key verifies identically to one from a key you actually
  trust. Pass `--trusted` (or `--trust-roots <path>`) to additionally
  cross-check `signer` against the trust-roots registry `mkit trust`
  manages, failing closed (nonzero exit, distinct from a bad-signature
  failure) on an unlisted signer. `--trust-roots` defaults to
  `$XDG_CONFIG_HOME/mkit/trust-roots.toml`; an in-repo path is refused
  unless passed explicitly (see `mkit trust` below and
  `docs/THREAT-MODEL.md` §5).
- `mkit cat <hash>` &mdash; display an object by its hash.
- `mkit hash <file>` &mdash; hash a file and store it as a blob.
- `mkit tree` &mdash; snapshot the working directory as a tree object.

Read-only plumbing (object/ref inspection, for scripts and agents):

- `mkit cat-file (-t | -s | -p) <object>` / `mkit cat-file --batch` &mdash;
  inspect a stored object (like `git cat-file`). `-t` prints the type
  (`blob`/`tree`/`commit`/`tag`; mkit's `remix` is the one non-git type);
  `-s` prints the size (the content byte length for blobs &mdash; matching git &mdash;
  but mkit's serialized size for trees/commits, which differs); `-p`
  pretty-prints (a blob's raw bytes, a tree as `<mode> <type> <hash>\t<name>`
  lines, or a readable commit/tag summary). `--batch` reads object names
  from stdin (one per line) and emits, per object, a `<hash> <type> <size>`
  header line followed by the content and a trailing newline (`<name>
  missing` for unknown objects); `<size>` is the byte length of the content
  that follows, so blobs are byte-exact with git while commit/tree content
  (and its size) is mkit-shaped, as with `-p`. `<object>` resolves through
  the shared revspec grammar (hash, ref, `HEAD`, `HEAD~n`/`^`).
- `mkit show [--stat] [<object>...]` &mdash; display objects (like `git show`),
  defaulting
  to `HEAD`. A **commit**/**remix** prints a header (`commit <hash>`,
  `Author:`, `Date:`, message indented four spaces &mdash; matching `mkit log`)
  followed by the unified diff against its first parent; that diff body is
  produced by the same code as `mkit diff`, so `show <commit>` is
  byte-identical to `diff <parent> <commit>` (modulo abbreviated `index`
  ids). `--stat` shows a diffstat instead of the full patch for
  commit/remix objects (like `git show --stat`); non-commit objects are
  shown as usual. A **tag** prints its header then the peeled target object; a **tree**
  is listed as `<mode> <type> <hash>\t<name>` lines; a **blob** prints its raw
  contents. Multiple objects may be given. As with `log`, the commit/tag
  header carries mkit's signed `Identity` and 64-hex BLAKE3 ids, so those
  header lines diverge from git's `Author: Name <email>` / 40-hex form (the
  same documented divergence as `log`); the diff body, tree listing, and blob
  output match git. `<object>` resolves through the revspec grammar.
- `mkit ls-tree [-r] [-z] <tree-ish> [<path>...]` &mdash; list a tree's entries
  as `<mode> <type> <hash>\t<name>` (git octal modes
  `100644`/`100755`/`120000`/`040000`; the hash is 64-hex BLAKE3). `-r`
  recurses, showing leaf blobs with full paths and omitting tree lines
  (like git); `-z` NUL-terminates records and emits raw paths (otherwise
  special-byte paths are C-style quoted). Trailing pathspecs limit the
  listing.
- `mkit ls-files [-s] [-z] [--others] [--ignored] [--exclude-standard]` &mdash;
  list files in the index or untracked worktree files (like
  `git ls-files`). Default prints tracked paths, one per line, sorted. `-s`
  (`--stage`) prints stage info as `<mode> <hash> <stage>\t<path>` (git
  octal mode; `<stage>` is always `0` &mdash; mkit has no merge stages). `--others`
  lists untracked worktree files instead; `--exclude-standard` drops
  ignored ones (per `.gitignore`/`.mkitignore`) and `--ignored` inverts to
  show only ignored files (`--ignored` requires `--others`, like git's `-i`
  outside an
  `-o`/`-c` selection). `-z` NUL-terminates records and emits raw paths
  (otherwise special-byte paths &mdash; including under `-s` &mdash; are C-style quoted).
- `mkit rev-parse [--verify] [--short[=N]] [--abbrev-ref] [--show-toplevel] [<rev>...]`
  &mdash; resolve revisions to object ids. Bare `<rev>...` prints each resolved
  64-hex id; `--short[=N]` abbreviates (default 7, a BLAKE3 prefix);
  `--abbrev-ref HEAD` prints the current branch; `--verify` is accepted for
  git-script compatibility but is a **no-op** &mdash; mkit always errors on an
  unresolvable revision, with or without it; `--show-toplevel` prints the
  repository root (the directory holding `.mkit`, found by walking up from
  cwd).
- `mkit rev-list [--count] <rev>` &mdash; list the commit ids reachable from
  `<rev>` in reverse-chronological (topological) order, one 64-hex id per
  line; `--count` prints the number instead. Reuses `log`'s walk so the
  order matches. (Range/filter forms are a follow-up.)
- `mkit merge-base [--is-ancestor] <a> <b>` &mdash; print the best common
  ancestor of two commits (64-hex; exit 1 with no output when there is
  none). `--is-ancestor` tests whether `<a>` is an ancestor of `<b>`,
  exiting 0 (yes) or 1 (no) with no output. Reuses the merge engine.
- `mkit show-ref [--heads] [--tags]` &mdash; list refs as `<hash> <refname>`,
  sorted by ref name. Default shows `refs/heads/*`, `refs/tags/*`, and
  any `refs/remotes/*` tracking refs; `--heads`/`--tags` filter to one
  namespace.
- `mkit for-each-ref [--format=<fmt>] [<pattern>...]` &mdash; iterate refs
  (heads, tags, and remote-tracking refs), sorted by ref name (like
  `git for-each-ref`). The default line
  is `<objectname> <objecttype>\t<refname>`. `--format` substitutes
  `%(atom)` tokens (`refname`, `refname:short`, `objectname`,
  `objectname:short`, `objecttype`; `%%` is a literal `%`); the object id is
  64-hex BLAKE3. Optional `<pattern>` arguments filter to refs whose full
  name equals or is under each pattern.
- `mkit symbolic-ref [--short] <name> [<ref>]` &mdash; read or write a symbolic ref
  (currently only `HEAD`), like `git symbolic-ref`. Without `<ref>`, prints
  the full target (`refs/heads/main`), or just the branch name with `--short`;
  errors when HEAD is detached / not symbolic. With `<ref>` (which must be
  under `refs/heads/`), repoints HEAD at that branch &mdash; the plumbing form,
  which does **not** touch the worktree; the branch need not exist yet
  (matching git).
- `mkit update-ref [-d] <ref> [<newvalue> [<oldvalue>]]` &mdash; create, update, or
  delete a ref under `refs/heads/` or `refs/tags/` (other namespaces are
  rejected), like `git update-ref`. `<newvalue>`/`<oldvalue>` resolve through
  the revspec grammar. With no `<oldvalue>` the write is unconditional; with
  one it is a compare-and-swap that fails unless the ref currently holds that
  value. In update mode an all-zero `<oldvalue>` requires the ref to be absent
  (git's create-only form). `-d` deletes the ref (optionally verifying a
  **concrete** `<oldvalue>` first &mdash; an all-zero value is rejected, since a ref
  asserted absent has nothing to delete); deleting a branch refuses the
  currently checked-out one &mdash; an mkit safety divergence (git's plumbing would,
  leaving HEAD dangling).
- `mkit ref list [--pattern <glob>]` &mdash; print every ref's full name and
  resolved hash, one `<refname> <hash>` line per ref, sorted lexicographically
  by name. Covers `refs/heads/*`, `refs/tags/*`, and `refs/remotes/*/*` &mdash; the
  same read scope as `show-ref`/`for-each-ref`. An empty repo (no commits yet)
  prints nothing and still exits 0. `--pattern` filters to full ref names
  matching a shell glob (`*` spans `/`, `?` matches one char, `[...]` is a
  character class &mdash; the same matcher as `branch --list`/`tag -l`). This is
  the stable inspection surface for refs (#652): scripts should use it
  instead of `ls`/`cat` on `.mkit/refs/`, which is not a supported interface.
- `mkit ref cat <name>` &mdash; print the resolved hash for exactly one ref,
  following `HEAD`'s symbolic indirection (`HEAD` is mkit's only symbolic
  ref). `<name>` must be a fully-qualified ref name &mdash; `refs/heads/<b>`,
  `refs/tags/<t>`, `refs/remotes/<r>/<b>` &mdash; or the literal `HEAD`; these are
  exactly the names `ref list` prints, so the two commands round-trip.
  Errors (exit 1) if the ref does not exist, or if HEAD is symbolic but its
  target branch has no commit yet.

Attestations:

- `mkit attest [--commit <hash>] [--algorithm <alg>] [--signer <kind>]
  [--predicate-type <uri>] [--predicate-file <path>]
  [--external-signer-arg <V>]... [--additional-signer "<spec>"]...` &mdash;
  produce a signed DSSE attestation for a commit. The signed payload is
  an [in-toto v1 Statement](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
  carrying the commit hash as `subject` and the user-supplied
  predicate, wrapped in a DSSE envelope. On success prints the
  att-id (BLAKE3 over the canonical envelope, 64 hex) and stores the
  envelope under `.mkit/attestations/<commit>/<att-id>.dsse`.

  Flags:

  - `--commit <hash>` &mdash; commit to attest. Defaults to HEAD.
  - `--algorithm <alg>` &mdash; `ed25519`, `secp256k1`, or `p256`.
    Defaults to `attest.default_algorithm` in config, else `ed25519`.
  - `--signer <kind>` &mdash; `repo-key` (default), `keystore`, or
    `external`. Picks the primary signer.
  - `--predicate-type <uri>` &mdash; predicate-type URI written into the
    Statement. Defaults to the empty-predicate placeholder URI.
  - `--predicate-file <path>` &mdash; JCS-canonical JSON object used as the
    predicate body. Omitted ⇒ `{}`.
  - `--external-signer-arg <V>` &mdash; repeatable argv token passed to the
    external-signer subprocess. If any instance is supplied the full
    list REPLACES `attest.external_signer_args` from config.
  - `--additional-signer "<spec>"` &mdash; repeatable; adds a second (or
    third, …) signature to the envelope. `<spec>` is a
    comma-separated `key=value` list: `algorithm=<alg>,signer=<kind>
    [,path=<file-or-binary>][,args=<a>|<b>|<c>]`. Here `signer=`
    accepts only `repo-key` or `external` (**not** `keystore`) &mdash; unlike
    the top-level `--signer`, which also takes `keystore`. Signers run in
    the
    order given; the resulting `{keyid, sig}` tuples appear in that
    same order in the envelope. Any signer failure aborts the
    attestation &mdash; no partial envelopes are written.

  Example &mdash; sign with two algorithms at once:

  ```sh
  mkit attest --algorithm ed25519 \
              --additional-signer "algorithm=p256,signer=repo-key" \
              --predicate-type https://example.com/review/v1 \
              --predicate-file review.json
  ```

- `mkit verify-attest [--commit <hash>] [--trust-roots <path>]
  [--algorithm <alg>] [--format=json]` &mdash; verify every attestation attached to a
  commit. For each envelope, looks each signature's `keyid` up in the
  trust-roots registry and verifies the DSSE PAE. Reports per-
  signature verdicts to stderr; with `--format=json`, also emits one JSON
  object to stdout: `{"ok":<bool>,"commit":"<64-hex>","error":"<string>|null",
  "attestations":[{"id":"<64-hex>|null","error":"<string>|null",
  "signatures":[{"keyid":"...","algorithm":"<string>|null","verified":<bool>,
  "reason":"<string>|null"}]}]}` &mdash; the JSON `signatures` list is unfiltered
  (it always carries every signature, independent of `--algorithm`, which
  only filters the stderr report). Exits `0` iff every listed attestation has
  at least one verified signature, `65` (`dataerr`) if any failed,
  `1` (`general_error`) if the commit has no attestations.

  Flags:

  - `--commit <hash>` &mdash; commit to verify. Defaults to HEAD.
  - `--trust-roots <path>` &mdash; path to a trust-roots TOML file
    (`[[trust_root]]` entries with `keyid`, `kind`, `pubkey_hex`).
    Defaults to `$XDG_CONFIG_HOME/mkit/trust-roots.toml`. mkit refuses
    to verify against an in-repo path unless `--trust-roots` is
    passed explicitly &mdash; without that gate, a hostile clone could
    ship its own trust-roots and have verification print "ok"
    against attacker keys.
  - `--algorithm <alg>` &mdash; filter reported signatures by algorithm
    (`ed25519`, `secp256k1`, `p256`). Unmatched signatures are
    omitted from the report.

  Example:

  ```sh
  mkit verify-attest --trust-roots ~/.config/mkit/trust-roots.toml
  ```

- `mkit trust add <keyid> <pubkey-hex> [--kind <kind>] [--trust-roots <path>] [--force]` /
  `mkit trust list [--trust-roots <path>] [--json]` /
  `mkit trust remove <keyid> [--trust-roots <path>] --yes` &mdash; manage the
  trust-roots registry `mkit verify --trusted` and `mkit verify-attest`
  read (same `[[trust_root]]` TOML file, same default path). `add`
  validates `pubkey-hex` decodes and, if `keyid` embeds a hex/digest
  body (the `<algorithm>:<hex>` or `blake3:<hex>` shapes), that it
  matches the given pubkey &mdash; a mismatch is rejected, not silently
  dropped. `--kind` defaults to `ed25519` (commit/remix/tag signing is
  Ed25519-only today); `p256-sec1`, `secp256k1`, and `bls12381-thr`
  (with the `bls-threshold` feature) only matter to `verify-attest`.
  `add` refuses to overwrite an existing keyid without `--force`;
  `remove` requires `--yes` and fails if the keyid isn't registered.
  `list --json` emits a JSON array of `{keyid, kind, pubkey_hex}`.

  Example:

  ```sh
  mkit keygen --print-pubkey                     # ed25519:<hex>
  mkit trust add ed25519:<hex> <hex>              # trust your own key
  mkit trust list
  mkit verify --trusted HEAD
  ```

Branches / refs:

- `mkit branch` / `mkit branch <name>` / `mkit branch -d <name>` &mdash;
  list, create, or delete branches. The default list prints `<marker>
  <name>` with no commit id (like `git branch`); `* ` marks the current
  branch. `-v`/`--verbose` adds the abbreviated tip id and commit subject
  (`<marker> <name> <short> <subject>`, name column padded like
  `git branch -v`); the abbreviated id is a BLAKE3 prefix, not a 40-hex
  SHA-1 prefix. `--format=json` on the list form emits JSONL with keys
  `name`, `current`, `hash`.
- `mkit branch -D <name>` &mdash; force-delete. mkit does not track per-branch
  merge status, so `-D` behaves like `-d` here: both error on an absent
  branch (like `git branch -D <missing>`) and both refuse the checked-out
  branch (deleting it would dangle HEAD).
- `mkit branch -m [<old>] <new>` &mdash; rename a branch (the current branch
  when `<old>` is omitted). CAS-guarded: refuses to clobber an existing
  `<new>`, and moves HEAD when the renamed branch is checked out.
- `mkit branch --show-current` &mdash; print the checked-out branch name (empty
  output on a detached HEAD), like `git branch --show-current`.
- `mkit branch [--list] [--contains [<c>]] [--no-contains [<c>]] [--merged [<c>]] [--no-merged [<c>]] [<pattern>...]`
  &mdash; filter the listing (like `git branch`). `<pattern>` arguments are
  shell globs matched against branch names (`*`, `?`, `[…]`; `*` spans
  `/`, so `feature/*` works &mdash; git's non-pathname `wildmatch`); a branch is
  kept if it matches any pattern. Patterns are only treated as filters in
  list mode &mdash; with `--list` or any ancestry filter present &mdash; so
  `mkit branch <name>` still creates a branch. `--contains [<c>]` keeps only
  branches whose tip has `<c>` as an ancestor; `--no-contains [<c>]` inverts
  it. `--merged [<c>]` keeps only branches already merged into `<c>` (that is,
  whose tip is an ancestor of it); `--no-merged [<c>]` inverts it. All four
  ancestry commit args **default to `HEAD`** when omitted (like git).
  Patterns and ancestry filters combine (a branch must satisfy all of
  them). `--list` is an explicit list selector &mdash; listing is already the
  default when no create/delete/rename flag is given, but `--list` also
  enables `<pattern>` filtering (for example, `mkit branch --list "release/*"`, or
  `mkit branch --list main` to test existence).
- `mkit checkout <branch>` &mdash; switch HEAD and restore files. Refuses to
  run when staged changes, dirty tracked files, or untracked path
  collisions would be overwritten. Non-colliding untracked files are
  preserved across the switch (git branch-switch semantics); tracked
  files the target tree drops are removed, with emptied directories
  pruned. Prints `Switched to branch '<n>'`, or `Already on '<n>'` for a
  no-op switch (which still runs the dirty-worktree guard).
- `mkit checkout -b|-B <new> [<start>]` &mdash; create a branch at the
  start-point (default HEAD) and switch to it; `-b` refuses to clobber an
  existing branch, `-B` create-or-resets. Prints `Switched to a new branch
  '<new>'`.
- `mkit switch <branch>` / `mkit switch -c|-C <new> [<start>]` &mdash; git's
  modern branch-switch UX; a thin front-end over `checkout` with the same
  clobber guard and output. `-c` creates (refuses to clobber), `-C`
  create-or-resets, then switches. (`switch -`/`@{-1}` is a follow-up:
  mkit does not yet track a previous branch.)
- `mkit clean [-n] [-f] [-d] [-x|-X] [<path>...]` &mdash; remove untracked files
  from the worktree. **Destructive, so it refuses to delete without an
  explicit `-f`** (matching git's `clean.requireForce` default); `-n`
  previews with `Would remove <path>` lines. Without `-d`, untracked
  directories are left alone (git semantics); `-d` recurses into them and
  removes them &mdash; but, like git, an untracked directory is only removed
  *wholesale* (shown `<dir>/`) when nothing inside survives: **ignored
  files are kept** (unless `-x`) and keep their parent directory, and a
  **nested repository** (a subdirectory containing `.mkit`/`.git`) is left
  untouched (git needs the double-force `-ff` to remove one, which mkit
  doesn't offer). `-x` also removes ignored files, `-X` removes *only*
  ignored (`-x` and `-X` are mutually exclusive). Trailing pathspecs limit
  the scope to matching top-level entries and whole directories (`.` means
  everything under cwd); a pathspec naming a file *inside* an otherwise
  fully-removable untracked directory is a known limitation &mdash; name the
  directory or use `.`. Ignore matching uses the shared path-aware ignore
  matcher (see "Ignore files" below).
- `mkit tag [--format=json]` &mdash; list, create, or delete tags.
  - `mkit tag` (no args) &mdash; list tags; annotated/signed tags are marked.
  - `mkit tag -l [<pattern>]` &mdash; list tags, optionally filtered by a shell
    glob (for example, `mkit tag -l 'v*'`), reusing `branch`'s `wildmatch` engine.
  - `mkit tag <name> [<commit>]` &mdash; create a lightweight tag (a ref
    pointing straight at `<commit>`, default HEAD).
  - `mkit tag -a <name> [-m <msg>] [<commit>]` &mdash; create an annotated tag
    object (target, tagger identity, message, timestamp). Without `-m`,
    `$EDITOR` is launched.
  - `mkit tag -s <name> [-m <msg>] [<commit>]` &mdash; create a signed
    annotated tag: an Ed25519 signature over the canonical tag bytes
    under the distinct `mkit.tag` domain. Verify with
    `mkit verify <name>`.
  - `mkit tag -d <name>` &mdash; delete a tag.
  - `--author <spec>` overrides the tagger identity (same grammar as
    `commit --author`).
  - `--format=json` &mdash; on the list form, JSONL with keys `name`, `hash`,
    `annotated`, `signed` (mirroring `branch --format=json`); on
    create/delete, one `{"ok":true,"kind":"…",...}` outcome object.
- `mkit merge [--no-commit] [-m <msg>] [--format=json] <branch> | --continue | --abort` &mdash;
  three-way merge into
  HEAD. Fast-forwards and clean merges refuse to overwrite staged
  changes, dirty tracked files, or untracked path collisions. On
  conflict, the conflicting paths are materialized for resolution and a
  resumable state is recorded; see "Resolving conflicts" below.
  `-m`/`--message` overrides the merge commit message (default `Merge
  branch '<name>'`). `--no-commit` performs the merge and **stops before
  committing**: it stages the merged tree and records `MERGE_HEAD`, then
  leaves you to finish with `mkit commit` (which records a two-parent
  merge commit) or `mkit merge --continue`. A fast-forward creates no
  commit, so `--no-commit` does not affect it.
  `--format=json` emits one JSON object to stdout for every outcome:
  `{"ok":true,"kind":"up-to-date"|"fast-forward"|"no-commit"|"merge-commit"|"aborted",...}`
  on success, or `{"ok":false,"kind":"conflict","conflicts":[<path>,...],
  "error":"..."}` on a conflict pause (and `{"ok":false,"error":"..."}` for
  any other error).
- `mkit cherry-pick [-n|--no-commit] [-m|--mainline <parent-number>] [--format=json] <hash> | --continue | --abort`
  &mdash; apply a commit to
  the current branch. Refuses to overwrite staged changes, dirty tracked
  files, or untracked path collisions. On conflict, records resumable
  state; see "Resolving conflicts" below. `-n`/`--no-commit` applies a
  **clean** pick to the index plus worktree without creating a commit (run
  `mkit commit` when ready; the result has the current branch as its
  single parent). A `-n` pick that **conflicts** is refused before anything
  is written &mdash; mkit cannot represent a staged-but-unresolved conflict, and a
  later `mkit commit` only guards merges, so re-run without `-n` to use the
  resumable `--continue` flow. `-m`/`--mainline <parent-number>` selects which parent
  of a **merge** commit is the mainline (git semantics): it is required
  when replaying a merge (mkit refuses to guess which side to diff
  against) and rejected for a non-merge commit. Note this differs from
  `git commit -m` &mdash; git's `cherry-pick -m` is mainline selection, not a
  message override.
  `--format=json` emits one JSON object to stdout, same shape as `merge`
  (`"kind":"commit"|"no-commit"|"aborted"` on success, `"kind":"conflict"`
  with a `conflicts` array on a pause).
- `mkit revert <commit> | --continue | --abort` `[-n|--no-commit] [--format=json]` &mdash;
  create a new commit that undoes `<commit>` (the inverse of cherry-pick:
  it applies the reverse of the target's diff). The commit message is
  `Revert "<subject>"` with a `This reverts commit <hash>.` trailer.
  This is a **forward** commit &mdash; it does not rewrite history, so the
  reverted commit stays reachable (no gc/recovery interaction). Same
  safety guards and resumable conflict workflow as cherry-pick.
  `-n`/`--no-commit` stages the reverted tree (index plus worktree) without
  committing, so you can revert several commits and commit once.
  **Reverting a merge commit is refused** &mdash; the inverse depends on which
  parent is the mainline, and `-m`/mainline selection is not yet
  supported. `--format=json` emits the same outcome-object shape as
  `merge`/`cherry-pick`.
- `mkit rebase [-i|--interactive] [--format=json] <revspec> | --continue | --abort | --skip`
  &mdash; replay commits onto a different base. The target is resolved through
  the shared revspec resolver (branch, tag, `HEAD~n`, full/short hash).
  Restore steps refuse to overwrite staged changes, dirty tracked files,
  or untracked path collisions. On conflict the rebase pauses with
  resumable state; `--skip` drops the current commit. See "Resolving
  conflicts" below.
  `-i`/`--interactive` opens the todo list in `$EDITOR` before any
  mutation. Each line is `<command> <commit> <subject>`, oldest-first
  (top is applied first). Reorder lines to reorder commits; delete a line
  (or use `drop`/`d`) to drop a commit; `reword`/`r` edits a commit's
  message when it is replayed; `squash`/`s` folds a commit into the
  previous one and combines their messages (via the editor); `fixup`/`f`
  folds in but keeps the previous message. A `squash`/`fixup` cannot be
  the first line (nothing to fold into) and is rejected before any
  mutation. Removing every line resets the branch to the base. A
  `reword`/`squash` whose replay hits a conflict still reopens the editor
  on `--continue`. `edit` (stop-to-amend) is not yet supported.
  `--format=json` emits one JSON object to stdout on the top-level
  outcomes: `{"ok":true,"kind":"up-to-date"|"rebased"|"aborted",...}` on
  success, `{"ok":false,"kind":"conflict","conflicts":[<path>,...],
  "error":"..."}` on a conflict pause. Best-effort on the interactive
  (`-i`) editing path and a handful of deep internal errors (for example, signer
  setup), which stay stderr-only.
- `mkit bisect start | good | bad | skip | reset | run <cmd> [args…]` &mdash;
  binary search for a bug. `run` drives the loop automatically: it checks
  out each candidate, runs `<cmd>`, and classifies from the exit status
  (git's contract: `0`=good, `125`=skip, `1`–`127` else=bad, `≥128`=abort),
  then restores the original HEAD and prints the first bad commit. The
  candidate hash is also exported as `MKIT_BISECT_COMMIT`. (mkit's bisect is
  otherwise print-candidate &mdash; `start`/`good`/`bad`/`skip` print the next
  candidate rather than checking it out &mdash; so `run` checks out transiently
  for the test and parks nothing at the end.) Each candidate is checked out
  with `--force`, so a test command that scribbles on tracked files (a
  `Cargo.lock` refresh, a regenerated snapshot) doesn't block the next
  checkout. If every remaining candidate is skipped (exit `125`), `run`
  reports the result is ambiguous &mdash; like git's "the first bad commit could
  be any of …" &mdash; and exits non-zero rather than guessing. Caveat: in a
  sparse-checkout repo `run` materializes the **full** tree for each
  candidate (the transient checkout doesn't re-apply a persisted sparse
  cone).
- `mkit gc [-n|--dry-run] [--grace-secs <secs>]` &mdash; reclaim unreachable
  objects (mark-and-sweep). Under the repo lock it expires stale recovery
  entries, computes the live set reachable from the retention roots (refs,
  stash, in-progress operations, attestations, and the recovery log of
  commits superseded by `commit --amend`/`reset`/`rebase`), then deletes
  unreachable objects older than the grace window (default 14 days).
  `-n`/`--dry-run` reports what would be pruned without deleting.
  `--grace-secs 0` prunes every unreachable object, but **bypasses the
  grace window** &mdash; the grace window is gc's concurrency-safety net (some
  root-publishing paths such as `tag` and `fetch` write an object before
  publishing the ref that makes it reachable), so `--grace-secs 0` must
  only be run when **no other mkit process is operating on the repo**
  (gc prints a warning). **Fail-closed:** a missing/corrupt root, a
  malformed ref, or the reachability cap aborts the run with nothing
  deleted, and an object whose age can't be read is kept. See
  [`docs/specs/SPEC-GC.md`](specs/SPEC-GC.md).

### Resolving conflicts

`merge`, `cherry-pick`, and `rebase` all share one resumable-conflict
workflow. A path where both sides changed the **same regular file on
disjoint lines** is auto-merged line-by-line (the union of both edits, no
markers) &mdash; changes on different lines merge cleanly even when adjacent. A
conflict is only raised when the two sides' changed regions **overlap**
(modify the same or interleaving lines), or for binary files. When a 3-way
merge cannot auto-resolve a path, the command:

1. Applies the merge's **clean (non-conflicting) changes** to the index
   and worktree (so, for example, files the operation adds/removes/modifies away
   from the conflict are already staged), then materializes the
   conflicting paths into the worktree (staging the ours-side blob so
   each path is "resolvable"):
   - **text** modify/modify (with *overlapping* line changes &mdash; disjoint
     ones auto-merge) and add/add → classic 2-way Git markers
     (`<<<<<<< ours` / `=======` / `>>>>>>> theirs`) are written into
     the file.
   - **binary**, **symlink / executable-mode**, **delete/modify**, and
     **file-vs-directory** → no markers (they would corrupt the file);
     the surviving side's content is left in place. Resolve these by
     hand. Each prints a per-path note.
2. Records resumable operation state under `.mkit/` (see below) and exits
   non-zero.

To finish, for each conflicting path: edit the worktree file to its
resolved content (remove all conflict markers), `mkit add <path>`, then:

```sh
mkit merge --continue        # or cherry-pick --continue / rebase --continue
```

`--continue` refuses while any text-marker file still contains markers,
**and** refuses whenever a conflicted path's worktree resolution does not
match what is staged in the index &mdash; so an unstaged resolution can't be
silently dropped. This covers every shape: an edited regular **or
executable** file, a path deleted without `mkit rm`, and a file replaced
by a symlink or directory without `mkit add`. An *unchanged* conflict
(the worktree still equals the auto-staged ours-side, including its
executable / symlink mode) needs no re-`add` and continues. The committed
tree is built from the **resolved index/worktree** &mdash; not the
conflict-time "ours wins" snapshot &mdash; so your edits (including a third
distinct resolution) and the merge's clean changes both land.

Alternatively:

```sh
mkit merge --abort           # restore HEAD, branch ref, index, and worktree
mkit rebase --skip           # rebase only: drop the current commit, keep going
```

`--abort` restores the pre-operation state (or fails with a clear,
recoverable error and changes nothing). Starting a new merge / cherry-pick
/ rebase while one is already in progress is refused.

#### Operation-state files

All live under `.mkit/`; rebase keeps its state inside
`.mkit/rebase-apply/`. These use Git-compatible names plus one documented
mkit sidecar. The `.mkit/index` stays a single-stage **resolved** staging
area &mdash; there are no unmerged index stages (SPEC-INDEX is unchanged).

| File                          | Meaning                                              |
| ----------------------------- | ---------------------------------------------------- |
| `MERGE_HEAD`                  | other parent of an in-progress merge (presence ⇒ merge) |
| `CHERRY_PICK_HEAD`            | commit being applied by an in-progress cherry-pick   |
| `ORIG_HEAD`                   | HEAD before the operation, used by `--abort`         |
| `MERGE_MSG` / `CHERRY_PICK_MSG` | pending commit message                             |
| `mkit-conflicts`              | mkit sidecar: one line per conflicting path with the conflict kind and base/ours/theirs blob hashes |
| `rebase-apply/`               | rebase state (`head-name`, `orig-head`, `onto`, `todo`, `actions`, `done`) plus a `mkit-conflicts` sidecar when paused. `actions` is parallel to `todo` (`pick`/`reword`/`squash`/`fixup`, from `rebase -i`); absent ⇒ all `pick` |

Remote / sync:

- `mkit remote [-v|--verbose] [--format=json]` &mdash; list the configured
  remotes. Bare `remote` prints **one remote name per line** (git-shaped);
  `-v`/`--verbose` adds the URL and direction
  (`<name>\t<url> (fetch)` / `(push)`). `--format=json` emits the remote
  configuration as JSON; an unset remote produces empty stdout.
- `mkit remote add [<name>] <url>` &mdash; add a remote. With a `<name>`,
  registers a named remote (`remote.<name>.url`); without one, sets the
  flat default `remote_endpoint`. The URL MUST start with
  `mkit+<scheme>://` (see below).
- `mkit remote set [<name>] <url>` &mdash; alias for `mkit remote add`.
- `mkit remote remove <name>` (alias `rm`) &mdash; delete a named remote. The
  reserved name `default` clears the flat `remote_endpoint`.
- `mkit remote rename <old> <new>` (alias `mv`) &mdash; rename a named remote
  and repoint any `branch.<b>.remote` upstream tracking it. Refuses to
  clobber an existing `<new>`. Removing or renaming a remote never
  touches the user-scoped `trusted_remote_endpoint`, which is keyed by
  exact URL rather than remote name (so the #97 credential-trust gate is
  preserved).
- `mkit remote get-url <name>` &mdash; print a remote's URL (use `default` for
  the flat default remote). `mkit remote set-url <name> <url>` &mdash; change an
  existing remote's URL (validated like `remote add`).
- `mkit clone [--depth N] [--sparse ...] [-b <branch>] [-o <name>]
  [--no-verify-signatures] [-q|--quiet] <url> [<dir>]` &mdash; clone a repository
  into `<dir>` (defaults to the final URL path segment). `--sparse
  <pattern>...` persists the patterns and materializes only the
  matching files via the verifiable sparse-checkout pipeline (requires
  a build with `--features sparse-checkout`). Note this is an
  **enhancement over git**: mkit's `--sparse` takes one or more PATTERN
  arguments, whereas git's `clone --sparse` is a boolean flag (it cones
  to the top-level files and you add patterns afterward). **`--depth N` is parsed but
  not yet wired**: passing it fails with a clear `--depth is not yet
  wired` usage error rather than silently producing a full clone; see
  "Divergences from Git".
  - `-b`/`--branch <name>` &mdash; check out `<name>` instead of the remote's
    default branch. The branch MUST exist among the remote's advertised
    refs; unlike the default heuristic (current default branch, falling
    back to whatever the remote advertises first) an explicit `-b` never
    silently substitutes another branch &mdash; a missing branch fails the
    clone with a "remote branch not found" error.
  - `-o`/`--origin <name>` &mdash; name the cloned remote `<name>` in the new
    repo's `.mkit/config` instead of the implicit flat `default` remote
    (mirrors `mkit remote add <name> <url>` at clone time). The name
    must be dot-free and ref-safe, like a named `remote add`. Tracking
    refs land under `refs/remotes/<name>/*` to match.
- `mkit fetch [<remote>] [--all] [--no-verify-signatures] [--format=json]
  [-q|--quiet]` &mdash; download from remote without merging. Fetched branch tips
  are stored
  under `refs/remotes/<remote>/<branch>` (`refs/remotes/default/<branch>`
  for the flat default remote) and do not move local branches. `--all`
  fetches every configured remote (the flat default plus every named
  `remote.<name>.url`) in one invocation, printing each remote's usual
  `From <url>` plus per-ref summary in turn; mutually exclusive with an
  explicit `<remote>` argument. A per-remote failure does not stop the
  others &mdash; `fetch --all` continues through the full list and exits
  non-zero if any remote failed. `--format=json` emits one JSON object
  per remote fetched to stdout: `{"ok":true,"remote":"...","endpoint":"...",
  "updated":[{"name":"...","old":"<hex>|null","new":"<hex>"}]}` on
  success, or `{"ok":false,"error":"..."}` on failure.
- `mkit pull [<remote>] [--all] [--no-verify-signatures] [--format=json]
  [-q|--quiet]` &mdash; fetch, then fast-forward the current branch from
  `refs/remotes/<remote>/<branch>`. Divergent histories are refused; use
  explicit merge/rebase flows after resolving the divergence. Fresh repos
  with no local branch tip initialize the current branch/worktree from
  the remote default branch. `--all` pulls from every configured remote
  in turn (same enumeration and failure-tolerance as `fetch --all`),
  fast-forwarding the current branch from each; mutually exclusive with
  an explicit `<remote>` argument. `--format=json` emits one JSON object
  per remote pulled: `{"ok":true,"remote":"...","endpoint":"...",
  "branch":"...","old":"<hex>|null","new":"<hex>|null",
  "up_to_date":<bool>}` on success, or `{"ok":false,"error":"..."}` on
  failure.
- **Post-fetch signature verification (issue #692, default ON).**
  `clone`/`pull`/`fetch` verify every commit/remix/tag the fetch newly
  introduces &mdash; the same check `mkit verify <rev>` runs manually
  (`mkit_core::sign::{verify_commit,verify_remix,verify_tag}`) &mdash; before
  publishing the remote-tracking ref. A structurally invalid or missing
  signature aborts with exit 65 (`DATAERR`) and leaves local branch/
  remote-tracking refs and the working tree untouched. Only the objects
  a given fetch actually introduces are checked, not the whole history
  (bounded cost per fetch). Opt out per invocation with
  `--no-verify-signatures`, or persistently for scripted/CI use via the
  **user-scoped** `pull.require_signed = false` config key &mdash; it cannot be
  set from a cloned repo's own `.mkit/config` (see THREAT-MODEL.md §4).
  `--all` applies the same verification (and the same opt-out) to every
  remote it iterates.
- `mkit push [<remote>] [--all] [--force|--force-with-lease] [--dry-run]
  [--format=json] [-q|--quiet]`
  &mdash; push refs and packs to a remote. With no `<remote>`, pushes the
  **current branch to its upstream** (the `branch.<b>.remote`/`.merge`
  tracking pair), falling back to the configured default remote; an
  explicit `<remote>` name overrides that choice. The default push is
  CAS-protected: a non-fast-forward is rejected using the remote-tracking
  ref as the lease. `--all` mirrors every `refs/heads/*` (also CAS-safe).
  `--force` overwrites the remote branch unconditionally (skips CAS);
  `--force-with-lease` overwrites only if the remote hasn't moved past
  the last-seen tip (the two are mutually exclusive); `-f` is an alias of
  `--force`. `-u`/`--set-upstream` records the pushed remote as the
  branch's upstream even if one was already set. `--dry-run`
  resolves the push plan without contacting the remote. Every endpoint
  flows through the per-endpoint credential-trust gate, which is keyed on
  the resolved endpoint URL, never the remote name. On success `push`
  prints git's `To <url>` plus ref-update summary (or `Everything
  up-to-date`). `--format=json` emits one JSON object to stdout:
  `{"ok":true,"remote":"...","endpoint":"...","branch":"...",
  "remote_branch":"...","old":"<hex>|null","new":"<hex>","forced":<bool>,
  "up_to_date":<bool>}` on success, or `{"ok":false,"rejected":true,
  "branch":"...","error":"..."}` on a non-fast-forward (CAS) rejection
  (`{"ok":false,"error":"..."}` for any other failure).
- **Transfer progress (#711).** `clone`/`push`/`pull`/`fetch` stream a
  live, honest progress line on stderr while the network transfer runs &mdash;
  `Writing objects: N objects, B bytes` while building/uploading the
  outgoing pack, `Unpacking objects: N objects` while applying a
  downloaded one. The counts are real (objects actually staged/unpacked,
  bytes actually handed to the transport); mkit never fabricates git's
  `Enumerating/Counting/Compressing objects` or `Total N (delta D)` lines
  &mdash; mkit's transport is one-object-per-pack and computes no cross-branch
  delta graph. Progress shows only when stderr is a tty; `-q`/`--quiet`
  forces it off, and `MKIT_PROGRESS=always`/`never` overrides the
  tty-detection explicitly (mirrors `NO_COLOR`/`CLICOLOR_FORCE`).
- `mkit serve <path>` &mdash; internal SSH transport server. Speaks the
  mkit-rpc SSH framing on stdin/stdout by default.
- `mkit serve <path> --listen-enc <addr>` &mdash; bind a TCP socket on
  `<addr>` (for example, `0.0.0.0:9418`) and serve the same protocol over
  an encrypted-stream transport. Requires building the binary with
  `--features enc-transport`. **Fail-closed**: the listener refuses to
  bind unless one of the following is supplied:
  - `--enc-authorized-peers <PATH>` &mdash; an allowlist of authorized client
    public keys, one per line (64-hex or 43-char url-safe base64; `#`
    comments and blank lines ignored). A client whose static ed25519
    key is not listed is rejected at the handshake and receives no data.
    This path MUST be CLI-supplied or user-scoped &mdash; peer-authorization
    is never read from repo-local `.mkit/config`.
  - `--unsafe-allow-any-enc-peer` &mdash; a development escape that accepts
    ANY peer. Prints a loud warning; never use in production.
  These two flags are mutually exclusive.

  Post-handshake resource bounds (slow-loris hardening):
  - `--enc-idle-timeout-secs <SECS>` &mdash; per-frame idle timeout applied
    after the handshake completes. A peer that does not send its next
    verb/upload frame within this window has its session dropped, so a
    peer that finishes the handshake then stalls cannot pin a worker plus
    socket indefinitely. `0` disables the timeout (not recommended).
    Default: `60`.
  - `--enc-handshake-timeout-secs <SECS>` &mdash; overall deadline for
    completing the cryptographic handshake. SPEC-TRANSPORT-ENC §6.2
    recommends tightening to ≤5–10s on real networks; the default is
    deliberately generous. Default: `60`.

  `--enc-server-key <PATH>` selects the server's stable raw 32-byte
  ed25519 key file (auto-created with `0600`/`0700` hardening on first
  run). When allowlisting and the flag is omitted, the key is
  auto-created at the user-scoped default `~/.config/mkit/enc/server.key`
  so the advertised `?pubkey=` is **stable across restarts**. Only the
  unsafe allow-any mode without a key file falls back to an ephemeral
  per-process key. The server prints its public key to stderr at
  startup; clients dial `mkit+enc://<host>:<port>?pubkey=<key>` after
  copying that key out-of-band. A client may pin its own identity (so
  an allowlisting server can recognize it across restarts) by pointing
  the `MKIT_ENC_CLIENT_KEY` environment variable at a user-scoped raw
  32-byte key file; otherwise the client uses an ephemeral key. The
  default port advertised by `mkit+enc://` URLs when none is supplied
  is **9418**. Full keystore integration is deferred (see
  SPEC-TRANSPORT-ENC §6.2).
- `mkit serve <path> --http <addr>` &mdash; self-hosted Connect remote: bind
  `<addr>` (for example, `0.0.0.0:8443`) and host `mkit.transport.v1.TransportService`
  (SPEC-TRANSPORT-CONNECT) over axum/HTTP, instead of the SSH-frame
  protocol. Requires building with `--features http-transport`. This is
  a plaintext HTTP listener &mdash; put a TLS-terminating reverse proxy in
  front for production use (or bind to loopback and tunnel).
  **Fail-closed**, mirroring `--listen-enc`: refuses to bind unless one
  of the following is supplied:
  - `--http-token <TOKEN>` (or the `MKIT_API_TOKEN` environment variable
    &mdash; the same variable `mkit+https://` clients already send as
    `Authorization: Bearer <token>`, SPEC-TRANSPORT §5.2) &mdash; every RPC
    (unary and streaming, including `UploadPack`/`DownloadPack`) is
    rejected with `unauthenticated` unless it carries a matching bearer
    token, checked in constant time.
  - `--unsafe-allow-any-http-peer` &mdash; a development escape that accepts
    ANY caller with no authentication at all. Prints a loud warning;
    never use in production.
  These two are mutually exclusive, and mutually exclusive with
  `--listen-enc`. `Ctrl-C`/`SIGTERM` drain in-flight requests before
  exiting (the same cooperative shutdown flag the rest of the CLI uses).
- `mkit pack-shard <hash> [--out <dir>] [--force]` &mdash; encode a stored
  pack into Reed-Solomon shards plus a manifest, ready to publish to
  an HTTP / S3 origin. Producer side of the SPEC-PACK-SHARDS
  wire-format and transport-delivery stage. The
  pack must already be in the local object store. Output layout:
  `<out>/packs/<hex>/shards/<index>` and
  `<out>/packs/<hex>/shards.manifest`. The manifest is written last
  so racing readers either see "no manifest" (clean fall-through to
  the monolithic pack) or "manifest plus all shards". Requires building
  the binary with `--features pack-shards`.
- `mkit git export <dest> [--remote-name <name>] [--ref <ref>]...
  [--no-attest] [--algorithm <alg>] [--signer <kind>] [--passthrough] [--json]`
  &mdash; deterministic **one-way** export of
  branches and tags to a git mirror
  ([`SPEC-GIT-BRIDGE`](specs/SPEC-GIT-BRIDGE.md)). `<dest>` is a git URL or
  a local path (a missing/empty local path is initialized bare);
  `--remote-name` defaults to `mirror`, and `--ref` takes full names
  (`refs/heads/...` / `refs/tags/...`).
  Translation is byte-deterministic: the same history yields the same
  git SHA-1s on every machine, and mkit-only fields (signer,
  signature, identity, annotation slots) ride in `mkit-*` commit
  headers so the original signed objects are reconstructible. Refs a
  conformant bridge cannot represent (git-illegal names, remix
  ancestry, non-canonical chunking) are skipped per-ref with a
  warning; an export where everything was skipped exits non-zero.
  Pushes use per-ref `--force-with-lease` from recorded state under
  `.mkit/git/<name>/`; mkit-side history rewrites mirror as
  force-pushes. Unless `--no-attest`, each exported head gets a
  signed `git-bridge/v1` DSSE attestation (saved like `mkit attest`,
  published on the mirror's `refs/mkit/attestations` ref &mdash; fetch it
  with an explicit refspec; git clones skip it by default).
  Attestation signing uses the same signer resolution as `mkit
  attest` (`--algorithm`/`--signer` flags, else config defaults), so
  a signing key must exist unless `--no-attest`. Branch deletion
  never propagates (export is add/update-only), and each plain-export
  `--remote-name` state dir is bound to one destination and one
  direction (fork-mode state dirs lease against a fresh observation
  per push and are not destination-bound); bidirectional sync does
  not exist.
- `mkit git import <url> [<dir>] [--remote-name <name>] [--key <path>]
  [--json]` &mdash; import a git upstream as an **importer-signed downstream
  fork** ([`SPEC-GIT-IMPORT`](specs/SPEC-GIT-IMPORT.md)). With `<dir>`:
  init a fresh mkit repo, import all branches/tags, and check out the
  upstream default branch. Without: add the upstream to the current
  repo as `refs/remotes/<name>/*` tracking refs plus tags. Every
  translated commit/tag is signed by a DEDICATED import key
  (`.mkit/keys/git-import.key`, generated on first use and pinned per
  state dir &mdash; collaborative tracking requires sharing it; a different
  key produces an unrelated fork). Original authorship rides in the
  author identity; original git bytes are retained under
  `.mkit/git/<name>/` with a `git-import/v1` attestation per head.
  Unrepresentable refs skip per-ref with warnings (submodules,
  mkit-illegal names, historic-mode trees in fork state dirs).
  Upstream history imports once per (key, upstream); hashes are a
  function of the import key by design. Plain `git export` toward an
  imported-from upstream is refused (the origin guard); export to new
  mirrors works normally. Expect total disk ≈ 2–3× the upstream
  `.git` (staging mirror plus translated store).
- `mkit git fetch [--remote-name <name>] [--key <path>] [--json]` &mdash; fetch
  new upstream
  commits into the tracking refs and imported tags (a force-pushed
  upstream moves tracking refs with a loud warning; a tag you moved
  locally is never clobbered &mdash; fetch warns and leaves it). `--key` points
  at the import signing key (default: the pinned key file), and `--json`
  emits machine-readable JSON on stdout. `mkit git pull [--remote-name
  <name>] [--key <path>] [--json]` additionally
  fast-forwards the current branch; divergence refuses with the
  executable hint (`mkit merge <name>/<branch>` &mdash; imported history is
  ordinary mkit history, integrated natively).
- `mkit git export --passthrough --remote-name <import-name> <fork-url>`
  &mdash; **fork mode** (SPEC-GIT-BRIDGE §14): publish an imported repo as a
  true git fork. Imported objects re-emit their ORIGINAL sha1s; only
  native commits on top translate, so the pushed branch sits directly
  on the upstream commits and PRs/merge-bases work. Upgrades the
  import state to direction `fork` (sticky); plain export under that
  name is then refused, while `git fetch`/`pull` keep working.
- `mkit git verify [--remote-name <name>] [--fork-audit] [--ref <ref>]...`
  &mdash; audit recorded bridge state against the local store:
  bridge-translated objects shallow-verify (SPEC-GIT-BRIDGE §10) and
  must reconstruct to their mapped twin; imported objects must have
  retained raw bytes hashing to their sha1 and a twin signed by the
  pinned importer key. `--fork-audit` (§14.3) additionally re-derives
  every tree/blob referenced by bridge commits from its mkit twin and
  requires the exact sha1. Exits non-zero listing each failing object;
  unsigned (all-zero-signature) objects also fail, reported as a count
  ("unsigned", never "tampered" &mdash; SPEC-GIT-BRIDGE §10).
- `mkit git status` &mdash; one block per `.mkit/git/<name>/` state dir:
  direction, recorded source/dest, pinned importer key, tracking refs
  (import) and lease positions (export), staging health.
- `mkit git format-patch <A..B> [-o <dir>] [--stdout]` &mdash; render
  native commits as `git am`-able mbox patches (oldest first, merges
  skipped) &mdash; the contribution path that needs no writable fork. A
  single rev means `<rev>..HEAD`; for example,
  `mkit git format-patch upstream/main -o patches/`.

  All `mkit git` subcommands require building the binary with
  `--features git-bridge` (alias: `git-export`); they shell out to `git`.

Agent integration:

- `mkit mcp [--repository <path>]` &mdash; start a Model Context Protocol
  server on stdio so LLM agents (Claude, Cursor, etc.) can drive local
  mkit repositories through structured tool calls instead of raw shell.
  Exposes a conservative tool surface: status / diff (unstaged, staged,
  vs target) / log / show / branch / cat-file inspection, staging
  (`add`, unstage), signed `commit`, branch create/checkout, `init`,
  `keygen` (ed25519 commit key, or secp256k1/p256 attestation keys),
  plus the differentiators &mdash; `verify` (signature check), `attest`
  (DSSE; supports `algorithm` and `repo-key`/`keystore` signer), and
  `verify-attest` (trust-roots-gated, with an `algorithm` filter). Every
  tool takes an explicit `repo_path`; `--repository <path>` confines all
  calls (symlink resolved) to that root. The server runs **no network
  operations** (push/pull/fetch/clone are not exposed), performs no
  history surgery (merge/rebase/cherry-pick are not exposed), and
  **never passes `-f`/`--force`** &mdash; mkit's data-loss guards stay in
  force, and a "refuses without -f" error is surfaced to the agent
  verbatim. Additional guardrails specific to the agent threat model:
  a predicate file passed to `attest` must resolve **inside** the repo
  (no reading outside files into a signed attestation), a `trust_roots`
  path passed to `verify-attest` must resolve **outside** the repo (a
  hostile clone's in-repo `.mkit/attest-trust-roots.toml` can never be
  selected via the MCP &mdash; see THREAT-MODEL §"Trust-roots scope"), and the
  external/multi-signer attestation controls are intentionally omitted
  because they can direct subprocess execution (use the `attest` CLI for
  that flow). `initialize` must precede tool calls. Tool results carry
  the child command's output and its sysexits code on failure. Register
  with an MCP client, for example:

  ```sh
  claude mcp add mkit-repo -- mkit mcp --repository /path/to/repo
  ```

Config / keys / version:

- `mkit keygen` &mdash; generate a new Ed25519 signing keypair.
- `mkit key generate [--backend B] [--label L] [--algorithm ALG]` &mdash; generate
  a signing key in a keystore backend. `ALG` is `ed25519`, `secp256k1`, or
  `p256`; default is `ed25519`.
- `mkit key list [--backend B] [--json]` &mdash; list keys visible to a backend.
- `mkit key import --algorithm ALG (--hex HEX | --file PATH) [--backend B]
  [--label L]` &mdash; import 32 bytes of signing key material where the backend
  allows import.
- `mkit key export [--backend B] [--label L] [--algorithm ALG]
  --unsafe-print-secret` &mdash; export extractable key material. Non-extractable
  backends fail closed.
- `mkit key delete [--backend B] [--label L] [--algorithm ALG] --yes` &mdash; delete
  exactly one backend key where deletion is supported.
- `mkit config [--format=json]` &mdash; show all configuration values.
  `--format=json` emits a flat JSON object with every known key.
- `mkit config <key> [--format=json]` &mdash; show one value.
- `mkit config --unset <key>` &mdash; remove a configuration value. Deletes
  from whichever scope a `set` of that key would use &mdash; the repo layer
  (`<repo>/.mkit/config`) for a repo-safe key, or the user-scoped layer
  (`$XDG_CONFIG_HOME/mkit/config`) for a `REPO_FORBIDDEN_KEYS` key &mdash;
  unless overridden by `--local`/`--global`. Idempotent: unsetting an
  already-absent key is a silent success (like `rm -f`), not an error;
  only an unknown key name is rejected. Takes no positional arguments.
- `mkit config [--local|--global] <key> <value>` &mdash; set a configuration
  value, or `--unset <key>` to remove one. `--local` forces the
  repo-scoped layer (refused for a `REPO_FORBIDDEN_KEYS` key, which can
  never live in a clone-traveling repo config); `--global` forces the
  user-scoped layer even for an otherwise repo-safe key. **Put
  `--local`/`--global` before `--unset`** (`mkit config --global --unset
  <key>`, not `--unset --global <key>`) &mdash; like any clap value-taking
  option, `--unset` consumes the very next token as `<KEY>`, so a flag
  placed between `--unset` and the key is swallowed as (invalid) key
  text rather than parsed separately. The two flags
  are mutually exclusive; neither is needed for the common case, where
  scope is chosen automatically by whether the key is in
  `REPO_FORBIDDEN_KEYS`.
- `mkit config <key> <value>` &mdash; set a configuration value. Config
  **section** and **variable** names are matched **case-insensitively**
  (canonicalized to lowercase), like git &mdash; so `user.Name`, `USER.EMAIL`,
  etc. resolve to the same key as their lowercase form, in both this
  command and the config-file parser. **Subsection** names &mdash; the middle
  segment of `remote.<name>.url` or `branch.<branch>.remote` &mdash; stay
  **case-sensitive** (git semantics), so a remote added as `Origin` is not
  silently folded to `origin`.
  - `user.name` / `user.email` &mdash; git-compatibility aliases. They are
    accepted and round-trip like `git config user.name`, but are
    **non-authoritative**: mkit's commit author is cryptographic
    (`user.identity` or the signing key's derived Identity), and these
    values **never** feed it. They are repo-safe (stored in
    `.mkit/config`) precisely because they cannot influence the signed
    author &mdash; unlike `user.identity`, which stays user-scoped and in
    `REPO_FORBIDDEN_KEYS` so a hostile clone cannot spoof authorship.
  - `core.*` &mdash; git-compatibility keys. An **inert** allowlist
    (`core.autocrlf`, `core.bare`, `core.filemode`, `core.ignorecase`,
    `core.quotepath`, `core.symlinks`) is accepted and round-tripped for
    parity but **not honored** &mdash; mkit has no CRLF translation, tracks exec
    bits natively, etc. Dangerous `core.*` keys that would change what mkit
    runs (`core.sshCommand`, `core.pager`, `core.editor`, `core.hooksPath`,
    `core.fsmonitor`) are **rejected** rather than stored. Names match
    case-insensitively and canonicalize to lowercase, like git.
- `mkit self update [--version <tag>] [--check] [--allow-downgrade]
  [--format human|json]` &mdash; update this binary in place from a signed
  GitHub Release. The downloaded archive is checked against its sha256
  sidecar asset when the release publishes one; this runs entirely
  in-process, no `cosign` and no GitHub attestation API are involved.
  Only **installer-managed** binaries are updated:
  the `.mkit-installed-tag` receipt written by `install.sh` must sit
  next to the (canonicalized) executable, and the global
  `$MKIT_STATE_DIR/installed-tag` (default `~/.local/state/mkit`) must
  agree with it when present. Homebrew/cargo installs are refused with
  channel-specific guidance (`brew upgrade mkit`,
  `cargo install --locked mkit-cli`). Both receipts are rewritten
  after a successful swap, in the installer's exact format, so
  installer and updater stay interchangeable.
  - `--check` &mdash; only report whether an update is available (works for
    any install method; compares against the running binary's own
    version); exits 0 either way, and `--format json` carries the
    machine-readable bit (`status: up-to-date | update-available`).
  - Downgrade policy mirrors `install.sh`: resolving `latest` never
    downgrades; an explicit `--version` pin may downgrade only with
    `--allow-downgrade`, loudly.
  - The staged binary must pass a pre-swap self-check (`version` must
    emit exactly `mkit <X.Y.Z>`); the swap is a same-directory atomic
    rename. Group-/world-writable install dirs are refused (installer
    parity).
  - Environment: `GH_TOKEN`/`GITHUB_TOKEN` (API bearer; optional,
    raises the unauthenticated GitHub API rate limit), `MKIT_STATE_DIR`,
    `MKIT_SELF_UPDATE_API_BASE` (test/mirror override).
  - There is **no background update check** &mdash; the command only ever
    acts when invoked.
- `mkit version` &mdash; print the version. Emits exactly `mkit <X.Y.Z>\n`.
  The top-level `mkit --version` / `mkit -V` flags are aliases of this
  subcommand and emit the identical string. Note this is `mkit <X.Y.Z>`,
  not Git's `git version <X.Y.Z>` form &mdash; an intentional, documented
  divergence (the string is pinned by packaging asserts).

## Ignore files

mkit reads ignore patterns from **both** `.gitignore` and `.mkitignore` at
the repository root. `.gitignore` is applied first and `.mkitignore` last, so
under gitignore's last-match-wins rule a repo's own `.mkitignore` can override
(including re-include via `!`) anything `.gitignore` set. Matching is honored
by `add`, `clean`, `ls-files --others`, `restore`/`checkout`, and the
worktree tree-builder.

Matching is **path-relative** and follows the gitignore semantics for this
v1 subset:

- A pattern with no `/` (other than a trailing one) matches at **any depth**
  (`*.log` matches `a/b/c.log`). A pattern containing a `/` &mdash; including a
  leading `/` &mdash; is **anchored** to the repo root (`/foo` matches only the
  top-level `foo`; `src/gen` only that path).
- `*` and `?` match within a single path segment; `[abc]`, `[a-z]`, and
  `[!abc]` character classes are supported; `\` escapes the next character.
- `**` as a whole segment crosses `/`: leading `**/` and middle `/**/` match
  zero or more directories, and a trailing `/**` matches everything *inside*
  a directory.
- A trailing `/` restricts a pattern to directories. A leading `!` negates
  (last match wins); `\#` / `\!` escape a leading `#` / `!` to a literal.
  Trailing unescaped spaces are trimmed.
- `.mkit` and `.git` are always ignored (matched on the basename, ASCII
  case-insensitively).

**Deferred (documented non-goals for now, #256):** nested per-directory
ignore files (only the repo root is read), global excludes
(`core.excludesFile`), and escaped trailing spaces.

## Divergences from Git

mkit's local commands intentionally diverge from Git in a few places.
These are documented behaviors, not bugs, with tracked follow-ups:

- **Human output goes to stderr; stdout is reserved for porcelain/data.**
  mkit's command summaries (`commit`/`merge`/`push`/`status` …) are
  shaped like git's but are written to **stderr**, so `mkit status` and
  friends stay empty-on-clean in a pipeline and stdout carries only
  machine output (`--porcelain`, `rev-parse`, `rev-list`, …). git puts
  some of these on stdout; mkit keeps its stderr convention.
- **Object ids in human output are 64-hex BLAKE3 prefixes**, not git's
  40-hex SHA-1 &mdash; the inherent hash-length divergence. Output otherwise
  matches git's shape (for example, `To <url>` plus `<old>..<new>  main -> main`,
  `[main <hash>] <subject>` plus diffstat, `Fast-forward`).
- **git's object-count / delta-compression progress lines**
  (`Enumerating/Counting/Compressing objects`, `Total N (delta D)`) are
  **not** emitted: mkit's transport is one-object-per-pack and computes
  no cross-branch delta graph, so those specific numbers would be
  fabricated. `clone`/`push`/`pull`/`fetch` do stream an honest
  `Writing objects: N objects, B bytes` / `Unpacking objects: N objects`
  progress line (#711) &mdash; real counts only; see "Transfer progress"
  above.
- **`mkit remote`** lists remote **names only** (git-shaped); use
  `mkit remote -v` for `<name>\t<url> (fetch)`/`(push)`.
- **`mkit log --graph` is a no-op (v1 non-goal).** The flag is accepted
  for compatibility so existing scripts don't break, but no ASCII commit
  graph is drawn. Full graph parity is unachievable because mkit's default
  `log` body already diverges from git's `commit/Author/Date` (mkit
  `Identity` plus 64-hex ids); an `--oneline --graph` renderer for the
  linear/DAG case is a tracked post-v1 follow-up, not a v1 blocker.
- **`mkit log --author`/`--grep` are plain substring matches, not
  regexes.** git's `--author`/`--grep` default to POSIX extended-regex
  matching against a free-text `Name <email>` header; mkit identities are
  opaque (Ed25519 keys, `mid:N` numbers, DID keys), so a regex engine
  would buy little for the common case. A literal substring (the typical
  `--author=me` / `--grep=fix:` usage) behaves the same either way.
- **`mkit log --since`/`--until` use a small, explicit date grammar, not
  git's `approxidate`.** Accepted forms: `@<unix-seconds>`,
  `now`/`today`/`yesterday`, `<N> <unit> ago`, `YYYY-MM-DD`, and
  `YYYY-MM-DD HH:MM:SS` / `YYYY-MM-DDTHH:MM:SS[Z]` (UTC). git's fuzzier
  natural-language forms (`last Tuesday`, `3am`, `noon`) are not accepted.
- **`mkit status --porcelain=v2`** matches git's format except that object
  ids are full 64-hex BLAKE3 (git's are 40-hex SHA-1). Exact renames emit a
  `2` record (`R100`); `--branch` header lines are not emitted.
- **`mkit clone --depth N` is parsed but not yet wired.** The flag is
  accepted by the parser but `clone` rejects it with a `--depth is not
  yet wired` usage error rather than silently producing a full clone.
  Shallow-clone history truncation is a follow-up.
- **`mkit blame --ignore-rev-precise` (opt-in) is a content-addressed
  refinement of `--ignore-rev` fall-through, not git's positional guess.**
  git's `--ignore-rev` pairs a changed hunk's k-th added line with its k-th
  removed line purely by position; mkit hashes line content, so it can
  identify a fallen-through line's true surviving origin across a
  reformat/reorder &mdash; including cases the positional pass leaves credited
  to the noise commit as a "genuine insertion" because its own hunk has no
  local counterpart. The **default** `--ignore-rev` fall-through is
  unchanged and stays byte-identical to git; `--ignore-rev-precise` must be
  passed explicitly (and requires `--ignore-rev`/`--ignore-revs-file`).
- `mkit reset [--soft|--mixed|--hard] [-f] [<commit>]` &mdash; `--soft` moves
  HEAD only; `--mixed` (the default) also resets the index; both leave the
  worktree untouched. `--hard` additionally resets the worktree to the
  target tree &mdash; overwriting tracked-file changes and removing tracked
  files the target drops. Untracked files are kept (like git), **except**
  an untracked path that *collides* with one the target writes. As a
  safety divergence, `--hard` **refuses** (without `-f`/`--force`) when
  discarding would lose locally-modified or staged content, or overwrite
  such a colliding untracked path; with `-f` it is overwritten. git's
  `reset --hard` discards silently. The guard re-checks each dropped path
  directly, so it also covers a tracked file that matches an ignore rule
  (`.gitignore`/`.mkitignore`). `<commit>` defaults to `HEAD`.

### Commands deliberately not implemented (by design)

Several Git commands that were once "wontfix-by-design" have been
**reinstated under safety guards** as part of the git-parity
porcelain-completion work (#250): `mkit revert`, `mkit mv`, `mkit clean`, and
`mkit reset --hard` are all available and documented above. Each keeps an
mkit data-loss guard &mdash; for example, `clean` and `reset --hard` refuse to delete or
discard without an explicit `-f` &mdash; rather than adopting git's silent
destructive default. Rename *detection* in diff/log output remains a
separate, unscheduled follow-up (decision #226): `mkit mv` stages the move
but `status` shows it as a delete plus add, not `R`.

Note: object garbage collection (`mkit gc`) **is shipped** (issue #233).
History-rewriting commands (`commit --amend`, `reset`, `rebase`) record
the superseded commit in the recovery log, and `mkit gc` reclaims
unreachable objects once they fall outside the grace window. See
[`docs/specs/SPEC-GC.md`](specs/SPEC-GC.md).

## Config keys

Stored in `.mkit/config` as `key = value` lines &mdash; **except** security-sensitive
keys, which are **user-scoped only** and ignored if set in a repo's
`.mkit/config` (a hostile repo must not be able to redirect signing or trust).
Those keys &mdash; `user.identity`, `signing_key`, `signer`, `key.*`, `attest.*`,
`ssh.*`, and `trusted_remote_endpoint` &mdash; live in the user config
(`$XDG_CONFIG_HOME/mkit/config`); set them with `mkit config <key> <value>`,
which routes them to the user scope automatically.

| Key | Value | Default | Notes |
|-----|-------|---------|-------|
| `user.identity` | hex Identity | unset | **User-scoped only**; see below |
| `signing_key` | path | `.mkit/keys/default.key` | Ed25519 seed file; **user-scoped only** |
| `default_branch` | name | `main` | Branch for `mkit init` |
| `remote_endpoint` | URL / path | empty | Set via `mkit remote add` |
| `remote_bucket` | name | empty | For s3 remotes |
| `remote_type` | `file` / `http` / `s3` / `ssh` / `memory` | auto | |
| `transport_auth` | `bearer` / `envelope` | `bearer` | Write-auth mode for `mkit+https://`/`mkit+http://`; `envelope` additionally Ed25519-signs writes with the commit-signing key (see `signer`/`signing_key`/`key.ed25519_ref`) |
| `ssh.strict_host_key_checking` | `yes` / `no` / `accept-new` | inherit | User-scoped only |
| `ssh.user_known_hosts_file` | path | inherit | User-scoped only |
| `ssh.identity_file` | path | inherit | User-scoped only |
| `signer` | `legacy` / `keystore` | `legacy` | User-scoped commit signing source |
| `key.backend` | backend name | `software` | User-scoped default for `mkit key` |
| `key.default_ref` | `<backend>:<label>` | `software:default` | User-scoped fallback key ref |
| `key.ed25519_ref` | `<backend>:<label>` | `software:default` | User-scoped Ed25519 ref |
| `key.secp256k1_ref` | `<backend>:<label>` | `software:default-secp256k1` | User-scoped secp256k1 ref |
| `key.p256_ref` | `<backend>:<label>` | `software:default-p256` | User-scoped P-256 ref |
| `attest.signer` | `repo-key` / `keystore` / `external` | `repo-key` | User-scoped attestation signer |

Keystore backend names include `software`, `software-raw`, `macos-keychain`,
`linux-secret-service`, `systemd-creds`, and `yubikey`
when the target build enables the corresponding backend feature. Security-
sensitive selector keys are ignored from repo-local config; set them in
`$XDG_CONFIG_HOME/mkit/config` or with explicit command flags.

### `user.identity`

The commit author Identity, encoded as `[kind:u8][len:u16 LE][bytes]`
in lowercase hex per `docs/specs/SPEC-OBJECTS.md §9`. Accepted shorthands at
parse time:

```
user.identity = ed25519:<64-char-hex>   # kind=0x01, 32-byte pubkey
user.identity = mid:<u64 decimal>       # kind=0x03, 8-byte LE opaque
user.identity = <raw-hex>               # already-encoded Identity
```

When unset, the CLI derives an Ed25519 Identity from the signing key's
public key at commit time. Most users don't need to set this.

The legacy `author_mid = <N>` key from pre-0.1.0 is rejected at
`mkit config` time with a hint pointing to `user.identity`. `parseConfig`
silently ignores stray `author_mid` lines that may still be on disk.

### `ssh.*`

Thin overrides for the `ssh` child process spawned by the SSH
transport. Empty string (`""`) means "do not pass the flag; inherit the
user's `~/.ssh/config` default". See `docs/SSH-SECURITY.md` for the
recommended trust model.

## URL schemes

`mkit remote add <url>` accepts the strict `mkit+<scheme>://...` form
only. Anything else is hard-rejected:

```
error: invalid remote URL '<input>': must start with 'mkit+<scheme>://'
hint: URL must start with mkit+<scheme>:// (e.g. mkit+https://, mkit+ssh://, mkit+file://, mkit+s3://)
```

Accepted schemes:

| Scheme | Form | Use |
|--------|------|-----|
| `mkit+file` | `mkit+file:///abs/path` | local filesystem mirror |
| `mkit+https` | `mkit+https://host[:port][/path]` | ConnectRPC gateway (for example, VCS Worker) |
| `mkit+s3` | `mkit+s3://endpoint/bucket[/prefix]` | S3-compatible object store |
| `mkit+ssh` | `mkit+ssh://user@host[:port]:path` | SSH with the mkit shell |
| `mkit+memory` | `mkit+memory://` | in-memory (testing only) |

`mkit+https` (and loopback-only `mkit+http`) speaks
`mkit.transport.v1.TransportService` over ConnectRPC &mdash; see
`docs/specs/SPEC-TRANSPORT-CONNECT.md`. Any `/path` on the URL is
accepted (for shape-consistency with the other schemes) but currently
has no wire effect: every RPC resolves to the fixed
`/mkit.transport.v1.TransportService/<Method>` path regardless.
Write RPCs against a deployment that requires the Ed25519 write envelope
(for example, `apps/vcs-worker`, the reference server) need
`mkit config transport_auth envelope` &mdash; see the config table above and
SPEC-TRANSPORT-CONNECT §7.3.

See `docs/specs/SPEC-TRANSPORT.md` for the other transports' wire
protocols.

## Version output contract

`mkit version` prints exactly:

```
mkit <X.Y.Z>\n
```

Downstream packagers (Homebrew) assert on this substring. The
format is pinned by a snapshot test in the CLI crate.

## *nix conventions

mkit follows common POSIX CLI conventions so shell scripts, pipelines,
and interactive use behave predictably.

### Exit codes

Based on BSD `sysexits(3)`:

| Code | Constant         | Meaning                                      |
| ---- | ---------------- | -------------------------------------------- |
| 0    | `ok`             | Success                                      |
| 1    | `general_error`  | Catch-all for other failures                 |
| 64   | `usage`          | Wrong args or unknown subcommand             |
| 65   | `dataerr`        | Malformed input (corrupt object, bad hash)   |
| 66   | `noinput`        | Missing / unreadable input file              |
| 69   | `unavailable`    | Transport could not connect                  |
| 73   | `cantcreat`      | Cannot create output file                    |
| 75   | `tempfail`       | Temporary failure; retry is safe             |
| 76   | `protocol_error` | Bad URL scheme or malformed server response  |
| 77   | `noperm`         | Permission denied                            |
| 78   | `config_error`   | Unknown config key or invalid value          |

The constants live in `rust/crates/mkit-cli/src/exit.rs`. Shell scripts
can distinguish user typos (64) from transient failures (75) without
parsing stderr.

### Environment variables

- **`GIT_EDITOR` / `EDITOR` / `VISUAL`** &mdash; the editor `mkit commit`
  opens when neither `-m` nor `-F` is supplied, tried in that order. If
  none is set it falls back to `vi`, matching git. In a headless or
  non-interactive context (CI, an agent), always pass `-m`/`-F` so the
  commit never blocks on an editor.
- **`NO_COLOR`** &mdash; if set (any value, including empty) ANSI color on
  stdout is suppressed. See <https://no-color.org>.
- **`CLICOLOR_FORCE=1`** &mdash; force ANSI color even when stdout is piped.
  `NO_COLOR` overrides this.
- **`SSH_AUTH_SOCK`** &mdash; standard OpenSSH agent socket, used by
  `mkit+ssh://` transports.
- **`XDG_CONFIG_HOME`**, **`XDG_DATA_HOME`**, **`XDG_CACHE_HOME`**,
  **`XDG_STATE_HOME`** &mdash; XDG Base Directory roots for user-level config,
  keystore, cache, and state respectively. Defaults per the freedesktop
  spec (`~/.config`, `~/.local/share`, `~/.cache`, `~/.local/state`).

### File layout

| Path                                | Purpose                                          |
| ----------------------------------- | ------------------------------------------------ |
| `.mkit/`                            | Repo-local state (like `.git/`)                  |
| `.mkit/config`                      | Repo-local config &mdash; overrides user-level values  |
| `.mkit/keys/default.key`            | Repo-local Ed25519 signing key                   |
| `.mkit/index`                       | Staging index                                    |
| `.mkit/index.lock`                  | Held by commit/checkout/merge/rebase             |
| `.mkit/COMMIT_EDITMSG`              | Scratch file for `mkit commit` without `-m`      |
| `$XDG_CONFIG_HOME/mkit/config`      | User-level config (cross-repo defaults)          |
| `$XDG_DATA_HOME/mkit/keys/`         | User-level keystore (optional)                   |
| `$XDG_CACHE_HOME/mkit/`             | User-level cache                                 |
| `$XDG_STATE_HOME/mkit/`             | User-level state                                 |

Repo-local values in `.mkit/config` win over user-level config except for
security-sensitive signer, keystore, external-signer, and identity selector keys
that mkit intentionally accepts only from user scope or explicit flags.

### Signals

- **`SIGINT`** (Ctrl-C) and **`SIGTERM`** set a graceful-shutdown flag.
  Long-running operations (push, pull, clone, log) poll it at natural
  checkpoints and exit with `tempfail` (75) so the operation can be
  retried. Wired via `signal-hook`'s `flag` module so the CLI stays
  under its crate-level `#![deny(unsafe_code)]`.
- **`SIGPIPE`** is ignored. Pipelines like `mkit log | head -1` exit
  cleanly without a "Broken pipe" message &mdash; the next write just
  propagates `EPIPE` as a normal I/O error. This is the Rust runtime
  default (since 1.65); mkit does not register over it. The behavior
  is pinned by an integration test (`tests/sigpipe.rs`).

### Man page

```sh
# System install (requires root):
sudo cp man/mkit.1 /usr/local/share/man/man1/

# User install (preferred if ~/.local/share/man is on MANPATH):
mkdir -p ~/.local/share/man/man1
cp man/mkit.1 ~/.local/share/man/man1/

man mkit
```

Homebrew users installing from the tap get the man page automatically.

### Shell completions

```sh
# bash (macOS / Homebrew)
cp completions/mkit.bash /usr/local/etc/bash_completion.d/

# bash (most Linux)
sudo cp completions/mkit.bash /etc/bash_completion.d/

# zsh (anywhere on $fpath; example for Homebrew)
cp completions/mkit.zsh /usr/local/share/zsh/site-functions/_mkit
```

Then restart your shell (or run `compinit` on zsh). Completion covers
the full subcommand list plus common flags; per-argument completion
(branch names, remote URLs) is deferred to a future release.

### Using mkit as `git` (opt-in shim)

`mkit` exposes a git-compatible CLI surface, so existing git habits &mdash; and AI
agents that emit `git <cmd>` &mdash; can drive it. `contrib/git-shim/mkit-git` is an
**opt-in** forwarder (`git <args>` → `mkit <args>`) that you install yourself;
it is never installed automatically and **never shadows the real `git`**.

```sh
# simplest (interactive shells):
alias git=mkit

# or, to also cover scripts/agents, put the shim on PATH as `git` for a
# specific project/environment, ahead of the real git:
ln -s "$PWD/contrib/git-shim/mkit-git" ~/.local/mkit-shim/git
export PATH="$HOME/.local/mkit-shim:$PATH"
command -v git && git version   # verify it resolves to the shim
```

See `contrib/git-shim/README.md` for details. The shim is a pure forwarder:
an unsupported command exits with mkit's usage error rather than falling
through to real git.
