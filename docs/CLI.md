# mkit — CLI reference

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
Identity is automatically derived from your signing key's public key —
no config needed.

## Global flags

These are parsed **before** the subcommand (so they apply to repo
discovery too), like git:

- `mkit -C <path> <command>` — run as if `mkit` were started in `<path>`.
  Repeatable; relative paths resolve against the prior `-C` (git semantics).
- `mkit -c <key>=<value> <command>` — set a config value for this one
  invocation. It is applied to the **effective** config only (never written
  to disk) and flows through the same enforcement as a per-repo config
  file: security-sensitive keys (`user.identity`, signing/transport trust —
  the `REPO_FORBIDDEN_KEYS` set) are **refused** with a warning, and
  dangerous `core.*` keys are dropped. So `-c` cannot spoof the signed
  author or redirect trust; use it for inert/allowlisted keys (e.g.
  `-c user.email=ci@example.com`).
- `mkit --no-pager` / `-P` / `--paginate` — accepted **no-ops**. mkit never
  paginates (better for agents and scripts); the flags exist so defensive
  invocations like `mkit --no-pager log` don't error.

`--git-dir`, `--work-tree`, and `--exec-path` are **non-goals** — mkit uses
the `.mkit/` marker and has no split work-tree / exec-path model.

## Subcommand reference

Working-tree commands:

- `mkit init` — create a new repository in `.mkit/`.
- `mkit add [-A|-u] [-f] [-p] <path>...` / `mkit add .` — stage files for the
  next commit. Multiple pathspecs may be given. `.` stages every non-ignored
  file under the current directory. `-A`/`--all` stages every change in
  the worktree including deletions of tracked files (takes no path
  arguments). `-u`/`--update` restages only already-tracked files —
  updating modified ones and recording deletions — without adding
  untracked paths (takes no path arguments). `-A` and `-u` are mutually
  exclusive. An explicitly-named path that is ignored (by
  `.gitignore`/`.mkitignore`) is refused unless `-f`/`--force` is given
  (git parity); already-tracked paths are never subject to ignore.
  `-p`/`--patch` interactively presents each hunk between the staged (or
  HEAD) blob and the worktree file and stages only the accepted ones —
  per hunk: `y` stage, `n` skip, `a` stage this and all later hunks, `d`
  skip this and all later hunks, `q` quit (keeping hunks already chosen).
  It requires explicit path arguments, is incompatible with `-A`/`-u`,
  and operates on regular text files only: a binary file is **skipped**
  with a message (the command still succeeds), and symlinks/directories
  are **refused**. An explicitly-named ignored path is refused unless
  `-f`/`--force` (like plain `add`); a path that escapes the repo through
  a symlinked parent is refused. The hunk view and prompts go to stderr;
  `s` (split) and `e` (manual edit) are follow-ups.
- `mkit rm [--cached] [-r|--recursive] [-f|--force] <path>...` — remove
  paths and stage the deletion for the next commit. By default this
  **deletes the worktree file(s)** and stages the removal; now-empty
  parent directories are pruned. Multiple pathspecs are accepted.
  - `--cached` — stage the removal only, leaving the worktree file(s)
    on disk (the historical mkit behaviour).
  - `-r`/`--recursive` — required to remove a directory and everything
    under it; without it, a directory pathspec is refused.
  - `-f`/`--force` — remove worktree files even when their content has
    diverged from the staged blob. Without `--force`, `rm` refuses to
    destroy a locally-modified tracked file (a dirty-worktree guard in
    the spirit of the #176 restore guards); use `--cached` to keep the
    file or `--force` to discard the local changes.
- `mkit mv [-f|--force] <source>... <dest>` — move or rename a tracked
  path and stage the change. `mv <src> <dst>` renames `src` to `dst`, or
  moves it into `dst` when `dst` is an existing directory; with more than
  one source, `<dest>` must be an existing directory. The worktree file is
  moved and the index updated (the source staged as removed, the
  destination staged with the source's blob and mode — content is
  unchanged, so the existing object is reused). Because the blob keeps the
  same content id at the new path, `mkit status` / `mkit diff` detect the
  move as an exact rename and report git's `R` by default; `--no-renames`
  shows the underlying deletion plus addition instead.
  - `-f`/`--force` — overwrite an existing destination. Without it, `mv`
    refuses to clobber an existing path (matching git's `mv` guard) — an
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
    at its new path (each a delete + add, per the no-rename-detection note
    above). The repo-escape and validate-before-move guards all apply.
    A directory move **refuses a pre-existing destination even with `-f`**
    (recursively removing it would strand its tracked files in the index and
    delete untracked ones — git won't clobber a directory with `mv` either),
    rejects **overlapping sources** up front (`mv dir dir/file <dest>`), and
    refuses moving a directory into itself.
- `mkit status [--porcelain[=v1|v2]] [-s|--short] [-z]` — show staged and
  unstaged changes. Default-mode prose (banner + section headers + per-file
  lines) goes to **stderr**; stdout is reserved for machine output.
  `-s`/`--short` is an alias for `--porcelain=v1`; both select the same
  renderer. Porcelain emits one entry per line in `git status --porcelain=v1`
  format (`XY <path>`, with mkit's `T` for `ModeChanged` as the only
  non-git extension). `--porcelain=v2` selects git's richer per-path
  format — `1 <XY> <sub> <mH> <mI> <mW> <hH> <hI> <path>` for tracked
  changes (octal modes; full 64-hex BLAKE3 object ids; `<sub>` always
  `N...`) and `? <path>` for untracked — with no rename (`2`) records and
  no `--branch` header lines. Paths with special bytes are **C-style quoted**
  (matching git's default `core.quotePath`). `-z` (which implies
  porcelain) NUL-terminates records and emits **raw, unquoted** paths —
  the round-trip-safe form for paths containing newlines or other special
  bytes. Empty stdout means clean.
- `mkit diff [--staged|--cached] [--name-only|--name-status|--stat] [--merge-base] [-z] [<rev> [<rev>] | <a>..<b> | <a>...<b>] [<path>...]`
  — show changes as a unified patch. With no arguments, compares the HEAD
  tree to a fresh worktree snapshot. `--staged` (alias `--cached`) compares
  the HEAD tree to the staged index tree — the change `mkit commit`
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
  printing the patch; `--quiet` is the same but prints nothing — the CI
  idiom for "fail if the tree changed". `--color[=always|auto|never]`
  colorizes the patch (git's palette: bold metadata, cyan hunk headers,
  green additions, red deletions); the default `auto` colorizes only on a
  tty (honoring `NO_COLOR`/`CLICOLOR_FORCE`), and `--no-color` forces it
  off. (Color for `status`/`log`/`branch` is a tracked follow-up.)
- `mkit stash [save|list|pop|apply|drop|clear|show]` — save/restore WIP
  changes. `apply` restores an entry without removing it; `clear` drops
  every entry. `pop`/`apply`/`drop`/`show` select an entry by index
  (default `0`), accepting either a bare `N` or the `stash@{N}` form
  printed by `stash list`. `pop`/`apply` accept `--index`, which also
  restores the **staged** state recorded when the stash was created (like
  `git stash pop --index`), not just the worktree changes. `save` records
  that staged snapshot as the stash commit's second parent (git-style
  `[HEAD, index]`) — no on-disk manifest change, and it stays gc-reachable
  through the stash commit. The snapshot is the **serialized index** (a blob
  in the index commit's wrapper tree, paired with a content subtree that
  keeps staged blobs gc-reachable), so `--index` restores the index exactly,
  **including staged deletions** (`mkit rm`-staged) — which a tree could not
  encode. Stashes created before this feature carry no index snapshot, so
  `--index` is a no-op for them (with a note).
- `mkit sparse-checkout` — manage sparse checkout patterns.

History / commits:

- `mkit commit [-a|--all] [--amend] [--author <spec>] [-m <msg> | -F <file>]`
  — create
  a signed commit from the staging index. The index is built by `mkit
  add` / `mkit rm`; `commit` with an empty index is an error. Use `mkit
  add .` to snapshot the whole worktree before committing. `-m` supplies
  the message inline; `-F`/`--file` reads it from `<file>` (like `git
  commit -F`), with `-` meaning standard input — `-m` and `-F` are
  mutually exclusive, and omitting both launches `$EDITOR`. `-a` / `--all`
  follows Git's tracked-only shortcut: it stages modified tracked files
  and tracked deletions before committing, but does not add untracked
  files. `mkit commit -am <msg>` is accepted as shorthand for `-a -m
  <msg>`. `--author <spec>` overrides the recorded author Identity for
  this commit (highest precedence — above `user.identity` config and the
  signing-key-derived default). The `<spec>` grammar is `ed25519:<hex>`
  (32-byte public key), `did:key:<multibase>` (the multibase payload after
  `did:key:`, e.g. `did:key:z6Mk…`, stored verbatim — must be a non-empty
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
- `mkit log [--oneline] [--abbrev-commit] [--abbrev[=N]] [--format=json] [--graph] [-n N] [<rev> | <A>..<B> | <A>...<B>]` — show
  commit history. With no argument the walk starts at `HEAD`; an optional
  `<rev>` starts it there instead, a range `<A>..<B>` shows commits
  reachable from `B` but not from `A` (an empty side means `HEAD`, so `A..`
  is `A..HEAD` and `..B` is `HEAD..B`), and a symmetric range `<A>...<B>`
  shows commits reachable from `A` or `B` but not their common ancestors
  (the merge base). Commits are ordered
  reverse-chronologically with a topological tie-break (a parent never
  precedes a child) — git's `--date-order`, which matches git's default for
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
- `mkit reflog [<ref>] [--format=json] [-n N]` — **read-only** view of a
  branch's recorded movement history. Defaults to the branch `HEAD`
  points at (a detached `HEAD` needs an explicit `<ref>`, since the
  ref-history journal is keyed per-branch). Walks the branch tip's
  first-parent chain newest-first, addressing each entry `<ref>@{N}`
  (`@{0}` is the current tip). The underlying journal (the per-branch
  commit-history MMR written on every branch advance) stores a count of
  advances and a tamper-evident root, but its leaf digests cannot be
  decoded back to commit hashes — so the listed hashes are reconstructed
  from the reachable chain. On a build with `--features history-mmr`
  each entry is additionally cross-checked against the journaled MMR root
  via an inclusion proof, and the recorded-advance count is printed.
  `--format=json` emits JSONL with keys `ref`, `selector`, `index`,
  `hash`, `title`, `journaled` (`true`/`false`/`null`). **This is not a
  full Git reflog:** `@{N}` indexes the reachable first-parent chain, so
  commits superseded by `commit --amend` or a reset are not listed; see
  "Divergences from Git" below.
- `mkit blame [--format=json] [-w] [-M] [-C] [--ignore-rev <rev>]
  [--ignore-revs-file <file>] [--first-parent] [--reverse] [-L <start>,<end>]
  [<rev>] <file>` —
  show line-level commit attribution. `-w` ignores whitespace when
  matching lines across revisions (like `git blame -w`, ignoring *all*
  whitespace), so a whitespace-only edit — reindent, tab↔space, spacing
  tweak — doesn't reattribute the line; output still shows the file's
  current bytes. `-M` detects lines moved *within* the file and `-C` lines
  copied *from other files* (like `git blame -M`/`-C`; `-C` implies `-M`,
  and repeating it — `-C -C` — widens the search from files changed in the
  commit to every file in the parent). Detection is block-based: the
  longest contiguous moved/copied block above git's default thresholds (20
  alphanumeric characters for `-M`, 40 for `-C`) is credited to its origin,
  so a moved block next to genuinely-new lines is still split out, and
  combined with `-w` a block copied with a whitespace change is still
  detected. Divergences from git: inline numeric threshold forms
  (`-M<num>`/`-C<num>`) aren't exposed on the CLI (the core API accepts a
  custom threshold); a single unmatched run over 10,000 lines is matched
  only as a whole, not by sub-block. Move/copy detection is merge-aware: at
  a merge both `-M` and `-C -C` search every relevant parent's tree, so a
  block moved or copied in from a non-first-parent side is credited to that
  side (matching `git blame -M`/`-C`). `-C` copy ties across parents follow
  two distinct git rules (pinned against git 2.50.1): for a file that already
  exists on every parent, a tie is resolved by skipping the first parent
  entirely and crediting the first parent after it (in order) that holds the
  block — a sole candidate on only the first parent is left on the merge; for
  a file *newly added by the merge* (no parent has it), the opposite rule
  applies — every real parent is searched including the first, first-found
  wins, so the first parent can win that tie. `-M`, `--ignore-rev`, and
  `--first-parent` are fully merge-aware throughout.
  `--ignore-rev <rev>` (repeatable) and `--ignore-revs-file <file>` skip
  "noise" commits — mass reformats, license-header sweeps, renames — during
  attribution, like `git blame --ignore-rev`: a line that would be credited
  to an ignored commit falls through to the commit that previously changed
  it, while a line the ignored commit genuinely inserted stays put.
  `--ignore-rev` accepts any revision (short hash, ref, `HEAD~2`);
  `--ignore-revs-file` entries must be full hex object names, one per line,
  with blank lines and `#` comments (including inline) skipped — both
  matching git. (mkit does not auto-read a `.git-blame-ignore-revs` file or
  a `blame.ignoreRevsFile` config key; pass the file explicitly.) Blame is
  **merge-aware by default** (like `git blame`): at a merge, a line is
  credited to whichever parent's side actually wrote it, so a line merged in
  from a side branch is attributed to its authoring commit rather than the
  merge. `--first-parent` (like `git blame --first-parent`) follows only
  each commit's first parent, so such a line is instead credited to the
  merge commit — the older linear-history behavior; it composes with
  `-w`/`-M`/`-C`/`--ignore-rev`. `-L`
  restricts output to a line range —
  `<start>,<end>`, `<start>,+<n>` (n lines forward), `<start>,-<n>` (n
  lines back, ending at `<start>`), `<start>,` (to EOF), `,<end>` (from
  start of file), or a bare `<start>` (to EOF); bounds are 1-based and
  inclusive, an inverted range is swapped, and an over-long end is
  clamped to EOF, matching `git blame -L`. An optional
  `<rev>` (a ref, hash, or `HEAD~2`-style spec) blames the file as of
  that revision instead of `HEAD`. `--reverse <start>..<end>` walks
  history *forward* instead of backward (like `git blame --reverse`):
  it blames the `<start>` version of the file and attributes each line to
  the **last** commit in the range in which it still existed — useful for
  "which commit removed or last touched this line." `<start>..` defaults
  `<end>` to `HEAD`; an explicit `<start>` is required (mkit reports a
  clear error for a missing range or open start, where `git` prints a
  cryptic "dig up from" message — a deliberate divergence, like the `-L`
  diagnostics). A line that never survives a step stays on `<start>`
  (git marks such lines with a leading `^`; mkit's tab format carries no
  `^`, consistent with its existing boundary-marker omission). `-w` and
  `-L` compose with `--reverse`. Default emits
  `<short12>\t<line_num>\t<text>` per line; `--format=json` emits JSONL
  with keys `hash`, `line_num`, `author`, `timestamp`, `text`.
- `mkit verify <rev>` — verify the signature on a commit, remix, or
  signed tag. `<rev>` is an object hash, a branch/tag name, or `HEAD`; a
  tag name resolves to its annotated-tag object when one exists.
- `mkit cat <hash>` — display an object by its hash.
- `mkit hash <file>` — hash a file and store it as a blob.
- `mkit tree` — snapshot the working directory as a tree object.

Read-only plumbing (object/ref inspection, for scripts and agents):

- `mkit cat-file (-t | -s | -p) <object>` / `mkit cat-file --batch` —
  inspect a stored object (like `git cat-file`). `-t` prints the type
  (`blob`/`tree`/`commit`/`tag`; mkit's `remix` is the one non-git type);
  `-s` prints the size (the content byte length for blobs — matching git —
  but mkit's serialized size for trees/commits, which differs); `-p`
  pretty-prints (a blob's raw bytes, a tree as `<mode> <type> <hash>\t<name>`
  lines, or a readable commit/tag summary). `--batch` reads object names
  from stdin (one per line) and emits, per object, a `<hash> <type> <size>`
  header line followed by the content and a trailing newline (`<name>
  missing` for unknown objects); `<size>` is the byte length of the content
  that follows, so blobs are byte-exact with git while commit/tree content
  (and its size) is mkit-shaped, as with `-p`. `<object>` resolves through
  the shared revspec grammar (hash, ref, `HEAD`, `HEAD~n`/`^`).
- `mkit show [--stat] [<object>...]` — display objects (like `git show`),
  defaulting
  to `HEAD`. A **commit**/**remix** prints a header (`commit <hash>`,
  `Author:`, `Date:`, message indented four spaces — matching `mkit log`)
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
- `mkit ls-tree [-r] [-z] <tree-ish> [<path>...]` — list a tree's entries
  as `<mode> <type> <hash>\t<name>` (git octal modes
  `100644`/`100755`/`120000`/`040000`; the hash is 64-hex BLAKE3). `-r`
  recurses, showing leaf blobs with full paths and omitting tree lines
  (like git); `-z` NUL-terminates records and emits raw paths (otherwise
  special-byte paths are C-style quoted). Trailing pathspecs limit the
  listing.
- `mkit ls-files [-s] [-z] [--others] [--ignored] [--exclude-standard]` —
  list files in the index or untracked worktree files (like
  `git ls-files`). Default prints tracked paths, one per line, sorted. `-s`
  (`--stage`) prints stage info as `<mode> <hash> <stage>\t<path>` (git
  octal mode; `<stage>` is always `0` — mkit has no merge stages). `--others`
  lists untracked worktree files instead; `--exclude-standard` drops
  ignored ones (per `.gitignore`/`.mkitignore`) and `--ignored` inverts to
  show only ignored files (`--ignored` requires `--others`, like git's `-i`
  outside an
  `-o`/`-c` selection). `-z` NUL-terminates records and emits raw paths
  (otherwise special-byte paths — including under `-s` — are C-style quoted).
- `mkit rev-parse [--verify] [--short[=N]] [--abbrev-ref] [--show-toplevel] [<rev>...]`
  — resolve revisions to object ids. Bare `<rev>...` prints each resolved
  64-hex id; `--short[=N]` abbreviates (default 7, a BLAKE3 prefix);
  `--abbrev-ref HEAD` prints the current branch; `--verify` is accepted for
  git-script compatibility but is a **no-op** — mkit always errors on an
  unresolvable revision, with or without it; `--show-toplevel` prints the
  repository root (the directory holding `.mkit`, found by walking up from
  cwd).
- `mkit rev-list [--count] <rev>` — list the commit ids reachable from
  `<rev>` in reverse-chronological (topological) order, one 64-hex id per
  line; `--count` prints the number instead. Reuses `log`'s walk so the
  order matches. (Range/filter forms are a follow-up.)
- `mkit merge-base [--is-ancestor] <a> <b>` — print the best common
  ancestor of two commits (64-hex; exit 1 with no output when there is
  none). `--is-ancestor` tests whether `<a>` is an ancestor of `<b>`,
  exiting 0 (yes) or 1 (no) with no output. Reuses the merge engine.
- `mkit show-ref [--heads] [--tags]` — list refs as `<hash> <refname>`,
  sorted by ref name. Default shows `refs/heads/*`, `refs/tags/*`, and
  any `refs/remotes/*` tracking refs; `--heads`/`--tags` filter to one
  namespace.
- `mkit for-each-ref [--format=<fmt>] [<pattern>...]` — iterate refs
  (heads, tags, and remote-tracking refs), sorted by ref name (like
  `git for-each-ref`). The default line
  is `<objectname> <objecttype>\t<refname>`. `--format` substitutes
  `%(atom)` tokens (`refname`, `refname:short`, `objectname`,
  `objectname:short`, `objecttype`; `%%` is a literal `%`); the object id is
  64-hex BLAKE3. Optional `<pattern>` arguments filter to refs whose full
  name equals or is under each pattern.
- `mkit symbolic-ref [--short] <name> [<ref>]` — read or write a symbolic ref
  (currently only `HEAD`), like `git symbolic-ref`. Without `<ref>`, prints
  the full target (`refs/heads/main`), or just the branch name with `--short`;
  errors when HEAD is detached / not symbolic. With `<ref>` (which must be
  under `refs/heads/`), repoints HEAD at that branch — the plumbing form,
  which does **not** touch the worktree; the branch need not exist yet
  (matching git).
- `mkit update-ref [-d] <ref> [<newvalue> [<oldvalue>]]` — create, update, or
  delete a ref under `refs/heads/` or `refs/tags/` (other namespaces are
  rejected), like `git update-ref`. `<newvalue>`/`<oldvalue>` resolve through
  the revspec grammar. With no `<oldvalue>` the write is unconditional; with
  one it is a compare-and-swap that fails unless the ref currently holds that
  value. In update mode an all-zero `<oldvalue>` requires the ref to be absent
  (git's create-only form). `-d` deletes the ref (optionally verifying a
  **concrete** `<oldvalue>` first — an all-zero value is rejected, since a ref
  asserted absent has nothing to delete); deleting a branch refuses the
  currently checked-out one — an mkit safety divergence (git's plumbing would,
  leaving HEAD dangling).

Attestations:

- `mkit attest [--commit <hash>] [--algorithm <alg>] [--signer <kind>]
  [--predicate-type <uri>] [--predicate-file <path>]
  [--external-signer-arg <V>]... [--additional-signer "<spec>"]...` —
  produce a signed DSSE attestation for a commit. The signed payload is
  an [in-toto v1 Statement](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
  carrying the commit hash as `subject` and the user-supplied
  predicate, wrapped in a DSSE envelope. On success prints the
  att-id (BLAKE3 over the canonical envelope, 64 hex) and stores the
  envelope under `.mkit/attestations/<commit>/<att-id>.dsse`.

  Flags:

  - `--commit <hash>` — commit to attest. Defaults to HEAD.
  - `--algorithm <alg>` — `ed25519`, `secp256k1`, or `p256`.
    Defaults to `attest.default_algorithm` in config, else `ed25519`.
  - `--signer <kind>` — `repo-key` (default), `keystore`, or
    `external`. Picks the primary signer.
  - `--predicate-type <uri>` — predicate-type URI written into the
    Statement. Defaults to the empty-predicate placeholder URI.
  - `--predicate-file <path>` — JCS-canonical JSON object used as the
    predicate body. Omitted ⇒ `{}`.
  - `--external-signer-arg <V>` — repeatable argv token passed to the
    external-signer subprocess. If any instance is supplied the full
    list REPLACES `attest.external_signer_args` from config.
  - `--additional-signer "<spec>"` — repeatable; adds a second (or
    third, …) signature to the envelope. `<spec>` is a
    comma-separated `key=value` list: `algorithm=<alg>,signer=<kind>
    [,path=<file-or-binary>][,args=<a>|<b>|<c>]`. Here `signer=`
    accepts only `repo-key` or `external` (**not** `keystore`) — unlike
    the top-level `--signer`, which also takes `keystore`. Signers run in
    the
    order given; the resulting `{keyid, sig}` tuples appear in that
    same order in the envelope. Any signer failure aborts the
    attestation — no partial envelopes are written.

  Example — sign with two algorithms at once:

  ```sh
  mkit attest --algorithm ed25519 \
              --additional-signer "algorithm=p256,signer=repo-key" \
              --predicate-type https://example.com/review/v1 \
              --predicate-file review.json
  ```

- `mkit verify-attest [--commit <hash>] [--trust-roots <path>]
  [--algorithm <alg>]` — verify every attestation attached to a
  commit. For each envelope, looks each signature's `keyid` up in the
  trust-roots registry and verifies the DSSE PAE. Reports per-
  signature verdicts to stderr; stdout is reserved for a future
  `--format=json` mode. Exits `0` iff every listed attestation has
  at least one verified signature, `65` (`dataerr`) if any failed,
  `1` (`general_error`) if the commit has no attestations.

  Flags:

  - `--commit <hash>` — commit to verify. Defaults to HEAD.
  - `--trust-roots <path>` — path to a trust-roots TOML file
    (`[[trust_root]]` entries with `keyid`, `kind`, `pubkey_hex`).
    Defaults to `$XDG_CONFIG_HOME/mkit/trust-roots.toml`. mkit refuses
    to verify against an in-repo path unless `--trust-roots` is
    passed explicitly — without that gate, a hostile clone could
    ship its own trust-roots and have verification print "ok"
    against attacker keys.
  - `--algorithm <alg>` — filter reported signatures by algorithm
    (`ed25519`, `secp256k1`, `p256`). Unmatched signatures are
    omitted from the report.

  Example:

  ```sh
  mkit verify-attest --trust-roots ~/.config/mkit/trust-roots.toml
  ```

Branches / refs:

- `mkit branch` / `mkit branch <name>` / `mkit branch -d <name>` —
  list, create, or delete branches. The default list prints `<marker>
  <name>` with no commit id (like `git branch`); `* ` marks the current
  branch. `-v`/`--verbose` adds the abbreviated tip id and commit subject
  (`<marker> <name> <short> <subject>`, name column padded like
  `git branch -v`); the abbreviated id is a BLAKE3 prefix, not a 40-hex
  SHA-1 prefix. `--format=json` on the list form emits JSONL with keys
  `name`, `current`, `hash`.
- `mkit branch -D <name>` — force-delete. mkit does not track per-branch
  merge status, so `-D` behaves like `-d` here: both error on an absent
  branch (like `git branch -D <missing>`) and both refuse the checked-out
  branch (deleting it would dangle HEAD).
- `mkit branch -m [<old>] <new>` — rename a branch (the current branch
  when `<old>` is omitted). CAS-guarded: refuses to clobber an existing
  `<new>`, and moves HEAD when the renamed branch is checked out.
- `mkit branch --show-current` — print the checked-out branch name (empty
  output on a detached HEAD), like `git branch --show-current`.
- `mkit branch [--list] [--contains [<c>]] [--no-contains [<c>]] [--merged [<c>]] [--no-merged [<c>]] [<pattern>...]`
  — filter the listing (like `git branch`). `<pattern>` arguments are
  shell globs matched against branch names (`*`, `?`, `[…]`; `*` spans
  `/`, so `feature/*` works — git's non-pathname `wildmatch`); a branch is
  kept if it matches any pattern. Patterns are only treated as filters in
  list mode — with `--list` or any ancestry filter present — so
  `mkit branch <name>` still creates a branch. `--contains [<c>]` keeps only
  branches whose tip has `<c>` as an ancestor; `--no-contains [<c>]` inverts
  it. `--merged [<c>]` keeps only branches already merged into `<c>` (i.e.
  whose tip is an ancestor of it); `--no-merged [<c>]` inverts it. All four
  ancestry commit args **default to `HEAD`** when omitted (like git).
  Patterns and ancestry filters combine (a branch must satisfy all of
  them). `--list` is an explicit list selector — listing is already the
  default when no create/delete/rename flag is given, but `--list` also
  enables `<pattern>` filtering (e.g. `mkit branch --list "release/*"`, or
  `mkit branch --list main` to test existence).
- `mkit checkout <branch>` — switch HEAD and restore files. Refuses to
  run when staged changes, dirty tracked files, or untracked path
  collisions would be overwritten. Non-colliding untracked files are
  preserved across the switch (git branch-switch semantics); tracked
  files the target tree drops are removed, with emptied directories
  pruned. Prints `Switched to branch '<n>'`, or `Already on '<n>'` for a
  no-op switch (which still runs the dirty-worktree guard).
- `mkit checkout -b|-B <new> [<start>]` — create a branch at the
  start-point (default HEAD) and switch to it; `-b` refuses to clobber an
  existing branch, `-B` create-or-resets. Prints `Switched to a new branch
  '<new>'`.
- `mkit switch <branch>` / `mkit switch -c|-C <new> [<start>]` — git's
  modern branch-switch UX; a thin front-end over `checkout` with the same
  clobber guard and output. `-c` creates (refuses to clobber), `-C`
  create-or-resets, then switches. (`switch -`/`@{-1}` is a follow-up:
  mkit does not yet track a previous branch.)
- `mkit clean [-n] [-f] [-d] [-x|-X] [<path>...]` — remove untracked files
  from the worktree. **Destructive, so it refuses to delete without an
  explicit `-f`** (matching git's `clean.requireForce` default); `-n`
  previews with `Would remove <path>` lines. Without `-d`, untracked
  directories are left alone (git semantics); `-d` recurses into them and
  removes them — but, like git, an untracked directory is only removed
  *wholesale* (shown `<dir>/`) when nothing inside survives: **ignored
  files are kept** (unless `-x`) and keep their parent directory, and a
  **nested repository** (a subdirectory containing `.mkit`/`.git`) is left
  untouched (git needs the double-force `-ff` to remove one, which mkit
  doesn't offer). `-x` also removes ignored files, `-X` removes *only*
  ignored (`-x` and `-X` are mutually exclusive). Trailing pathspecs limit
  the scope to matching top-level entries and whole directories (`.` means
  everything under cwd); a pathspec naming a file *inside* an otherwise
  fully-removable untracked directory is a known limitation — name the
  directory or use `.`. Ignore matching uses the shared path-aware ignore
  matcher (see "Ignore files" below).
- `mkit tag` — list, create, or delete tags.
  - `mkit tag` (no args) — list tags; annotated/signed tags are marked.
  - `mkit tag -l [<pattern>]` — list tags, optionally filtered by a shell
    glob (e.g. `mkit tag -l 'v*'`), reusing `branch`'s `wildmatch` engine.
  - `mkit tag <name> [<commit>]` — create a lightweight tag (a ref
    pointing straight at `<commit>`, default HEAD).
  - `mkit tag -a <name> [-m <msg>] [<commit>]` — create an annotated tag
    object (target, tagger identity, message, timestamp). Without `-m`,
    `$EDITOR` is launched.
  - `mkit tag -s <name> [-m <msg>] [<commit>]` — create a signed
    annotated tag: an Ed25519 signature over the canonical tag bytes
    under the distinct `mkit.tag` domain. Verify with
    `mkit verify <name>`.
  - `mkit tag -d <name>` — delete a tag.
  - `--author <spec>` overrides the tagger identity (same grammar as
    `commit --author`).
- `mkit merge [--no-commit] [-m <msg>] <branch> | --continue | --abort` —
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
- `mkit cherry-pick [-n|--no-commit] [-m|--mainline <parent-number>] <hash> | --continue | --abort`
  — apply a commit to
  the current branch. Refuses to overwrite staged changes, dirty tracked
  files, or untracked path collisions. On conflict, records resumable
  state; see "Resolving conflicts" below. `-n`/`--no-commit` applies a
  **clean** pick to the index + worktree without creating a commit (run
  `mkit commit` when ready; the result has the current branch as its
  single parent). A `-n` pick that **conflicts** is refused before anything
  is written — mkit cannot represent a staged-but-unresolved conflict, and a
  later `mkit commit` only guards merges, so re-run without `-n` to use the
  resumable `--continue` flow. `-m`/`--mainline <parent-number>` selects which parent
  of a **merge** commit is the mainline (git semantics): it is required
  when replaying a merge (mkit refuses to guess which side to diff
  against) and rejected for a non-merge commit. Note this differs from
  `git commit -m` — git's `cherry-pick -m` is mainline selection, not a
  message override.
- `mkit revert <commit> | --continue | --abort` `[-n|--no-commit]` —
  create a new commit that undoes `<commit>` (the inverse of cherry-pick:
  it applies the reverse of the target's diff). The commit message is
  `Revert "<subject>"` with a `This reverts commit <hash>.` trailer.
  This is a **forward** commit — it does not rewrite history, so the
  reverted commit stays reachable (no gc/recovery interaction). Same
  safety guards and resumable conflict workflow as cherry-pick.
  `-n`/`--no-commit` stages the reverted tree (index + worktree) without
  committing, so you can revert several commits and commit once.
  **Reverting a merge commit is refused** — the inverse depends on which
  parent is the mainline, and `-m`/mainline selection is not yet
  supported.
- `mkit rebase [-i|--interactive] <revspec> | --continue | --abort | --skip`
  — replay commits onto a different base. The target is resolved through
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
- `mkit bisect start | good | bad | reset` — binary search for a bug.
- `mkit gc [-n|--dry-run] [--grace-secs <secs>]` — reclaim unreachable
  objects (mark-and-sweep). Under the repo lock it expires stale recovery
  entries, computes the live set reachable from the retention roots (refs,
  stash, in-progress operations, attestations, and the recovery log of
  commits superseded by `commit --amend`/`reset`/`rebase`), then deletes
  unreachable objects older than the grace window (default 14 days).
  `-n`/`--dry-run` reports what would be pruned without deleting.
  `--grace-secs 0` prunes every unreachable object, but **bypasses the
  grace window** — the grace window is gc's concurrency-safety net (some
  root-publishing paths such as `tag` and `fetch` write an object before
  publishing the ref that makes it reachable), so `--grace-secs 0` must
  only be run when **no other mkit process is operating on the repo**
  (gc prints a warning). **Fail-closed:** a missing/corrupt root, a
  malformed ref, or the reachability cap aborts the run with nothing
  deleted, and an object whose age can't be read is kept. See
  [`docs/SPEC-GC.md`](SPEC-GC.md).

### Resolving conflicts

`merge`, `cherry-pick`, and `rebase` all share one resumable-conflict
workflow. A path where both sides changed the **same regular file on
disjoint lines** is auto-merged line-by-line (the union of both edits, no
markers) — changes on different lines merge cleanly even when adjacent. A
conflict is only raised when the two sides' changed regions **overlap**
(modify the same or interleaving lines), or for binary files. When a 3-way
merge cannot auto-resolve a path, the command:

1. Applies the merge's **clean (non-conflicting) changes** to the index
   and worktree (so e.g. files the operation adds/removes/modifies away
   from the conflict are already staged), then materializes the
   conflicting paths into the worktree (staging the ours-side blob so
   each path is "resolvable"):
   - **text** modify/modify (with *overlapping* line changes — disjoint
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
match what is staged in the index — so an unstaged resolution can't be
silently dropped. This covers every shape: an edited regular **or
executable** file, a path deleted without `mkit rm`, and a file replaced
by a symlink or directory without `mkit add`. An *unchanged* conflict
(the worktree still equals the auto-staged ours-side, including its
executable / symlink mode) needs no re-`add` and continues. The committed
tree is built from the **resolved index/worktree** — not the
conflict-time "ours wins" snapshot — so your edits (including a third
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
area — there are no unmerged index stages (SPEC-INDEX is unchanged).

| File                          | Meaning                                              |
| ----------------------------- | ---------------------------------------------------- |
| `MERGE_HEAD`                  | other parent of an in-progress merge (presence ⇒ merge) |
| `CHERRY_PICK_HEAD`            | commit being applied by an in-progress cherry-pick   |
| `ORIG_HEAD`                   | HEAD before the operation, used by `--abort`         |
| `MERGE_MSG` / `CHERRY_PICK_MSG` | pending commit message                             |
| `mkit-conflicts`              | mkit sidecar: one line per conflicting path with the conflict kind and base/ours/theirs blob hashes |
| `rebase-apply/`               | rebase state (`head-name`, `orig-head`, `onto`, `todo`, `actions`, `done`) plus a `mkit-conflicts` sidecar when paused. `actions` is parallel to `todo` (`pick`/`reword`/`squash`/`fixup`, from `rebase -i`); absent ⇒ all `pick` |

Remote / sync:

- `mkit remote [-v|--verbose] [--format=json]` — list the configured
  remotes. Bare `remote` prints **one remote name per line** (git-shaped);
  `-v`/`--verbose` adds the URL and direction
  (`<name>\t<url> (fetch)` / `(push)`). `--format=json` emits the remote
  configuration as JSON; an unset remote produces empty stdout.
- `mkit remote add [<name>] <url>` — add a remote. With a `<name>`,
  registers a named remote (`remote.<name>.url`); without one, sets the
  flat default `remote_endpoint`. The URL MUST start with
  `mkit+<scheme>://` (see below).
- `mkit remote set [<name>] <url>` — alias for `mkit remote add`.
- `mkit remote remove <name>` (alias `rm`) — delete a named remote. The
  reserved name `default` clears the flat `remote_endpoint`.
- `mkit remote rename <old> <new>` (alias `mv`) — rename a named remote
  and repoint any `branch.<b>.remote` upstream tracking it. Refuses to
  clobber an existing `<new>`. Removing or renaming a remote never
  touches the user-scoped `trusted_remote_endpoint`, which is keyed by
  exact URL rather than remote name (so the #97 credential-trust gate is
  preserved).
- `mkit remote get-url <name>` — print a remote's URL (use `default` for
  the flat default remote). `mkit remote set-url <name> <url>` — change an
  existing remote's URL (validated like `remote add`).
- `mkit clone [--depth N] [--sparse ...] <url> [<dir>]` — clone a
  repository into `<dir>` (defaults to the final URL path segment).
  `--sparse <pattern>...` persists the patterns and materialises only the
  matching files via the verifiable sparse-checkout pipeline (requires a
  build with `--features sparse-checkout`). Note this is an
  **enhancement over git**: mkit's `--sparse` takes one or more PATTERN
  arguments, whereas git's `clone --sparse` is a boolean flag (it cones
  to the top-level files and you add patterns afterward). **`--depth N` is parsed but
  not yet wired**: passing it fails with a clear `--depth is not yet
  wired` usage error rather than silently producing a full clone; see
  "Divergences from Git".
- `mkit fetch` — download from remote without merging. Fetched branch
  tips are stored under `refs/remotes/default/<branch>` and do not move
  local branches.
- `mkit pull` — fetch, then fast-forward the current branch from
  `refs/remotes/default/<branch>`. Divergent histories are refused; use
  explicit merge/rebase flows after resolving the divergence. Fresh repos
  with no local branch tip initialize the current branch/worktree from
  the remote default branch.
- `mkit push [<remote>] [--all] [--force|--force-with-lease] [--dry-run]`
  — push refs and packs to a remote. With no `<remote>`, pushes the
  **current branch to its upstream** (the `branch.<b>.remote`/`.merge`
  tracking pair), falling back to the configured default remote; an
  explicit `<remote>` name overrides that choice. The default push is
  CAS-protected: a non-fast-forward is rejected using the remote-tracking
  ref as the lease. `--all` mirrors every `refs/heads/*` (also CAS-safe).
  `--force` overwrites the remote branch unconditionally (skips CAS);
  `--force-with-lease` overwrites only if the remote hasn't moved past
  our last-seen tip (the two are mutually exclusive); `-f` is an alias of
  `--force`. `-u`/`--set-upstream` records the pushed remote as the
  branch's upstream even if one was already set. `--dry-run`
  resolves the push plan without contacting the remote. Every endpoint
  flows through the per-endpoint credential-trust gate, which is keyed on
  the resolved endpoint URL, never the remote name. On success `push`
  prints git's `To <url>` + ref-update summary (or `Everything
  up-to-date`).
- `mkit serve <path>` — internal SSH transport server. Speaks the
  mkit-rpc SSH framing on stdin/stdout by default.
- `mkit serve <path> --listen-enc <addr>` — bind a TCP socket on
  `<addr>` (e.g. `0.0.0.0:9418`) and serve the same protocol over
  an encrypted-stream transport. Requires building the binary with
  `--features enc-transport`. **Fail-closed**: the listener refuses to
  bind unless one of the following is supplied:
  - `--enc-authorized-peers <PATH>` — an allowlist of authorized client
    public keys, one per line (64-hex or 43-char url-safe base64; `#`
    comments and blank lines ignored). A client whose static ed25519
    key is not listed is rejected at the handshake and receives no data.
    This path MUST be CLI-supplied or user-scoped — peer-authorization
    is never read from repo-local `.mkit/config`.
  - `--unsafe-allow-any-enc-peer` — a development escape that accepts
    ANY peer. Prints a loud warning; never use in production.
  These two flags are mutually exclusive.

  Post-handshake resource bounds (slow-loris hardening):
  - `--enc-idle-timeout-secs <SECS>` — per-frame idle timeout applied
    after the handshake completes. A peer that does not send its next
    verb/upload frame within this window has its session dropped, so a
    peer that finishes the handshake then stalls cannot pin a worker +
    socket indefinitely. `0` disables the timeout (not recommended).
    Default: `60`.
  - `--enc-handshake-timeout-secs <SECS>` — overall deadline for
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
  an allowlisting server can recognise it across restarts) by pointing
  the `MKIT_ENC_CLIENT_KEY` environment variable at a user-scoped raw
  32-byte key file; otherwise the client uses an ephemeral key. The
  default port advertised by `mkit+enc://` URLs when none is supplied
  is **9418**. Full keystore integration is deferred (see
  SPEC-TRANSPORT-ENC §6.2).
- `mkit pack-shard <hash> [--out <dir>] [--force]` — encode a stored
  pack into Reed-Solomon shards plus a manifest, ready to publish to
  an HTTP / S3 origin. Producer side of the SPEC-PACK-SHARDS
  wire-format & transport-delivery stage. The
  pack must already be in the local object store. Output layout:
  `<out>/packs/<hex>/shards/<index>` and
  `<out>/packs/<hex>/shards.manifest`. The manifest is written last
  so racing readers either see "no manifest" (clean fall-through to
  the monolithic pack) or "manifest + all shards". Requires building
  the binary with `--features pack-shards`.
- `mkit git export <dest> [--remote-name <name>] [--ref <ref>]...
  [--no-attest] [--algorithm <alg>] [--signer <kind>] [--passthrough] [--json]`
  — deterministic **one-way** export of
  branches and tags to a git mirror
  ([`SPEC-GIT-BRIDGE`](SPEC-GIT-BRIDGE.md)). `<dest>` is a git URL or
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
  published on the mirror's `refs/mkit/attestations` ref — fetch it
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
  [--json]` — import a git upstream as an **importer-signed downstream
  fork** ([`SPEC-GIT-IMPORT`](SPEC-GIT-IMPORT.md)). With `<dir>`:
  init a fresh mkit repo, import all branches/tags, and check out the
  upstream default branch. Without: add the upstream to the current
  repo as `refs/remotes/<name>/*` tracking refs + tags. Every
  translated commit/tag is signed by a DEDICATED import key
  (`.mkit/keys/git-import.key`, generated on first use and pinned per
  state dir — collaborative tracking requires sharing it; a different
  key produces an unrelated fork). Original authorship rides in the
  author identity; original git bytes are retained under
  `.mkit/git/<name>/` with a `git-import/v1` attestation per head.
  Unrepresentable refs skip per-ref with warnings (submodules,
  mkit-illegal names, historic-mode trees in fork state dirs).
  Upstream history imports once per (key, upstream); hashes are a
  function of the import key by design. Plain `git export` toward an
  imported-from upstream is refused (the origin guard); export to new
  mirrors works normally. Expect total disk ≈ 2–3× the upstream
  `.git` (staging mirror + translated store).
- `mkit git fetch [--remote-name <name>] [--key <path>] [--json]` — fetch
  new upstream
  commits into the tracking refs and imported tags (a force-pushed
  upstream moves tracking refs with a loud warning; a tag you moved
  locally is never clobbered — fetch warns and leaves it). `--key` points
  at the import signing key (default: the pinned key file), and `--json`
  emits machine-readable JSON on stdout. `mkit git pull [--remote-name
  <name>] [--key <path>] [--json]` additionally
  fast-forwards the current branch; divergence refuses with the
  executable hint (`mkit merge <name>/<branch>` — imported history is
  ordinary mkit history, integrated natively).
- `mkit git export --passthrough --remote-name <import-name> <fork-url>`
  — **fork mode** (SPEC-GIT-BRIDGE §14): publish an imported repo as a
  true git fork. Imported objects re-emit their ORIGINAL sha1s; only
  native commits on top translate, so the pushed branch sits directly
  on the upstream commits and PRs/merge-bases work. Upgrades the
  import state to direction `fork` (sticky); plain export under that
  name is then refused, while `git fetch`/`pull` keep working.
- `mkit git verify [--remote-name <name>] [--fork-audit] [--ref <ref>]...`
  — audit recorded bridge state against the local store:
  bridge-translated objects shallow-verify (SPEC-GIT-BRIDGE §10) and
  must reconstruct to their mapped twin; imported objects must have
  retained raw bytes hashing to their sha1 and a twin signed by the
  pinned importer key. `--fork-audit` (§14.3) additionally re-derives
  every tree/blob referenced by bridge commits from its mkit twin and
  requires the exact sha1. Exits non-zero listing each failing object;
  unsigned (all-zero-signature) objects also fail, reported as a count
  ("unsigned", never "tampered" — SPEC-GIT-BRIDGE §10).
- `mkit git status` — one block per `.mkit/git/<name>/` state dir:
  direction, recorded source/dest, pinned importer key, tracking refs
  (import) and lease positions (export), staging health.
- `mkit git format-patch <A..B> [-o <dir>] [--stdout]` — render
  native commits as `git am`-able mbox patches (oldest first, merges
  skipped) — the contribution path that needs no writable fork. A
  single rev means `<rev>..HEAD`; e.g.
  `mkit git format-patch upstream/main -o patches/`.

  All `mkit git` subcommands require building the binary with
  `--features git-bridge` (alias: `git-export`); they shell out to `git`.

Agent integration:

- `mkit mcp [--repository <path>]` — start a Model Context Protocol
  server on stdio so LLM agents (Claude, Cursor, etc.) can drive local
  mkit repositories through structured tool calls instead of raw shell.
  Exposes a conservative tool surface: status / diff (unstaged, staged,
  vs target) / log / show / branch / cat-file inspection, staging
  (`add`, unstage), signed `commit`, branch create/checkout, `init`,
  `keygen` (ed25519 commit key, or secp256k1/p256 attestation keys),
  plus the differentiators — `verify` (signature check), `attest`
  (DSSE; supports `algorithm` and `repo-key`/`keystore` signer), and
  `verify-attest` (trust-roots-gated, with an `algorithm` filter). Every
  tool takes an explicit `repo_path`; `--repository <path>` confines all
  calls (symlink resolved) to that root. The server runs **no network
  operations** (push/pull/fetch/clone are not exposed), performs no
  history surgery (merge/rebase/cherry-pick are not exposed), and
  **never passes `-f`/`--force`** — mkit's data-loss guards stay in
  force, and a "refuses without -f" error is surfaced to the agent
  verbatim. Additional guardrails specific to the agent threat model:
  a predicate file passed to `attest` must resolve **inside** the repo
  (no reading outside files into a signed attestation), a `trust_roots`
  path passed to `verify-attest` must resolve **outside** the repo (a
  hostile clone's in-repo `.mkit/attest-trust-roots.toml` can never be
  selected via the MCP — see THREAT-MODEL §"Trust-roots scope"), and the
  external/multi-signer attestation controls are intentionally omitted
  because they can direct subprocess execution (use the `attest` CLI for
  that flow). `initialize` must precede tool calls. Tool results carry
  the child command's output and its sysexits code on failure. Register
  with an MCP client, e.g.:

  ```sh
  claude mcp add mkit-repo -- mkit mcp --repository /path/to/repo
  ```

Config / keys / version:

- `mkit keygen` — generate a new Ed25519 signing keypair.
- `mkit key generate [--backend B] [--label L] [--algorithm ALG]` — generate
  a signing key in a keystore backend. `ALG` is `ed25519`, `secp256k1`, or
  `p256`; default is `ed25519`.
- `mkit key list [--backend B] [--json]` — list keys visible to a backend.
- `mkit key import --algorithm ALG (--hex HEX | --file PATH) [--backend B]
  [--label L]` — import 32 bytes of signing key material where the backend
  allows import.
- `mkit key export [--backend B] [--label L] [--algorithm ALG]
  --unsafe-print-secret` — export extractable key material. Non-extractable
  backends fail closed.
- `mkit key delete [--backend B] [--label L] [--algorithm ALG] --yes` — delete
  exactly one backend key where deletion is supported.
- `mkit config [--format=json]` — show all configuration values.
  `--format=json` emits a flat JSON object with every known key.
- `mkit config <key> [--format=json]` — show one value.
- `mkit config <key> <value>` — set a configuration value. Config
  **section** and **variable** names are matched **case-insensitively**
  (canonicalized to lowercase), like git — so `user.Name`, `USER.EMAIL`,
  etc. resolve to the same key as their lowercase form, in both this
  command and the config-file parser. **Subsection** names — the middle
  segment of `remote.<name>.url` or `branch.<branch>.remote` — stay
  **case-sensitive** (git semantics), so a remote added as `Origin` is not
  silently folded to `origin`.
  - `user.name` / `user.email` — git-compatibility aliases. They are
    accepted and round-trip like `git config user.name`, but are
    **non-authoritative**: mkit's commit author is cryptographic
    (`user.identity` or the signing key's derived Identity), and these
    values **never** feed it. They are repo-safe (stored in
    `.mkit/config`) precisely because they cannot influence the signed
    author — unlike `user.identity`, which stays user-scoped and in
    `REPO_FORBIDDEN_KEYS` so a hostile clone cannot spoof authorship.
  - `core.*` — git-compatibility keys. An **inert** allowlist
    (`core.autocrlf`, `core.bare`, `core.filemode`, `core.ignorecase`,
    `core.quotepath`, `core.symlinks`) is accepted and round-tripped for
    parity but **not honored** — mkit has no CRLF translation, tracks exec
    bits natively, etc. Dangerous `core.*` keys that would change what mkit
    runs (`core.sshCommand`, `core.pager`, `core.editor`, `core.hooksPath`,
    `core.fsmonitor`) are **rejected** rather than stored. Names match
    case-insensitively and canonicalize to lowercase, like git.
- `mkit version` — print the version. Emits exactly `mkit <X.Y.Z>\n`.
  The top-level `mkit --version` / `mkit -V` flags are aliases of this
  subcommand and emit the identical string. Note this is `mkit <X.Y.Z>`,
  not Git's `git version <X.Y.Z>` form — an intentional, documented
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
  (`*.log` matches `a/b/c.log`). A pattern containing a `/` — including a
  leading `/` — is **anchored** to the repo root (`/foo` matches only the
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
These are documented behaviours, not bugs, with tracked follow-ups:

- **Human output goes to stderr; stdout is reserved for porcelain/data.**
  mkit's command summaries (`commit`/`merge`/`push`/`status` …) are
  shaped like git's but are written to **stderr**, so `mkit status` and
  friends stay empty-on-clean in a pipeline and stdout carries only
  machine output (`--porcelain`, `rev-parse`, `rev-list`, …). git puts
  some of these on stdout; mkit keeps its stderr convention.
- **Object ids in human output are 64-hex BLAKE3 prefixes**, not git's
  40-hex SHA-1 — the inherent hash-length divergence. Output otherwise
  matches git's shape (e.g. `To <url>` + `<old>..<new>  main -> main`,
  `[main <hash>] <subject>` + diffstat, `Fast-forward`).
- **The git object-count / delta-compression progress lines**
  (`Enumerating/Counting/Compressing/Writing objects`,
  `Total N (delta D)`) are **not** emitted: mkit's transport is
  one-object-per-pack and computes no deltas, so those numbers would be
  fabricated. A tracked follow-up may add an honest object count.
- **`mkit remote`** lists remote **names only** (git-shaped); use
  `mkit remote -v` for `<name>\t<url> (fetch)`/`(push)`.
- **`mkit log --graph` is a no-op (v1 non-goal).** The flag is accepted
  for compatibility so existing scripts don't break, but no ASCII commit
  graph is drawn. Full graph parity is unachievable because mkit's default
  `log` body already diverges from git's `commit/Author/Date` (mkit
  `Identity` + 64-hex ids); an `--oneline --graph` renderer for the
  linear/DAG case is a tracked post-v1 follow-up, not a v1 blocker.
- **`mkit status --porcelain=v2`** matches git's format except that object
  ids are full 64-hex BLAKE3 (git's are 40-hex SHA-1). Exact renames emit a
  `2` record (`R100`); `--branch` header lines are not emitted.
- **`mkit clone --depth N` is parsed but not yet wired.** The flag is
  accepted by the parser but `clone` rejects it with a `--depth is not
  yet wired` usage error rather than silently producing a full clone.
  Shallow-clone history truncation is a follow-up.
- `mkit reset [--soft|--mixed|--hard] [-f] [<commit>]` — `--soft` moves
  HEAD only; `--mixed` (the default) also resets the index; both leave the
  worktree untouched. `--hard` additionally resets the worktree to the
  target tree — overwriting tracked-file changes and removing tracked
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
mkit data-loss guard — e.g. `clean` and `reset --hard` refuse to delete or
discard without an explicit `-f` — rather than adopting git's silent
destructive default. Rename *detection* in diff/log output remains a
separate, unscheduled follow-up (decision #226): `mkit mv` stages the move
but `status` shows it as a delete + add, not `R`.

Note: object garbage collection (`mkit gc`) **is shipped** (issue #233).
History-rewriting commands (`commit --amend`, `reset`, `rebase`) record
the superseded commit in the recovery log, and `mkit gc` reclaims
unreachable objects once they fall outside the grace window. See
[`docs/SPEC-GC.md`](SPEC-GC.md).

## Config keys

Stored in `.mkit/config` as `key = value` lines — **except** security-sensitive
keys, which are **user-scoped only** and ignored if set in a repo's
`.mkit/config` (a hostile repo must not be able to redirect signing or trust).
Those keys — `user.identity`, `signing_key`, `signer`, `key.*`, `attest.*`,
`ssh.*`, and `trusted_remote_endpoint` — live in the user config
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
`windows-credential`, `linux-secret-service`, `systemd-creds`, and `yubikey`
when the target build enables the corresponding backend feature. Security-
sensitive selector keys are ignored from repo-local config; set them in
`$XDG_CONFIG_HOME/mkit/config` or with explicit command flags.

### `user.identity`

The commit author Identity, encoded as `[kind:u8][len:u16 LE][bytes]`
in lowercase hex per `docs/SPEC-OBJECTS.md §9`. Accepted shorthands at
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
| `mkit+https` | `mkit+https://host[:port]/path` | HTTP gateway (e.g. VCS Worker) |
| `mkit+s3` | `mkit+s3://endpoint/bucket[/prefix]` | S3-compatible object store |
| `mkit+ssh` | `mkit+ssh://user@host[:port]:path` | SSH with the mkit shell |
| `mkit+memory` | `mkit+memory://` | in-memory (testing only) |

See `docs/SPEC-TRANSPORT.md` for the wire protocol.

## Version output contract

`mkit version` prints exactly:

```
mkit <X.Y.Z>\n
```

Downstream packagers (Homebrew, Scoop) assert on this substring. The
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

- **`GIT_EDITOR` / `EDITOR` / `VISUAL`** — the editor `mkit commit`
  opens when neither `-m` nor `-F` is supplied, tried in that order. If
  none is set it falls back to `vi` (Unix) / `notepad` (Windows),
  matching git. In a headless or non-interactive context (CI, an agent),
  always pass `-m`/`-F` so the commit never blocks on an editor.
- **`NO_COLOR`** — if set (any value, including empty) ANSI color on
  stdout is suppressed. See <https://no-color.org>.
- **`CLICOLOR_FORCE=1`** — force ANSI color even when stdout is piped.
  `NO_COLOR` overrides this.
- **`SSH_AUTH_SOCK`** — standard OpenSSH agent socket, used by
  `mkit+ssh://` transports.
- **`XDG_CONFIG_HOME`**, **`XDG_DATA_HOME`**, **`XDG_CACHE_HOME`**,
  **`XDG_STATE_HOME`** — XDG Base Directory roots for user-level config,
  keystore, cache, and state respectively. Defaults per the freedesktop
  spec (`~/.config`, `~/.local/share`, `~/.cache`, `~/.local/state`).

### File layout

| Path                                | Purpose                                          |
| ----------------------------------- | ------------------------------------------------ |
| `.mkit/`                            | Repo-local state (like `.git/`)                  |
| `.mkit/config`                      | Repo-local config — overrides user-level values  |
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
  cleanly without a "Broken pipe" message — the next write just
  propagates `EPIPE` as a normal I/O error. This is the Rust runtime
  default (since 1.65); mkit does not register over it. The behaviour
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

`mkit` exposes a git-compatible CLI surface, so existing git habits — and AI
agents that emit `git <cmd>` — can drive it. `contrib/git-shim/mkit-git` is an
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
