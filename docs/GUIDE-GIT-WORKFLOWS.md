# Git workflows with mkit

How to live with git from mkit: migrate a repository, track a git
upstream while working natively, and send work back. Everything here
needs a binary built with `--features git-bridge` (alias
`git-export`) and a `git` on `PATH`. The mechanics are specified in
[`SPEC-GIT-IMPORT.md`](SPEC-GIT-IMPORT.md) (inbound) and
[`SPEC-GIT-BRIDGE.md`](SPEC-GIT-BRIDGE.md) (outbound, fork mode);
this guide is the journey-level view.

One model to keep in mind: an import is a **downstream fork**, not a
mirror. Every translated commit is signed by a dedicated import key
("I vouch for this translation"); original git authorship rides in
the author identity field, and the original git bytes are retained
for audit. Hashes are a function of (upstream, import key) — same
key, same upstream, same hashes, on any machine.

## 1. Migrate a git repository to mkit

```console
$ mkit git import git@github.com:org/repo.git repo
$ cd repo
$ mkit log -n 3        # readable original authorship
$ mkit verify HEAD     # ordinary signed mkit history
```

This initializes a fresh mkit repo in `repo/`, imports every branch
and tag, and checks out the upstream default branch. From here it is
a normal mkit repository — commit, branch, merge, push to mkit
remotes. The first import generates `.mkit/keys/git-import.key` with
a loud notice; backups of that key matter if you ever want to reuse
or share the import mapping (see §4).

If the old repository keeps receiving pushes during a transition
window, this is journey 2 — pull from it until the cutover, then
stop.

Disk expectation: roughly 2–3× the upstream `.git` (a staging mirror
under `.mkit/git/<name>/repo.git` plus the translated store). The
staging mirror is durable state, not a cache — keep it.

## 2. Track a git upstream

```console
$ mkit git import https://github.com/org/repo.git work
$ cd work
$ mkit keygen                          # your own signing key
# ... commit local work ...
$ mkit git pull                        # upstream moved? fast-forward
$ mkit git pull                        # diverged? it refuses:
error: pull would not fast-forward branch 'main'; integrate with
`mkit merge upstream/main` (or `mkit rebase upstream/main`)
$ mkit merge upstream/main             # ordinary native merge
```

`mkit git fetch` moves the `upstream/<branch>` tracking refs and
imported tags (a tag you moved locally is never clobbered); `pull`
adds a fast-forward of the current branch and **never** merges on
its own. Imported history is ordinary mkit history, so
integration is the native `mkit merge` with full conflict handling.

Upstream force-pushes move the tracking refs with a loud warning
(rebase local work that built on the rewritten segment). Upstream
branch deletions prune the tracking refs, like `git fetch --prune`;
local tags are kept.

`mkit git status` shows every bridge binding (direction, source,
pinned key, tracking and lease positions). `mkit git verify` audits
the recorded state against the local store at any time.

## 3. Send work back to the git upstream

Two paths, by increasing setup:

### Patches (no fork needed)

```console
$ mkit git format-patch upstream/main..HEAD -o patches/
0001-Add-feature-file.patch
0002-Extend-feature-file.patch
```

The output is `git am`-able mbox — a maintainer on plain git applies
it directly. Patches are text-only (binary changes refuse loudly)
and merges are skipped; keep contribution branches linear.

### A real fork (PRs)

```console
$ mkit git export --passthrough --remote-name upstream git@github.com:you/repo.git
```

Fork mode (SPEC-GIT-BRIDGE §14) re-emits imported objects as their
ORIGINAL git sha1s and bridge-translates only your native commits on
top. The pushed branch sits directly on the upstream's own commits —
merge bases exist, diffs show only your work, and the GitHub PR flow
works. `--remote-name` must be the state that imported the upstream
(its map carries the original objects); the state's direction
upgrades to `fork` and sticks.

Verification of a fork: `mkit git verify --fork-audit` deep-checks
the bridge segment, checks every imported boundary object against
its retained raw bytes and the pinned importer key, and re-derives
all referenced content from the mkit twins (§14.3).

### What is refused, and why

- **Plain `mkit git export` toward an imported-from upstream** — the
  origin guard (§14.2). A plain export is a fresh translation that
  shares no sha1s with the upstream; pushing it there would replace
  the upstream's history with a disconnected mirror that happens to
  pass its lease. Passthrough through the importing state is the
  supported path.
- **Passthrough through a different state than the one that imported
  the destination** — same disconnection, same guard.
- **Native `mkit push`/`pull` against `git+…` remotes** — the
  dispatch matrix points at `mkit git` commands; the object models
  do not interoperate silently.

## 4. Collaborating on an imported repository

Per-key determinism means the import mapping is shared by sharing
the **import key**, not the map file: a colleague with the same key
and upstream reproduces identical mkit hashes independently. Without
it they produce an unrelated fork (and `mkit git fetch` refuses a
mismatched key against pinned state). The usual setup is one
designated importer (a person or CI job) whose imported history
everyone else pulls over normal mkit transport — see SPEC-GIT-IMPORT
§4 before sharing key material.

## 5. State, recovery, and hygiene

Everything per-remote lives in `.mkit/git/<name>/`: the staging
mirror (durable), the blake3↔sha1 map (rebuildable cache), recorded
ref state, direction/source/dest/key bindings, and retained raw git
bytes (`raw/`, audit evidence). An interrupted import/fetch leaves a
crash marker; the next run discards the map cache and re-translates
every ref from scratch (recorded ref state is kept — it carries tag
ownership and prune memory) — determinism makes the rebuild exact,
including for fork-mode state. A missing or corrupt map without a
marker triggers the same rebuild.

`mkit remote rename` moves bridge state with the remote;
`mkit remote remove` keeps it (raw bytes are audit evidence) and
tells you the path if you want it gone.
