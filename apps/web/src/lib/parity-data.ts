/**
 * Static mkit-vs-git parity data — the single source of truth for the per-command parity matrix rendered at `/parity`.
 * User-facing notes only; the surrounding scope gate, machine-output contract, and internal phase/issue tracking live
 * in `docs/PARITY.md`. The framing that matters: mkit targets CLI/UX parity, not on-disk or wire interop with real
 * `.git` repositories. A BLAKE3 object store cannot share bytes with git's SHA-1 store.
 *
 * `parity-sync.test.ts` parses `docs/PARITY.md`'s "Deferred flags" list and fails CI if a command listed there is
 * rendered with an unqualified `'parity'` status below — keep a command's status/note here honest with that list when
 * either file changes.
 */

export type ParityStatus = 'parity' | 'divergent' | 'non-goal'

export type ParityItem = {
  /** Command or convention, rendered in mono. */
  cmd: string
  status: ParityStatus
  /** One-line, user-facing summary of how mkit's behavior relates to git's. */
  note: string
}

export type ParityCategory = {
  name: string
  /** Optional one-line framing shown under the category heading. */
  blurb?: string
  items: ParityItem[]
}

export type ParityNote = {
  label: string
  body: string
}

export const legend: { status: ParityStatus; symbol: string; label: string; meaning: string }[] = [
  { status: 'parity', symbol: '✅', label: 'parity', meaning: 'Matches Git for the flags in scope.' },
  { status: 'divergent', symbol: '⚠️', label: 'divergent', meaning: 'Works, with documented differences.' },
  { status: 'non-goal', symbol: '🚫', label: 'non-goal', meaning: 'Intentionally not supported.' },
]

export const categories: ParityCategory[] = [
  {
    name: 'Everyday',
    blurb: 'Stage, commit, inspect, and undo changes.',
    items: [
      { cmd: 'init', status: 'parity', note: 'Creates .mkit/ instead of .git/.' },
      {
        cmd: 'add',
        status: 'divergent',
        note: 'Pathspecs, -A, -u, and -p interactive hunk staging. -n/--dry-run is not implemented.',
      },
      {
        cmd: 'status',
        status: 'parity',
        note: '--porcelain v1 and v2, -s, -z. Git-compatible output, adding T for a mode change.',
      },
      {
        cmd: 'diff',
        status: 'parity',
        note: 'Worktree, --staged, ranges, --stat, --name-status, -w/-b whitespace modes, -U<n> context, and byte-exact Myers hunks.',
      },
      { cmd: 'commit', status: 'parity', note: '-m, -a, --amend, --author. Every commit is signed.' },
      { cmd: 'rm', status: 'parity', note: '--cached, -r, -f. Refuses to destroy modified content without -f.' },
      {
        cmd: 'mv',
        status: 'parity',
        note: "Renames or moves files and directories, including moves into a directory and multi-source moves, with Git's `-f` overwrite guard (a directory destination is never overwritten). Content addressing gives exact rename detection, so `status` and `diff` show `R` like Git (`--no-renames` turns it off).",
      },
      {
        cmd: 'checkout / switch',
        status: 'parity',
        note: 'Switch branches (checkout -b/-B, switch -c/-C to create) or restore files. Refuses to overwrite modified or colliding files.',
      },
      { cmd: 'restore / reset', status: 'parity', note: '--staged, --worktree, --soft, --mixed, --hard.' },
    ],
  },
  {
    name: 'Branches, tags, and merging',
    blurb: 'Create branches and tags, then merge history back together.',
    items: [
      {
        cmd: 'branch',
        status: 'divergent',
        note: "Create, list, -v, -d/-D, -m. Remote-tracking listing and upstream flags (-r, -a, -u, --unset-upstream) aren't implemented yet.",
      },
      { cmd: 'tag', status: 'parity', note: 'Lightweight, -a, -s, -m, -d.' },
      {
        cmd: 'merge / cherry-pick / rebase',
        status: 'parity',
        note: 'Full conflict workflow. rebase -i supports reorder, drop, reword, squash, and fixup.',
      },
      {
        cmd: 'revert',
        status: 'parity',
        note: 'Creates an inverse commit and handles conflicts. Reverting a merge commit is not yet supported.',
      },
    ],
  },
  {
    name: 'History and inspection',
    blurb: 'Read what happened, and find when it changed.',
    items: [
      {
        cmd: 'log',
        status: 'divergent',
        note: 'Ranges, -n, --oneline, --format=json, --author/--grep (substring), --since/--until, --no-merges, --first-parent. --graph is accepted as a no-op. -p, --stat, --decorate, and --all are not yet implemented.',
      },
      {
        cmd: 'show',
        status: 'parity',
        note: 'Commits, trees, blobs, and tags. The diff body matches git; the commit header differs.',
      },
      {
        cmd: 'reflog',
        status: 'divergent',
        note: "Rebuilds the branch's reachable first-parent chain (@{N}) and checks it against a tamper-evident Merkle log of commit history. Unlike Git's per-operation reflog, it shows each commit's subject without operation labels and omits commits replaced by amend or reset.",
      },
      {
        cmd: 'blame',
        status: 'divergent',
        note: "Supports -L line ranges, a [<rev>] argument, -w, -M/-C move and copy detection (including inline -M<num>/-C<num> thresholds and Git's three-level -C -C -C whole-history search), --ignore-rev fall-through, and Git-compatible --porcelain/--line-porcelain. Move/copy and --ignore-rev attribution follows every real merge parent using Git's per-parent -C candidate mechanism (modified files vs whole tree, porigin-keyed) and Git's ancestor tie-break, pinned against Git 2.50.1. Opt-in --ignore-rev-precise resolves --ignore-rev fall-through by content matching instead of Git's positional per-hunk guess; the default matches Git. Two differences remain: --format=json and --porcelain show an mkit Identity instead of Name <email>, as log does; and blame follows a fixed path, so it does not trace lines across a whole-file rename as Git does (use -C to credit copied blocks).",
      },
      {
        cmd: 'bisect',
        status: 'divergent',
        note: 'start, good, bad, skip, reset, and run <cmd> (automatic bisect using Git’s 0/125/1-127 exit codes). Prints the next candidate to stdout instead of checking it out; you check it out yourself. run checks out each candidate temporarily, then prints the first bad commit instead of leaving it checked out.',
      },
    ],
  },
  {
    name: 'Workspace',
    blurb: 'Manage linked worktrees, partial checkouts, and stashed changes.',
    items: [
      {
        cmd: 'worktree',
        status: 'divergent',
        note: 'add, list, remove, and prune linked working trees. All trees share one object store and one set of refs; each has its own HEAD, index, in-progress operation state, and stash. A branch can be checked out in only one tree at a time. Differences from Git: the stash is per-worktree (Git shares one stash across trees), and move, lock, and repair are not yet implemented.',
      },
      {
        cmd: 'sparse-checkout',
        status: 'parity',
        note: 'set, list, disable, reapply over pattern sets (stored in .mkit/sparse-checkout). The sparse clone/fetch that transfers only matching paths is feature-gated.',
      },
      {
        cmd: 'stash',
        status: 'parity',
        note: 'save, list, pop, apply, drop, clear, show. Per-worktree (Git shares one stash across trees).',
      },
    ],
  },
  {
    name: 'Cleanup and maintenance',
    blurb: 'Remove untracked files and reclaim object storage.',
    items: [
      { cmd: 'clean', status: 'parity', note: '-n, -f, -d, -x, -X. Refuses without -f, matching clean.requireForce.' },
      {
        cmd: 'gc',
        status: 'parity',
        note: 'Mark-and-sweep, recovery-aware, and fail-closed. Collects retention roots from every linked worktree.',
      },
    ],
  },
  {
    name: 'Plumbing',
    blurb: 'Low-level commands for scripts and tools.',
    items: [
      { cmd: 'rev-parse', status: 'parity', note: '--verify, --short, --abbrev-ref, --show-toplevel.' },
      { cmd: 'cat-file', status: 'parity', note: '-t, -s, -p, --batch. Byte-exact for blobs.' },
      {
        cmd: 'ls-files / ls-tree',
        status: 'parity',
        note: 'ls-files: -s, -z, --others, --ignored, --exclude-standard. ls-tree: -r, -z. Output matches Git except for hash length.',
      },
      { cmd: 'show-ref / for-each-ref', status: 'parity', note: '--heads, --tags, --format.' },
      {
        cmd: 'symbolic-ref / update-ref',
        status: 'parity',
        note: 'Read or repoint HEAD. update-ref accepts <old> for compare-and-swap; -d refuses to delete the current branch.',
      },
      {
        cmd: 'merge-base',
        status: 'parity',
        note: '<a> <b> prints the common ancestor; --is-ancestor tests ancestry via exit code.',
      },
      {
        cmd: 'rev-list',
        status: 'parity',
        note: 'Lists commit IDs reachable from a revision; --count prints the number.',
      },
    ],
  },
  {
    name: 'Remotes and Git interop',
    blurb: "Sync over mkit's own transports, with one-way bridges to and from Git.",
    items: [
      {
        cmd: 'remote',
        status: 'parity',
        note: "List (-v), add, remove, rename, get-url, set-url. Accepts mkit+file, mkit+https, mkit+s3, mkit+ssh, plus git+https / git+ssh / git+file bridge remotes. When names nest (a and a/b both configured), rename keeps the other remote's tracking refs; Git renames them as well.",
      },
      {
        cmd: 'push / pull / fetch / clone',
        status: 'parity',
        note: "Use mkit's own transports and protocol, not Git's wire protocol. push is compare-and-swap safe and supports --force-with-lease. fetch/pull support --all (every configured remote); clone supports -b <branch> and -o <name>.",
      },
      {
        cmd: 'git import',
        status: 'divergent',
        note: 'One-way, importer-signed translation from a Git remote (a downstream fork). Experimental and feature-gated.',
      },
      {
        cmd: 'git export',
        status: 'divergent',
        note: 'One-way deterministic mirror to Git. Experimental and feature-gated.',
      },
      {
        cmd: 'on-disk / wire interop with .git',
        status: 'non-goal',
        note: "A BLAKE3 object store can't share bytes with Git's SHA-1 store. Native push/pull refuse bridge schemes, and bidirectional sync will not be supported.",
      },
    ],
  },
  {
    name: 'Config and conventions',
    blurb: 'Git-compatible settings and ignore rules.',
    items: [
      {
        cmd: 'config user.name / user.email',
        status: 'parity',
        note: 'Stored and read back, but they do not determine the signing identity.',
      },
      {
        cmd: 'config --unset / --local / --global',
        status: 'parity',
        note: 'Removes a key from the scope a set would write to (repository or user), or from the scope --local/--global selects. Unsetting a key that is not set succeeds.',
      },
      {
        cmd: 'config core.*',
        status: 'parity',
        note: 'An inert subset is stored; dangerous keys (sshCommand, pager, editor, hooksPath, fsmonitor) are rejected.',
      },
      {
        cmd: '.gitignore',
        status: 'parity',
        note: 'Reads .gitignore and .mkitignore. Supports **, anchors, negation, and char classes (root-level only; nested ignore files are not yet supported).',
      },
      { cmd: 'abbreviated hashes', status: 'parity', note: 'Short-prefix resolution and display, as BLAKE3 prefixes.' },
    ],
  },
]

/** Divergences that fall out of choosing BLAKE3, and cannot change without dropping it. */
export const inherentDivergences: ParityNote[] = [
  {
    label: 'Hash length',
    body: "mkit object IDs are 64 hex characters (BLAKE3); Git's are 40 hex characters (SHA-1). A Git hash never resolves in mkit. Short prefixes and abbreviated display work, as prefixes of the BLAKE3 ID.",
  },
  {
    label: 'Repository directory',
    body: 'mkit stores repository state in .mkit/, not .git/, and does not detect repositories by .git/. An opt-in git alias shim exists but is never installed by default.',
  },
]

/** Places mkit deliberately refuses git's defaults. These stay even once a command reaches parity. */
export const safetyDivergences: ParityNote[] = [
  {
    label: 'Destructive commands require --force',
    body: 'rm, restore, reset --hard, clean, stash pop, mv, checkout, and worktree remove refuse to destroy modified or untracked content without an explicit -f / --force.',
  },
  {
    label: 'Repository-local identity settings are rejected',
    body: 'Repository config cannot set user.identity or other security-sensitive keys, so a cloned repository cannot redirect signing or transport trust.',
  },
  {
    label: 'Rewrites stay recoverable',
    body: 'commit --amend, reset, and rebase record each replaced commit in a recovery log, and gc keeps it recoverable for the retention window.',
  },
]

/** Explicitly out of scope for v1 parity. */
export const nonGoals: string[] = [
  'Submodules and subtrees',
  'Hooks (core.hooksPath)',
  'The full refspec grammar and wildcard push/fetch maps',
  'Wire protocol v2 and smart-HTTP negotiation',
  'git notes',
  'Partial / shallow clone beyond what clone already exposes',
  '.git/ on-disk interop and SHA-1/SHA-256 objects',
  'Shadowing the git binary on PATH by default',
  'log --graph ASCII commit-graph rendering',
]
