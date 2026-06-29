/**
 * Static mkit-vs-git parity data, distilled from `docs/PARITY.md` (the authoritative scope gate). User-facing notes
 * only — internal phase/issue tracking is dropped. The framing that matters: mkit targets CLI/UX parity, not on-disk or
 * wire interop with real `.git` repositories. A BLAKE3 object store cannot share bytes with git's SHA-1 store.
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
  { status: 'parity', symbol: '✅', label: 'parity', meaning: "Behaves like git's in-scope subset today." },
  { status: 'divergent', symbol: '⚠️', label: 'divergent', meaning: 'Works, with a known, documented difference.' },
  { status: 'non-goal', symbol: '🚫', label: 'non-goal', meaning: "Deliberately not git's behavior." },
]

export const categories: ParityCategory[] = [
  {
    name: 'Everyday',
    items: [
      { cmd: 'init', status: 'parity', note: 'Create a repo. The marker is .mkit/, not .git/.' },
      { cmd: 'add', status: 'parity', note: 'Pathspecs, -A, -u, and -p interactive hunk staging.' },
      {
        cmd: 'status',
        status: 'parity',
        note: '--porcelain v1 and v2, -s, -z. Git-shaped output, adding T for a mode change.',
      },
      {
        cmd: 'diff',
        status: 'parity',
        note: 'Worktree, --staged, ranges, --stat, --name-status, and byte-exact Myers hunks.',
      },
      { cmd: 'commit', status: 'parity', note: '-m, -a, --amend, --author. Every commit is signed.' },
      { cmd: 'rm', status: 'parity', note: '--cached, -r, -f. Refuses to destroy modified content without -f.' },
      {
        cmd: 'mv',
        status: 'parity',
        note: "Renames or moves files and directories (including move-into-directory and multi-source moves) with git's `-f` file-clobber guard (a directory destination is never overwritten). Content addressing gives exact rename detection, so `status` and `diff` show `R` like git (`--no-renames` to opt out).",
      },
      {
        cmd: 'checkout / switch',
        status: 'parity',
        note: 'Switch branches (checkout -b/-B, switch -c/-C to create) or restore files, guarded against clobbering dirty or colliding files.',
      },
      { cmd: 'restore / reset', status: 'parity', note: '--staged, --worktree, --soft, --mixed, --hard.' },
    ],
  },
  {
    name: 'Branches, tags, and merging',
    items: [
      { cmd: 'branch', status: 'parity', note: 'Create, list, -v, -d/-D, -m.' },
      { cmd: 'tag', status: 'parity', note: 'Lightweight, -a, -s, -m, -d.' },
      {
        cmd: 'merge / cherry-pick / rebase',
        status: 'parity',
        note: 'Full conflict workflow. rebase -i reorders, drops, rewords, squashes, and fixups.',
      },
      {
        cmd: 'revert',
        status: 'parity',
        note: 'Inverse commit, conflict-aware. Reverting a merge commit is not yet supported.',
      },
    ],
  },
  {
    name: 'History and inspection',
    items: [
      { cmd: 'log', status: 'parity', note: 'Ranges, -n, --oneline, --format=json. --graph is accepted as a no-op.' },
      {
        cmd: 'show',
        status: 'parity',
        note: 'Commits, trees, blobs, and tags. The diff body matches git; the commit header differs.',
      },
      {
        cmd: 'reflog',
        status: 'divergent',
        note: "Backed by a tamper-evident commit-history Merkle log, not git's reflog. No per-entry op label or message.",
      },
      {
        cmd: 'blame',
        status: 'divergent',
        note: 'Supports -L line ranges and a [<rev>] argument. Attribution is first-parent only, with no -w / -M / -C and no --porcelain. --format=json carries an mkit Identity, not Name <email>.',
      },
      {
        cmd: 'bisect',
        status: 'divergent',
        note: 'start, good, bad, skip, reset. Prints the next candidate to stdout rather than auto-checking-out the midpoint (you check it out yourself); no bisect run.',
      },
    ],
  },
  {
    name: 'Cleanup and maintenance',
    items: [
      { cmd: 'clean', status: 'parity', note: '-n, -f, -d, -x, -X. Refuses without -f, matching clean.requireForce.' },
      { cmd: 'stash', status: 'parity', note: 'save, list, pop, apply, drop, clear, show.' },
      { cmd: 'gc', status: 'parity', note: 'Mark-and-sweep, recovery-aware, and fail-closed.' },
      {
        cmd: 'sparse-checkout',
        status: 'parity',
        note: 'set, list, disable, reapply over pattern sets (stored in .mkit/sparse-checkout). The sparse clone/fetch that transfers only matching paths is feature-gated.',
      },
    ],
  },
  {
    name: 'Plumbing',
    items: [
      { cmd: 'rev-parse', status: 'parity', note: '--verify, --short, --abbrev-ref, --show-toplevel.' },
      { cmd: 'cat-file', status: 'parity', note: '-t, -s, -p, --batch. Byte-exact for blobs.' },
      {
        cmd: 'ls-files / ls-tree',
        status: 'parity',
        note: 'ls-files: -s, -z, --others, --ignored, --exclude-standard. ls-tree: -r, -z. Output matches git modulo hash length.',
      },
      { cmd: 'show-ref / for-each-ref', status: 'parity', note: '--heads, --tags, --format.' },
      {
        cmd: 'symbolic-ref / update-ref',
        status: 'parity',
        note: 'Read or repoint HEAD. CAS via <old>; -d refuses the current branch.',
      },
      {
        cmd: 'merge-base',
        status: 'parity',
        note: '<a> <b> prints the common ancestor; --is-ancestor tests ancestry via exit code.',
      },
      {
        cmd: 'rev-list',
        status: 'parity',
        note: 'Lists commit ids reachable from a revision; --count prints the number.',
      },
    ],
  },
  {
    name: 'Remotes and git interop',
    items: [
      {
        cmd: 'remote',
        status: 'parity',
        note: 'List (-v), add, remove, rename, get-url, set-url. Accepts mkit+file, mkit+https, mkit+s3, mkit+ssh, plus git+https / git+ssh / git+file bridge remotes.',
      },
      {
        cmd: 'push / pull / fetch / clone',
        status: 'parity',
        note: "Over mkit's own transports, with CAS-safe push and --force-with-lease. They speak mkit's protocol, not git's wire protocol.",
      },
      {
        cmd: 'git import',
        status: 'divergent',
        note: 'One-way, importer-signed translation from a git remote (a downstream fork). Experimental and feature-gated.',
      },
      {
        cmd: 'git export',
        status: 'divergent',
        note: 'One-way deterministic mirror to git. Experimental and feature-gated.',
      },
      {
        cmd: 'on-disk / wire interop with .git',
        status: 'non-goal',
        note: "A BLAKE3 object store can't share bytes with git's SHA-1 store. Native push/pull refuse bridge schemes, and bidirectional sync is a permanent non-goal.",
      },
    ],
  },
  {
    name: 'Config and conventions',
    items: [
      {
        cmd: 'config user.name / user.email',
        status: 'parity',
        note: 'Accepted and round-tripped, but non-authoritative: they never feed the signed identity.',
      },
      {
        cmd: 'config core.*',
        status: 'parity',
        note: 'An inert subset is stored; dangerous keys (sshCommand, pager, editor, hooksPath, fsmonitor) are rejected.',
      },
      {
        cmd: '.gitignore',
        status: 'parity',
        note: 'Reads .gitignore and .mkitignore. Supports **, anchors, negation, and char classes (root-level; nested ignore files deferred).',
      },
      { cmd: 'abbreviated hashes', status: 'parity', note: 'Short-prefix resolution and display, as BLAKE3 prefixes.' },
    ],
  },
]

/** Divergences that fall out of choosing BLAKE3, and cannot change without dropping it. */
export const inherentDivergences: ParityNote[] = [
  {
    label: 'Hash length',
    body: "mkit object IDs are 64-hex BLAKE3; git's are 40-hex SHA-1. A git SHA pasted into mkit will never resolve. mkit matches the UX shape (short prefixes, abbreviated display) but not the length.",
  },
  {
    label: 'Repo marker',
    body: "mkit's state lives in .mkit/, not .git/. Detecting a repo by .git/ is not built into the core; an opt-in git alias shim exists, but is never installed by default.",
  },
]

/** Places mkit deliberately refuses git's defaults. These stay even once a command reaches parity. */
export const safetyDivergences: ParityNote[] = [
  {
    label: 'No silent data loss',
    body: 'rm, restore, reset --hard, clean, stash pop, mv, and checkout refuse to destroy modified or untracked content without an explicit -f / --force.',
  },
  {
    label: "A hostile clone can't spoof you",
    body: 'user.identity and other security-sensitive keys are forbidden in repo-local config, so a checked-out repo cannot redirect signing or transport trust.',
  },
  {
    label: 'Rewrites stay recoverable',
    body: 'commit --amend, reset, and rebase record the superseded commit in a recovery log, so gc keeps it recoverable within the retention window.',
  },
]

/** Explicitly out of scope for v1 parity. */
export const nonGoals: string[] = [
  'Submodules and subtrees',
  'Hooks (core.hooksPath)',
  'Multiple working trees (git worktree)',
  'The full refspec grammar and wildcard push/fetch maps',
  'Wire protocol v2 and smart-HTTP negotiation',
  'git notes',
  'Partial / shallow clone beyond what clone already exposes',
  '.git/ on-disk interop and SHA-1/SHA-256 objects',
  'Shadowing the git binary on PATH by default',
  'log --graph ASCII commit-graph rendering',
]
