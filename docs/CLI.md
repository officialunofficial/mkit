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

## Subcommand reference

Working-tree commands:

- `mkit init` — create a new repository in `.mkit/`.
- `mkit add [-A|-u] <path>...` / `mkit add .` — stage files for the next
  commit. Multiple pathspecs may be given. `.` stages every non-ignored
  file under the current directory. `-A`/`--all` stages every change in
  the worktree including deletions of tracked files (takes no path
  arguments). `-u`/`--update` restages only already-tracked files —
  updating modified ones and recording deletions — without adding
  untracked paths (takes no path arguments). `-A` and `-u` are mutually
  exclusive. Interactive hunk staging (`add -p`) is **not supported**;
  see "Divergences from Git" below.
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
- `mkit status [--porcelain] [-s|--short]` — show staged and unstaged
  changes. Default-mode prose (banner + section headers + per-file
  lines) goes to **stderr**; stdout is reserved for machine output.
  `-s`/`--short` is an alias for `--porcelain=v1`; both select the same
  renderer. Porcelain emits one entry per line in `git status --porcelain=v1`
  format (`XY <path>`, with mkit's `T` for `ModeChanged` as the only
  non-git extension). Empty stdout means clean. There is **no `-z`/NUL
  termination or path-quoting** support; see "Divergences from Git".
- `mkit diff [--staged|--cached] [<rev> [<rev>] | <a>..<b>] [<path>...]` — show
  changes as a unified patch. With no arguments, compares the HEAD tree
  to a fresh worktree snapshot. `--staged` (alias `--cached`) compares
  the HEAD tree to the staged index tree — the change `mkit commit`
  would record. A single revision compares that revision against the
  worktree; two revisions (or an `<a>..<b>` range) diff the two
  resolved trees directly. Revisions may be refs, commit hashes, short
  hashes, or `HEAD~n` (a raw 64-hex tree hash also works, since it
  resolves to itself). Any remaining positional arguments are pathspecs
  that limit the output to entries at or below them. Output is a
  Git-compatible unified diff: a
  `diff --mkit a/<path> b/<path>` header per changed path followed by
  `@@`-delimited hunks (or `Binary files a/<p> and b/<p> differ` for
  non-text blobs). The hunk algorithm is a line-based LCS unified diff,
  not a full Myers diff — adequate for human-readable parity output.
- `mkit stash [save|list|pop|apply|drop|clear|show]` — save/restore WIP
  changes. `apply` restores an entry without removing it; `clear` drops
  every entry.
- `mkit sparse-checkout` — manage sparse checkout patterns.

History / commits:

- `mkit commit [-a|--all] [--amend] [--author <spec>] -m <msg>` — create
  a signed commit from the staging index. The index is built by `mkit
  add` / `mkit rm`; `commit` with an empty index is an error. Use `mkit
  add .` to snapshot the whole worktree before committing. `-a` / `--all`
  follows Git's tracked-only shortcut: it stages modified tracked files
  and tracked deletions before committing, but does not add untracked
  files. `mkit commit -am <msg>` is accepted as shorthand for `-a -m
  <msg>`. `--author <spec>` overrides the recorded author Identity for
  this commit (highest precedence — above `user.identity` config and the
  signing-key-derived default). The `<spec>` grammar is `ed25519:<hex>`
  (32-byte public key), `did:key:<hex>` (opaque DID-key bytes), or
  `opaque:<bytes>` (raw UTF-8); note this differs from the `user.identity`
  *config* grammar (which also accepts `mid:<N>` and raw encoded hex).
  The signature is always produced by your signing key regardless of the
  recorded author.
  `--amend` **replaces HEAD** instead of adding a new commit: the new
  commit re-uses HEAD's parent(s) as its own parent(s), takes its tree
  from the index, and is re-signed; the branch is moved to it and the
  move is recorded in the ref-history journal. Without `-m` the previous
  commit's message is reused (no editor is launched). The superseded
  commit is recorded in the recovery log so it stays recoverable, and is
  reclaimed by `mkit gc` once it falls out of the retention window.
- `mkit log [--oneline] [--abbrev-commit] [--abbrev[=N]] [--format=json] [--graph] [-n N]` — show
  commit history. The default format prints the **full commit message
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
- `mkit blame [--format=json] <file>` — show line-level commit
  attribution. Default emits `<short12>\t<line_num>\t<text>` per line;
  `--format=json` emits JSONL with keys `hash`, `line_num`, `author`,
  `timestamp`, `text`.
- `mkit verify <rev>` — verify the signature on a commit, remix, or
  signed tag. `<rev>` is an object hash, a branch/tag name, or `HEAD`; a
  tag name resolves to its annotated-tag object when one exists.
- `mkit cat <hash>` — display an object by its hash.
- `mkit hash <file>` — hash a file and store it as a blob.
- `mkit tree` — snapshot the working directory as a tree object.

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
    [,path=<file-or-binary>][,args=<a>|<b>|<c>]`. Signers run in the
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
  list, create, or delete branches. `--format=json` on the list form
  emits JSONL with keys `name`, `current`, `hash`.
- `mkit branch -D <name>` — force-delete. mkit does not track per-branch
  merge status, so `-D` differs from `-d` only in that an absent branch
  is a clean no-op; both still refuse the checked-out branch (deleting
  it would dangle HEAD).
- `mkit branch -m [<old>] <new>` — rename a branch (the current branch
  when `<old>` is omitted). CAS-guarded: refuses to clobber an existing
  `<new>`, and moves HEAD when the renamed branch is checked out.
- `mkit checkout <branch>` — switch HEAD and restore files. Refuses to
  run when staged changes, dirty tracked files, or untracked path
  collisions would be overwritten.
- `mkit tag` — list, create, or delete tags.
  - `mkit tag` (no args) — list tags; annotated/signed tags are marked.
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
- `mkit merge <branch> | --continue | --abort` — three-way merge into
  HEAD. Fast-forwards and clean merges refuse to overwrite staged
  changes, dirty tracked files, or untracked path collisions. On
  conflict, the conflicting paths are materialized for resolution and a
  resumable state is recorded; see "Resolving conflicts" below.
- `mkit cherry-pick <hash> | --continue | --abort` — apply a commit to
  the current branch. Refuses to overwrite staged changes, dirty tracked
  files, or untracked path collisions. On conflict, records resumable
  state; see "Resolving conflicts" below.
- `mkit revert <commit> | --continue | --abort` — create a new commit
  that undoes `<commit>` (the inverse of cherry-pick: it applies the
  reverse of the target's diff). The commit message is
  `Revert "<subject>"` with a `This reverts commit <hash>.` trailer.
  This is a **forward** commit — it does not rewrite history, so the
  reverted commit stays reachable (no gc/recovery interaction). Same
  safety guards and resumable conflict workflow as cherry-pick.
- `mkit rebase <branch> | --continue | --abort | --skip` — replay
  commits onto a different base. Restore steps refuse to overwrite staged
  changes, dirty tracked files, or untracked path collisions. On conflict
  the rebase pauses with resumable state; `--skip` drops the current
  commit. See "Resolving conflicts" below.
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
workflow. When a 3-way merge cannot auto-resolve a path, the command:

1. Applies the merge's **clean (non-conflicting) changes** to the index
   and worktree (so e.g. files the operation adds/removes/modifies away
   from the conflict are already staged), then materializes the
   conflicting paths into the worktree (staging the ours-side blob so
   each path is "resolvable"):
   - **text** modify/modify and add/add → classic 2-way Git markers
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
| `rebase-apply/`               | rebase state (`head-name`, `orig-head`, `onto`, `todo`, `done`) plus a `mkit-conflicts` sidecar when paused |

Remote / sync:

- `mkit remote [--format=json]` — show the configured remotes.
  `--format=json` emits the remote configuration as JSON; an unset
  remote produces empty stdout.
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
- `mkit clone [--depth N] [--sparse ...] <url> [<dir>]` — clone a
  repository into `<dir>` (defaults to the final URL path segment).
  `--sparse <pattern>...` persists the patterns and materialises only the
  matching files via the verifiable sparse-checkout pipeline (requires a
  build with `--features sparse-checkout`). **`--depth N` is parsed but
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
  our last-seen tip (the two are mutually exclusive). `--dry-run`
  resolves the push plan without contacting the remote. Every endpoint
  flows through the per-endpoint credential-trust gate, which is keyed on
  the resolved endpoint URL, never the remote name.
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
  an HTTP / S3 origin. Producer side of SPEC-PACK-SHARDS Phase 2. The
  pack must already be in the local object store. Output layout:
  `<out>/packs/<hex>/shards/<index>` and
  `<out>/packs/<hex>/shards.manifest`. The manifest is written last
  so racing readers either see "no manifest" (clean fall-through to
  the monolithic pack) or "manifest + all shards". Requires building
  the binary with `--features pack-shards`.

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
- `mkit config <key> <value>` — set a configuration value.
- `mkit version` — print the version. Emits exactly `mkit <X.Y.Z>\n`.
  The top-level `mkit --version` / `mkit -V` flags are aliases of this
  subcommand and emit the identical string. Note this is `mkit <X.Y.Z>`,
  not Git's `git version <X.Y.Z>` form — an intentional, documented
  divergence (the string is pinned by packaging asserts).

## Divergences from Git

mkit's local commands intentionally diverge from Git in a few places.
These are documented behaviours, not bugs, with tracked follow-ups:

- **`mkit log --graph` is a no-op.** The flag is accepted for
  compatibility so existing scripts don't break, but no ASCII commit
  graph is drawn. A real graph renderer is a follow-up.
- **`mkit status` has no `-z` / NUL termination or path quoting.**
  Porcelain output is newline-delimited with raw (unquoted) paths.
  Paths containing newlines or other special bytes are therefore not
  round-trippable through porcelain. NUL-termination and C-style path
  quoting are a follow-up.
- **`mkit add -p` (interactive hunk staging) is not supported.** Stage
  whole files with pathspecs, `.`, `-A`, or `-u`. Interactive hunk
  selection is a follow-up.
- **`mkit clone --depth N` is parsed but not yet wired.** The flag is
  accepted by the parser but `clone` rejects it with a `--depth is not
  yet wired` usage error rather than silently producing a full clone.
  Shallow-clone history truncation is a follow-up.
- **`mkit reset --hard` is intentionally not implemented.** `reset`
  offers `--soft` (move HEAD only) and `--mixed` (move HEAD + reset the
  index; the default); both leave the worktree untouched. For a guarded
  worktree-resetting path use `mkit checkout <commit>`, which refuses to
  clobber dirty/untracked files.

### Commands deliberately not implemented (by design)

The following Git commands are **intentionally absent** from mkit. These
are design decisions, not missing features, and are tracked as closed
"wontfix-by-design" follow-ups. mkit offers equivalent workflows for
each:

- **`mkit mv` — not implemented.** There is no rename/move command;
  mkit's content-addressed model records moves implicitly (the blob hash
  is unchanged and the path simply moves between tree entries). Move the
  file in the worktree, then `mkit add` the new path and `mkit rm` (or
  `mkit add -A`) the old one. Rename *detection* in diff/log output is a
  separate, unscheduled follow-up (decision #226).
- **`mkit clean` — not implemented.** mkit will not bulk-delete
  untracked files. Remove stray files with your shell (`rm`), which keeps
  the destructive step explicit and outside mkit's data path (decision
  #226).

Note: object garbage collection (`mkit gc`) **is shipped** (issue #233).
History-rewriting commands (`commit --amend`, `reset`, `rebase`) record
the superseded commit in the recovery log, and `mkit gc` reclaims
unreachable objects once they fall outside the grace window. See
[`docs/SPEC-GC.md`](SPEC-GC.md).

## Config keys

Stored in `.mkit/config` as `key = value` lines.

| Key | Value | Default | Notes |
|-----|-------|---------|-------|
| `user.identity` | hex Identity | unset | See below |
| `signing_key` | path | `.mkit/keys/default.key` | Ed25519 seed file |
| `default_branch` | name | `main` | Branch for `mkit init` |
| `remote_endpoint` | URL / path | empty | Set via `mkit remote add` |
| `remote_bucket` | name | empty | For s3 remotes |
| `remote_type` | `file` / `http` / `s3` / `ssh` / `memory` | auto | |
| `ssh.strict_host_key_checking` | `yes` / `no` / `accept-new` | inherit | |
| `ssh.user_known_hosts_file` | path | inherit | |
| `ssh.identity_file` | path | inherit | |
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

- **`EDITOR`** (fallback: `VISUAL`) — used by `mkit commit` when `-m`
  is not supplied. If neither is set, the commit aborts with a clear
  error rather than silently running `vi`.
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
