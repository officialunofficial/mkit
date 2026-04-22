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
- `mkit add <path>` / `mkit add .` — stage a file (or every non-ignored
  file) for the next commit.
- `mkit rm <path>` — mark a file for removal in the next commit.
- `mkit status` — show staged and unstaged changes.
- `mkit diff [<hash1> <hash2>]` — show changes. With no args, compares
  HEAD to the working directory.
- `mkit stash [save|list|pop|drop|show]` — save/restore WIP changes.
- `mkit sparse-checkout` — manage sparse checkout patterns.

History / commits:

- `mkit commit -m <msg>` — create a signed commit from the index (or
  the working directory if the index is empty).
- `mkit log [--oneline] [--graph] [-n N]` — show commit history.
- `mkit blame <file>` — show line-level commit attribution.
- `mkit verify <hash>` — verify the signature on a commit or remix.
- `mkit cat <hash>` — display an object by its hash.
- `mkit hash <file>` — hash a file and store it as a blob.
- `mkit tree` — snapshot the working directory as a tree object.

Branches / refs:

- `mkit branch` / `mkit branch <name>` / `mkit branch -d <name>` —
  list, create, or delete branches.
- `mkit checkout <branch>` — switch HEAD and restore files.
- `mkit tag` — list, create, or delete tags.
- `mkit merge <branch>` — three-way merge into HEAD.
- `mkit cherry-pick <hash>` — apply a commit to the current branch.
- `mkit rebase <branch> | --continue | --abort` — replay commits onto
  a different base.
- `mkit bisect start | good | bad | reset` — binary search for a bug.

Remote / sync:

- `mkit remote` — show the configured remote.
- `mkit remote add <url>` — set the remote. URL MUST start with
  `mkit+<scheme>://` (see below).
- `mkit remote set <url>` — alias for `mkit remote add`.
- `mkit clone [--depth N] [--sparse ...] <url>` — clone a repository.
- `mkit fetch` — download from remote without merging.
- `mkit pull` — fetch and merge.
- `mkit push [--dry-run]` — push refs and packs to the configured
  remote.
- `mkit serve <path>` — internal SSH transport server.

Config / keys / version:

- `mkit keygen` — generate a new Ed25519 signing keypair.
- `mkit config` — show all configuration values.
- `mkit config <key> <value>` — set a configuration value.
- `mkit version` — print the version. Emits exactly `mkit <X.Y.Z>\n`.

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
| `mkit+s3` | `mkit+s3://bucket/prefix` | S3-compatible object store |
| `mkit+ssh` | `mkit+ssh://user@host[:port]:path` | SSH with the mkit shell |
| `mkit+memory` | `mkit+memory://` | in-memory (testing only) |

See `docs/SPEC-TRANSPORT.md` for the wire protocol.

## Version output contract

`mkit version` prints exactly:

```
mkit <X.Y.Z>\n
```

Downstream packagers (Homebrew, Scoop) assert on this substring. The
format is pinned by a snapshot test in `src/cli_test.zig`.

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

The constants live in `src/exit.zig`. Shell scripts can distinguish
user typos (64) from transient failures (75) without parsing stderr.

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

Repo-local values in `.mkit/config` always win over user-level config.

### Signals

- **`SIGINT`** (Ctrl-C) and **`SIGTERM`** set a graceful-shutdown flag.
  Long-running operations (push, pull, clone) poll it at natural
  checkpoints and exit with `tempfail` (75) so the operation can be
  retried.
- **`SIGPIPE`** is ignored. Pipelines like `mkit log | head -1` exit
  cleanly without a "Broken pipe" message — the next write just
  propagates `EPIPE` as a normal I/O error.

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
