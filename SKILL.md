---
name: mkit
description: >
  Drive the `mkit` CLI — a content-addressed version control tool with BLAKE3
  object IDs, Ed25519-signed commits, and native in-toto/DSSE attestation. Use
  this when working in a `.mkit/` repository, making signed commits, managing
  signing keys, producing or verifying supply-chain attestations, inspecting
  content-addressed objects, or syncing over `mkit+ssh`/`https`/`s3`/`file`
  transports. mkit mirrors git's CLI/UX, so git muscle memory applies — this
  skill focuses on the parts that are *not* like git.
---

# mkit

`mkit` is a git-like CLI that produces **signed, content-addressed** objects.
Every commit is Ed25519-signed and named by its BLAKE3 hash, so object chains
are self-verifying independent of where they're stored, and any commit can
carry **attestations** (in-toto v1 Statements in DSSE envelopes) that downstream
services verify against a trust-roots registry.

If you already know git, you can drive `add`/`commit`/`log`/`branch`/`merge`/
`rebase`/`stash`/`diff`/`status` etc. by reflex. **Spend your attention on the
four differences below and the differentiator commands** — that's where mkit is
not git.

## Setup

```sh
# Install the CLI from crates.io (the public channel). The binary is `mkit`.
cargo install mkit-cli
#   ^ NOTE: install `mkit-cli`, NOT `mkit` — `mkit` on crates.io is a
#     different, unrelated crate. Do not run `cargo install mkit`.
#   (Signed release archives exist too, but the source repo is private, so
#    crates.io is the channel that works without repo access.)

mkit --version          # must print exactly: mkit <X.Y.Z>

# Start a repo and make your first signed commit:
mkit init               # creates .mkit/ in the current directory
mkit keygen             # generate an Ed25519 signing key (.mkit/keys/default.key)
echo hello > hi.txt
mkit add hi.txt
mkit commit -m "first commit"   # commits are ALWAYS Ed25519-signed
```

A signing key is mandatory: `commit`/`tag -s`/`attest` need one. If you skip
`keygen`, commits fail. `commit` opens `$EDITOR` (then `$VISUAL`) when `-m` is
omitted, and aborts if neither is set rather than guessing.

## Mental model: like git, with four differences that matter

1. **Object IDs are 64-hex BLAKE3, not 40-hex SHA-1.** A git SHA pasted into
   mkit will never resolve. Use `--short[=N]` / `rev-parse --short` for
   abbreviations. Short-prefix lookups work like git.
2. **The repo marker is `.mkit/`, not `.git/`.** Layout is parallel:
   `.mkit/objects/`, `.mkit/refs/`, `.mkit/HEAD`, `.mkit/config`.
3. **Safety guards over git's destructive defaults.** Data-losing operations
   refuse without `-f`, and most accept `-n`/`--dry-run` to preview:
   `reset --hard`, `clean`, `restore`, `branch -D` (still refuses the *current*
   branch), `push --force` (prefer `--force-with-lease`), `gc`.
4. **Authorship is cryptographic.** The signed author defaults to your signing
   key's public key (an `ed25519:<hex>` identity) — no config needed. `user.identity`
   overrides it (`ed25519:<hex>` / `mid:<N>`); `user.name` / `user.email` are
   accepted as git-compat aliases but are **non-authoritative** — they never set
   who signed.

Accepted-but-no-op / out of scope (so you don't wait on them): `log --graph` is
accepted but does nothing; submodules, hooks, `git worktree`, `git notes`, and
`.git/`-format interop are explicit non-goals.

## Signing keys

**Commits and tags are always Ed25519-signed.** The commit/tag signing key is
Ed25519 and lives at `.mkit/keys/default.key`:

```sh
mkit keygen [--force] [--print-pubkey]   # Ed25519 -> .mkit/keys/default.key
mkit verify <rev>                        # check the signature on a commit, remix, or signed tag
mkit tag -s <name> -m "msg"              # signed tag (always pass -m; no -m opens an editor)
```

Instead of the repo-local file, an **Ed25519** key in the OS keystore can sign
(custody that persists across repos — Keychain / libsecret / systemd-creds /
YubiKey / Windows Credential Manager):

```sh
mkit key generate            # also: list | import | export | delete
```

The signed author is auto-derived from the signing key (difference #4 above); set
`user.identity` only to pin a different one.

> **`keygen --algorithm secp256k1|p256` does NOT make a commit key.** It writes a
> separate *attestation* signer key (`.mkit/keys/<alg>.key`) consumed by `attest`
> (below). Generating one and then running `commit` fails with "no signing key" —
> run plain `mkit keygen` for the Ed25519 commit key.

## Attestation (in-toto v1 + DSSE)

Attach signed, verifiable claims (provenance, review, SBOM, …) to a commit:

```sh
# Produce a DSSE attestation for HEAD (or --commit <hash>), optionally with a
# predicate document and multiple co-signers (all-or-nothing — any signer
# failure aborts; no partial envelopes are written):
mkit attest --algorithm ed25519 \
            --additional-signer "algorithm=p256,signer=repo-key" \
            --predicate-type https://example.com/review/v1 \
            --predicate-file review.json

# Verify every attestation on a commit against a trust-roots registry:
mkit verify-attest --commit <hash> --trust-roots ~/.config/mkit/trust-roots.toml
```

**Security gate:** `verify-attest` refuses to use an *in-repo* trust-roots file
unless you pass `--trust-roots` explicitly — otherwise a hostile clone could
ship its own roots and make verification print "ok" against attacker keys.
Default roots path is `$XDG_CONFIG_HOME/mkit/trust-roots.toml`. Exit `0` iff
every attestation has ≥1 verified signature, `65` if any failed, `1` if the
commit has no attestations.

## Content-addressed object inspection

```sh
mkit hash <file>                 # hash a file and store it as a blob → prints its id
mkit cat <hash>                  # dump an object by id
mkit cat-file -t <object>        # type | -s size | -p pretty (blob/tree/commit/tag)
mkit cat-file --batch            # stream object ids on stdin
mkit tree                        # snapshot the working dir as a tree object
mkit ls-tree -r <tree-ish>       # list tree entries (-r recurse, -z NUL-terminate)
mkit rev-parse --short <rev>     # resolve a revision to an (abbreviated) id
```

## Remotes & transports

Remote URLs use the **strict `mkit+<scheme>://` form only** (anything else is
hard-rejected):

| Scheme | Form | Use |
|--------|------|-----|
| `mkit+file` | `mkit+file:///abs/path` | local filesystem mirror |
| `mkit+https` | `mkit+https://host[:port]/path` | HTTP gateway |
| `mkit+s3` | `mkit+s3://endpoint/bucket[/prefix]` | S3-compatible store |
| `mkit+ssh` | `mkit+ssh://user@host[:port]:path` | SSH with the mkit shell |

```sh
mkit remote add origin mkit+https://gateway.example/repo
mkit clone [--depth N] [--sparse <pattern>...] mkit+ssh://user@host:path
mkit push [--all] [--force-with-lease] [--dry-run]
mkit pull            # or: mkit fetch  (download without merging)

# Trust an HTTP/S3 remote for ambient env credentials, or tune SSH policy:
mkit config trusted_remote_endpoint <url>
mkit config ssh.strict_host_key_checking <yes|no|accept-new>
mkit config ssh.identity_file <path>
```

`mkit+ssh` uses `SSH_AUTH_SOCK` (standard OpenSSH agent). `mkit serve <path>`
starts the SSH-transport server (internal/host side).

## Durability: pack-shards

```sh
mkit pack-shard <hash>   # Reed-Solomon erasure-code a stored pack into shards
                         # (requires the `pack-shards` build feature)
```

## Rules for agents

- **Run `mkit keygen` before the first commit** (or use an Ed25519 keystore key).
  Commits/signed tags/attestations always sign; without a key they fail.
- **Never invoke the interactive variants** — they block on `$EDITOR` or stdin
  and will hang you: plain `commit` (always pass `-m`), annotated/signed `tag -a`/
  `-s` (pass `-m`), `rebase -i`, and `add -p`. Use the non-interactive forms.
- **No pager, ever.** `log`/`diff`/`show`/`blame` print straight to stdout and
  exit — capture them directly; you don't need `--no-pager` or to pipe to `cat`.
- **Parse machine output, not prose.** Many commands take `--format=json`
  (`log`, `branch`, `blame`, `remote`, `config`, `reflog`) and `status` takes
  `--porcelain[=v1|v2]`. Use `-z` for NUL-terminated paths. Note several commands
  put human prose on **stderr** and reserve **stdout** for machine output.
- **Branch on exit codes, not stderr text** (see table) — distinguish a usage
  typo (`64`) from a retryable transient (`75`) without scraping messages.
- **Preview destructive ops with `-n`/`--dry-run`, commit them with `-f`.**
- **Treat ids as 64-hex.** Don't hardcode 40-char SHA assumptions.
- `NO_COLOR=1` (or piping) disables ANSI; `CLICOLOR_FORCE=1` forces it.

## Exit codes (BSD `sysexits`)

| Code | Meaning | Code | Meaning |
|------|---------|------|---------|
| 0 | success | 69 | transport could not connect |
| 1 | general error / no attestations | 73 | cannot create output |
| 64 | wrong args / unknown subcommand | 75 | transient — retry is safe |
| 65 | malformed input (corrupt object/bad hash) | 76 | bad URL scheme / server response |
| 66 | missing / unreadable input | 77 | permission denied |
| | | 78 | unknown config key / invalid value |

## Common issues

| Symptom | Cause / fix |
|---------|-------------|
| `cargo install mkit` installs the wrong tool | Install `mkit-cli`; the binary is `mkit`. |
| A pasted id won't resolve | mkit ids are 64-hex BLAKE3, not git's 40-hex SHA-1. |
| `commit` fails complaining about signing/identity | Run `mkit keygen` (or set up a keystore key) first. |
| "no signing key" right after `keygen --algorithm p256`/`secp256k1` | Those make *attestation* keys, not the commit key — run plain `mkit keygen` (Ed25519). |
| `mkit` command appears to hang | You hit an interactive variant opening `$EDITOR`/a prompt — pass `-m`, or avoid `rebase -i` / `add -p`. |
| `reset --hard` / `clean` / `restore` "refuses" | A safety guard — re-run with `-f` (use `-n` to preview). |
| `remote add` rejects the URL | Must be `mkit+file://`, `mkit+https://`, `mkit+s3://`, or `mkit+ssh://`. |
| `verify-attest` won't use the repo's trust-roots | Intentional — pass `--trust-roots <path>` explicitly. |
| `commit` opens an editor / aborts with no message | Pass `-m`, or set `$EDITOR`/`$VISUAL`. |

## Going deeper

If the **mkit MCP** is connected (`mcp.mkit.makechain.net`), prefer its tools for
authoritative depth: `get_command <name>` for a subcommand's full flags,
`get_spec <NAME>` / `list_specs` for wire & on-disk formats, `search_docs` /
`search_code` to find behavior, and `get_file 'docs/CLI.md'` for the complete
reference. In a checkout, the same content lives at:

- Full command reference: `docs/CLI.md` and `man mkit`.
- Git-parity scope & deliberate divergences: `docs/PARITY.md`.
- Wire/on-disk formats and subsystems: `docs/SPEC-*.md` (objects, signing,
  attestations, transport, packfile, keystore, …).
- Install channels (release archives, hardware signers, WASM/npm): `docs/INSTALL.md`.
