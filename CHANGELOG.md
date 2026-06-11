# Changelog

All notable changes to mkit are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **git-bridge: deterministic one-way export to git mirrors**
  (`mkit git export`, behind the default-off `git-export` feature;
  [#330](https://github.com/officialunofficial/mkit/pull/330)).
  New normative spec [`docs/SPEC-GIT-BRIDGE.md`](docs/SPEC-GIT-BRIDGE.md)
  pins a byte-deterministic mkit→git object mapping (BLAKE3/SHA-1
  translation with mkit-only fields — signer, signature, identity,
  annotation slots — carried in `mkit-*` commit/tag headers), so the
  original signed mkit objects are reconstructible bit-exactly from a
  mirror and their Ed25519 signatures re-verify (shallow and deep
  verification modes are specified). New `mkit-git-bridge` crate
  implements the mapping with golden vectors under
  `rust/tests/golden/git-bridge/`, round-trip + determinism +
  differential-vs-real-git tests (`git hash-object` id agreement,
  `git fsck --strict`). The exporter pushes with per-ref
  `--force-with-lease` from rebuildable state under `.mkit/git/`,
  skips untranslatable refs loudly (remix ancestry, git-illegal
  names, non-canonical chunking), and the import direction is
  explicitly out of scope. PARITY.md gains a scope amendment per its
  own renegotiation rule. Closes the Phase 0+1 scope of the
  git-interop exploration.

### Changed

- **buffa 0.6 → 0.7.1** across all crates (mkit-rpc, mkit-attest,
  mkit-cli, mkit-transport-ssh, mkit-transport-enc, and the
  contrib/signers reference binaries), with the vendored mkit-rpc
  codegen regenerated under the 0.7.1 toolchain. The wire format and
  all existing generated APIs are unchanged; regeneration adds the new
  `*OwnedView` wrapper types, `HasMessageView` impls, and idiomatic
  `UpperCamelCase` enum value aliases. The declared requirement is
  `0.7.1` (not `0.7`) because regenerated packed-view decoders call the
  `RepeatedView::reserve` hook introduced in 0.7.1.

### Security

- **New `git-bridge/v1` attestation predicate** (SPEC-GIT-BRIDGE §11;
  [#330](https://github.com/officialunofficial/mkit/pull/330)):
  `mkit git export` mints one DSSE/in-toto attestation per exported
  head, signed with the exporter's configured signer — subject is the
  mkit commit (BLAKE3) + ref name; the predicate carries the
  `gitCommit` SHA-1 as a locator (not a proof — SHA-1 is git's naming
  function, never a security boundary here), the mirror URL, and
  schema/spec versions. Bridge attestations are distinguishable from
  author signatures by predicate type and keyid; they assert "this
  exporter translated this commit", never authorship. Published on
  the mirror under `refs/mkit/attestations`. Threat model unchanged:
  carried signatures verify only over reconstructed mkit bytes, and
  translated history that fails reconstruction fails closed.

## [0.2.0] - 2026-06-10

### Added

- **Annotated and signed tags** (`mkit tag -a` / `-s` / `-m`,
  [#230](https://github.com/officialunofficial/mkit/issues/230)). Adds
  a new storable object type `tag` (`object_type = 0x07`) carrying the
  tagged object's hash + type, the tagger identity, a message, a
  timestamp, the signer public key, and a 64-byte signature. `-a`
  creates an unsigned annotated tag; `-s` creates a signed tag whose
  signature is Ed25519 over the canonical tag bytes under a **new,
  distinct** signing domain `mkit.tag\0` (deliberately separate from
  the commit/remix domains to prevent cross-protocol signature reuse).
  Lightweight `mkit tag <name>` is unchanged. `mkit verify <rev>` now
  verifies signed tags (resolving a tag name to its tag object), and
  `mkit cat` surfaces annotated-tag metadata. The new object type is an
  **additive** allocation within object schema v1 — no existing object
  layout, signing bytes, hash, or golden vector changes. New golden
  vectors are pinned under `rust/tests/golden/phase9/`. Specs:
  [`docs/SPEC-OBJECTS.md`](docs/SPEC-OBJECTS.md) §6a,
  [`docs/SPEC-SIGNING.md`](docs/SPEC-SIGNING.md) §4a.
- **`mkit-keystore` crate** — pluggable signing-key vault subsystem
  (PR [#109](https://github.com/officialunofficial/mkit/pull/109),
  hardened in
  [#135](https://github.com/officialunofficial/mkit/pull/135) and a
  long tail of review-feedback follow-ups). Ships with backends for
  software (encrypted-at-rest, the foundation backend), software-raw,
  macOS Keychain, Windows Credential Store, Linux Secret Service,
  systemd-creds, and YubiKey (PIV and OpenPGP applets). Public
  interface and threat model are documented in
  [`docs/SPEC-KEYSTORE.md`](docs/SPEC-KEYSTORE.md).
- **`mkit key …` subcommand family** — `generate`, `list`, `import`,
  `export`, and `delete` against any built-in keystore backend, with
  `--backend`/`--label`/`--algorithm` selectors and a `--json`
  output mode on `list`.
- **`<backend>:<label>` key-reference routing** — commit signing,
  attestation signing, and the `mkit key …` commands resolve their
  signing key through user-scoped `key.default_ref`,
  `key.ed25519_ref`, `key.secp256k1_ref`, and `key.p256_ref`
  selectors. Repo-local config cannot override these for security
  reasons; the selector keys are accepted from
  `$XDG_CONFIG_HOME/mkit/config` and explicit flags only.
- **`mkit-rpc` crate** — shared length-prefixed framing and wire
  schemas (`signer.proto`, `common.proto`) used by the external
  signer subprocess protocol and reserved for future agent
  protocols. See [`docs/SPEC-RPC.md`](docs/SPEC-RPC.md).
- **`mkit status --porcelain=v1`** — machine-readable status output
  matching the `git status --porcelain=v1` shape, plus the mkit-
  specific `T` (mode change) status letter as the only extension.
- **`mkit log --format=json`** — JSONL output (one commit per line)
  with `hash`, `parents`, `tree`, `author`, `timestamp`, `title`,
  and `message`.
- **`--format=json` on `blame`, `branch`, `remote`, `config`** —
  machine-readable output across the remaining read-style commands.
- **`mkit commit -a` / `-am <msg>`** — Git-style "stage tracked
  modifications and tracked deletions before committing" shortcut.
- **Criterion-based benchmark suite** under `rust/benches/` with a
  `render-charts` binary emitting buffa-style SVG charts; powers the
  Performance section of the README.
- **CLI port to `clap-derive`** — every subcommand is now parsed by
  a derive-based parser routed through a sysexits-aware shim in
  `mkit-cli/src/clap_shim.rs`, replacing the prior hand-rolled
  parsers.
- **Cooperative SIGINT/SIGTERM shutdown**
  ([#111](https://github.com/officialunofficial/mkit/pull/111)) —
  long-running operations poll a graceful-shutdown flag set by
  `signal-hook` and exit with `tempfail` (75) at natural checkpoints.
- **Writing style guide** at
  [`docs/STYLE-GUIDE.md`](docs/STYLE-GUIDE.md)
  ([#127](https://github.com/officialunofficial/mkit/pull/127)).

### Changed

- **Keystore capabilities now report structural operation support.** Operation
  booleans match the corresponding `Keystore` operation accessors and no longer
  promise that the current session, daemon, hardware token, or protector is
  available at probe time. Operations still fail closed when runtime support is
  unavailable.
- **`mkit commit` now reads the staging index** (`.mkit/index`)
  instead of recursively snapshotting the worktree.
  ([#102](https://github.com/officialunofficial/mkit/issues/102))
  Pre-fix, `mkit add` and `mkit rm` wrote to the index but `mkit
  commit` ignored it — a half-state that surprised any user reasoning
  by analogy from git. Post-fix, `mkit add` (or `mkit add .`) is
  required before `mkit commit`; an empty index is now a hard error.
  The "snapshot the whole worktree" workflow is `mkit add . && mkit
  commit -m "..."`.

  New helper: `mkit_core::worktree::build_tree_from_index`. Pinned
  invariant: for a worktree whose contents match an index entry-for-
  entry, `build_tree` and `build_tree_from_index` produce the same
  root tree hash, so attestations signed under either path
  cross-verify against trees built under the other.
- **Confirmation prose and progress lines move to stderr** across 17
  commands; stdout is reserved for machine output so `mkit status
  > /tmp/out` in a clean tree produces an empty file.

### Fixed

- **Keystore vault follow-up hardening**
  ([#135](https://github.com/officialunofficial/mkit/pull/135)) —
  protector AAD binding, length-prefixed encrypted-record AAD,
  authenticated software metadata, zeroizing transient secret
  buffers, software metadata authentication, no-clobber imports,
  PIV-only YubiKey support, runtime-availability honesty in
  capability reports, and other review-feedback items collected
  across `946975e`, `524d3fc`, and `a5b382c`.
- **Silent failure exits** in several subcommands now return proper
  sysexits-aware codes instead of exiting 1 with no diagnostic.
- **`mkit commit` index follow-ups** — preserve executable modes on
  `-a`/`-am`, stage tracked deletions on `add .`, clear stale index
  path conflicts, and keep the index aligned with committed trees
  after PR
  [#103](https://github.com/officialunofficial/mkit/pull/103)
  review.
- **`mkit rebase` preflights its signing key** so the operation fails
  early instead of midway through a replay when no key is configured.
- **Benchmark chart axes** are now apples-to-apples wallclock + ops/s
  across the criterion and `git2`/git-CLI comparison rows.

## [0.1.0] - 2026-05-07

Initial public release. mkit is a content-addressed VCS for creative
work with native cryptographic attestations. Earlier development tags
(`v0.1.0`, `v0.2.0`, `v0.2.1` from the pre-release iteration) are
superseded by this release; the repository history was flattened
prior to publication.

### Added

- **mkit-core** — content-addressed object model (BLAKE3 hashing,
  canonical objects, refs, packs), FastCDC chunker, delta encoding,
  Bao verified streaming, Ed25519 commit signing.
- **mkit-attest** — DSSE + in-toto v1 attestations with multi-algorithm
  signers (Ed25519, secp256k1, P-256) and an RFC 8785 JCS encoder.
- **mkit-cli** — the `mkit` binary, with subcommands for init, add,
  commit, log, status, branch, checkout, merge, cherry-pick, rebase,
  push, pull, fetch, clone, attest, verify-attest, keygen, config.
- **Transports** — memory (test), file (local), http (REST + rustls),
  s3 (SigV4 over rustls, R2-compatible), ssh (forced-command server
  pattern over `ssh(1)`).
- **mkit-wasm** — wasm-bindgen surface for browsers and Cloudflare
  Workers, published to npm as `@makechain/mkit-wasm`.
- **External signers** — reference implementations under `contrib/`
  for FIDO2/WebAuthn (CTAP-HID), TPM 2.0 P-256, and a raw-key file
  signer for development.
- **Release pipeline** — cosign keyless OIDC signing, CycloneDX SBOMs,
  reproducible-build smoke tests, MSRV checks on Linux + macOS.

### Security

- Per-repo `.mkit/config` is partitioned: security-sensitive keys
  (signing key paths, external-signer paths, SSH trust knobs) are
  user-scoped only. A hostile clone cannot redirect signing or
  weaken transport trust via repo-local config.
- `mkit verify-attest` defaults to `$XDG_CONFIG_HOME/mkit/trust-roots.toml`
  rather than a repo-local path; in-repo trust-roots require an
  explicit `--trust-roots` flag.
- Key files are opened with `O_NOFOLLOW`, written via tmp + fsync +
  rename + parent fsync, owner-checked against the running euid, and
  parent directory mode is enforced `0700`.
- HTTP and S3 transports require an explicit user-scoped
  `trusted_remote_endpoint` before they will use ambient environment
  credentials for repo-configured remotes.
- Reference external signer keeps secret material in a zeroizing
  buffer until the per-algorithm signer consumes it.

[Unreleased]: https://github.com/officialunofficial/mkit/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/officialunofficial/mkit/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/officialunofficial/mkit/releases/tag/v0.1.0
