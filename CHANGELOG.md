# Changelog

All notable changes to mkit are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

_Nothing yet._

## [0.1.0] - 2026-04-22

Initial public release. The binary is extracted from the upstream `zmit`
project and re-homed under the `mkit` name with a fresh license.

### Added

- Extracted from `zmit`: renamed binary, paths, environment variables, and
  on-disk magic values (`"ZMIT"` → `"MKIT"` packfile magic, `"ZMITFCDC"` →
  `"MKITFCDC"` FastCDC seed). See `scripts/verify-rename.sh` for the rename
  gate, enforced in CI.
- Dual **MIT OR Apache-2.0** licensing with SPDX headers on every source
  file.
- **`Notary` trait** (`src/notary.zig`) as a library extension point for
  downstream consumers. The public `mkit` binary ships only `NullNotary`
  and exposes no notary surface in its CLI. See `docs/NOTARY.md` for the
  trait contract.
- **`Identity` opaque tagged union** replaces zmit's `u64 author_mid`.
  Kinds: `ed25519`, `did_key`, `opaque`. 4096-byte length cap.
- **v1 on-disk format**: every object carries `[ObjectType:u8]["MKIT":4]
  [schema_version:u8]` prologue. Timestamps widened to `u64` (no 2106
  overflow). TreeEntry gains `executable` mode.
- **Domain-separated signing**: commit hashes use `BLAKE3("mkit.commit\0"
  ‖ canonical_bytes)`; remix uses `"mkit.remix\0"`. Cross-domain signature
  reuse is structurally prevented.
- **Format specification** (`docs/SPEC-*.md`): 8 normative docs covering
  objects, signing, packfile, delta, refs, transport, FastCDC, and index
  formats. Every byte mkit writes to disk is specified.
- **Strict URL schemes** for remotes: `mkit+file://`, `mkit+https://`,
  `mkit+s3://`, `mkit+ssh://`, `mkit+memory://`. No implicit defaults; a
  bare `https://` URL is rejected with a clear hint.
- **File transport atomicity**: refs use tmp-rename + `File.sync()`;
  CAS uses an `O_EXCL` lock-file with 5-second timeout.
- **S3 + HTTP transports**: exponential retry (500 → 1000 → 2000 → 4000
  → 8000 ms) on 5xx and 429; no retry on 4xx (incl. 412 CAS mismatch).
  Hard `error.PackTooLargeForSinglePut` for >5 GiB uploads (multipart is
  post-0.1.0 work).
- **SSH `OP_HELLO`** handshake (opcode `0x00`): version + binary-name
  negotiation; `STATUS_UNSUPPORTED` for future-proto rejection. Pre-v1
  servers get a clean `error.IncompatiblePeer` (no silent garbage).
- **SSH security knobs**: `ssh.strict_host_key_checking`,
  `ssh.user_known_hosts_file`, `ssh.identity_file` config keys. See
  `docs/SSH-SECURITY.md` for the trust model.
- **\*nix conventions**: sysexits-style exit codes, `NO_COLOR` /
  `CLICOLOR_FORCE` / `isatty` discipline, SIGINT/SIGTERM/SIGPIPE
  handlers, repo-level `.mkit/index.lock` for `commit`/`checkout`/
  `merge`/`rebase`, **XDG Base Directory** support
  (`$XDG_CONFIG_HOME/mkit/config` etc.), `$EDITOR` integration for
  `mkit commit` without `-m`. `man/mkit.1` (mdoc) page,
  bash + zsh completions in `completions/`.
- **CLI surface**: `mkit version`, `mkit config user.identity` (replaces
  `author_mid`). 30 subcommands snapshot-tested in `src/cli_test.zig`.
- **Bounded property fuzz**: parsers for packfile, tree, and delta are
  fuzzed in CI under a `FixedBufferAllocator` cap (100 iterations,
  64 KiB inputs, deterministic PRNG seeds). See `docs/FUZZ.md`.
- **Reproducible builds**: CI smoke-tests that `zig build` is
  byte-deterministic on the same commit. See
  `docs/release/REPRODUCIBILITY.md`.
- **Release pipeline**: cosign-keyless-signed archives for macOS (arm64 +
  x86_64) and Linux (x86_64 + arm64), CycloneDX SBOM, Homebrew tap
  template, and documented verification steps in
  `docs/release/SIGNING.md`.
- **Security policy**: `SECURITY.md` with a coordinated-disclosure
  timeline.

### Fixed

- Pre-existing `std.testing.fuzz` block in `src/delta.zig` that allocated
  192 GiB under `zig build --fuzz` (attacker-controlled `expected_size`).
  Replaced with a bounded property test using the same FBA pattern as the
  new fuzz harnesses.
- File transport `updateRef(.match)` was a non-atomic read-then-write
  race. Now serialized through an advisory lock-file.

### Removed

- `user.mid` config key (numeric MID) — superseded by `user.identity` (hex
  Identity). No back-compat: existing `author_mid = N` config files are
  rejected with a clear "did you mean user.identity?" hint.

### Security

- Supply-chain policy (`docs/release/SUPPLY-CHAIN.md`): zero external Zig
  packages; any new `build.zig.zon` entry must be `.hash`-pinned and
  reviewed by two maintainers.

### Deferred to 0.2.0

- Zig 0.16 migration (the `std.Io` overhaul touches ~500 sites; needs its
  own multi-session workstream).
- Windows support (Scoop manifest stub already in `contrib/scoop/`).
- S3 multipart upload for >5 GiB packs.
- Cross-transport conformance test matrix.
- SSH operational-verb retry (hello handshake is deterministic).
- File transport directory-fsync (`std.fs.Dir.sync` not exposed in 0.15.2).
- Symlink-restore fuzz harness + SSH-wire fuzz harness.
- Per-subcommand man pages (`mkit-commit(1)` etc.); 0.1.0 ships one
  comprehensive `mkit(1)`.
- Fish shell completions.

[Unreleased]: https://github.com/officialunofficial/mkit/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/officialunofficial/mkit/releases/tag/v0.1.0
