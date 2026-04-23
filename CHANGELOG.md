# Changelog

All notable changes to mkit are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

A pass of input-validation + resource-limit hardening across the parsers,
transports, and on-disk code. Most of the work came from an external review
(an offline Codex agent); I audited, ported to 0.16, and fixed a latent
`fastcdc.StreamingChunker` bug the strengthened test surfaced.

- **Packfile format v3 (`VERSION_DELTA = 3`)** — delta entries now carry
  the base hash, expected reconstructed hash, and expected raw size, so
  unpack can reject a malformed / attacker-crafted delta *before*
  persistence. The legacy v2 delta format is explicitly rejected
  (`VERSION_DELTA_LEGACY`) since its delta payload lacked integrity info.
  Adds `MAX_OBJECT_COUNT = 10M` and `MAX_PACK_TOTAL_BYTES = 4 GiB` caps.
- **Delta apply bounds-checked** — COPY `offset + length` can't escape
  the base buffer; INSERT plus accumulated length can't exceed the
  declared target size (`error.DeltaSizeMismatch` / `DeltaCorrupt`).
- **`serialize.zig` bounds checks** — reject tree/chunked_blob headers
  whose declared count exceeds `remaining() / min_entry_bytes`
  (prevents OOM-via-malformed-header).
- **`store.zig` MAX_RAW_OBJECT_SIZE = 1 GiB** — `putRaw` / `getRaw`
  reject anything larger with `error.ObjectTooLarge`.
- **`config.zig` `validateConfigValue`** — rejects control chars and
  null bytes in values before they can reach the config writer.
- **`protocol.zig` `validateSshPath`** — rejects empty / dot / dot-dot
  path components and non-ASCII-safe characters in `mkit+ssh://` URLs.
  Pairs with…
- **`transport/ssh.zig` `shellEscapeArg` / `buildRemoteServeCommand`** —
  hardens the remote command string against shell-metacharacter
  injection via a malicious repo path. Also rejects malformed ref names
  during ref-list decode.
- **`transport/http.zig` + `transport/s3.zig`** — rewritten onto the
  0.16 `std.http.Client` API (`sendBodyUnflushed`, `receiveHead`,
  `Uri.parse`); add a `Content-Length`-bounded response cap
  (`error.ResponseTooLarge`); correct decompress buffer sizing.
- **`restore.zig` atomic symlink** — `restoreSymlink` now creates
  under a temp name and renames into place; idempotent on
  `PathAlreadyExists`.
- **`sign.zig` `KeyPair.zeroize`** — explicit memory wipe helper for
  callers that want to drop a keypair before process exit.
- **`worktree.zig` / `restore.zig` symlink-safe traversal** — pre-stat
  every entry with `follow_symlinks = false` and reject kind
  mismatches before opening. Zig 0.16's `Io.Dir.OpenFileOptions` /
  `OpenOptions` don't expose a no-follow knob, so the pre-stat is the
  equivalent defence.

### Fixed

- **`fastcdc.StreamingChunker` could return bytes overwritten by its
  own shift** — the chunk slice `buf[0..chunk_len]` was aliased against
  the `copyForwards(buf[0..remaining], buf[chunk_len..buf_len])` shift,
  so the caller's slice read post-shift bytes, not the actual chunk.
  Unit tests only compared chunk *lengths* so the bug never showed.
  The strengthened `expectEqualSlices` test from this round surfaced
  it. Fix: preserve chunk bytes in the buffer's second half
  (allocated `max_size * 2`) before the shift, and cap the fill read
  at `max_size - buf_len` so the preservation region can never overlap
  the shift's source.

## [0.2.1] - 2026-04-23

Patch release. v0.2.0's release workflow was pinned to the `macos-13`
GitHub-Actions runner image, which GitHub retired in ~March 2026; the
`x86_64-macos` job queued forever and the Release page never published.
v0.2.1 ships with the four platform binaries v0.2.0 intended to, plus
one real-bug backfill that surfaced while auditing the "deferred" list.

### Fixed

- File transport now fsyncs the containing directory after a ref rename,
  closing the crash-durability gap in `atomicWriteRef`. Previously flagged
  as "deferred, blocked on `std.Io.Dir.sync`"; the block was wrong —
  `std.Io.Dir.handle` is the raw `fd_t` and `std.c.fsync` (mkit links
  libc unconditionally) works on directory descriptors on Linux and
  Darwin. Classic atomic-write-through-rename pattern now complete.
- `tests/e2e-ssh.sh` now runs in CI on ubuntu-latest (previously
  manual-only), guarding the 0.16 SSH transport rewrite against
  regressions on every PR.
- SSH wire `CLIENT_VERSION` / `SERVER_VERSION` now derived from
  `cli.cli_version` at comptime; v0.2.0's handshake still advertised
  the stale `"mkit 0.1.0"` string (no protocol break — OP_HELLO only
  validates `BINARY_NAME` + `PROTO_VERSION` — but misleading in packet
  captures).

### Build

- `.github/workflows/release.yml`: `x86_64-macos` matrix entry now runs
  on `macos-14` (arm64 host) with `zig build -Dtarget=x86_64-macos`
  cross-compiling Mach-O to x86_64. Unblocks the release after GitHub's
  `macos-13` image retirement.

### Added

- `-Djemalloc` CI smoke on `ubuntu-latest`: installs `libjemalloc-dev`,
  builds with `-Djemalloc`, ldd-checks that the produced binary actually
  links `libjemalloc.so`, and runs an init/keygen/commit/log lifecycle
  to exercise the alt allocator end-to-end.

## [0.2.0] - 2026-04-23

### Changed

- **Toolchain bumped to Zig 0.16.0.** The `std.Io` overhaul is landed: every
  subsystem that touches the filesystem, clock, RNG, or child processes now
  threads an explicit `std.Io` capability. Public signatures for
  `ObjectStore.{init,open,isRepoRoot}`, `refs.*`, `index.*`, `worktree.*`,
  `restore.*`, `rebase.*`, `bisect.*`, `stash.*`, `ignore.load`,
  `config.{readConfig,writeConfig}`, `diff.statusDiff`, `format.printObject`,
  and the `*Transport.init` family now take `io: std.Io`. Consumers
  consuming mkit as a library will need to thread `io` through their own
  callers.
- `std.meta.intToEnum` replaced with `std.enums.fromInt` (optional return,
  not error-union).
- `std.mem.trimRight` / `trimLeft` renamed to `trimEnd` / `trimStart`.
- `ArrayList(T) = .{}` default-init replaced with `.empty`.
- FUZZ harnesses (`fuzz_packfile`, `fuzz_tree`, `fuzz_delta`) now use
  `std.Io.Clock.awake.now(io)` for the per-iteration deadline in place of
  the removed `std.time.nanoTimestamp`; every FUZZ.md invariant is
  preserved verbatim (≤100 iters, ≤64 KiB inputs, 2 MiB FBA, 100 ms cap,
  seeded DefaultPrng, no `std.testing.fuzz`).

### Fixed

- `mkit blame` no longer panics with `integer overflow` on non-opaque
  authors. The slice-bound `tmp[0 .. take * 2]` in `formatAuthorShort`
  tripped Zig 0.16's stricter int-inference; pinning `take: usize` and
  lifting the multiplication into its own binding restores correct behaviour
  for the default ed25519 identity mkit derives from the signing pubkey.
- `parseUrl` now strips the `mkit+` scheme prefix before legacy-scheme
  matching, so `mkit clone mkit+file:///path` routes to `FileTransport`
  instead of falling through to an S3-style endpoint/bucket split that
  surfaced as `error.ConnectionFailed` on the first ref op.

### Added

- `tests/e2e-ssh.sh` — wire-level e2e harness for `mkit+ssh://` transport,
  running inside a `debian:12-slim` container with a loopback sshd. Covers
  OP_HELLO handshake, ref read/write, and pack upload/download over a real
  pipe — the piece of the 0.16 SSH rewrite that unit tests never touched.
- `tests/e2e-file.sh` / `tests/e2e-https.sh` / `tests/e2e-r2.sh` now use
  `mkit+<scheme>://` URLs, have the legacy `--project` notary flag removed,
  and split clone → pull explicitly to match mkit's `clone = init + remote
  set` semantics. `tests/e2e-file.sh` passes 64 / 64 locally.

### Build

- `build.zig` sets `link_libc = true` on every module (`lib_mod`, `exe_mod`,
  `test_mod`, `integration_test_mod`, `bench_mod`), not just under
  `-Djemalloc`. Needed for `std.c.isatty` / `std.c.environ` / `std.c.fchmod`
  on Linux — macOS silently linked libc for any `std.c.*` reference so the
  bug only surfaced on cross-compile.
- Release modules (`optimize != .Debug`) get `strip = true` to drop the Zig
  compiler's per-build cache-hash path from embedded DWARF, restoring
  byte-reproducibility. Debug builds keep debug info for interactive use.

## [0.1.0] - 2026-04-22

Initial public release.

### Added

- Dual **MIT OR Apache-2.0** licensing with SPDX headers on every source
  file.
- **`Notary` trait** (`src/notary.zig`) as a library extension point for
  downstream consumers. The public `mkit` binary ships only `NullNotary`
  and exposes no notary surface in its CLI. See `docs/NOTARY.md` for the
  trait contract.
- **`Identity` opaque tagged union** for commit authorship. Kinds:
  `ed25519`, `did_key`, `opaque`. 4096-byte length cap.
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

### Deferred

- Windows support (Scoop manifest stub already in `contrib/scoop/`).
- S3 multipart upload for >5 GiB packs.
- Cross-transport conformance test matrix.
- SSH operational-verb retry (hello handshake is deterministic).
- `-Djemalloc` CI matrix ([#13](https://github.com/officialunofficial/mkit/issues/13)).
- Symlink-restore fuzz harness + SSH-wire fuzz harness.
- Per-subcommand man pages (`mkit-commit(1)` etc.); 0.2.0 still ships one
  comprehensive `mkit(1)`.
- Fish shell completions.

[Unreleased]: https://github.com/officialunofficial/mkit/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/officialunofficial/mkit/releases/tag/v0.2.1
[0.2.0]: https://github.com/officialunofficial/mkit/releases/tag/v0.2.0
[0.1.0]: https://github.com/officialunofficial/mkit/releases/tag/v0.1.0
