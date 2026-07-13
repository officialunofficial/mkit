# mkit

![status: alpha](https://img.shields.io/badge/status-alpha-orange)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)
[![crates.io](https://img.shields.io/crates/v/mkit-cli.svg)](https://crates.io/crates/mkit-cli)
[![docs.rs](https://img.shields.io/docsrs/mkit-core)](https://docs.rs/mkit-core)
[![codecov](https://codecov.io/gh/officialunofficial/mkit/branch/main/graph/badge.svg)](https://codecov.io/gh/officialunofficial/mkit)

A content-addressed version control toolkit written in Rust.

`mkit` is a generic content-addressed VCS &mdash; Git-like commits, refs,
and transports &mdash; with a native, predicate-agnostic attestation
subsystem (in-toto v1 Statements in DSSE envelopes) that lets any
downstream service attach witness signatures to commits. Golden
vectors under [`rust/tests/golden/`](rust/tests/golden/) pin the v1
on-disk and wire formats.

## Status

**Alpha (pre-1.0).** The v1 wire and on-disk formats are stable
through the 0.x line; APIs, CLI flags, and unpinned internals may
change in any 0.x release. See [`CHANGELOG.md`](CHANGELOG.md) for the
breaking-change record.

**MSRV** is Rust 1.95.0, pinned in
[`rust/rust-toolchain.toml`](rust/rust-toolchain.toml). The
CHANGELOG documents MSRV bumps; the policy is "current stable minus
one" unless a feature requires otherwise.

## Quick start

```sh
# install the CLI from crates.io (see "Installing" below for other channels)
cargo install mkit-cli

# make your first signed commit
mkit init           # create .mkit/ in the current dir
mkit keygen         # generate an Ed25519 signing key
echo hello > hi.txt
mkit add hi.txt
mkit commit -m "first commit"

# push to a remote (strict scheme — mkit+{file,https,s3,ssh,enc}://)
mkit remote add origin mkit+file:///srv/mkit/my-repo
mkit push origin            # first push records `origin` as the branch upstream
mkit push                   # subsequent pushes go to the recorded upstream
```

Bare `mkit push` pushes the current branch to its recorded upstream
and rejects a non-fast-forward update unless you pass
`--force-with-lease` or `--force`; `mkit push --all` mirrors every
local branch with the same CAS safety. `mkit remote add <url>` (no
name) still configures the flat default remote for back-compat.

Full CLI reference: [`docs/CLI.md`](docs/CLI.md).

## Installing

Pick one. Long-form guide with verification steps in
[`docs/INSTALL.md`](docs/INSTALL.md).

### Quick install (signed release binary)

```sh
curl mkit.sh | sh
```

Detects your OS and architecture, downloads the matching signed
release archive, verifies its cosign signature by default, and
installs `mkit` into `~/.local/bin`. Equivalent explicit form:
`curl -sSfL https://mkit.sh/install.sh | sh`; append
`-s -- --version v0.3.0` to pin an exact release.

On native Windows (PowerShell, no WSL/Git-Bash), use the PowerShell
installer instead:

```powershell
irm https://mkit.sh/install.ps1 | iex
```

### From source

```sh
cargo install --git https://github.com/officialunofficial/mkit mkit-cli
```

Requires Rust 1.95 (rustup picks it up from `rust/rust-toolchain.toml`
on first build). Drops `mkit` into `~/.cargo/bin/`.

> [!WARNING]
> Do **not** run `cargo install mkit` &mdash; the `mkit` name on crates.io
> belongs to an unrelated project. The CLI is published as **`mkit-cli`**
> (`cargo install mkit-cli`), and is also available via the release
> archives / `install.sh` above or `--git` from this repository.

### From GitHub Releases

Cosign-signed archives for Linux (x86_64 plus arm64), macOS (arm64 plus
x86_64), and Windows (x86_64) on every `v*.*.*` tag:

```sh
VERSION=0.3.0
TARGET=aarch64-apple-darwin
curl -LO "https://github.com/officialunofficial/mkit/releases/download/v${VERSION}/mkit-${VERSION}-${TARGET}.tar.gz"
tar -xzf "mkit-${VERSION}-${TARGET}.tar.gz"
```

Verification steps &mdash; cosign bundle, `SHA256SUMS`, SBOM &mdash; are in
[`docs/INSTALL.md`](docs/INSTALL.md).

### WASM (npm)

```sh
bun add @makechain/mkit-wasm     # or: npm i @makechain/mkit-wasm
```

The `@makechain` scope is intentional (Makechain is an internal team
at Official Unofficial, Inc., not a separate entity). TypeScript and
Cloudflare Workers examples in
[`docs/INSTALL.md`](docs/INSTALL.md#wasm--npm).

### Hardware signers (optional)

External signers are separate binaries that mkit drives over the
[v1 stdio protocol](docs/specs/SPEC-EXTERNAL-SIGNER.md). The signer crates
live under [`contrib/signers/`](contrib/signers/) outside the
top-level Cargo workspace at `rust/`, so the install path is
`git clone` plus `cargo install --path .`:

```sh
git clone https://github.com/officialunofficial/mkit
cd mkit/contrib/signers
cargo install --path mkit-sign-file                  # any platform
cargo install --path mkit-sign-tpm --features tpm2   # Linux/Windows TPM 2.0
cargo install --path mkit-sign-ctap                  # FIDO2 / CTAP-HID
# Apple Secure Enclave (macOS, Swift):
cd mkit-sign-se && swift build -c release \
  && cp .build/release/mkit-sign-se /usr/local/bin/
```

Each signer ships its own README under
[`contrib/signers/`](contrib/signers/).

## Keystore

Signing keys live in a pluggable keystore vault. Out of the box mkit
recognizes:

- **software** / **software-raw** &mdash; encrypted-at-rest software vault
  on disk; the cross-platform foundation backend.
- **macos-keychain**, **windows-credential**, **linux-secret-service**
  &mdash; native OS keychains where available.
- **systemd-creds** &mdash; systemd's encrypted credential store on Linux
  hosts that have it.
- **yubikey** &mdash; hardware-backed via PIV / OpenPGP applets.
- **external signers** &mdash; separate subprocess binaries speaking the
  [v1 stdio protocol](docs/specs/SPEC-EXTERNAL-SIGNER.md); reference
  signers under [`contrib/signers/`](contrib/signers/).

The keystore vault abstracts these behind one interface so commit
signing, attestation signing, and SSH push-auth share key references.
The normative interface is in
[`docs/specs/SPEC-KEYSTORE.md`](docs/specs/SPEC-KEYSTORE.md); end-user overview
in [`docs/keystore.md`](docs/keystore.md). The backends a given
binary supports depend on enabled build features &mdash; see
[`docs/CLI.md`](docs/CLI.md) §"Config keys".

## Architecture

mkit is layered into `mkit-core` (object model, hashing, refs,
packfile, signing, transport trait), one crate per transport, and
the `mkit-cli` binary. The same core is exposed to the browser via
`mkit-wasm` and to programmatic users via `cargo add mkit-core`.

```text
┌──────────────────────────────────────────────────────────────┐
│  mkit-cli                     — argv parser + dispatcher     │
└──────────────────────────────────────────────────────────────┘
                              │
┌──────────────────────────────────────────────────────────────┐
│  mkit-core                    — content-addressed primitives │
│   hash · object · pack · index · refs · store · sign · ops   │
│                  protocol::Transport (trait)                 │
└──────────────────────────────────────────────────────────────┘
                              │
   ┌──────────┬──────────┬────┴─────┬──────────┬──────────┐
   ▼          ▼          ▼          ▼          ▼          ▼
┌──────┐  ┌──────┐  ┌─────────┐  ┌──────┐  ┌──────┐  ┌────────┐
│memory│  │ file │  │  http   │  │  s3  │  │ ssh  │  │  wasm  │
│tests │  │local │  │ gateway │  │ R2,… │  │forced│  │ browser│
│      │  │      │  │ worker  │  │      │  │ cmd  │  │  + CFW │
└──────┘  └──────┘  └─────────┘  └──────┘  └──────┘  └────────┘
```

Workspace crates:

| Crate | Purpose |
|---|---|
| `mkit-core` | hash, object, serialize, store, sign, chunker, delta, pack, refs, index, worktree, ignore, repo_lock, ops, protocol |
| `mkit-attest` | JCS, in-toto v1 Statement, DSSE envelope, signers, verify |
| `mkit-git-bridge` | deterministic mkit↔git bridge: export mirroring, importer-signed import, fork-mode publishing ([`docs/specs/SPEC-GIT-BRIDGE.md`](docs/specs/SPEC-GIT-BRIDGE.md), [`docs/specs/SPEC-GIT-IMPORT.md`](docs/specs/SPEC-GIT-IMPORT.md), [`docs/GUIDE-GIT-WORKFLOWS.md`](docs/GUIDE-GIT-WORKFLOWS.md)) |
| `mkit-keystore` | platform-aware signing-key vault (software, OS keychains, systemd-creds, YubiKey, external signers) &mdash; see [`docs/specs/SPEC-KEYSTORE.md`](docs/specs/SPEC-KEYSTORE.md) |
| `mkit-rpc` | shared wire schemas plus length-prefixed framing for stdio subprocess protocols (external signers) |
| `mkit-transport-{memory,file,http,s3,ssh,enc}` | Transport trait implementations (`enc` = the `mkit+enc://` no-OpenSSH encrypted transport) |
| `mkit-cli` | the `mkit` binary |
| `mkit-wasm` | wasm-bindgen surface for browsers / Cloudflare Workers, published to npm as `@makechain/mkit-wasm` |
| `mkit-fuzz` (at `rust/fuzz/`, not `rust/crates/`) | bounded property tests (cargo-fuzz compatible) |

Each transport implements the same trait &mdash; `list_refs`, `read_ref`,
`write_ref`, `pack_exists`, `download_pack`, `upload_pack` &mdash; described
in [`docs/specs/SPEC-TRANSPORT.md`](docs/specs/SPEC-TRANSPORT.md). The URL scheme
picks the transport: `mkit+ssh://`, `mkit+enc://`, `mkit+s3://`,
`mkit+https://`, `mkit+file://`. There is no "smart" fallback &mdash; the scheme is part of
the contract. Deeper layering notes in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

### Content addressing

Every object is identified by the BLAKE3 hash of its canonical
serialization. No hashing-algorithm negotiation, no SHA-1 / SHA-256
dichotomy. Hashes are stable across all transports and storage
backends, including WASM.

Object kinds (full schema in
[`docs/specs/SPEC-OBJECTS.md`](docs/specs/SPEC-OBJECTS.md)):

| Kind         | Purpose                                                    |
|--------------|------------------------------------------------------------|
| Blob         | File contents (or chunked via FastCDC for large files)     |
| Tree         | Directory snapshot                                         |
| Commit       | Tree plus parents plus Ed25519 signature plus author Identity       |
| Remix        | Signed derivative of one or more commits                   |
| ChunkedBlob  | Index of FastCDC chunks for blobs over the chunk threshold |
| Delta        | Bsdiff-like delta between two blobs (pack-internal)        |
| Tag          | Annotated, optionally signed pointer to another object     |

## Attestations

mkit ships **native attestation as a first-class object type**, not a
side-channel. mkit stores a signed in-toto v1 Statement in a DSSE
envelope (spec:
[`docs/specs/SPEC-ATTESTATIONS.md`](docs/specs/SPEC-ATTESTATIONS.md))
under `.mkit/attestations/<commit-hash>/<att-id>.dsse`; any signer
that speaks the
[v1 stdio protocol](docs/specs/SPEC-EXTERNAL-SIGNER.md) can produce
one:

```text
                       ┌──────────────────────────────┐
                       │       mkit attest            │
                       │   (in-toto v1 + DSSE)        │
                       └──────────┬───────────────────┘
                                  │
                 ┌────────────────┴────────────────┐
                 ▼                                  ▼
       ┌─────────────────┐              ┌──────────────────────┐
       │ repo-key signer │              │ external signer      │
       │  (Ed25519 from  │              │ (subprocess, stdio   │
       │   .mkit/keys)   │              │   protocol; TPM,     │
       │                 │              │   FIDO2/CTAP, SE,…)  │
       └─────────────────┘              └──────────────────────┘
                    implemented today, at parity

       ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄
       ┆ keyless / sigstore  — roadmap, not implemented       ┆
       ┆ (OIDC → short-lived cert; `SigstoreSigner` returns   ┆
       ┆  `Error::SigstoreNotImplemented` unconditionally)    ┆
       ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄
```

Attestations carry the commit hash as the in-toto `subject`, so they
verify with off-the-shelf tooling (cosign, in-toto-go, custom
verifiers). Anything that produces a valid DSSE envelope with an
in-toto v1 Statement can attest to an mkit commit; conversely, mkit's
attestations are consumable by any standards-compliant verifier.
Multi-signer envelopes (one envelope, N signatures) work out of the
box &mdash; see [`docs/specs/SPEC-ATTESTATIONS.md`](docs/specs/SPEC-ATTESTATIONS.md) §6.

Multi-algo attestation flow:

```sh
mkit keygen --algorithm p256 --print-pubkey
mkit attest --algorithm ed25519 \
            --additional-signer "algorithm=p256,signer=repo-key" \
            --predicate-type https://example.com/sign-off/v1
mkit verify-attest --trust-roots .mkit/attest-trust-roots.toml
```

## Identity and push auth

**.mkit/keys/default.key** is a raw Ed25519 seed. The same seed covers:

- commit / remix signing ([`docs/specs/SPEC-SIGNING.md`](docs/specs/SPEC-SIGNING.md));
- DSSE attestation signing via the `repo-key` signer
  ([`docs/specs/SPEC-ATTESTATIONS.md`](docs/specs/SPEC-ATTESTATIONS.md) §6.2);
- SSH transport authentication &mdash; OpenSSH 8.0+ accepts a raw Ed25519
  seed as `id_ed25519`, so the same key authenticates `mkit push`
  over `mkit+ssh://`.

For `mkit+ssh://` push authorization the idiomatic pattern is Git's:
server `sshd` runs an `AuthorizedKeysCommand` that maps an incoming
pubkey to an account, and `mkit serve` executes as that account. mkit
core ships **no custom push-auth protocol** &mdash; SSH's KEX already does
the nonce/signature exchange, and `AuthorizedKeysCommand` is the
standard server-side hook for `pubkey → account`. A downstream
service can wire its own identity model (for example, pubkey → on-chain
owner address) through that hook without changing the wire protocol.
See [`docs/SSH-SECURITY.md`](docs/SSH-SECURITY.md) for the transport
trust model.

## CLI ergonomics

Every subcommand parses arguments through `clap-derive` and follows
POSIX conventions documented in [`docs/CLI.md`](docs/CLI.md):

- **stdout = data, stderr = diagnostics.** `mkit status > /tmp/out`
  produces an empty file in a clean tree; banners and progress go to
  stderr.
- **`--porcelain` / `--format=json`** modes on every read-style
  command (`status`, `log`, `branch`, `blame`, `remote`, `config`).
- **Exit codes follow BSD `sysexits(3)`.** Shell scripts can
  distinguish user typos (64) from transient transport failures (75)
  without parsing stderr.
- **Signals:** SIGINT/SIGTERM set a graceful-shutdown flag polled by
  long-running operations. SIGPIPE is ignored; pipelines like
  `mkit log | head -1` exit cleanly.

## Performance

mkit names every object by a **BLAKE3** hash and splits large files
into content-defined chunks, so a small edit to a large file costs the
edit &mdash; not the file &mdash; on disk, on the wire, and in wall-clock time.

The comparison that matters is end to end: real `add`, `commit`, and
`push` operations measured head to head against Git with `hyperfine`.
Those results, with full methodology, live on the
[performance page](https://mkit.sh/performance). mkit pulls clearly
ahead on large files and their edits, and runs roughly even with Git
on everyday operations.

Component microbenchmarks &mdash; signature throughput by algorithm, and
object-commit/pack-create against `git2` and the `git` CLI &mdash; live in
[`benchmarks/charts/`](benchmarks/charts/). Numbers vary by
hardware, kernel, filesystem, and cache warmth; reproduce locally with:

```sh
# Name the bench targets explicitly. The `--workspace -- --quick`
# form fails: --quick is not a valid option for the lib unittest target.
cargo bench -p mkit-benches --bench hashing --bench sign_verify \
  --bench object_commit --bench pack_create -- --quick
cargo run -p mkit-benches --bin render-charts
```

## Documentation

Guides and operational docs live in [`docs/`](docs/); the wire-format
and subsystem specifications live in [`docs/specs/`](docs/specs/README.md).
Each spec carries its own `status:` header reflecting how settled that
document is; regardless of header, the test vectors under
[`rust/tests/golden/`](rust/tests/golden/) pin the v1 wire and
on-disk formats they describe, which remain stable through the 0.x
series.

| Doc | Audience |
|---|---|
| [`docs/INSTALL.md`](docs/INSTALL.md) | End users &mdash; install channels, verification, hardware signers |
| [`docs/CLI.md`](docs/CLI.md) | End users &mdash; subcommands, env vars, exit codes |
| [`docs/keystore.md`](docs/keystore.md) | End users &mdash; keystore overview, picking a backend |
| [`docs/GUIDE-GIT-WORKFLOWS.md`](docs/GUIDE-GIT-WORKFLOWS.md) | End users &mdash; migrate from git, track a git upstream, push work back |
| [`docs/specs/`](docs/specs/README.md) | Implementers plus integrators &mdash; the wire-format and subsystem specifications, indexed with one-line summaries |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Contributors &mdash; module layering and design notes |
| [`docs/PARITY.md`](docs/PARITY.md) | Contributors &mdash; v1 scope gate, machine-output contract, and tracked divergences (the per-command matrix is the web `/parity` page) |
| [`docs/PROFILING.md`](docs/PROFILING.md) | Contributors &mdash; benchmarking and profiling workflow |
| [`docs/FUZZ.md`](docs/FUZZ.md) | Contributors &mdash; fuzz harness conventions |
| [`docs/STYLE-GUIDE.md`](docs/STYLE-GUIDE.md) | Contributors &mdash; writing style for docs and commits |
| [`docs/SSH-SECURITY.md`](docs/SSH-SECURITY.md) | Operators &mdash; SSH transport trust model |
| [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) | Operators plus reviewers &mdash; trust boundaries and security assumptions |
| [`apps/repo-worker/README.md#run-your-own-instance-self-hosting`](apps/repo-worker/README.md#run-your-own-instance-self-hosting) | Operators &mdash; self-hosting the anonymous-multiplayer repo server: Cloudflare plan/cost requirements, R2 bucket plus route overrides |
| [`docs/RELEASE.md`](docs/RELEASE.md) | Maintainers &mdash; release runbook: checklist, signing, reproducibility, supply chain, crates.io |

## Build

```sh
cd rust
cargo build --release                       # mkit binary → target/release/mkit
cargo test --workspace                      # all crates
cargo fmt --check                           # formatting gate (CI-enforced)
cargo clippy --all-targets -- -D warnings   # lint gate
```

## Contributing

Issues and PRs welcome. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for
build/test/style expectations and the inbound-license policy
(inbound = outbound, no DCO/CLA). Security-sensitive disclosures: see
[`SECURITY.md`](SECURITY.md).

## License

Dual-licensed under either of:

- MIT License ([`LICENSE-MIT`](LICENSE-MIT))
- Apache License, Version 2.0 ([`LICENSE-APACHE`](LICENSE-APACHE))

at your option. Unless you explicitly state otherwise, any
contribution intentionally submitted for inclusion in this project
shall be dual-licensed as above, without any additional terms or
conditions.

mkit is published by Official Unofficial, Inc.; the mkit name and
marks are owned by the company.
