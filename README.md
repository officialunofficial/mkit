# mkit

![status: alpha](https://img.shields.io/badge/status-alpha-orange)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)
[![crates.io](https://img.shields.io/crates/v/mkit-cli.svg)](https://crates.io/crates/mkit-cli)
[![docs.rs](https://img.shields.io/docsrs/mkit-core)](https://docs.rs/mkit-core)
[![codecov](https://codecov.io/gh/officialunofficial/mkit/branch/main/graph/badge.svg)](https://codecov.io/gh/officialunofficial/mkit)

**Version control you can prove.** mkit is a content-addressed version control toolkit written in Rust.

mkit gives you what you expect from Git: commits, refs, branches, and remotes. It also treats signatures and attestations as part of the object model. Every commit carries an Ed25519 signature, and any service can attach witness signatures to it as in-toto v1 Statements in DSSE envelopes.

> [!NOTE]
> **Alpha (pre-1.0).** The v1 on-disk and wire formats are stable through the 0.x line, pinned by [golden vectors](rust/tests/golden/). APIs, CLI flags, and unpinned internals may change in any 0.x release. See [`CHANGELOG.md`](CHANGELOG.md).

## Install

```sh
curl mkit.sh | sh
```

The script downloads the signed release binary for your platform, verifies its cosign signature, and installs `mkit` into `~/.local/bin`.

Other options:

```sh
cargo install mkit-cli                        # crates.io (Rust 1.95+)
bun add @officialunofficial/mkit-wasm         # WASM, or: npm i @officialunofficial/mkit-wasm
```

> [!WARNING]
> Do **not** run `cargo install mkit`. That crate name belongs to an unrelated project. The CLI is published as **`mkit-cli`**.

mkit supports Linux and macOS. On Windows, run it under [WSL](https://learn.microsoft.com/windows/wsl/). [`docs/INSTALL.md`](docs/INSTALL.md) covers pinned versions, release archives, verification (cosign, `SHA256SUMS`), and hardware signers.

## Quick start

```sh
mkit init                      # create .mkit/ in the current directory
mkit keygen                    # generate an Ed25519 signing key
echo hello > hi.txt
mkit add hi.txt
mkit commit -m "first commit"

mkit remote add origin mkit+file:///srv/mkit/my-repo
mkit push origin               # first push records origin as the upstream
mkit push                      # later pushes go to the upstream
```

That's your first signed commit. Push rejects non-fast-forward updates unless you pass `--force-with-lease` or `--force`.

Attest to the commit, then verify the attestation:

```sh
mkit attest --predicate-type https://example.com/sign-off/v1
mkit verify-attest --trust-roots .mkit/attest-trust-roots.toml
```

`verify-attest` trusts only keys you register with `mkit trust add`. [SPEC-ATTESTATIONS §6.5](docs/specs/SPEC-ATTESTATIONS.md) walks through trust roots. The full command reference is in [`docs/CLI.md`](docs/CLI.md). Coming from Git? Read [`docs/GUIDE-GIT-WORKFLOWS.md`](docs/GUIDE-GIT-WORKFLOWS.md).

## Why mkit

- **One hash, everywhere.** An object's ID is the BLAKE3 hash of its canonical serialization. There is no algorithm negotiation and no SHA-1/SHA-256 split. Large files split into content-defined chunks, so a small edit costs only the edit. See [`SPEC-OBJECTS`](docs/specs/SPEC-OBJECTS.md).
- **Attestations built in.** `mkit attest` stores in-toto v1 Statements in DSSE envelopes, with the commit hash as the subject. Standard tools such as cosign and in-toto-go can verify them, and one envelope can carry several signatures. See [`SPEC-ATTESTATIONS`](docs/specs/SPEC-ATTESTATIONS.md).
- **Keys stay where you want them.** Keys can live in an encrypted software vault, the macOS Keychain, Linux Secret Service, systemd-creds, or a YubiKey. External signers (TPM 2.0, FIDO2/CTAP, Apple Secure Enclave) plug in over a [v1 stdio protocol](docs/specs/SPEC-EXTERNAL-SIGNER.md). One key reference covers commit signing, attestations, and SSH push auth. See [`SPEC-KEYSTORE`](docs/specs/SPEC-KEYSTORE.md).
- **Strict transports.** The URL scheme picks the transport: `mkit+file://`, `mkit+https://`, `mkit+s3://`, `mkit+ssh://`, or `mkit+enc://`. mkit never falls back to another transport. See [`SPEC-TRANSPORT`](docs/specs/SPEC-TRANSPORT.md).
- **Proof without a clone.** Anyone holding a trusted commit ID can prove that a path, chunk, or whole object set belongs to it. See [`docs/VERIFY.md`](docs/VERIFY.md).
- **Script-friendly CLI.** Data goes to stdout and diagnostics to stderr. Read commands support `--format=json`, and exit codes follow `sysexits(3)`.

## Performance

mkit pulls clearly ahead of Git on large files and their edits, and runs roughly even on everyday operations. Pack creation for 100 files of 1 MiB each:

![Pack creation wallclock at 100 files x 1 MiB: mkit finishes in 143 ms versus 1,645 ms for git2 and 2,957 ms for git pack-objects](benchmarks/charts/pack_create-100__1_mib.svg)

The [performance page](https://mkit.sh/performance) has end-to-end `add`/`commit`/`push` comparisons with Git and the methodology. More microbenchmarks live in [`benchmarks/charts/`](benchmarks/charts/). Reproduce them with:

```sh
cargo bench -p mkit-benches --bench hashing --bench sign_verify \
  --bench object_commit --bench pack_create -- --quick
cargo run -p mkit-benches --bin render-charts
```

## Documentation

| Doc | For |
|---|---|
| [`docs/INSTALL.md`](docs/INSTALL.md) | Install channels, verification, hardware signers |
| [`docs/CLI.md`](docs/CLI.md) | Subcommands, config keys, env vars, exit codes |
| [`docs/GUIDE-GIT-WORKFLOWS.md`](docs/GUIDE-GIT-WORKFLOWS.md) | Migrating from Git and tracking a Git upstream |
| [`docs/VERIFY.md`](docs/VERIFY.md) | Verifying a commit hash without repository access |
| [`docs/specs/`](docs/specs/README.md) | Wire-format and subsystem specifications |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Crate layout and design notes |
| [`docs/SSH-SECURITY.md`](docs/SSH-SECURITY.md) · [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) | Trust model and security assumptions |
| [Self-hosting the repo server](apps/repo-worker/README.md#run-your-own-instance-self-hosting) | Running your own instance |
| [`docs/RELEASE.md`](docs/RELEASE.md) | Cutting a release |

Want the library instead of the CLI? Run `cargo add mkit-core` ([docs.rs](https://docs.rs/mkit-core)).

## Build and contribute

```sh
cd rust
cargo build --release                       # → target/release/mkit
cargo test --workspace
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

The MSRV is Rust 1.95.0, pinned in [`rust/rust-toolchain.toml`](rust/rust-toolchain.toml).

Issues and PRs are welcome. [`CONTRIBUTING.md`](CONTRIBUTING.md) covers build, test, and style expectations. Inbound contributions use the project license, with no DCO or CLA. Follow [`docs/STYLE-GUIDE.md`](docs/STYLE-GUIDE.md) for docs and commit messages.

To report a security issue, follow [`SECURITY.md`](SECURITY.md).

## License

mkit is dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option. Unless you explicitly state otherwise, any contribution you intentionally submit for inclusion is dual-licensed the same way, with no additional terms or conditions.

mkit is published by Official Unofficial, Inc., which owns the mkit name and marks.
