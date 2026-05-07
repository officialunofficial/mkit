# mkit

A content-addressed version control toolkit written in Rust.

`mkit` is a generic content-addressed VCS — Git-like commits, refs,
transports — plus a native, predicate-agnostic attestation subsystem
(in-toto v1 Statements wrapped in DSSE envelopes) that any downstream
service can attach witness signatures to commits with.

The v1 on-disk and wire formats are pinned by golden vectors under
`rust/tests/golden/`.

## Quick start

Install (see [Installing](#installing) for all four channels):

```sh
cargo install --git https://github.com/officialunofficial/mkit mkit-cli
```

To push to a remote, declare a strict URL scheme (`mkit+file://`,
`mkit+https://`, `mkit+s3://`, `mkit+ssh://`):

```sh
mkit remote add origin mkit+file:///srv/mkit/my-repo
mkit push
```

See [`docs/CLI.md`](docs/CLI.md) for the full CLI reference.

## Build

Requires **Rust 1.95** (pinned in `rust/rust-toolchain.toml`; rustup
will install it automatically on first build).

```sh
cd rust
cargo build --release                       # mkit binary → target/release/mkit
cargo test --workspace                      # all crates
cargo fmt --check                           # formatting gate (CI-enforced)
cargo clippy --all-targets -- -D warnings   # lint gate
```

Workspace crates:

| Crate | Purpose |
|---|---|
| `mkit-core` | hash, object, serialize, store, sign, chunker, delta, pack, refs, index, worktree, ignore, repo_lock, ops, protocol |
| `mkit-attest` | JCS, in-toto v1 Statement, DSSE envelope, signers, verify |
| `mkit-transport-{memory,file,http,s3,ssh}` | Transport trait implementations |
| `mkit-cli` | the `mkit` binary |
| `mkit-fuzz` | bounded property tests (cargo-fuzz compatible) |

`scripts/verify-rename.sh` is the rename-gate enforced in CI; it greps
the public build surface (`rust/`) for forbidden legacy strings that
should never appear in the generic `mkit` utility (see the script's
`FORBIDDEN` array for the full list).

## Architecture

mkit is a thin, generic VCS with a predicate-agnostic attestation layer
built on industry-standard primitives:

```
┌─────────────────────────────────────────────────────────┐
│  mkit core binary                                       │
│  - objects, packs, refs, transports, CLI                │
│  - attestations: in-toto v1 Statement + DSSE envelopes  │
└────────────────────┬────────────────────────────────────┘
                     │
        ┌────────────┼────────────────┐
        │            │                │
┌───────┴────────┐   │   ┌────────────┴────────────────┐
│ repo-key       │   │   │ external subprocess signer  │
│ (Ed25519, the  │   │   │ (custom notary, blockchain  │
│  commit key)   │   │   │  attestor, settlement svc)  │
└────────────────┘   │   └─────────────────────────────┘
                     │
            ┌────────┴────────┐
            │ sigstore-keyless │
            │ (planned)        │
            └──────────────────┘
```

Attestations are plain DSSE envelopes carrying an in-toto v1 Statement
with the commit hash as subject — no mkit-specific schema. Any service
(CI provenance producer, human reviewer sign-off tool, external
settlement attestor) can produce or verify them with off-the-shelf
tooling. See
[`docs/SPEC-ATTESTATIONS.md`](docs/SPEC-ATTESTATIONS.md) for the full
contract.

## Identity & push auth — one key, many roles

`.mkit/keys/default.key` is a raw Ed25519 seed. The same seed covers:

- commit / remix signing (`docs/SPEC-SIGNING.md`);
- DSSE attestation signing via the `repo-key` signer (`docs/SPEC-ATTESTATIONS.md` §6.2);
- SSH transport authentication — OpenSSH 8.0+ accepts a raw Ed25519
  seed as `id_ed25519`, so the same key authenticates your
  `mkit push` over `mkit+ssh://`.

For `mkit+ssh://` push authorisation the idiomatic pattern is Git's:
the server's `sshd` runs an `AuthorizedKeysCommand` that maps an
incoming pubkey to an account, and `mkit serve` executes as that
account. mkit core ships **no custom push-auth protocol** — SSH's own
KEX handshake already does the nonce/signature exchange, and
`AuthorizedKeysCommand` is the standard server-side extension point
for resolving `pubkey → account`. A downstream service can wire its
own identity model (e.g. pubkey → on-chain owner address) through
that hook without changing the wire protocol.

See `docs/SPEC-SIGNING.md` §8 for the convention and
`docs/SSH-SECURITY.md` for transport trust model.

## Documentation

| Doc | Audience |
|---|---|
| [`docs/INSTALL.md`](docs/INSTALL.md) | End users — install channels, verification, hardware signers |
| [`docs/CLI.md`](docs/CLI.md) | End users — subcommands, env vars, exit codes |
| [`docs/SPEC-ATTESTATIONS.md`](docs/SPEC-ATTESTATIONS.md) | Implementers + integrators — native attestation primitive (in-toto v1 + DSSE) |
| [`docs/SPEC-OBJECTS.md`](docs/SPEC-OBJECTS.md) | Implementers of compatible tools — on-disk format |
| [`docs/SPEC-SIGNING.md`](docs/SPEC-SIGNING.md) | Implementers — commit signing format |
| [`docs/SPEC-PACKFILE.md`](docs/SPEC-PACKFILE.md) | Implementers — packfile wire format |
| [`docs/SPEC-DELTA.md`](docs/SPEC-DELTA.md) | Implementers — delta encoding |
| [`docs/SPEC-REFS.md`](docs/SPEC-REFS.md) | Implementers — ref names and CAS |
| [`docs/SPEC-TRANSPORT.md`](docs/SPEC-TRANSPORT.md) | Implementers — 7-verb transport protocol incl. SSH OP_HELLO |
| [`docs/SPEC-FASTCDC.md`](docs/SPEC-FASTCDC.md) | Implementers — content chunking |
| [`docs/SSH-SECURITY.md`](docs/SSH-SECURITY.md) | Operators — SSH transport trust model |
| [`docs/FUZZ.md`](docs/FUZZ.md) | Contributors — fuzz harness conventions |
| [`docs/release/`](docs/release/) | Maintainers — release checklist, signing, reproducibility, supply chain |

## Installing

Four channels. Pick one. Long-form guide with verification steps in
[`docs/INSTALL.md`](docs/INSTALL.md).

### From source (works today)

```sh
cargo install --git https://github.com/officialunofficial/mkit mkit-cli
```

Requires Rust 1.95 (rustup picks it up from `rust/rust-toolchain.toml`
on first build). Drops `mkit` into `~/.cargo/bin/`.

### From GitHub Releases (works today)

Cosign-signed archives for macOS (arm64 + x86_64) and Linux (x86_64 +
arm64) on every `v*.*.*` tag:

```sh
VERSION=0.1.0
TARGET=aarch64-apple-darwin
curl -LO "https://github.com/officialunofficial/mkit/releases/download/v${VERSION}/mkit-${VERSION}-${TARGET}.tar.gz"
tar -xzf "mkit-${VERSION}-${TARGET}.tar.gz"
```

The one-liner `curl -sSfL …/install.sh | sh` picks the right archive
and verifies the cosign bundle by default. Pass `--version vX.Y.Z` to
pin an exact release.

### WASM for browsers and Cloudflare Workers

```sh
bun add @makechain/mkit-wasm     # or: npm i @makechain/mkit-wasm
```

TypeScript + Workers examples in
[`docs/INSTALL.md`](docs/INSTALL.md#wasm--npm).

### Hardware signers (optional)

External signers are separate binaries that mkit drives over the
[v1 stdio protocol](docs/SPEC-EXTERNAL-SIGNER.md):

```sh
# File-backed reference signer (any platform)
cargo install --git https://github.com/officialunofficial/mkit --bin mkit-sign-file

# TPM 2.0 (Linux/Windows; install libtss2-dev first on Debian/Ubuntu)
cargo install --git https://github.com/officialunofficial/mkit --bin mkit-sign-tpm --features tpm2

# Apple Secure Enclave (macOS, Swift)
cd contrib/signers/mkit-sign-se && swift build -c release \
  && cp .build/release/mkit-sign-se /usr/local/bin/

# FIDO2 / WebAuthn (CTAP-HID)
cargo install --git https://github.com/officialunofficial/mkit --bin mkit-sign-ctap
```

Each signer ships its own README under
[`contrib/signers/`](contrib/signers/) with setup notes.

## Getting started

```sh
mkit init
mkit keygen
mkit add file.txt
mkit commit -m "first commit"
mkit log
```

Multi-algo attestation flow — sign with two algorithms at once and
verify against trust roots:

```sh
mkit keygen --algorithm p256 --print-pubkey
mkit attest --algorithm ed25519 \
            --additional-signer "algorithm=p256,signer=repo-key" \
            --predicate-type https://example.com/sign-off/v1
mkit verify-attest --trust-roots .mkit/attest-trust-roots.toml
```

See [`docs/CLI.md`](docs/CLI.md) for every subcommand and
[`docs/SPEC-ATTESTATIONS.md`](docs/SPEC-ATTESTATIONS.md) for the
attestation contract.

## Status

0.1.0 is the initial public release. See [`CHANGELOG.md`](CHANGELOG.md)
for the full change list.

## Contributing

This is a young project. Open issues and PRs welcome.

Security-sensitive disclosures: see [`SECURITY.md`](SECURITY.md).

## License

Dual-licensed under either of:

- MIT License ([LICENSE-MIT](LICENSE-MIT))
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

at your option. Unless you explicitly state otherwise, any contribution
intentionally submitted for inclusion in this project shall be dual-licensed
as above, without any additional terms or conditions.
