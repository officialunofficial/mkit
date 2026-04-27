# Installing mkit

mkit ships through four distribution channels. This guide is the
long-form companion to the install section in
[`README.md`](../README.md): pick a channel, follow its steps, then
verify the result.

## Table of contents

1. [Pick your channel](#pick-your-channel)
2. [From source](#from-source)
3. [From GitHub Releases](#from-github-releases)
4. [WASM / npm](#wasm--npm)
5. [Hardware signers](#hardware-signers)
6. [Verify your install](#verify-your-install)

## Pick your channel

| Use case                              | Channel                              | Command                                                                                              |
|---------------------------------------|--------------------------------------|------------------------------------------------------------------------------------------------------|
| CLI on a dev machine                  | Release archive or `cargo install --git` | `curl -sSfL …/install.sh \| sh` *or* `cargo install --git https://github.com/officialunofficial/mkit mkit-cli` |
| CI / backend (pin a version)          | Release archive                      | `curl -L …/releases/download/<tag>/mkit-<tag>-<target>.tar.gz \| tar xz`                              |
| Browser / Cloudflare Worker           | npm (v0.2.0+)                        | `bun add @makechain/mkit-wasm`                                                                                  |
| Library inside another Rust crate     | Path or git dependency (crates.io is planned) | `mkit-core = { git = "https://github.com/officialunofficial/mkit" }`                                 |

Pick the leftmost channel that satisfies your constraints — release
archives are the lowest-overhead path for end users, source builds the
right answer for contributors and air-gapped CI.

## From source

Currently the canonical channel: the workspace is on GitHub and Cargo
can fetch + build it directly.

**Toolchain.** Rust 1.95, edition 2024, pinned by
[`rust/rust-toolchain.toml`](../rust/rust-toolchain.toml). `rustup` will
auto-install on the first build.

**Install the CLI:**

```sh
cargo install --git https://github.com/officialunofficial/mkit mkit-cli
```

Drops `mkit` into `~/.cargo/bin/`. Make sure that directory is on your
`PATH`.

**Build modes.** From a checkout of the repository:

```sh
cd rust
cargo build --release        # mkit binary → rust/target/release/mkit
cargo build                  # debug build, faster compile, slower runtime
cargo test --workspace       # all crates, all tests
```

**Workspace layout.** The Rust tree is one Cargo workspace under
[`rust/`](../rust/). The publishable surface is in `rust/crates/`:

| Crate                                | Role                                                       |
|--------------------------------------|------------------------------------------------------------|
| `mkit-core`                          | object model, store, chunker, packs, refs, transports, ops |
| `mkit-attest`                        | DSSE + in-toto v1, multi-algo signers                      |
| `mkit-cli`                           | the `mkit` binary                                          |
| `mkit-transport-{memory,file,http,s3,ssh}` | one crate per transport scheme                       |
| `mkit-wasm`                          | wasm-bindgen surface for browsers / Workers                |

## From GitHub Releases

The [`release.yml`](../.github/workflows/release.yml) workflow fires on
every `v*.*.*` tag and produces a per-target archive plus signing
material:

- `mkit-<version>-<target>.tar.gz` — the archive (binary + man pages +
  completions + per-archive `SHA256SUMS`).
- `mkit-<version>-<target>.tar.gz.sha256` — archive-level checksum.
- `mkit-<version>-<target>.tar.gz.cosign.bundle` — keyless OIDC
  signature (Sigstore Fulcio + Rekor).

Targets shipped today:

- `aarch64-apple-darwin` (macOS, Apple Silicon)
- `x86_64-apple-darwin` (macOS, Intel)
- `x86_64-unknown-linux-gnu` (Linux x86_64)
- `aarch64-unknown-linux-gnu` (Linux arm64)

**Download the latest release for your platform:**

```sh
curl -L https://github.com/officialunofficial/mkit/releases/latest/download/mkit-aarch64-apple-darwin.tar.gz | tar xz
```

**Pin a version (recommended for CI):**

```sh
VERSION=v0.1.0
TARGET=x86_64-unknown-linux-gnu
URL=https://github.com/officialunofficial/mkit/releases/download/${VERSION}/mkit-${VERSION}-${TARGET}.tar.gz
curl -L "$URL" | tar xz
```

**Verify the SHA256.** Each archive ships with a sibling `.sha256`:

```sh
curl -LO "$URL"
curl -LO "$URL.sha256"
shasum -a 256 -c "mkit-${VERSION}-${TARGET}.tar.gz.sha256"
```

**Verify the cosign signature.** Keyless OIDC, no public key needed —
the signer identity is bound to the GitHub Actions OIDC issuer:

```sh
cosign verify-blob \
  --bundle "mkit-${VERSION}-${TARGET}.tar.gz.cosign.bundle" \
  --certificate-identity-regexp 'https://github.com/officialunofficial/mkit/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "mkit-${VERSION}-${TARGET}.tar.gz"
```

Full reproducibility, signing, and supply-chain notes live under
[`docs/release/`](release/).

## WASM / npm

> **Status:** the `mkit-wasm` crate exists in tree
> ([`rust/crates/mkit-wasm`](../rust/crates/mkit-wasm)) and is built
> with `wasm-pack`. The npm pipeline lands in v0.2.0 — until that tag
> is cut, install via the published package is not yet live.

**Install (v0.2.0+):**

```sh
bun add @makechain/mkit-wasm
# or
npm i @makechain/mkit-wasm
# or
pnpm add @makechain/mkit-wasm
```

**Why `wasm-pack` with `--target bundler`.** mkit-wasm targets the
`bundler` output by default so Vite / Rspack / esbuild can consume the
ESM entrypoint and tree-shake unused exports. For inline browser use
without a bundler, build the same crate with `--target web`; for
Cloudflare Workers' ESM modules format, `bundler` is correct because
wrangler's bundler will inline the `.wasm` import.

**TypeScript usage:**

```ts
import init, { hash, parse_envelope } from "@makechain/mkit-wasm";

await init();
const id = hash(new TextEncoder().encode("hello"));
console.log(id);
```

**Cloudflare Workers (ESM modules format):**

```ts
import init, { hash } from "@makechain/mkit-wasm";
import wasmModule from "mkit-wasm/mkit_wasm_bg.wasm";

export default {
  async fetch(req: Request): Promise<Response> {
    await init(wasmModule);
    const body = new Uint8Array(await req.arrayBuffer());
    return new Response(hash(body));
  },
};
```

**Plain browser (no bundler):**

```html
<script type="module">
  import init, { hash } from "https://esm.sh/mkit-wasm";
  await init();
  console.log(hash(new TextEncoder().encode("hi")));
</script>
```

## Hardware signers

External signers are separate binaries that mkit drives over the
[v1 stdio protocol](SPEC-EXTERNAL-SIGNER.md). Wire one up with
`attest.external_signer_path` in `.mkit/config`. Each signer ships its
own README with setup, hardware notes, and troubleshooting — the lines
below cover only how to install the binary.

### `mkit-sign-file` — file-backed reference (any platform)

Pure software signer for development and as the wire-protocol contract
test:

```sh
cargo install --git https://github.com/officialunofficial/mkit --bin mkit-sign-file
```

See [`contrib/signers/mkit-sign-file`](../contrib/signers/mkit-sign-file).

### `mkit-sign-se` — Apple Secure Enclave (macOS, Swift)

P-256 only, optional biometric gate:

```sh
cd contrib/signers/mkit-sign-se
swift build -c release
cp .build/release/mkit-sign-se /usr/local/bin/
```

Setup, biometric notes, and `attest.external_signer_path` wiring live
in [`contrib/signers/mkit-sign-se/README.md`](../contrib/signers/mkit-sign-se/README.md).

### `mkit-sign-tpm` — TPM 2.0 persistent handle (Linux / Windows)

P-256, talks to the platform TPM via `tss-esapi`:

```sh
# Debian / Ubuntu
sudo apt install libtss2-dev
cargo install --git https://github.com/officialunofficial/mkit \
  --bin mkit-sign-tpm --features tpm2
```

Windows uses TBS via `tss-esapi`'s `tbs` feature; macOS has no TPM and
the binary builds without `--features tpm2` for tooling/CI checks
only. Full requirements and `swtpm` test recipe in
[`contrib/signers/mkit-sign-tpm/README.md`](../contrib/signers/mkit-sign-tpm/README.md).

### `mkit-sign-ctap` — FIDO2 / WebAuthn over CTAP-HID

P-256, speaks Protocol **v1.1** (WebAuthn wrapping mode); works with
YubiKey, Nitrokey, SoloKey, etc.:

```sh
cargo install --git https://github.com/officialunofficial/mkit --bin mkit-sign-ctap
```

See [`contrib/signers/mkit-sign-ctap`](../contrib/signers/mkit-sign-ctap).

## Verify your install

After any install path, confirm the binary speaks the expected
version:

```sh
$ mkit version
mkit 0.1.0
```

The exact format `mkit <X.Y.Z>\n` (no extra whitespace, no banner) is
contract-tested in
[`.github/workflows/rust.yml`](../.github/workflows/rust.yml) under the
`Version contract` step — if you ever see anything else, the binary
on your `PATH` is not a release build of this repo.

Run `mkit --help` to enumerate subcommands, then jump into the
[CLI reference](CLI.md) or the
[attestation spec](SPEC-ATTESTATIONS.md).
