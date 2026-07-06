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
7. [Updating](#updating)

## Pick your channel

| Use case                              | Channel                              | Command                                                                                              |
|---------------------------------------|--------------------------------------|------------------------------------------------------------------------------------------------------|
| CLI on a dev machine                  | Release archive or `cargo install --git` | `curl mkit.sh \| sh` *or* `cargo install --git https://github.com/officialunofficial/mkit mkit-cli` |
| CI / backend (pin a version)          | Release archive                      | `curl -LO …/releases/download/v<VERSION>/mkit-<VERSION>-<target>.tar.gz && tar -xzf mkit-<VERSION>-<target>.tar.gz` |
| Browser / Cloudflare Worker           | npm                                  | `bun add @makechain/mkit-wasm`                                                                                  |
| Library inside another Rust crate     | crates.io (or git dependency)        | `mkit-core = "0.3"`                                                                                  |

Pick the leftmost channel that satisfies your constraints — release
archives are the lowest-overhead path for end users, source builds the
right answer for contributors and air-gapped CI.

## From source

Source builds are the right path for contributors and air-gapped CI. For
everyday CLI use, `cargo install mkit-cli` from crates.io (see
[`README.md`](../README.md)) is the shortest route.

**Toolchain.** Rust 1.95, edition 2024, pinned by
[`rust/rust-toolchain.toml`](../rust/rust-toolchain.toml). `rustup` will
auto-install on the first build.

**Install the CLI:**

```sh
cargo install mkit-cli                                                   # from crates.io
cargo install --git https://github.com/officialunofficial/mkit mkit-cli  # from git HEAD
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
| `mkit-keystore`                      | key vault interface + backends                             |
| `mkit-git-bridge`                    | git import/export bridge                                   |
| `mkit-rpc`                           | shared stdio framing for subprocess protocols              |
| `mkit-cli`                           | the `mkit` binary                                          |
| `mkit-transport-{memory,file,http,s3,ssh}` | one crate per transport scheme                       |
| `mkit-transport-enc`                 | mkit+enc:// encrypted transport                            |
| `mkit-wasm`                          | wasm-bindgen surface for browsers / Workers (npm-only, not on crates.io) |

## From GitHub Releases

The [`release.yml`](../.github/workflows/release.yml) workflow fires on
strict-semver `v*.*.*` tags after verifying the tag is an annotated GPG-signed
tag from an allowlisted release signer and points at a commit reachable from
`main`. It then produces a per-target archive plus signing material:

- `mkit-<version>-<target>.tar.gz` — the archive (binary, licenses,
  README, optional changelog, `share/man/man1/mkit.1`, shell completions,
  and per-archive `SHA256SUMS`).
- `mkit-<version>-<target>.tar.gz.sha256` — archive-level checksum.
- `mkit-<version>-<target>.tar.gz.cosign.bundle` — keyless OIDC
  signature (Sigstore Fulcio + Rekor).

Targets shipped today:

- `aarch64-apple-darwin` (macOS, Apple Silicon)
- `x86_64-apple-darwin` (macOS, Intel)
- `x86_64-unknown-linux-gnu` (Linux x86_64)
- `aarch64-unknown-linux-gnu` (Linux arm64)

If you want "latest", use the hosted installer — `curl mkit.sh | sh` (or
the explicit `curl -sSfL https://mkit.sh/install.sh | sh`). It resolves
the current tag, fetches the matching archive for your platform, and
verifies cosign by default. Direct release URLs are best when you want a
pinned artifact.

> [!NOTE]
> Like any `curl | sh`, the *installer script* is trusted on download —
> cosign verifies the downloaded **binary**, not the script itself. The
> script is served over HTTPS from `mkit.sh`; `https://mkit.sh/install.sh`
> and the byte-identical
> [`raw.githubusercontent.com/.../main/install.sh`](https://raw.githubusercontent.com/officialunofficial/mkit/main/install.sh)
> are the same file. If you'd rather not trust the hosted script, read it
> first (`curl -sSfL https://mkit.sh/install.sh | less`) or skip it and use
> the pinned release + cosign steps below.

**Download a pinned release for your platform:**

```sh
VERSION=0.3.0
TARGET=aarch64-apple-darwin
curl -LO "https://github.com/officialunofficial/mkit/releases/download/v${VERSION}/mkit-${VERSION}-${TARGET}.tar.gz"
tar -xzf "mkit-${VERSION}-${TARGET}.tar.gz"
```

**Pin a version (recommended for CI):**

```sh
VERSION=0.3.0
TARGET=x86_64-unknown-linux-gnu
TAG="v${VERSION}"
URL="https://github.com/officialunofficial/mkit/releases/download/${TAG}/mkit-${VERSION}-${TARGET}.tar.gz"
curl -LO "$URL"
tar -xzf "mkit-${VERSION}-${TARGET}.tar.gz"
```

**Verify the SHA256.** Each archive ships with a sibling `.sha256`:

```sh
curl -LO "${URL}.sha256"
sha256sum -c "mkit-${VERSION}-${TARGET}.tar.gz.sha256" || \
  shasum -a 256 -c "mkit-${VERSION}-${TARGET}.tar.gz.sha256"
```

**Verify the cosign signature.** Keyless OIDC, no public key needed.
This is the real authenticity check: it proves the archive was signed by
this repo's `release.yml` workflow on a strict-semver tag. The sibling
`.sha256` file is same-origin defense in depth only.

```sh
curl -LO "${URL}.cosign.bundle"
cosign verify-blob \
  --bundle "mkit-${VERSION}-${TARGET}.tar.gz.cosign.bundle" \
  --certificate-identity-regexp '^https://github\.com/officialunofficial/mkit/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "mkit-${VERSION}-${TARGET}.tar.gz"
```

Full reproducibility, signing, and supply-chain notes live under
[`docs/RELEASE.md`](RELEASE.md).

## WASM / npm

The `mkit-wasm` crate ([`rust/crates/mkit-wasm`](../rust/crates/mkit-wasm))
is built with `wasm-pack` and published to npm as
`@makechain/mkit-wasm`.

**Install:**

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
import wasmModule from "@makechain/mkit-wasm/mkit_wasm_bg.wasm";

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
  import init, { hash } from "https://esm.sh/@makechain/mkit-wasm";
  await init();
  console.log(hash(new TextEncoder().encode("hi")));
</script>
```

## Hardware signers

External signers are separate binaries that mkit drives over the
[v1 stdio protocol](specs/SPEC-EXTERNAL-SIGNER.md). Wire one up with
`attest.external_signer_path` in `.mkit/config`. Each signer ships its
own README with setup, hardware notes, and troubleshooting — the lines
below cover only how to install the binary.

The signer crates live under
[`contrib/signers/`](../contrib/signers/), outside the top-level
Cargo workspace at `rust/`. They inherit workspace settings via
`workspace = "../../../rust"` in their own `Cargo.toml`, so the
canonical install path is `git clone` + `cargo install --path .` from
the signer directory rather than `cargo install --git URL --bin …`
against the repository root.

### `mkit-sign-file` — file-backed reference (any platform)

Pure software signer for development and as the wire-protocol contract
test:

```sh
git clone https://github.com/officialunofficial/mkit
cd mkit/contrib/signers/mkit-sign-file
cargo install --path .
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
git clone https://github.com/officialunofficial/mkit
cd mkit/contrib/signers/mkit-sign-tpm
cargo install --path . --features tpm2
```

Windows uses TBS via `tss-esapi`'s `tbs` feature; macOS has no TPM and
the binary builds without `--features tpm2` for tooling/CI checks
only. Full requirements and `swtpm` test recipe in
[`contrib/signers/mkit-sign-tpm/README.md`](../contrib/signers/mkit-sign-tpm/README.md).

### `mkit-sign-ctap` — FIDO2 / WebAuthn over CTAP-HID

P-256, speaks Protocol **v1.1** (WebAuthn wrapping mode); works with
YubiKey, Nitrokey, SoloKey, etc.:

```sh
git clone https://github.com/officialunofficial/mkit
cd mkit/contrib/signers/mkit-sign-ctap
cargo install --path .
```

See [`contrib/signers/mkit-sign-ctap`](../contrib/signers/mkit-sign-ctap).

## Verify your install

After any install path, confirm the binary speaks the expected
version:

```sh
$ mkit version
mkit 0.3.0
```

The exact format `mkit <X.Y.Z>\n` (no extra whitespace, no banner) is
contract-tested in
[`.github/workflows/rust.yml`](../.github/workflows/rust.yml) under the
`Version contract` step — if you ever see anything else, the binary
on your `PATH` is not a release build of this repo.

Run `mkit --help` to enumerate subcommands, then jump into the
[CLI reference](CLI.md) or the
[attestation spec](specs/SPEC-ATTESTATIONS.md).

## Updating

If you installed via the install script (`curl mkit.sh | sh`), the
binary can update itself:

```sh
mkit self update            # update to the latest release
mkit self update --check    # just report whether an update exists
mkit self update --version v0.4.0   # pin a specific release
```

`self update` downloads the release archive for your platform and
verifies the **mkit-native release attestation** — a DSSE/in-toto
envelope over the archives' BLAKE3 digests, signed by the release key
whose public half is embedded in your binary — entirely in-process
(no `cosign` needed, unlike the install script). It refuses silent
downgrades, swaps the binary atomically, and rewrites the same
receipts `install.sh` writes, so the two stay interchangeable.

Installs it does **not** manage are refused with pointers to the right
channel instead:

- Homebrew: `brew upgrade mkit`
- cargo: `cargo install --locked mkit-cli` (or `cargo binstall mkit-cli`)

mkit never checks for updates in the background; `self update` acts
only when you run it. Full details (receipts, downgrade policy,
environment variables) are in [CLI.md](CLI.md); the attestation's
trust model and the key-rotation runbook are in
[RELEASE.md](RELEASE.md).
