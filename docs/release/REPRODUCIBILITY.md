# Reproducibility

A mkit release binary is a function of a small, pinned set of inputs. If
all of them match, any machine that can run the same Rust toolchain will
produce a byte-identical binary to the one published on GitHub Releases.

## The inputs

1. **Rust toolchain version.** Pinned in `rust-toolchain.toml` at the
   repo root. The release workflow installs this version verbatim.
2. **Target triple.** One of `aarch64-apple-darwin`,
   `x86_64-apple-darwin`, `x86_64-unknown-linux-gnu`,
   `aarch64-unknown-linux-gnu`. Passed as `--target=<triple>` to
   `cargo build`.
3. **Build profile.** `release`. Passed as `--release`.
4. **Source tree hash.** The Git commit the tag points at. Every source
   file consumed by the build is tracked in Git; the release workflow
   checks out the exact commit the tag resolves to.
5. **Dependency fingerprint.** `Cargo.lock` is committed to the repo
   and fully pins every transitive dependency. Any `cargo update`
   between releases is a visible change to that file.

## Reproducing a published binary from source

For a published release `vX.Y.Z`:

```sh
# 1. Clone at the release tag.
git clone --depth 1 --branch vX.Y.Z https://github.com/officialunofficial/mkit.git
cd mkit

# 2. Install the toolchain pinned in rust-toolchain.toml.
#    `rustup` picks this up automatically on first `cargo` invocation.

# 3. Build for your target.
cargo build --release --manifest-path rust/Cargo.toml --bin mkit

# 4. Hash the binary.
shasum -a 256 rust/target/release/mkit

# 5. Compare against SHA256SUMS from the GitHub Release.
```

If the hashes don't match, treat it as a supply-chain incident: open an
issue with (a) your host OS, (b) the output of `rustc --version`,
(c) the `sha256` you got, and (d) the expected one. `diffoscope` on the
two binaries will usually isolate the culprit to a section or symbol.

## CI safety net

`.github/workflows/reproducible-build.yml` builds mkit twice on the same
commit and fails if the two outputs diverge. It runs on every
source-touching PR and weekly on `main`. A failure there means a
non-deterministic input has crept in (embedded timestamps, random
seeds, absolute paths in debug info, unsorted directory reads, etc.)
and must be fixed before the next tag.

## What is **not** guaranteed

- Binaries built on your local macOS are not expected to match binaries
  built on GitHub's `macos-14` runner byte-for-byte unless your OS,
  SDK, and linker versions match. The Linux x86_64 build is the most
  reliable reproducibility target for third parties.
- Mach-O targets may drift across host SDK versions; use the Linux
  x86_64 archive if you need the strongest third-party guarantee.
