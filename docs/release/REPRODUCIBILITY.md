# Reproducibility

A mkit release binary is a function of exactly five inputs. If all five
match, any machine that can run the Zig toolchain will produce a
byte-identical binary to the one published on GitHub Releases.

## The five inputs

1. **Zig toolchain version.** Pinned in `.zigversion` and in
   `.github/workflows/release.yml` (`ZIG_VERSION`). The release workflow
   installs this version verbatim via `mlugg/setup-zig@v1`.
2. **Target triple.** One of
   `aarch64-macos`, `x86_64-macos`, `x86_64-linux`, `aarch64-linux`. Passed
   as `-Dtarget=<triple>`.
3. **Optimization mode.** `ReleaseSafe`. Passed as
   `-Doptimize=ReleaseSafe`.
4. **Source tree hash.** The Git commit the tag points at. Every source
   file consumed by the build is tracked in Git; the release workflow
   checks out the exact commit the tag resolves to.
5. **Dependency fingerprint.** `build.zig.zon`'s `dependencies` table (and
   their `.hash` fields). mkit 0.1.0 has **zero** external Zig packages, so
   this is currently the empty set — but any future dep must be pinned by
   hash, and that hash becomes part of the reproducibility contract.

## Reproducing a published binary from source

For a published release `vX.Y.Z`:

```sh
# 1. Clone at the release tag.
git clone --depth 1 --branch vX.Y.Z https://github.com/officialunofficial/mkit.git
cd mkit

# 2. Install the Zig version pinned in .zigversion.
#    On macOS/Linux via a version manager (zvm, asdf) or by downloading the
#    archive from https://ziglang.org/download/.
cat .zigversion   # => 0.16.0

# 3. Build for your target.
zig build -Doptimize=ReleaseSafe -Dtarget=aarch64-macos

# 4. Hash the binary.
sha256sum zig-out/bin/mkit    # or: shasum -a 256

# 5. Compare against SHA256SUMS from the GitHub Release.
```

If the hashes don't match, treat it as a supply-chain incident: open an
issue with (a) your host OS, (b) the output of `zig version`, (c) the
`sha256` you got, and (d) the expected one. Diffoscope on the two binaries
will usually isolate the culprit to a section or symbol.

## CI safety net

`.github/workflows/reproducible-build.yml` builds mkit twice on the same
commit and fails if the two outputs diverge. It runs on every source-touching
PR and weekly on `main`. A failure there means a non-deterministic input
has crept in (embedded timestamps, random seeds, absolute paths in debug
info, unsorted directory reads, etc.) and must be fixed before the next tag.

## What is **not** guaranteed

- Binaries built on your local macOS are not expected to match binaries
  built on GitHub's `macos-14` runner byte-for-byte unless your OS, SDK,
  and linker versions match. The Linux x86_64 build is the most reliable
  reproducibility target for third parties.
- Debug symbols and sections tied to host toolchain versions (e.g. Mach-O
  `LC_UUID`) may vary; a tighter pass would strip these before shipping.
  That is a post-0.1.0 improvement.
