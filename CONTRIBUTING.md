# Contributing to mkit

Thanks for taking the time. mkit is a security-sensitive project &mdash; a
Git-like content-addressed VCS with cryptographic attestations &mdash; so
every contribution lands under the same review bar that the
maintainers hold themselves to. This document describes that bar and
how to clear it efficiently.

By participating you agree to abide by the [Code of Conduct](CODE_OF_CONDUCT.md)
and to dual-license your contribution under MIT OR Apache-2.0 (see
[LICENSE-MIT](LICENSE-MIT), [LICENSE-APACHE](LICENSE-APACHE)).

## Reporting security issues

**Do not open a public issue for a vulnerability.** Use GitHub Security
Advisories. Full policy: [SECURITY.md](SECURITY.md).

## Quick orientation

| Area | Where |
|---|---|
| Rust workspace | `rust/` |
| CLI binary | `rust/crates/mkit-cli/` |
| Core library (objects, packs, refs, signing) | `rust/crates/mkit-core/` |
| Attestations (in-toto v1, DSSE, signers) | `rust/crates/mkit-attest/` |
| Transports | `rust/crates/mkit-transport-{memory,file,http,s3,ssh,enc}/` |
| External signers (TPM, SE, CTAP, file) | `contrib/signers/` |
| On-disk plus wire format specs | `docs/specs/SPEC-*.md` |
| Golden vectors | `rust/tests/golden/` |
| Fuzz harness | `rust/fuzz/` |

## Development setup

Requires **Rust 1.95** (auto-installed by rustup from
`rust/rust-toolchain.toml`).

```sh
cd rust
cargo build --workspace
cargo t                                      # alias for `cargo nextest run`
cargo fmt --check                            # CI-enforced
cargo clippy --all-targets -- -D warnings    # CI-enforced
```

`cargo t` shells out to `cargo nextest run` via the workspace
`.cargo/config.toml` alias &mdash; nextest is up to 3× faster than the
in-process `cargo test` on the mkit workspace because each test runs
in its own process. Install with `cargo install cargo-nextest --locked`
if `cargo t` errors with "no such subcommand".

Useful extras:

```sh
cargo install cargo-deny cargo-audit cargo-nextest    # supply-chain + faster tests
cargo install cargo-mutants                           # mutation testing (see Test-first below)
cargo deny check                                      # licenses, sources, advisories
cargo audit                                           # RUSTSEC advisories
```

### Local CI

The root [`justfile`](../justfile) mirrors the gates CI actually runs
([`cloudbuild/ci.yaml`](../cloudbuild/ci.yaml),
[`cloudbuild/security.yaml`](../cloudbuild/security.yaml),
[`cloudbuild/docs.yaml`](../cloudbuild/docs.yaml),
[`cloudbuild/geiger.yaml`](../cloudbuild/geiger.yaml), and
[`rust.yml`](../.github/workflows/rust.yml)'s `build-and-test`/
`windows-smoke` jobs) so you can check whether a change would pass CI
before pushing, instead of finding out from a red PR check. Install
[`just`](https://github.com/casey/just#installation), then, from the repo
root:

```sh
just ci            # host-appropriate subset (Linux/macOS/Windows + security/docs/geiger)
just --list        # see every ci-* target and what it mirrors
```

Run an individual `ci-*` target (`just ci-linux`, `just ci-security`, ...)
to check one gate in isolation. The `keystore-backends` matrix (native
macOS Keychain/Windows Credential Manager/Linux Secret Service backends)
isn't mirrored here &mdash; it stays `workflow_dispatch`-only on GitHub Actions
by design; see `docs/RELEASE.md`'s pre-release checklist.

## Test-first discipline

Every bug fix PR MUST include a regression test that fails on the
fix's parent commit. The pattern that's worked across the recent
history:

1. Reproduce the bug as a failing test (`cargo t` shows it red).
2. Apply the fix.
3. Re-run; test goes green.
4. Commit test plus fix together so the test's failing state is preserved
   in the diff context of the fix.

Reviewers check this by running `git checkout <PR-parent> && cargo t
<new-test-name>` &mdash; if the new test passes at the parent, the test
doesn't actually demonstrate the bug.

For new features (not bug fixes), tests aren't required to fail at any
specific commit, but they MUST cover the documented behavior. Three
test classes earn their keep:

- **Example tests** (`#[test]`) &mdash; pin specific inputs/outputs; cite
  golden vectors where they exist.
- **Property tests** (`proptest!`) &mdash; encode round-trip invariants. The
  `serialize.rs` blob/commit round-trip and `chunker.rs` determinism
  property tests are the canonical examples.
- **Snapshot tests** (`insta::assert_snapshot!`) &mdash; pin human-readable
  output (CLI, JSON envelopes, formatted text). Update with
  `cargo insta review` after deliberate output changes.

For CLI black-box tests specifically (`mkit-cli`'s `tests/`), reach for
the right tool by what the test actually needs:

- **`Repo` builder** (`tests/common/mod.rs`) &mdash; the default for
  anything driving a real repo: sandboxed temp dir, fixed signing key,
  `.ok()`/`.run()` helpers, the invariant battery, and the conflict/
  fault-injection builders. Most CLI integration tests belong here.
- **`assert_cmd` + `predicates` + `assert_fs`** &mdash; simple black-box
  cases whose fluent `.assert().success().stdout(predicate!(...))` chain
  reads more directly than a manual `Output` + `assert!` pair (see
  `tests/blackbox_assert_cmd_demo.rs`). Not a replacement for `Repo` —
  reach for `Repo` first when a test needs its invariant battery or
  builders.
- **`trycmd`** (`tests/cmd/*.trycmd`, driven by `tests/cli_transcripts.rs`)
  &mdash; short, fully deterministic transcripts (exact error text, not
  just an exit code) where the fixture file doubles as human-readable
  documentation. Update with `TRYCMD=overwrite cargo test --test
  cli_transcripts` after a deliberate message change, same workflow as
  `cargo insta review`. Not for anything with a non-deterministic hash/
  timestamp, or for full `--help`/`version` output &mdash; those stay on
  `insta` (`help_snapshot.rs`).

Run `cargo-mutants` locally against `mkit-core` and `mkit-attest` to
surface logic that no test pins down; aim to add tests that close those
gaps over time. `mutants.yml`'s `mutants-diff` job also runs this
automatically on every PR (`--in-diff`, scoped to `mkit-core`/
`mkit-attest`/`mkit-keystore`'s changed lines), plus a weekly full sweep
of `mkit-attest` alone — see that workflow's header comment for why the
full sweep doesn't (yet) cover `mkit-core`/`mkit-keystore`.

Optional but recommended for repeated local rebuilds:

```sh
cargo install sccache                          # compile-output cache
export RUSTC_WRAPPER=sccache                   # in your shell rc / .envrc
```

CI does not currently use sccache (the GitHub Actions cache backend
that powers `SCCACHE_GHA_ENABLED` has had transient outages this
project doesn't want to gate the build on). Local sccache still gives you faster
incremental rebuilds.

### Workspace layout

The Cargo workspace root is `rust/Cargo.toml`. Most crates live under
`rust/crates/`. Three reference signers live outside the `rust/`
tree under `contrib/signers/`, which is its own separate Cargo
workspace (`contrib/signers/Cargo.toml`) &mdash; they are deliberately NOT
members of the `rust/` workspace and do NOT participate in
`cargo {test,clippy,build} --workspace` from `rust/`. Build and test
them on their own, for example `cargo test` from `contrib/signers/`. The
split exists because out-of-tree workspace members break release-plz
publishing (#225), as noted in `rust/Cargo.toml`.

```
rust/
  Cargo.toml                  # [workspace] root
  crates/
    mkit-attest/
    mkit-cli/
    mkit-core/
    mkit-keystore/
    mkit-rpc/                 # Protobuf-defined wire protocols
    mkit-transport-connect/   # ConnectRPC client for mkit.transport.v1.TransportService;
                               #   used for mkit+https:// / mkit+http://
    mkit-transport-enc/       # mkit+enc:// no-OpenSSH encrypted transport
    mkit-transport-file/
    mkit-transport-http/
    mkit-transport-memory/
    mkit-transport-s3/
    mkit-transport-ssh/
    mkit-wasm/
contrib/signers/
  Cargo.toml                  # separate [workspace] root (NOT rust/)
  mkit-sign-file/             # member of contrib/signers/ workspace
  mkit-sign-ctap/             # member of contrib/signers/ workspace
  mkit-sign-tpm/              # member of contrib/signers/ workspace
```

Run `cargo --workspace` commands from `rust/` for the core crates:
`(cd rust && cargo nextest run --workspace)`. The signers are built
and tested separately from `contrib/signers/`.

### Protobuf schemas (buf)

The repo-root [`buf.yaml`](buf.yaml) is a [Buf](https://buf.build) v2
workspace covering every `.proto` tree in the repo:

```
buf.yaml (repo root)
├── rust/crates/mkit-rpc/proto        → mkit.rpc.v1 (+ .signer, .ssh, .verify)  [wire-frozen, SPEC-RPC]
├── apps/repo-worker/proto            → mkit.repo.v1
└── proto                             → mkit.transport.v1  [SPEC-TRANSPORT-CONNECT]
```

Directory layout matches package name (`mkit/rpc/v1/common.proto` for
package `mkit.rpc.v1`, `mkit/rpc/v1/signer/signer.proto` for package
`mkit.rpc.v1.signer`, etc.) so `buf lint`'s `PACKAGE_DIRECTORY_MATCH`
rule holds with no directory exception. Run from the repo root:

```sh
buf lint                                          # schema style/consistency
buf breaking --against '.git#branch=main'         # wire-compat vs. main
```

`mkit-rpc`'s protos are wire-frozen (v1 SPEC-RPC promise) &mdash; `buf
breaking`'s `FILE` category is the mechanical enforcement of that
promise; a genuine break means a new `signer2.proto` /`ssh2.proto`
sibling, not an edit in place. Generated Rust is vendored, not built
fresh from `.proto` &mdash; see `rust/crates/mkit-rpc/README.md` and
`scripts/regen-rpc-proto.sh` / `scripts/regen-repo-proto.sh` after
schema edits.

## Continuous integration

Workflows live in `.github/workflows/`. Display names are prefixed by purpose so
the Actions tab self-groups: `CI:` (build/test/lint/coverage/docs), `Security:`,
`Nightly:` (scheduled fuzzing), `Release:`, and `Meta:` (workflow lint).

| Workflow | Triggers | Notes |
|----------|----------|-------|
| `CI: Rust` | every PR; push `main`¹ | Linux build/test/clippy/fmt run on every PR (Cloud Build, see below). `rust.yml` adds: a macOS build-and-test leg on `push` to `main` only (10x runner cost, so not on every PR); a Windows smoke build+`cargo test --lib` on every PR (2x cost); and a 3-OS `keystore-backends` matrix that stays `workflow_dispatch`-only (see `docs/RELEASE.md`'s pre-release checklist). A `ci-gate` job aggregates all three into one required check. |
| `CI: Coverage` | every PR; push `main`¹ | `cargo-llvm-cov` → Codecov |
| `CI: Docs` | every PR | rustdoc broken-link gate (`-D warnings`) |
| `CI: Web` / `CI: MCP` | push/PR, path-filtered | run only when `apps/web/**` / `apps/mcp/**` change; each has an always-run gate job so a required check is always present |
| `CI: Third-party notices` | push/PR, path-filtered | runs `cargo about generate` against `rust/about.toml`'s accepted-license policy when the dependency graph changes; same tool `Release: *`'s `third-party-notices` job uses to build `THIRD-PARTY-NOTICES` |
| `CI: Buf` | every PR; push `main` | `buf lint` plus `buf breaking` (via `bufbuild/buf-action`) against the repo-root `buf.yaml` workspace (all three proto modules). Unconditional &mdash; no path filter, no skip gate &mdash; so it can never read "skipped" as green. |
| `Security: Rust` | PR, weekly, dispatch | `cargo audit` plus `cargo deny` |
| `Nightly: Fuzz` | scheduled, dispatch | fuzz harnesses |
| `Release: *` | signed `v*` tag (or dispatch) | crates.io publish, binaries, MCP corpus seed |
| `Meta: Actionlint` | push/PR | workflow lint |

¹ Path-filtered: a docs/MCP/web-only push to `main` doesn't trigger the full
Rust matrix or coverage.

The toolchain plus protoc plus cargo-cache setup shared by the Rust CI workflows is
the `.github/actions/setup-rust` composite action &mdash; bump the pinned action SHAs
or the protoc version there, in one place, rather than per workflow.

## Commit conventions

This project uses [Conventional Commits](https://www.conventionalcommits.org/) with
the scopes you'll see in `git log`. Common scopes: `core`, `attest`,
`cli`, `transport`, `wasm`, `ci`, `docs`, `release`, `fuzz`, `metadata`.

Examples from the repo:

```
fix(core): correct off-by-one in pack index reader
ci(release): publish mkit-wasm to npm on every v*.*.* tag
docs(install): refresh README install section + add docs/INSTALL.md
```

Subject ≤ 72 chars, imperative mood, lowercase after the scope. The
body explains **why**, not what; `git diff` covers the latter.

## What to expect in review

Every PR is held to:

1. **Tests pass** &mdash; `cargo test --workspace` on Linux plus macOS.
2. **No new clippy warnings** &mdash; `clippy --all-targets -- -D warnings`.
3. **Formatted** &mdash; `cargo fmt --check`.
4. **No new RUSTSEC advisories** &mdash; `cargo deny check advisories`.
5. **Spec changes are versioned** &mdash; anything that mutates an on-disk
   or wire format requires a corresponding `docs/specs/SPEC-*.md` change
   and, where applicable, a new golden vector under
   `rust/tests/golden/`.
6. **Crypto / key-handling changes** require a second reviewer and an
   explicit threat-model note in the PR description.
7. **Public API changes** require a CHANGELOG entry under the
   "Unreleased" heading and a SemVer impact note.

## What this project will not merge

- Code that handles private key material without `Zeroize` on
  ephemeral buffers.
- New `unsafe` blocks without a `// SAFETY:` comment naming the
  invariants and a justification for not using a safe alternative.
- Dependencies pulled from a fork or a non-`crates.io` source without
  prior discussion in an issue.
- Network code with `.unwrap()` / `panic!()` on attacker-controlled
  inputs.
- `// TODO: …` markers without an associated GitHub issue.
- Changes to the release pipeline (`.github/workflows/release.yml`,
  `docs/RELEASE.md`) without a follow-up dry-run.

## Filing issues

Bug reports should include:

- mkit version (`mkit version`).
- OS plus arch (`uname -a` on \*nix).
- Minimal reproduction (if it touches on-disk state, attach the repo
  with private material redacted).
- Expected vs. observed behavior.

Feature requests should include the user story and at least one
alternative you considered.

## Pull request checklist

Before requesting review:

- [ ] `cargo fmt --check` clean
- [ ] `cargo clippy --all-targets -- -D warnings` clean
- [ ] `cargo t` (or `cargo nextest run --workspace`) passes
- [ ] CHANGELOG entry under "Unreleased" if user-visible
- [ ] Spec plus golden vector updated if format changed
- [ ] No new dependencies added without justification in the PR body
- [ ] If this PR fixes a bug, a regression test demonstrating it lives
      in this diff (see "Test-first discipline" above)

## License of contributions

mkit follows the Rust-ecosystem convention of **inbound = outbound**:
unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this repository, as defined in the Apache
License 2.0, shall be dual-licensed as `MIT OR Apache-2.0` (without any
additional terms or conditions), matching the project's outbound license.

Do not include third-party code unless it is already licensed under
MIT, Apache-2.0, BSD-2/3-Clause, ISC, Zlib, or another permissive
license compatible with the project's dual-license &mdash; and preserve attribution.

This project does not require a Developer Certificate of Origin (DCO) sign-off or a
Contributor License Agreement (CLA).
