# Contributing to mkit

Thanks for taking the time. mkit is a security-sensitive project — a
Git-like content-addressed VCS with cryptographic attestations — so
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
| Transports | `rust/crates/mkit-transport-{memory,file,http,s3,ssh}/` |
| External signers (TPM, SE, CTAP, file) | `contrib/signers/` |
| On-disk + wire format specs | `docs/SPEC-*.md` |
| Golden vectors | `rust/tests/golden/` |
| Fuzz harness | `rust/fuzz/` |

## Development setup

Requires **Rust 1.95** (auto-installed by rustup from
`rust/rust-toolchain.toml`).

```sh
cd rust
cargo build --workspace
cargo test --workspace
cargo fmt --check                            # CI-enforced
cargo clippy --all-targets -- -D warnings    # CI-enforced
```

Useful extras:

```sh
cargo install cargo-deny cargo-audit cargo-nextest    # supply-chain + faster tests
cargo deny check                                      # licenses, sources, advisories
cargo audit                                           # RUSTSEC advisories
cargo nextest run --workspace                         # what CI runs (faster + structured)
../scripts/verify-rename.sh                           # rename-gate (CI-enforced)
```

Optional but recommended for repeated local rebuilds:

```sh
cargo install sccache                          # compile-output cache
export RUSTC_WRAPPER=sccache                   # in your shell rc / .envrc
```

CI uses `sccache` with the GitHub Actions cache backend; setting it
locally just gives you the same speedup across branches.

### Workspace layout

The Cargo workspace root is `rust/Cargo.toml`. Most crates live under
`rust/crates/`. Three reference signers live outside the `rust/`
tree under `contrib/signers/` because they are integration references
rather than core crates; they are still workspace members and
participate in `cargo {test,clippy,build} --workspace`.

```
rust/
  Cargo.toml                  # [workspace] root
  crates/
    mkit-core/
    mkit-attest/
    mkit-cli/
    mkit-rpc/                 # buffa-defined wire protocols
    mkit-transport-{memory,file,http,s3,ssh}/
    mkit-wasm/
contrib/signers/
  mkit-sign-file/             # workspace = "../../../rust"
  mkit-sign-ctap/             # workspace = "../../../rust"
  mkit-sign-tpm/              # workspace = "../../../rust"
```

Run `cargo` commands from `rust/` so the workspace root resolves:
`(cd rust && cargo nextest run --workspace)`.

## Commit conventions

We use [Conventional Commits](https://www.conventionalcommits.org/) with
the scopes you'll see in `git log`. Common scopes: `core`, `attest`,
`cli`, `transport`, `wasm`, `ci`, `docs`, `release`, `fuzz`, `metadata`.

Examples from the repo:

```
fix(metadata): bump inter-crate version pins 0.1 → 0.2 to match workspace
ci(release): publish mkit-wasm to npm on every v*.*.* tag
docs(install): refresh README install section + add docs/INSTALL.md
```

Subject ≤ 72 chars, imperative mood, lowercase after the scope. The
body explains **why**, not what; `git diff` covers the latter.

## What to expect in review

Every PR is held to:

1. **Tests pass** — `cargo test --workspace` on Linux + macOS.
2. **No new clippy warnings** — `clippy --all-targets -- -D warnings`.
3. **Formatted** — `cargo fmt --check`.
4. **Rename-gate green** — `scripts/verify-rename.sh`.
5. **No new RUSTSEC advisories** — `cargo deny check advisories`.
6. **Spec changes are versioned** — anything that mutates an on-disk
   or wire format requires a corresponding `docs/SPEC-*.md` change
   and, where applicable, a new golden vector under
   `rust/tests/golden/`.
7. **Crypto / key-handling changes** require a second reviewer and an
   explicit threat-model note in the PR description.
8. **Public API changes** require a CHANGELOG entry under the
   "Unreleased" heading and a SemVer impact note.

## What we will not merge

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
  `docs/release/`) without a follow-up dry-run.

## Filing issues

Bug reports should include:

- mkit version (`mkit version`).
- OS + arch (`uname -a` on \*nix).
- Minimal reproduction (if it touches on-disk state, attach the repo
  with private material redacted).
- Expected vs. observed behaviour.

Feature requests should include the user story and at least one
alternative you considered.

## Pull request checklist

Before requesting review:

- [ ] `cargo fmt --check` clean
- [ ] `cargo clippy --all-targets -- -D warnings` clean
- [ ] `cargo test --workspace` passes
- [ ] `scripts/verify-rename.sh` passes
- [ ] CHANGELOG entry under "Unreleased" if user-visible
- [ ] Spec + golden vector updated if format changed
- [ ] No new dependencies added without justification in the PR body

## License

By contributing, you agree that your contributions will be dual-licensed
under MIT OR Apache-2.0, matching the rest of the repository. There is
no CLA; submitting a PR is taken as your assertion that you have the
right to license the contribution under those terms.
