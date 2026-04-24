# Changelog

All notable changes to mkit are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed — WIRE/SIGNATURE BREAK

- **`sign::domain_digest` now includes a 2-byte little-endian length
  prefix** in front of the domain label, so the hash input is
  `len_le16(domain) || domain || signing_bytes` instead of
  `domain || signing_bytes`. Closes a latent ambiguity where two
  distinct `(domain, signing_bytes)` splits could in principle
  produce identical hash input (finding H4). Commit and remix
  signatures produced by v0.1.0 **will NOT verify under this
  change**, and vice versa. Ship this in a coordinated release —
  there are no shipped artefacts to migrate, but downstream signers
  and pre-built test vectors must be regenerated.
- Golden signing hashes (`rust/crates/mkit-core/tests/golden_sign.rs`
  `signing_hashes_are_stable`) were re-pinned for the new digest
  shape.

## [0.1.0] — 2026-04-24

Initial release.

### Added

- **Content-addressed object store.** BLAKE3-named raw objects stored
  at `.mkit/objects/<dd>/<hex62>`. Atomic writes (temp-file + fsync +
  rename + parent-dir fsync on Unix). Hash verify-on-read. 1 GiB cap
  per object. Idempotent: identical bytes → identical path.
- **Object format v1.** Six object types with a shared prologue
  `[type][MKT1][schema_version=0x01]`: `blob`, `tree`, `commit`,
  `remix`, `chunked_blob`, `delta`. All little-endian, `u64`
  timestamps. Full wire contract documented in `docs/SPEC-OBJECTS.md`.
- **Content-defined chunking (FastCDC v1).** Frozen seed `MKITFCDC`,
  three-mask (`0x1FFFF` / `0xFFFF` / `0x7FFF`) boundary selection,
  16 KiB / 64 KiB / 256 KiB parameter set. Documented in
  `docs/SPEC-FASTCDC.md`.
- **Delta encoding.** Minimal COPY/INSERT instruction stream per
  `docs/SPEC-DELTA.md`. Decoder is attacker-tolerant: result-length
  pre-allocation is bounded against the stream size, so a 9-byte
  header claiming `result_len = u32::MAX` cannot trigger a 4 GiB
  allocation.
- **Packfile format.** `MKIT` magic + version 1 + BLAKE3 trailer,
  base-before-delta ordering, ≤10M entries / ≤4 GiB payload caps.
  Documented in `docs/SPEC-PACKFILE.md`.
- **Refs + index + worktree.** 65-byte ref wire (lowercase hex64 +
  `\n`), CAS variants `any` / `missing` / `match(H)`. Index magic
  `MKIX`, atomic writes. `.mkitignore` glob matcher. Repo lock via
  `std::fs::File::lock_exclusive`. Symlinks pointing outside the repo
  root are rejected during worktree traversal.
- **High-level history ops.** `diff`, `graph`, `merge`,
  `cherry_pick`, `rebase` (with `--abort` / `--continue`), `bisect`
  (with `skip` exclusion set), `blame`, `stash` (save / list / pop /
  drop / show), `restore` (including sparse patterns and full
  worktree materialization).
- **Ed25519 signing (SPEC-SIGNING).** Domain-prefixed BLAKE3 digests:
  `BLAKE3("mkit.commit\x00" ‖ signing_bytes)` and
  `BLAKE3("mkit.remix\x00" ‖ signing_bytes)`. `verify_strict` /
  ZIP-215 semantics — rejects non-canonical `R`, high-`s`, and
  non-canonical public-key encodings so all honest verifiers reach
  the same verdict on a given signature. RFC 8032 known-answer test.
  Keys live at `.mkit/keys/default.key` as the raw 32-byte seed,
  mode 0600 enforced on Unix.
- **Native attestation subsystem (`mkit-attest`).**
  - RFC 8785 JCS canonical-JSON encoder (hand-rolled; the spec's
    member-sort and escape rules don't round-trip through
    `serde_json`).
  - in-toto v1 Statement encoder with commit-subject binding.
  - DSSE envelope encode/decode + PAE builder.
    `attestationId = BLAKE3(envelope_bytes)` (no trailing newline
    — preserves the content-addressing invariant).
  - Signer trait with three implementations: `repo-key` (Ed25519 via
    the commit-signing key), `external` (JSON-over-stdin/stdout
    subprocess for KMS / HSM delegation), `sigstore` (scaffold; full
    Rekor / Fulcio walk to follow).
  - Trust-root registry + per-signature verification; attestation
    store at `.mkit/attestations/<commit-hex>/<keyid-hex>.dsse.json`.
- **Protocol + transports.** Seven-verb `Transport` trait
  (`upload_pack`, `download_pack`, `pack_exists`, `write_ref`,
  `update_ref`, `read_ref`, `list_refs`) with a shared error
  taxonomy, SSH wire framing (`OP_HELLO` first frame, 16 MiB payload
  cap), and retry backoff (5 attempts, 1–300 s exponential).
  Implementations for:
  - `mkit+memory://` — HashMap-backed, for tests.
  - `mkit+file://` — local filesystem, atomic CAS on POSIX via
    `link(2)` for the `Missing` variant.
  - `mkit+http://` / `mkit+https://` — reqwest + rustls, blocking.
    Bearer `MKIT_API_TOKEN` auth, `If-Match` / `If-None-Match` CAS,
    429 / 5xx retried via the shared backoff.
  - `mkit+s3://` — hand-rolled AWS SigV4 signer + R2 endpoints.
    MD5-of-wire ETag CAS. Creds from `MKIT_R2_ACCESS_KEY_ID` /
    `MKIT_R2_SECRET_ACCESS_KEY`.
  - `mkit+ssh://` — delegates host-key checking, `~/.ssh/config`,
    agent integration, and `ProxyCommand` to the system `ssh(1)` via
    `std::process::Command`. No async runtime, no bundled SSH crypto.
- **CLI.** 30 subcommands wired from `mkit-cli` to the library crates:
  `init`, `keygen`, `hash`, `cat`, `tree`, `add`, `rm`, `status`,
  `commit` (with `$EDITOR` / `$GIT_EDITOR` template fallback and a
  `--author` override), `log`, `branch`, `tag`, `checkout` (with
  worktree materialization), `diff`, `verify`, `config`, `remote`,
  `push` / `pull` / `fetch` (transfer full reachable object set, not
  just ref pointers), `clone`, `merge`, `cherry-pick`, `rebase`,
  `bisect`, `stash`, `blame`, `serve`, `sparse-checkout`, `version`,
  `help`. `mkit version` emits exactly `mkit <X.Y.Z>\n` — snapshot
  tested and a CI step asserts the byte-exact contract on every push.
- **Bounded fuzz harnesses.** `cargo-fuzz`-compatible targets for
  `delta::decode`, `pack::PackReader::read`, and
  `serialize::deserialize`. Six guardrails per `docs/FUZZ.md`: ≤100
  iterations, ≤64 KiB input, bounded per-op allocations, 100 ms
  per-iteration wall-clock cap, no unbounded loops, seeded PRNG.
- **Supply chain.** CI matrix on ubuntu-latest + macos-latest:
  `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
  `cargo test --workspace --locked`, rename gate
  (`scripts/verify-rename.sh`), and a `mkit version` byte-exact
  assertion. Weekly `cargo audit` + `cargo deny` (advisories, license
  allow-list, wildcards, sources). Two-pass reproducible-build smoke
  test (SHA256 diff under `-C codegen-units=1 -C strip=symbols`).
  Release workflow cross-compiles four targets (aarch64-apple-darwin,
  x86_64-apple-darwin via cross, x86_64-unknown-linux-gnu,
  aarch64-unknown-linux-gnu), cosign keyless OIDC signatures, and a
  CycloneDX SBOM.

[Unreleased]: https://github.com/officialunofficial/mkit/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/officialunofficial/mkit/releases/tag/v0.1.0
