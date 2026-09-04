# Invariants

Properties that must always hold across the mkit monorepo, outside any
single crate or spec. Each entry states the invariant, why it matters, and
what breaks when it is violated. A regression test enforces each one; find
it by the file path listed under "Enforced by".

## Dependabot ecosystem matches the lockfile format

**Always:** every directory with its own lockfile has a `.github/dependabot.yml`
update entry whose `package-ecosystem` matches that lockfile's format
(`cargo` for `Cargo.lock`, `bun` for `bun.lock`, `npm` for `package-lock.json`).
Every composite GitHub Action under `.github/actions/*/action.yml` has its
own `github-actions` entry, because a `directory: "/"` entry only scans
`.github/workflows/`.

**Because:** Dependabot edits only the manifest for the ecosystem it thinks
it is running. An `npm` entry pointed at a `bun`-only directory edits
`package.json` but never touches `bun.lock`. CI installs with
`bun install --frozen-lockfile`, which rejects a manifest whose lockfile did
not change with it.

**If violated:** every PR Dependabot opens for that directory fails CI on
the frozen-lockfile install step and gets closed unmerged, silently, on a
recurring weekly schedule. See `apps/web`'s Dependabot PRs #921, #922, #923,
#931, and #934 — all closed unmerged for exactly this reason before this
invariant was enforced.

**Enforced by:** `scripts/check-dependabot-coverage.sh`, run by the
"Meta: actionlint" workflow on any change to `.github/dependabot.yml`,
`.github/workflows/**`, or `.github/actions/**`.

## Single crypto-stack version across workspaces

**Always:** `ed25519-dalek` and `sha2` are pinned to the same
Cargo-semver-compatible version (for a `0.y.z` crate, `y` is the breaking
component; for `x.y.z` with `x >= 1`, `x` is) in every Cargo workspace that
declares them: `rust/`, `contrib/signers/`, and the `apps/*-worker`
standalone packages.

**Because:** several crates independently re-verify signatures/digests the
same byte-for-byte way another crate already does — `mkit-wasm`'s raw
Ed25519 exports vs. `mkit-core::sign`, and every `apps/*-worker`'s
write-envelope strict-verify vs. `mkit-core`'s own `verify_strict` call —
and the golden-vector and cross-impl-parity tests (e.g.
`mkit-wasm::ed25519::cross_impl_parity_with_dalek`,
`mkit-keystore`'s `*_matches_golden_vectors`) assert that stays true. A
drifted major/breaking version of the same crypto crate across workspaces
can silently diverge in wire-visible behavior (ed25519-dalek 2->3 dropped
the `std` feature and moved error types to `core::error::Error`; a future
bump could change verification semantics) with nothing forcing every
workspace to move together.

**If violated:** nothing fails to compile — each workspace has its own
lockfile, so two incompatible versions of the same crypto crate can coexist
silently. A behavior difference between them (a stricter/laxer signature
check, a different digest padding) would only surface as a hard-to-trace
cross-service inconsistency, not a build error.

**Enforced by:** `scripts/check-crypto-stack-version.sh`, run by the
"Meta: crypto-stack version" workflow on any change to a `Cargo.toml` under
`rust/`, `contrib/signers/`, or `apps/`.

## A live `mkit serve` is detectable by local worktree commands

**Always:** every live `mkit serve` process holds a **shared** kernel
lock (`mkit_core::repo_lock::acquire_shared`) on `<common_dir>/serve.lock`
for its entire lifetime, across all three of its modes (stdin SSH-frame,
`--listen-enc`, `--http`). Every command that acquires `worktree.lock`
or `worktrees.lock` (`mkit-cli`'s `acquire_worktree_lock` /
`acquire_worktrees_registry_lock`) immediately probes that same
`serve.lock` non-blocking-exclusive (`mkit_core::repo_lock::probe_exclusive`)
and, if it finds the lock busy, prints a warning to stderr naming the
served root before proceeding.

**Because:** `mkit-transport-file`'s only lock (`<root>/.mkit/refs/.lock`)
serializes file-transport instances against *each other*, not against
local worktree mutation or `gc` (SPEC-CONCURRENCY §3.1). Running `mkit
gc` or a worktree-mutating command directly against a root a live `mkit
serve` is also operating on is unsupported and uncoordinated; without
this invariant, nothing distinguishes that misuse from an ordinary,
safe invocation, and the failure (a `gc` sweep racing a concurrent
push's object write, or a lost ref update) surfaces only as
after-the-fact corruption with no diagnostic pointing at the cause.

**If violated:** a `gc` can silently sweep objects a concurrent `mkit
serve` client just uploaded, or a local commit/checkout can silently
lose a race against a client push — both without any warning ever
appearing, leaving an operator no reason to suspect the concurrent-serve
misconfiguration until data is already gone. This is detection only,
not coordination: a direct `mkit push mkit+file:///path` (bypassing
`mkit serve`) and a `serve` that starts *during* an already-in-flight
local critical section both remain undetected — see SPEC-CONCURRENCY
§3.1 for the full statement of what this warning does and does not
cover.

**Enforced by:** `mkit-cli/tests/serve_guard.rs`.
