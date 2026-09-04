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

## Single commonware release train across every manifest and lockfile

**Always:** every `commonware-<name>` dependency — in `rust/Cargo.toml`,
every `rust/crates/*/Cargo.toml`, `rust/fuzz/Cargo.toml`,
`contrib/signers/Cargo.toml`, and the `apps/*-worker` manifests — pins the
exact same version string (e.g. `=2026.9.0`, not merely a compatible
range), AND every `Cargo.lock` in those same trees that contains a
`commonware-*` package resolves to that same version.

**Because:** the commonware crates (`-storage`, `-cryptography`,
`-runtime`, `-coding`, `-codec`, `-parallel`, `-utils`, `-stream`,
`-invariants`) ship as one coordinated release; mkit's on-disk formats
(the history-journal MMR, the BLS threshold derivation) and wire
compatibility depend on the exact same version being linked everywhere a
crate touches them. A manifest bump without a matching `cargo update` in
every workspace leaves the *text* aligned while the *lockfile* — what
actually gets compiled — stays on the old train, silently defeating the
single-version intent this file's `check_crate` (ed25519-dalek/sha2)
already establishes.

**If violated:** nothing fails to compile — each workspace has its own
lockfile, so `rust/` can be on `2026.9.0` while `contrib/signers/` is still
locked to `2026.7.1`, undetected until an on-disk format or golden-vector
test run against the stale workspace disagrees with one run against the
bumped one.

**Enforced by:** `scripts/check-crypto-stack-version.sh`'s
`check_commonware_family`, run by the "Meta: crypto-stack version"
workflow (trigger paths include `**/Cargo.lock` under `rust/`,
`contrib/signers/`, and `apps/*`, not just `Cargo.toml`).

## History-journal page size and peak-bagging strategy are format-frozen

**Always:** `CommitHistory::open_at`'s journaled-MMR config
(`crates/mkit-core/src/history.rs`, `init_journaled`'s `JConfig`) keeps
these three parameters exactly as they are today: `items_per_blob =
4096`; the `CacheRef::from_pooler` page size passed as `NZU16!(4096)`
(a *logical* page size — the on-disk *physical* page is 4108 bytes,
logical + `commonware_runtime::buffer::paged::CHECKSUM_SIZE` = 12);
and `HISTORY_BAGGING = Bagging::ForwardFold`. In particular, do not
"upgrade" the page size to
`commonware_runtime::buffer::paged::page_size(4096)` (= 4084,
commonware 2026.9.0's own *aligned* logical size, chosen so 4084 + 12
divides the OS page evenly) — that is exactly the destructive change
this invariant exists to block. None of the three may change without
a new on-disk format version and an explicit migration.

**Because:** commonware-runtime 2026.9.0 documents blob layout and page
size as destructive format parameters — changing them truncates an
existing journal's blobs to empty on the next open rather than
reinterpreting the bytes. A page-size or bagging-strategy change is
therefore not a config tweak; it silently discards every already-written
`history/<branch>/` journal on the next `mkit` invocation that touches it.

**If violated:** every existing branch's history journal truncates (or its
stored root/proofs stop matching a fresh replay) the next time
`CommitHistory::open_at` runs against it after the change ships — a silent
data-loss-on-upgrade bug, not a build or test failure, because the bug
only manifests against pre-existing on-disk state a CI run never has.

**Enforced by:** nothing today catches a page-size or bagging change
before it ships. `crates/mkit-core/src/history.rs`'s
`open_at_root_matches_live_mem_root`-family tests and
`open_at_round_trip_100_commits` / `open_at_prove_after_reopen` build
and read back a journal within the SAME test run (same build, same
process) — a page-size or bagging change that is internally consistent
passes them just as well as the frozen values do, because there is no
fixture written by a *previous* build for them to reopen. Catching a
regression here needs a fixture generated by a build that predates the
change (a previously-written `history/<branch>/` journal directory
committed to the repo, reopened by the current build) — see MKIT-4 for
why that fixture has not been added yet.

## The shared commonware Context is post-shutdown after `open_at`

**Always:** `mkit-core`'s history module drives the shared
`commonware_runtime::tokio::Context` it bootstraps (see
`JournaledBackend.ctx` in `crates/mkit-core/src/history.rs`) only
through mkit's OWN executor (`Executor::block_on` — ambient
`tokio::task::spawn_blocking` inside commonware's blob/journal calls
runs there). Nothing on the journaled-history path ever calls
`commonware_runtime::Spawner::spawn` (or anything that internally
spawns, e.g. `Handle`/`Signal` machinery) on that shared `Context` or
a clone/child of it.

**Because:** commonware-runtime 2026.9.0's
`commonware_runtime::tokio::Runner::start` aborts its task tree,
closes task admission, and drops its inner tokio runtime *before*
returning control to the closure passed to `start` — so the `Context`
`bootstrap_commonware_context` returns (and therefore every
`JournaledBackend.ctx` clone) is already post-shutdown by the time
`CommitHistory::open_at` returns. At the previous pinned train
(`2026.7.1`), `Executor` was an owned `Runtime` and the Context's
inner `Arc<Executor>` genuinely kept that runtime alive for as long as
a clone survived; that was true then and is false now. The `Context`
is still held for the whole `CommitHistory` lifetime, but only for its
`.hold` flock, buffer pools, and metrics registry — not a runnable
executor.

**If violated:** a `Spawner::spawn` call through this `Context` is
silently admitted into an already-closed task tree and resolves to
`Err(commonware_runtime::Error::Closed)` — the spawned work never
runs, with no panic and no I/O error at the call site. A future change
that tried to route an fsync or a blob write through `ctx.spawn(...)`
instead of mkit's own executor would be a silent durability hole:
`CommitHistory::append`/`sync` would return `Ok` (or a channel-recv
error, depending on how the dropped work was awaited) without the
write having actually happened.

**Enforced by:** `crates/mkit-core/src/history.rs`'s
`shared_commonware_context_is_post_shutdown_and_must_not_be_spawned_through`,
which spawns a no-op task through `JournaledBackend.ctx` and asserts
it resolves to `Err(Error::Closed)`, then appends/reopens through the
same handle to confirm the journaled path itself is unaffected.

## One commonware storage Context per history dir per process

**Always:** every in-process `CommitHistory::open_at` call against the
same `<mkit_dir>/history` directory shares one bootstrapped
`commonware_runtime::tokio::Context` (cached by canonicalized history
directory path, released once the last handle referencing it drops) —
`open_at` never bootstraps a second, independent `Context` against a
history directory that already has a live one in this process.

**Because:** commonware-runtime 2026.9.0 added a per-`storage_directory`
advisory `.hold` file lock, taken (and blocked on) inside
`Storage::new`/`Runner::start` and held for as long as any clone of that
bootstrap's storage handle is alive. Two independent bootstraps against
the same directory — e.g. opening `CommitHistory` for two different
branches under the same `mkit_dir`, which both resolve to the same
`history/` storage directory — take two independent, mutually exclusive
flocks on the same file. commonware's `Storage::new` blocks (with only a
`tracing::warn!`, which mkit-cli does not surface — no subscriber is
installed) rather than erroring, so the second bootstrap in the same
process deadlocks forever instead of failing fast.

**If violated:** any code path that opens more than one branch's history
in one process (`mkit branch -d`/`-m` cleanup, multi-branch CLI commands,
a long-running `mkit serve` handling several branches, or simply two
sequential `CommitHistory::open_at` calls in a test) hangs indefinitely
instead of returning or erroring.

**Related cross-process gotcha (not fixed by the above, by design):**
the shared-`Context` cache only dedupes bootstraps *within one process*.
A live `CommitHistory` handle held by a test or long-running process
still blocks a *different* process's `open_at` against the same
`history/` directory — including a CLI subprocess spawned by that same
test. `crates/mkit-cli/tests/history_mmr_branch_lifecycle.rs`'s
`branch_rename_destroys_the_old_names_journal` hit exactly this after
the MKIT-2 bump: it kept an in-process `CommitHistory` handle alive
across several subsequent `mkit` subprocess invocations on the same
repo, and the second subprocess's `open_at` blocked forever on the
first (in-process) handle's still-held lock. Fixed by scoping the
handle to drop before the next subprocess call — the general rule for
any test mixing in-process `CommitHistory::open_at` with subprocess
`mkit` invocations against the same repo.

**Enforced by:** `crates/mkit-core/src/history.rs`'s
`two_branches_open_concurrently_in_one_process_does_not_block`, plus
`open_at_distinct_branches_have_distinct_roots` and
`destroy_of_one_branch_does_not_touch_a_sibling_branch`, all wrapped in
that module's `assert_completes_within` helper so a regression here is a
test *failure* (bounded timeout) rather than a hung `cargo test` binary.
The cross-process gotcha itself is enforced only by
`branch_rename_destroys_the_old_names_journal` no longer hanging (no
timeout wrapper on `mkit-cli`'s integration tests today).

## commonware `Strategy` cannot be spied on from outside commonware-parallel

**Always:** `crates/mkit-core/src/pack_shard.rs`'s test suite does not
attempt to assert that a caller-supplied `commonware_parallel::Strategy`
was *invoked* by the encode/decode core (only that a real, non-default
strategy compiles against the generic entry points and round-trips
correctly — see `round_trip_with_explicit_parallel_strategy`).

**Because:** commonware-parallel 2026.9.0 made `Strategy` impossible to
implement from outside the `commonware-parallel` crate itself:
`Strategy::manual` must return a `Manual<Self>`, and `Manual`'s fields are
private with no public constructor left (`Manual::new` was removed). The
`CountingStrategy` spy this test module used to define — an `impl
Strategy` that counted `fold_init` calls to prove the supplied strategy
was genuinely exercised, not merely accepted and discarded — can no
longer be written.

**If violated:** re-adding an external `impl Strategy` (e.g. to restore
the invocation-count assertion) will not compile against the pinned
commonware-parallel train; if it is somehow worked around, treat the
resulting test as unable to prove what its name claims.

**Enforced by:** `crates/mkit-core/src/pack_shard.rs`'s
`round_trip_with_explicit_parallel_strategy` (compiles + round-trips a
real `Rayon` strategy) as the remaining guard; the comment block above it
records why the invocation-count assertion cannot be rebuilt.

## Windows is not a build, test, or release target

**Always:** no workflow, action, `justfile` recipe, crate manifest, or
installer targets Windows — no `windows-latest` / `pc-windows-msvc` CI
runner, no `backend-windows-credential` / `windows-credential` keystore
feature, no `install.ps1` or Scoop packaging, and no
`[target.'cfg(windows)'.dependencies]` stanza in any `Cargo.toml`.
`BackendKind` has no Windows Credential Manager variant.

**Because:** commonware-runtime 2026.9.0's storage-sync path calls
`libc::sync()` on every non-Linux target (`rust/crates/mkit-transport-enc`
depends on `commonware-runtime` unconditionally, and `mkit-core`'s
`history-mmr`/`sparse-checkout` features and dev-dependencies pull it in
too) — `libc::sync()` does not exist on `x86_64-pc-windows-msvc`, so the
workspace and its test suite no longer build there. Maintaining a Windows
CI/release leg that cannot actually build or test the workspace would ship
an untested binary, so Windows was dropped as a supported target (MKIT-6)
rather than worked around. Windows users run mkit under WSL, which uses
the Linux binary.

**If violated:** a reintroduced Windows CI leg goes red on every PR (the
workspace fails to build there); a reintroduced Windows release leg ships
a binary no test ever exercised; a reintroduced
`backend-windows-credential` feature reopens a semver-breaking
`BackendKind` variant on a published crate (`mkit-keystore`) without the
required major bump.

**Enforced by:** `scripts/check-no-windows-target.sh`, run by the
"Meta: actionlint" workflow on any change to the CI workflows, `justfile`,
crate manifests, `install.sh`, or the web app's installer-staging scripts.
`mkit-keystore`'s `windows_credential_backend_name_is_not_recognized` test
(`crates/mkit-keystore/src/lib.rs`) pins that `"windows-credential"` is an
unrecognized `BackendKind`/`KeyRef` backend string, not a fail-closed one.
