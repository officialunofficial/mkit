## Purpose

New Connect deployments shard metadata per (repository, ref) (D34) without extra configuration, and existing
single-sharded data fails closed rather than silently misrouting. Clients tolerate the eventual listings D34 produces.
Worker deployments roll up namespace quota like native ones. Operators can turn on write grants on both adapters from
configuration, never accepting a loopback audience or relying party in production.

## A. Fixed (do not change)

1. **R-123:** there is no single → D34 migration. Existing single data is refused under a mismatched mode, never
   converted or hidden.
2. **R-93:** the sharding mismatch guards (native `bind_sharding`, the Worker `sm` guard with 503) stay and fail
   closed.
3. **STC §7.9:** ListRefs is eventual, and a head and its packmap may appear at different ages.
4. **R-126 and 1.26a B.7:**
   - on Single addressing with D34, quota is per (signer, branch);
   - the namespace cap applies only under Multi;
   - rollups are kind 5, `QUOTA_ROLLUP`.
5. **The core defaults stay single:** `Sharding::default()`, `PipelineConfig::new` and `mkit serve`.
6. **SPEC-WRITE-GRANTS §3.2, §4.3 and §11:** `mkit-attest` validation (`VerifierConfig`, `AcceptedSchemes`,
   `RelyingParty`) is the authority. Add no adapter-only origin rules.
7. **`GrantConfig::new` and `GrantConfig::new_allowing_loopback` keep their signatures,** and the pipeline's existing
   grant refusals stay: no auth v2, not Multi+Owner, or an audience mismatch.
8. **R-154 and SPEC-SERVER §18:** Stage 1 adapters expose no indexed mode, leases, GC, takedown, receipts or admin.

## B. Decided (do not change)

### Part 1: WP-1.28c

- **B1. Native default (D1).**
  - `--sharding` becomes optional.
  - Absent means `d34` when `--meta sqlite:…`, otherwise `single`. fs-layout can't run D34.
  - An explicit `--sharding d34` without SQLite metadata stays a `USAGE` error.
- **B2. `restore` default (D3).** Absent `--sharding` takes the mode recorded in the export's marker. An explicit flag
  that disagrees with the marker is refused, as today.
- **B3. Existing single data (D2).**
  - No migration.
  - A native database recorded as `single`, or unmarked with data, under the new default fails with `CONFIG_ERROR`.
    The message tells the operator to pass `--sharding single`. Drop the stale "there is no migration yet".
  - A Worker with single data keeps answering 503 until `SHARDING="single"` is pinned.
  - Document both in the native and Worker READMEs, `docs/INVARIANTS.md` and a **breaking-change** CHANGELOG line.
  - Also document the quota side effect: under Single addressing, quota becomes per (signer, branch) by default.
- **B4. Worker default.**
  - `SHARDING` unset means `d34`.
  - `apps/vcs-worker/wrangler.jsonc` sets `"d34"`.
  - Update the adapter unit test.
  - `"single"` stays honoured.
- **B5. Client stale-listing rule (D5).** When a listed branch's packmap `ReadRef` returns `None`, strongly re-read
  `refs/heads/<name>`:
  - **Head also absent:** the listing is stale after a delete. Skip the branch and don't write its tracking ref. Say so
    at verbose level.
  - **Head present:** keep `PackmapMissing`. Head and packmap share a shard under D34, so this is corruption, not lag.
  - **Any transport error:** it stays an error and never becomes a skip.

  Update the doc comments on `fetch_objects_inner`. Add a normative client sentence to STC §7.9, plus a
  version-history row (newest first).
- **B6. Worker script and CI (D4).**
  - `scripts/vcs-worker-conformance.sh` defaults to `--sharding d34`, following the Worker.
  - `.github/workflows/workers.yml` runs the default (D34) phase and an explicit `--sharding single` phase, keeping
    the snapshot round-trip and single growth coverage.
  - Run the `ci-yaml` gate.
  - **CI still runs only on the final PR to main.** Don't enable anything on `feat/*`.
- **B7. Native tests.**
  - Tests that are about single-sharding behaviour pin `--sharding single`. The others accept D34.
  - Update the `server_basics` default assertion.
  - Add a `client_e2e` D34 variant: push, then clone and fetch, polling for the listing with a bound of
    `RELAY_LAG_BOUND_MS`. **Never** a fixed sleep.

### Part 2: WP-1.26b

- **B8. Worker kind-5 registration.**
  - Register `QuotaRollup` for kind 5 in the RefShard, NsCoordinator and RefStore arms of `timer_registry`.
  - Wrap it like `WorkerRelay`: a `Retry` fallback on a config error.
  - Use an explicit `max_per_tick` of **4** for rollups.
  - Update the Free-plan subrequest budget comment with the rollup's worst case, from `quota_rollup.rs`.
  - Kind 5 stays unknown in other DO kinds.
- **B9. Test registry.** Add `QuotaRollup` to the `x-mkit-test-run-timers` registry in `pipeline/faults.rs`.
- **B10. Quota cases under D34.** When `sharding_d34` is set, the `quota.*` cases:
  - exhaust **one** branch through a CAS chain on a single ref;
  - show a different branch is unaffected;
  - show that no replay row is allocated on rejection.

  `bytes_exhaustion` is unchanged. Add an in-process D34 quota baseline, since today the D34 baselines set
  `quota = None`.
- **B11. Script phases.**
  - Un-skip the Worker phase 2 under D34, and filter out `growth.` there with a skip reason naming WP-1.27. The
    partition-scoped stats hook arrives in 1.27.
  - **Add a Multi+D34 quota phase** (D10) that exercises the namespace cap across branches after a rollup. Force the
    rollup with clock skew and `run-timers`, using a quota window longer than R = 60 s.

### Part 3: WP-1.30b

- **B12. Shared core parsing.**
  - Add `policy::parse_relying_parties` next to #1210's namespace-allowlist parser. The entry form is
    `id=origin[,origin…]`, split on the **first** `=`.
  - For Worker vars, entries are separated by `;` or newlines. Blank entries and duplicate ids are refused.
  - Schemes go through `AcceptedSchemes::from_tokens`, comma-separated.
  - All validation beyond syntax is `mkit-attest`'s.
- **B13. Native flags.**
  - `--grant-schemes <tokens>`;
  - a repeatable `--webauthn-rp <id=origins>`;
  - `--unsafe-allow-loopback-grants`, which prints the existing `UNSAFE_BANNER` pattern and selects
    `new_allowing_loopback`.

  There is **no** grant-audience flag: the grant audience is the auth v2 `--audience`.
- **B14. Worker vars.**
  - `GRANT_SCHEMES` and `WEBAUTHN_RPS`.
  - `UNSAFE_LOOPBACK_GRANTS` is honoured **only in `test-faults` builds**. In a release build, setting it is a
    `ConfigError`, never silently ignored.
  - The audience is `AUTH_AUDIENCE`.
  - Don't ship `GRANT_SCHEMES` in `wrangler.jsonc`: unset means grants are off.
- **B15. Fail closed.** Each of these is a startup refusal: native `CONFIG_ERROR`/`USAGE`, and on the Worker a
  `ConfigError`, so every RPC answers `unavailable`.
  - an unknown scheme;
  - a malformed relying-party entry;
  - a duplicate relying-party id;
  - `webauthn-p256` without a relying party;
  - a relying party without any scheme;
  - grant settings without Multi + auth v2;
  - `GRANT_SCHEMES` present but blank;
  - a loopback audience or relying party without the opt-in.

  A bad value never degrades to "grants off".
- **B16. `WorkerConfig` equality.** Store the validated **inputs** (the `AcceptedSchemes` and the `RelyingParty` list,
  which already derive `PartialEq`/`Eq`, plus the loopback bit). Build `GrantConfig` when the pipeline is built. Add no
  derives to `GrantConfig`. Validate once at config parse by building it, so errors surface at startup.
- **B17. Conformance.**
  - Enable the grant and epoch wire cases in #1210's Multi phases on native `wire_multi` and in the Worker `--multi`
    phase:
    - `GRANT_SCHEMES=ed25519,secp256k1-eip191,webauthn-p256`;
    - `WEBAUTHN_RPS=example.test=https://example.test`;
    - the loopback opt-in (test-faults or local only);
    - a namespace allowlist that includes `wire::grant_owner_namespaces()`.
  - These fixed test-seed namespaces are allowed **only** in local conformance configurations. Never put them in a
    shipped config or an example.
  - Remove the skip reasons #1210 left for the grant cases.

### Plan (in this PR)

- **B18. R-159, the M1 closure plan.** It records:
  - REL-1's registry deps gain **1.30b**, whose closure brings in 1.30 and 1.15;
  - the M1–M2 breakdown's staging run, the "≥ 8× on staging" bar, the staging push/clone exit criteria and the
    single → D34 migration text are **superseded** by R-154 and R-123. Mark them in `m1-m2-breakdown.md`;
  - 1.27's registry deps (1.26b, 1.28c) are correct, and the breakdown's (1.26, 1.28) are not;
  - **WP-1.27's scope decisions,** for its later prompt:
    - epoch-lease wire cases for bump, idle-shard wake, and expiry racing an ack via skew. Revoke-during-write and
      R-63 stay in-crate (`native/tests/epoch_leases.rs`) and are cited in the exit report, with no new pause faults;
    - the over-32 MiB listing is a native-only wire case, and the Worker keeps 1,000 refs (R-134);
    - a partition-scoped Worker stats hook, so `growth.*` runs under D34;
    - the exit evidence is `docs/plans/mkit-server/m1-exit-report.md` from local runs, with no staging.
- **R-157 (1.28c):** B1–B7. **R-158 (1.26b):** B8–B11. **R-136 extension (1.30b):** B12–B17.
- Add a CHANGELOG line per WP.

## C. Your decisions

- The internal shape of the conditional default in `config.rs`, and how `restore` reads the marker.
- Where the stale-listing skip is reported (verbose log vs summary line), as long as it's visible at verbose level.
- The Multi+D34 quota phase's exact skew and window values.
- The parser module layout.

## D. Escalate (stop and report) if

- The conditional native default can't be expressed without breaking an existing explicit-flag behaviour.
- Kind-5 rollups on the Worker would exceed the Free-plan subrequest budget even at `max_per_tick` = 4.
- Enabling the grant cases on either adapter reveals a server bug outside this bundle. Report it and skip that case
  with a reason; don't fix server grant logic here.
- Production code passes 3,000 lines.

## Tests (required)

**1.28c:**
- **Native config units:**
  - D34 by default with SQLite;
  - single with fs-layout or no `--meta`;
  - an explicit `--sharding d34` without SQLite gives `USAGE`.
- **`bind_sharding`:** a recorded or unmarked single database under the new default gives `CONFIG_ERROR` with the new
  text.
- `restore` follows the export marker, and a conflicting flag is refused.
- **Worker units:** unset gives D34, `"single"` is honoured, and the 503 mismatch path is unchanged.
- **Client, with a fake `Transport`:**
  - a listed branch whose head and packmap are both strongly absent is skipped, and other branches still fetch;
  - a present head with no packmap is `PackmapMissing` (`applied_packs_fetch.rs` stays);
  - a transport error on the re-read is an error.
- The `client_e2e` D34 variant with bounded polling.
- The Worker script passes in both the D34 (default) and single phases.

**1.26b:**
- **Worker registry:** kind 5 fires in the three DO kinds, stays unknown elsewhere, retries on a config error, and
  honours `max_per_tick`.
- **The D34 `quota.*` variants:** in-process, native D34, and Worker D34.
- **The Multi+D34 wire case:** namespace-cap exhaustion across branches after a forced rollup.

**1.30b:**
- **Parser units:** the `=` split, origin lists, empty and duplicate entries, and separators.
- **The native fail-closed matrix** (B15). Loopback is refused without the opt-in and accepted with it, with the banner.
- **The Worker `from_vars` matrix,** including `UNSAFE_LOOPBACK_GRANTS` refused in a non-`test-faults` build.
- `GetServerInfo` reports `grant_schemes`.
- The grant and epoch wire cases pass on native `wire_multi` and the Worker `--multi` phase.
- Existing `GrantConfig` callers compile unchanged.

## Gates

- The common gate set, plus `just ci-server`, `just ci-scripts` (with `check-cli-baseline.sh`), `just ci-security` and
  `ci-yaml`.
- `cargo nextest run --locked -p mkit-server -p mkit-server-native -p mkit-server-conformance -p mkit-server-worker -p mkit-cli --all-features`.
- The wasm32 check and the worker build.
- `scripts/vcs-worker-conformance.sh` in the D34 (default), `--sharding single`, `--multi` and Multi+D34 quota phases.
