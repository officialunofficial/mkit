## Purpose

Prove M3 end to end on both adapters. A push to a paying deployment:
1. is challenged with an MPP-shaped 402;
2. the client's admission helper produces a credential;
3. the retry is admitted;
4. exactly one terminal outcome per reservation is delivered at least once;
5. aborted and expired work settles nothing.

The admission and outcome wire behaviour, CORS and backpressure are pinned in conformance, and
`docs/plans/mkit-server/m3-exit-report.md` records the M3 exit evidence, with no staging.

## A. Fixed (do not change)

1. **Specs:** STC §5.1 and §7.7, and SPEC-SERVER §5–§8. **Spec overrides from the fact sheet §2:**
   - the credential is bound server-side;
   - "exactly once" means one distinct terminal outcome per reservation id, delivered at least once;
   - Aborted comes from an admitted `UpdateRef` CAS loss, while an unused upload ticket ends `Expired`;
   - no staging (R-154);
   - no fault proxy.
2. **No pipeline, spec, proto or golden changes.** A wire bug found by a case is escalated, not fixed inline, unless
   it's a one-line adapter bug.
3. **3.8's `stubs/hook.rs` contract:** additive hooks only (modes, a gate, a ledger).
4. **Test-only surfaces never ship** (fact sheet §4).

## B. Decided (do not change)

### Part 0: WP-3.7b, a public Rust surface for hook implementers (authentication re-exports). Do this first.

**Why:** external Rust hook implementers (uno-api) need the `mkit.server.hooks.v1` message types and a
`mkit-hook:v1` request verifier without depending on the server runtime.

- **B0.1 Location:** a new `hooks` feature on the published, lightweight `mkit-rpc` crate, which already holds
  mkit's versioned wire protocols.
  - Generate `mkit.server.hooks.v1` there with `buffa-build` (JSON enabled), following mkit-rpc's existing
    `build.rs`/`generated/` pattern.
  - Update `scripts/regen-hooks-proto.sh` (or `regen-rpc-proto.sh`) and the freshness check.
  - `mkit-server`'s `remote-hooks` depends on `mkit-rpc/hooks` and stops generating its own copy. The private
    `hooks::proto` module is removed or becomes a re-export.
- **B0.2 Move `HookSigner` and the public `HookVerifier`** (added by 3.8+3.9 in `mkit-server::hooks`) into
  `mkit_rpc::hooks`, with `mkit-server` re-exporting both.
  - The verifier checks the §7.1 headers, key id, validity (≤ 300 s, 30 s skew), audience, and the digest and
    signature over the raw body, with an injectable clock and optional nonce replay.
  - Keep them free of any server runtime dependency.
- **B0.3 Credential safety:** `AdmitRequest` carries credentials, and buffa-generated `Debug` prints fields.
  - Document the rule prominently on the module and the type.
  - If buffa allows it cheaply, also mark the credential fields so `Debug` redacts them; otherwise document why not.
  - `mkit-server` keeps its redacting wrappers.
- **B0.4 Additive evolution:** document that implementers build messages with `..Default::default()` or the
  provided constructors.
- **B0.5 Acceptance test,** as an external-crate-style integration test in `mkit-rpc/tests/`, using only public
  items:
  - decode each golden request in `rust/tests/golden/server-hooks/`;
  - build each golden response;
  - verify every `signature.json` vector.
- **B0.6** `scripts/check-wasm-dep-graph.sh` and the wasm build stay clean for `mkit-rpc --features hooks` and
  `mkit-server --features remote-hooks`. `cargo semver-checks` is additive for `mkit-rpc`.
- **B0.7** Add a registry row **3.7b** ("Public hooks.v1 types and mkit-hook:v1 verifier in mkit-rpc", M3, Stage 1,
  deps 3.7, 3.8). R-174 references authentication re-exports.
- **B0.8** The MPP stub (B1) uses these public types and `HookVerifier`, with no hand-written proto JSON.

### Parts 1–2: WP-3.12 + WP-3.13

- **B1.** The MPP stub is `stubs/mpp.rs` (feature `stubs`), plus a loopback control plane and a
  `mkit-server-conformance stub-hook` subcommand, as in fact sheet §2 (D1).
- **B2. Leg N** is `mkit-server-native/tests/admission_e2e.rs` with a real `mkit-server` binary, 3.8's flags, and a
  POSIX `sh` exec helper.
  - **D3:** prefer an existing public `mkit_cli` entry that builds the Connect transport from a `Config`. If none
    exists, add `#[doc(hidden)] pub use admission_helper::ExecResponder` and note it.
- **B3. Leg W** is `wrangler dev` with 3.9's `wrangler.hooks.jsonc`. Its JS stub becomes a forwarder to the Rust
  stub (D2); unsigned per §7.3.
- **B4.** The wire cases in fact sheet §2's table, keeping the reserved TODO names. The profile gains `--hook-stub`,
  `Feature::HookStub`, a backlog-cap knob and `ShortTickets`.
  - **D5:** set the knobs in-process on native lanes, and through test-faults-only Worker vars
    `TEST_OUTBOX_BACKLOG_ROWS` and `TEST_TICKET_TTL_MS`. No public flags.
- **B5.** The lanes and skip allowlists as in the fact sheet, plus a `vcs-worker-conformance.sh --hooks` phase and a
  Free-plan eventual-completeness case with at least 9 outcomes.
- **B6.** Release guards: `check-release-artifact-features.sh` fails on `stubs`; a marker scan; and a test that the
  `TEST_*` Worker vars are compiled out of release builds.
- **B7.** `m3-exit-report.md` in the m0 format, with the §7 table mapping each PRD M3 exit bullet to its test. Update
  the README status table and the registry.
- **B8. Docs:** R-172 and R-173, and a CHANGELOG line per WP.

## C. Your decisions

The stub module layout, the control-plane paths, the forwarder details, and the runner flag spellings.

## D. Escalate (stop and report) if

- A case exposes a server bug that isn't a one-line adapter fix. Skip it with a reason and report it.
- Leg N can't reach the exec helper without more than the one `#[doc(hidden)]` re-export.
- Production code passes 2,500 lines. Fall back to the fact sheet's PR-A/PR-B split: open 3.12 and list 3.13 as not
  done.

## Tests (required)

The fact sheet's §8, in full.

## Gates

- The common gate set, plus `just ci-server`, `ci-scripts` (`check-cli-baseline.sh`) and `ci-security`.
- `cargo nextest run --locked -p mkit-server-conformance -p mkit-server-native -p mkit-server-worker -p mkit-cli --all-features`.
- The Worker wasm32 build with and without `test-faults`.
- `scripts/vcs-worker-conformance.sh --test-faults --hooks` and the default phase, with `VCS_CONFORMANCE_PORT` set
  to a free port.
