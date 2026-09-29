## Purpose

A Multi-addressed deployment accepts writes authorized by an owner-signed write grant (`X-Write-Grant`). A grant lets
a non-owner key write to a namespace's repositories, and lets `0x` (secp256k1-eip191 or webauthn-p256) namespaces take
writes at all. It is the server half of SPEC-WRITE-GRANTS; the client half is WP-2.10.

## A. Fixed (do not change)

1. **SPEC-WRITE-GRANTS:**
   - §4: the header, schemes and the 8,192-byte bound.
   - §4.2: the part path ignores the header, which is outside the signed string.
   - §6: when a grant is present, it is the **only** path, even for the owner.
   - §7: verification steps 1–11.
   - §9.3: writes are not an oracle.
2. **The verifier is `mkit-attest`'s `grants` feature:** `verify_grant_owner`, `OwnerVerified::check`,
   `VerifiedGrant`, and `GrantError::reason()`. Do not re-implement any of it.
3. **The apply-time epoch guard already exists** (`plan.rs:~288-306`). It becomes live as soon as
   `AuthzFacts.grant` is `Some`.
4. **The stage order is replay lookup, then authorize, then admission/quota/lease.** A rejection allocates nothing.
5. **The owner schemes come from 2.5** (merged). No new cryptography.

## B. Decided (do not change)

### B1. The header at stage 0
- Capture `x-write-grant` only for signed write procedures: `UpdateRef`, `AdvanceRefs`, `BeginUpload`, and a ticketless
  `UploadPack`.
- Carry it on `Authenticated`, then on `Operation`.
- The part path and reads ignore it. Reads belong to 2.9.
- **Presence is lossless.** Two or more values are joined with `", "`, and a non-ASCII value maps to a sentinel that
  fails decoding. Both reach the pipeline as a *present, malformed* grant, which is `permission_denied`. They never
  count as absent.
- A grant header on a request without auth v2 headers is `unauthenticated`.
- Add `x-write-grant` to `CORS_ALLOW_HEADERS`.

### B2. The grant path in `authorize` (new `policy/grants.rs`)
1. The namespace allowlist runs first, unchanged. A `0x` namespace must be listed to take writes.
2. With a grant present:
   - `owner = false`;
   - any failure is `permission_denied`, including for the `ed25519-` owner;
   - an `Authority` hook never rescues a failure.
3. Run `verify_grant_owner` and then `OwnerVerified::check`, with:
   - `repository` = the resolved `X-Repository`;
   - `signer` = the auth v2 signer;
   - `Capability::Write`;
   - `now` = the business clock that auth v2 used.
4. **Step 11.** The grant's epoch must equal the observed stored epoch: `op.leased_epoch` under D34, and the
   `read_ahead` `e` key under Single sharding (absent means 0). A mismatch is `permission_denied`. When no epoch was
   observed, fail closed (for example a ticketless `UploadPack`, which is unreachable under Multi today).
5. `AuthzFacts { owner: false, grant: Some(GrantRef { id, epoch }) }`. The hook is still called and MAY deny.
6. With no grant, keep today's behavior.
7. Expiry is checked at authorize only. A grant that expires inside the apply window still commits; document this. No
   `NotAfter(expiry)`.
8. No cross-request cache.
9. Log the grant id only, never the header.

### B3. Interim ref-scope gate (fail-closed; replaced by 2.7)
`policy/grants.rs::interim_ref_gate`, strictly narrower than §8.2:
- `UpdateRef` of `refs/mkit/packmap/*`: deny.
- `UpdateRef`: `effective_flags(ref)` ⊇ `cuf` for a non-delete change, or ∋ `d` for a delete.
- `AdvanceRefs`:
  - the packmap equals `head_packmap(head)`;
  - the head's flags ⊇ `cuf`, or ∋ `d` for a delete.
- `BeginUpload`: the target ref has non-empty `effective_flags`.
- Mark it `TODO(WP-2.7)` and name it in R-135.

### B4. Configuration
- `PipelineConfig.grants: Option<GrantConfig>`, wrapping `VerifierConfig`: the schemes plus the relying parties (an id
  and its origins).
- **Startup refusals** (`invalid_argument`), when grants are configured:
  - without auth v2;
  - with Single addressing or `WritePolicy::Open`;
  - with a grant audience different from the auth v2 audience.
- `GrantConfig::new_allowing_loopback` exists for tests and dev only. The production constructor refuses loopback.
- **A header under Single/`Open`** is ignored and not parsed. **A present header under Multi/`Owner` with no
  `GrantConfig`** is `permission_denied` ("scheme not advertised").
- `mkit-attest` with `grants` becomes a non-optional dependency of `mkit-server`. Keep `scripts/check-wasm-dep-graph.sh`
  and `cargo deny` green.
- **Core only.** Adapter flags and variables (`--grant-schemes`, `--webauthn-rp`, `GRANT_SCHEMES`, …) belong to
  **WP-1.30**. Add WP-1.30 to `registry.json` and the 00-plan table as R-96 intended: "Adapters: Multi addressing mode,
  write-policy and grant flags". Its deps are 1.5 and 2.6.

### B5. Errors and discovery
- One mapping, `GrantError -> ServerError::permission_denied("write grant rejected: <reason>")`. An epoch mismatch keeps
  the existing `epoch_moved()` text.
- `grant_schemes` is the configured tokens in §4 order under Multi/`Owner` with grants, and empty otherwise.
- The conformance `info` case asserts that value with `Feature::Grants`, and empty without it.

### B6. Spec and plan
- Update the SPEC-WRITE-GRANTS status paragraph and the "Before the M2 implementation" notes in STC §7.5 and
  SPEC-WRITE-GRANTS §6 so that server enforcement exists.
- **R-135:**
  - B1–B5 in brief;
  - the interim gate replaced by 2.7;
  - `BeginUpload`'s §8.2 scope check moves to 2.7's scope;
  - WP-1.30 added;
  - apply-window expiry accepted;
  - the ticketless `UploadPack` epoch source is decided in 2.12.
- CHANGELOG entry.

## C. Your decisions

- The shape of the header plumbing on `Authenticated` and `Operation`.
- How the Single-sharding observed epoch reaches `authorize`.
- Test minting helpers for the three schemes, including a WebAuthn assertion builder.
- Module layout.

## D. Escalate (stop and report) if

- A grant cannot be verified without changing `mkit-attest`'s public API.
- The dep-graph or wasm32 check cannot stay green with `mkit-attest` as a dependency.
- The diff passes about 1,800 lines. Then propose 2.6a (the core plus ed25519 cases) and 2.6b (the secp256k1 and
  WebAuthn conformance cases), and continue with 2.6a.

## Tests (required)

1. **Unit:**
   - every `GrantError` maps to `permission_denied`;
   - the config refusals;
   - the interim-gate table;
   - `grant_schemes` order.
2. **Pipeline** (the allocate-nothing matrix pattern):
   - every rejection writes no replay, quota, reservation or `el` row;
   - the same nonce succeeds after a corrected grant;
   - a valid grant can still be denied by a `Check` hook;
   - an `Authority` hook cannot rescue a bad grant;
   - the hook sees `owner = false` and the grant;
   - an owner with a bad grant is denied, and an owner without a grant is OK;
   - an epoch bumped between authorize and apply (the `AfterAuthorize` fault) is `permission_denied` with nothing
     committed.
3. **Wire,** in new `wire/cases/grants.rs`, M2, requiring `[Grants, MultiRepo, AuthV2]`. Run in the in-process Single
   and D34 Multi harnesses:
   - valid grant: `valid_ed25519`, `valid_secp256k1_eip191` (`0x`), `valid_webauthn_p256` (`0x`, with a relying
     party), and `push_flow` (BeginUpload, ticketed UploadPack, AdvanceRefs under `refs/heads/main=cuf`);
   - binding: `zero_x_without_grant_denied`, `wrong_audience`, `repository_out_of_scope`,
     `namespace_scope_covers_new_repo`, `grantee_mismatch`, `read_only_grant_for_write`;
   - validity window: `expired` (at `now == expiry`), `not_yet_valid` (`created = now + 30_001`; `+30_000` passes);
   - schemes: `ed25519_scheme_on_0x_denied`, `webauthn_unconfigured_rp_denied`;
   - epochs: `epoch_above_stored`, `epoch_below_stored` (after `x-mkit-test-bump-epoch`), `new_epoch_grant_works`;
   - owner and header handling: `owner_with_bad_grant_denied`, `header_without_auth_unauthenticated`,
     `duplicate_header_denied`, `oversize_header_denied` (8,193 bytes), `non_ascii_header_denied`,
     `part_path_ignores_header`;
   - `retry_with_changed_grant_returns_saved_result`;
   - `info.shape_and_policy` with `Grants`.

## Gates

- `just ci-server`
- `cargo nextest run --locked -p mkit-server -p mkit-server-native -p mkit-server-conformance -p mkit-attest --all-features`
- the wasm32 check and the worker build
- `scripts/check-wasm-dep-graph.sh`
- `cargo deny check`
- `scripts/vcs-worker-conformance.sh` (default phase, which must stay green)
