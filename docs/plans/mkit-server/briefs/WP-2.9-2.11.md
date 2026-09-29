# WP-2.9 + WP-2.11 brief: signed reads, private repositories, visibility and object URL tokens

Bundle id `2-9-2-11`, one PR into `feat/mkit-server`. Copied from the executor prompt, "Purpose" to the end.

## Purpose

Repositories can be private:
- Reads are signed and verified in full.
- A private repository is readable only by its owner, a read-capable grant, or an authority hook.
- Every other caller gets a `not_found` byte-identical to a missing repository.
- Owners switch visibility with an envelope request, or with an unsigned signed statement.
- Authorized readers can mint short-lived signed URL tokens for HTTP object serving. WP-4.12/4.15 will verify them
  through the API this bundle ships.

## A. Fixed (do not change)

1. **SPEC-WRITE-GRANTS:**
   - §4.2: a grant header without auth is `unauthenticated`;
   - §6, and §7 steps 1–11;
   - **§9.1:** visibility modes and completion;
   - **§9.2:** signed reads verify in full; a failure is `unauthenticated`; there is no replay entry;
   - **§9.3:** read authorization, the uniform `not_found`, and the `GetReceipt` write-only exception;
   - **§9.4:** URL tokens;
   - §11.
2. **SPEC-SERVER §10.1:** `caller_view` is `writer`, `reader` or `anonymous`. M2 serves live refs.
3. **SPEC-HTTP-OBJECTS §3 step 5 and §6:** token verification has two phases. The stateless checks (syntax, key id,
   signature, audience, repository, target, expiry) run **before** any stored-epoch read, and every failure is one
   uniform rejection.
4. **R-125 bounds:**
   - `SetRepoVisibility` with `mode` unset, `UNSPECIFIED` or an unknown enum value is `invalid_argument`;
   - `IssueObjectUrl` with `target` unset, an `object_id` that is not 32 bytes, or a path over 1,024 bytes or outside
     the §9.4 grammar is `invalid_argument`;
   - **Statement size:** the parallel 2.8 bundle makes an oversize or undecodable `signed_statement`
     `permission_denied` (§5.2 check 1, §11). Apply the same rule to visibility statements; it is not
     `invalid_argument`.
5. **R-129:** the `DownloadPack` `body:` commitment covers the exact framed request body (the 5-byte prefix). Golden:
   `rust/tests/golden/auth-v2/read.json`, entry 2.
6. **The client is merged (2.10).** Don't change its signing.
7. **`GetServerInfo`, `GetGrantEpoch` and `SetGrantEpoch` stay outside `Procedure`.**

## B. Decided (do not change)

### Part 1: WP-2.9

- **B1. Procedures.**
  - Add `Procedure::{IssueObjectUrl, GetReceipt, SetRepoVisibility}`, each with an explicit read/write class.
  - `SetRepoVisibility` envelope mode is a write (replay-protected; see B6). `IssueObjectUrl` and `GetReceipt` are
    reads.
  - Keep a test asserting that every generated RPC is classified.
- **B2. Signed reads at stage 0.**
  - A read carrying any of `X-Envelope-Version`, `X-Public-Key` or `X-Signature` is **verified in full**.
    - A failure is `unauthenticated`; it never falls back to anonymous.
    - `signed = true` is passed to `resolve`.
    - There is no replay lookup and no replay record.
  - A read with no auth headers is `Anonymous`.
  - `IssueObjectUrl` without a signature is `unauthenticated`.
  - Capture `x-write-grant` on reads too. A grant header without auth v2 is `unauthenticated` on any procedure.
  - A compressed signed request is rejected, as unary requests already are.
- **B3. DownloadPack framed verification (R-129).**
  - Verify `body:` over the exact framed request body: `0x00‖len‖bytes`, with a compressed flag rejected.
  - Preferably, buffer the single bounded (≤1 KiB) inbound frame in `intercept_streaming`, verify, and re-inject.
  - If connectrpc 0.9.1 can't expose the encoded frame, verify in the handler over the deterministic buffa
    re-encoding of `DownloadPackRequest`, where unknown fields fail closed.
  - Document which one you used. Test against the golden.
- **B4. Visibility storage and the read path (orchestrator decision: no cache).**
  - A new coordinator key class `rv 00 <repo>` holds `{visibility, last_created_ms, last_statement_id}`. Absent means
    `public`.
  - It is **not** stored in `rr`: visibility may be recorded without creating the repository (§9.1). Add it to
    `keys.rs` tags, `parse`, and the codec goldens.
  - Replace `require_repository` on read paths with **one** coordinator `get_many{rr, rv, e}`, so there are no extra
    DO calls.
  - Visibility and the epoch are read authoritatively on every read. `SetRepoVisibility(private)` therefore completes
    on commit.
  - **The P-22 isolate cache is deferred again.** Any later WP adding it must add the §9.1 completion wait. Record
    this in R-152.
- **B5. Read authorization** (a new `policy/read.rs`, §9.3).
  - **Missing repository:** `not_found`.
  - **Public repository:** everyone reads. A grant is evaluated only to classify the caller, and a failing grant is
    never an error.
  - **Private repository:** requires a signed caller who is one of:
    - the owner key;
    - a grant with `read` capability passing §7 steps 1–11, with the epoch compared against the coordinator `e`;
    - an authority hook allowance.
  - **Every other outcome** answers the **byte-identical** `not_found`: same code, message, details and headers as a
    missing repository, from **one constructor**. That covers:
    - anonymous callers;
    - a bad, foreign or old-epoch grant;
    - a write-only grant (except on `GetReceipt`);
    - a hook deny or hook failure;
    - `X-Mkit-Ref` misses.
  - **Order of checks:**
    - envelope verification and URL-only `invalid_argument` bounds run **before** the coordinator read;
    - verify a supplied grant even when the repository is missing (timing uniformity is a SHOULD);
    - a coordinator read failure is `unavailable`, never "public".
  - **`GetReceipt` exception:** a `write`-only grant passes the read check for `GetReceipt` only. Ship this as a policy
    function with unit tests; the handler stays `unimplemented` for WP-5.8.
  - **D34 ListRefs:** authorize (visibility and `not_found`) **before** today's D34 `Unimplemented` branch. Skip
    positive D34 ListRefs cases with a reason until 1.28b.
  - **`caller_view`:** add it to `AuthzFacts`, which is `#[non_exhaustive]`.
    - `writer` means the owner, a grant with `write` or `read,write` valid for the repository, or a hook allowance
      with `writer_view`.
    - For a public repository, the hook is consulted only for this classification.
- **B6. `SetRepoVisibility`, both modes (§9.1).** The mode is chosen by whether auth headers are present
  (orchestrator decision):
  - **Auth headers present → envelope mode.** `visibility` is required; a `signed_statement` in this mode is
    `invalid_argument`.
    - It is authorized by the owner key or an authority hook. **A grant never authorizes it.**
    - It is **replay-protected like a write.** The replay record goes in the **coordinator** partition, committed
      atomically with the `rv` write, with expired `px` rows pruned in the same batch.
    - No admission and no quota.
  - **No auth headers → statement mode.** `signed_statement` is required; `visibility` in this mode is
    `unauthenticated`.
    - Verify with `verify_visibility_statement`. `X-Repository` must equal the statement's repository.
    - Only a `created` value greater than the stored one is accepted. Identical bytes are an idempotent success.
  - **Both modes:**
    - the namespace allowlist applies: an unserved namespace is `permission_denied` (orchestrator decision; record it);
    - R-125 bounds (A4);
    - other failures are `permission_denied`.
  - **Where visibility applies:** only for Multi + `write_policy = owner` + AuthV2. Elsewhere, reads are public and
    `SetRepoVisibility` is `failed_precondition`. Signed reads are verified whenever AuthV2 is configured.

### Part 2: WP-2.11

- **B7. The token codec** (a new **un-gated**, wasm-clean `mkit-server::url_token` module, with `ed25519-dalek` as a
  direct dependency). Serving's `http-objects` feature belongs to WP-4.12.
  - The statement is `mkit-url-token:v1`, with fields: audience, repository, target
    (`object:<hex>` | `path:<ref>:<b64url path>`), **epoch**, issued, expiry, key id.
  - **There is no `caller_view` field** (the breakdown was wrong; the spec wins).
  - The token is `b64url(stmt).b64url(ed25519 sig over BLAKE3(stmt))`, strict base64url.
  - The key id is 32 hex characters: the first 16 bytes of BLAKE3(pubkey).
  - A path is 0–1,024 bytes; empty names the root tree. The ref is any SPEC-REFS §3 ref. Note for 4.15 that refs
    outside `refs/`, or with a `-` segment, can't be served over HTTP.
- **B8. Minting (`IssueObjectUrl`).**
  - It is a signed read, and needs read access under B5: unauthorized is `not_found`.
  - The R-125 bounds run first.
  - The server does **not** resolve the target.
  - `epoch` is the stored coordinator epoch at issue time.
  - TTL is `min(requested, url_token_ttl)`, with a 15 min default; it is clamped, never refused.
  - With no URL-token key configured, answer `unimplemented("URL tokens not configured")`, checked before any
    repository access.
- **B9. The key set.**
  - One active dedicated Ed25519 key, held in `Zeroizing` and never logged, plus retired keys, each kept at least
    `url_token_ttl` after retirement.
  - A renderer for `/.well-known/mkit-url-token-keys.json` in the SPEC-SERVER §7.2 shape. Mounting it belongs to
    4.16.
  - Configuration refuses a URL-token key equal to any other configured role key. Document the rule for 5.8's receipt
    key.
  - Verification uses `verify_strict`.
  - Tokens never appear in `Debug` or logs.
- **B10. Two-phase verify API.**
  - `precheck`: syntax, key id and signature, before any repository lookup.
  - `check_binding`: audience, repository, target and expiry, **before** any stored-epoch read.
  - The caller then compares the epoch.
  - Every failure is one uniform rejection. For a public repository the serving caller ignores the result (4.12/4.15).
- **B11. Configuration.** `PipelineConfig.url_tokens: Option<UrlTokenConfig>` (keys, TTL), core only. The adapter
  flags belong to WP-1.30b; add them to its registry text if the row exists, otherwise to R-153's carry-forwards.
- **B12. Docs and plan.**
  - Remove the "Before the M2 implementation" read notes from SPEC-WRITE-GRANTS, and update its status paragraph.
  - **R-152 (2.9):**
    - B1–B6;
    - the no-cache decision and the deferred P-22 cache;
    - coordinator replay for envelope-mode visibility;
    - the allowlist on `SetRepoVisibility`;
    - 1.21's carry-forward: snapshots never serve private repositories, signed reads bypass them, and if a snapshot
      caches visibility, completion must wait for it or purge it.
  - **R-153 (2.11):**
    - B7–B11;
    - the breakdown/spec disagreements (no `caller_view` in tokens; an `epoch` field; two-phase verify; the path
      range; minting un-gated);
    - the 4.12/4.15/4.16 hand-offs.
  - A CHANGELOG line per WP.

## C. Your decisions

- The shape of `policy/read.rs`, and how `caller_view` threads to the handlers.
- The DownloadPack verification mechanism, within B3.
- The `UrlTokenConfig` shape and key-file format, documented.
- Test and golden layout.

## D. Escalate (stop and report) if

- Private-read `not_found` can't be made byte-identical to missing-repository `not_found` on some path.
- DownloadPack framed verification is impossible both in the interceptor and in the handler.
- Production code passes 3,000 lines. Cut in this order:
  1. the 2.11 key-set JSON renderer moves to 4.16;
  2. then open the PR with 2.9 alone, and list 2.11 as not done.

## Tests (required)

**Unit:**
- The `Procedure` class table covers every generated RPC.
- Every read against no auth, a valid signature, a bad signature, an expired one, the wrong repository, and a
  header-only grant, with the expected result.
- DownloadPack against `auth-v2/read.json`; a compressed flag is rejected.
- **The §9.3 decision table:** public and private × anonymous, owner, read grant, `read,write`, write-only, expired,
  wrong epoch and hook deny, plus the `GetReceipt` write-only exception.
- `caller_view` classification.
- Visibility statements: `created` monotonicity and the identical-bytes retry.
- The R-125 bounds.
- Token encode and parse rejections:
  - padding and alphabet;
  - trailing bits;
  - field count;
  - `.`, `..` and `//` paths;
  - a 1,025-byte path;
  - the empty root path.
- Key-id derivation, retired-key acceptance, unknown-key rejection.
- The TTL clamp (0 and `u32::MAX`).
- **The two-phase order:** a test verifier's epoch read is never called when a stateless check fails.
- No token in `Debug`.

**Pipeline and storage:**
- A signed read creates no `p` or `px` row.
- Envelope-mode `SetRepoVisibility` writes one replay row in the coordinator. A reused nonce with a different body is
  rejected.
- Visibility set on a missing repository writes no `rr` or `nr`, and the first write then creates the repository as
  private.
- A hook failure on a private read is `not_found`.

**Wire** (Single and D34, `SignedReads`; extend `pipeline_grants_single_and_d34` or add a harness):
- `reads.signed_verified_in_full`: a bad signature is `unauthenticated` on public, private and missing repositories
  alike.
- `reads.public_unsigned_ok`.
- Private reads:
  - `reads.private_anonymous_not_found`
  - `reads.private_owner_ok`
  - `reads.private_read_grant_ok`
  - `reads.private_write_only_not_found`
  - `reads.private_expired_signature_unauthenticated`
  - `reads.private_grant_old_epoch_not_found`, via `x-mkit-test-bump-epoch`
- **`reads.private_not_found_byte_identical`:** code, message, details and headers compared against a missing
  repository, for ReadRef, ListRefs, PackExists, DownloadPack and IssueObjectUrl, including `X-Mkit-Ref`.
- Visibility:
  - `visibility.envelope_owner`
  - `visibility.statement_ed25519`
  - `visibility.statement_eip191`
  - `visibility.grant_never_authorizes`
  - `visibility.older_created_denied`
  - `visibility.bad_mode_invalid_argument`
  - `visibility.oversize_statement_permission_denied`
- URL tokens:
  - `reads.url_token_mint_ok`
  - `reads.url_token_private_without_read_not_found`
  - `reads.url_token_anonymous_unauthenticated`
  - `reads.url_token_bounds_invalid_argument`
  - `reads.url_token_ttl_clamped`
- Multi-repo isolation stays green. D34 ListRefs positive cases are skipped with a reason until 1.28b.

**Goldens:** `rust/tests/golden/url-token/{tokens.json, reject/*.json, keyset.json, targets.json}` with a MANIFEST, and
an independent Python reference following the `scripts/golden/grants_ref.py` pattern.

## Gates

- `just ci-server`, `just ci-scripts` and `just ci-security`
- `cargo nextest run --locked -p mkit-server -p mkit-server-native -p mkit-server-conformance -p mkit-attest -p mkit-transport-connect --all-features`
- the wasm32 check and the worker build
- `scripts/check-wasm-dep-graph.sh`, since `ed25519-dalek` becomes a direct dependency
- `cargo deny check`
- `scripts/vcs-worker-conformance.sh` (default phase)
