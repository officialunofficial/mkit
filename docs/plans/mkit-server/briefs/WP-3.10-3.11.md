## Purpose

A client pushing to a paid deployment recognizes an HTTP 402 admission challenge. It surfaces the challenge safely, and
then either stops with a clear error or runs the user's configured admission helper once and retries with the headers
the helper returns. Payment receipts on successful writes reach an observer.

Everything is protocol-neutral:
- schemes and values are opaque;
- the helper is a pluggable trait with an exec implementation;
- the payment header names appear only as spec-fixed constants.

## A. Fixed (do not change)

1. **STC §5.1:**
   - admission challenges are 402 with `permission_denied` and an `AdmissionChallenge` detail;
   - the client never blindly retries;
   - the key names are `admission_helper` and `remote.<name>.admission_headers`;
   - the helper stdin object is exactly `{origin, repository, procedure, description, challenges, headers}`;
   - the default request allowlist, and the hard-reserved set: `X-Mkit-*` plus the enumerated names;
   - the fixed warning for reserved config entries.
2. **SPEC-CONFIG-SECURITY:** both keys are user-scoped, and forbidden in repository config and `-c`.
3. **SPEC-SERVER §6.3 and §6.6:** the receipt headers `Payment-Receipt` and `PAYMENT-RESPONSE` are sent with
   `Cache-Control: private`, and forwarded header values are visible ASCII.
4. **The 3.1 goldens** (`rust/tests/golden/transport/admission-challenge*`) and the bounds: at most 8 challenges, a
   scheme at most 64 bytes, a value at most 8,192 bytes, and a description at most 512 bytes.
5. **STC §7.7:** only `UpdateRef`, the ticketless `AdvanceRefs` and `BeginUpload` are admitted. Reads, `DownloadPack`,
   `UploadPack` and the part path are never admitted.

## B. Decided (do not change)

### Part 1: WP-3.10

- **B1. The error variant.** In `mkit-core/src/protocol.rs`, add
  `TransportError::AdmissionRequired(Box<AdmissionRequired>)`.
  - `AdmissionRequired` is a `#[non_exhaustive]` struct with `challenges` (`{scheme, value}`), `description`,
    `www_authenticate: Vec<String>` and `payment_required: Vec<String>`.
  - Mark `TransportError` itself `#[non_exhaustive]` in this PR, fix the exhaustive fakes, and flag the break in the PR
    body.
  - `is_retryable` is false for the new variant.
- **B2. Keeping the status.** A small `ClientTransport` wrapper (`status.rs`) around the HTTP client.
  - It strips any server-sent copy of a private marker header, `x-mkit-client-status`, from every response.
  - It sets that marker on a 402.
  - `map_connect_error` checks the marker. Never parse `err.message`.
- **B3. Detection** in `map_connect_error`, before the code table. Either of these triggers parsing:
  - a status-402 marker;
  - `permission_denied` carrying a detail of type `mkit.transport.v1.AdmissionChallenge`, with an optional
    `type.googleapis.com/` prefix.

  Then:
  - More than one such detail is `InvalidResponse`.
  - Base64 over 88,836 characters is refused before decoding. Decode with `STANDARD_NO_PAD`, falling back to
    `STANDARD`.
  - Decode, then validate the bounds. A violation is `InvalidResponse`.
  - A raw 402 with no detail gives empty challenges and an empty description.
  - Keep only the `www-authenticate` and `payment-required` values: at most 8 per name, each at most 8,192 bytes of
    visible ASCII, SP or HTAB.
  - A detail on any other code is ignored. Payment headers without a 402 are ignored too.
- **B4. Display.** `admission required by remote: <sanitized description> (schemes: …)`.
  - Escape C0, DEL, C1 and the bidi overrides U+202A–U+202E and U+2066–U+2069.
  - Never print challenge values or header values.
- **B5. Receipts.** `ConnectTransport::with_admission_receipt_observer(...)`, using the builder shape of the merged
  4.9 observer.
  - On a successful unary write, collect `payment-receipt` and `payment-response` values: at most 8, each at most
    8,192 bytes, dropping anything over.
  - Each becomes `AdmissionReceipt { procedure, header, value }`, where the value's `Debug` and `Display` show only its
    length.
  - The CLI prints `note: remote returned a <header> receipt for <procedure>`, never the value.
- **B6. Validator source.**
  - If the 3.2+3.3 bundle has merged `mkit_core::admission`, use its bounds.
  - Otherwise keep a private mirror of the constants in `mkit-transport-connect`, marked `TODO(R-138)`.

### Part 2: WP-3.11

- **B7. Layering.**
  - `mkit-transport-connect/src/admission.rs` holds:
    - `trait AdmissionResponder: Send + Sync { fn respond(&self, ctx: &AdmissionContext<'_>) -> Result<Vec<(String, String)>, AdmissionResponderError>; }`;
    - `AdmissionContext { origin, repository, procedure, required }`;
    - `AdmissionPolicy { responder, extra_allowed }`, set with `ConnectTransport::with_admission(policy)`;
    - the header filter;
    - the one-shot retry wrapper.
  - The CLI holds the exec responder, the config and the UX. No payment names appear in the types.
- **B8. Header filter.** It runs in this order, and the first failure aborts the operation:
  1. at most 8 headers;
  2. each name is an RFC 9110 token of at most 64 bytes; a case-insensitive duplicate aborts;
  3. each value is at most 8,192 bytes of visible ASCII, SP or HTAB, and is marked sensitive;
  4. hard-reserved names are refused (see below);
  5. the allowlist: defaults ∪ `extra_allowed`;
  6. already carried: a name already in the call's options, the client defaults, or the transport-owned names
     (`accept-encoding`, `grpc-*`) is refused.

  The hard-reserved set:
  - exact names: `x-public-key`, `x-signature`, `x-digest`, `x-created-at`, `x-expires-at`, `x-envelope-version`,
    `x-audience`, `x-repository`, `x-content-commitment`, `x-write-grant`, `x-mkit-ref`, `host`, `transfer-encoding`,
    `cookie`, `idempotency-key`, `connection`, `keep-alive`, `te`, `trailer` and `upgrade`;
  - prefixes: `x-mkit-`, `x-forwarded-`, `content-`, `connect-` and `proxy-`;
  - `authorization`, when a bearer token is configured.

  Errors name the header, and say whether it is reserved or not on the allowlist, with the `mkit config` hint.
- **B9. Retry.** Only the admitted writes are wrapped: `update_ref`, the ticketless `advance_refs`, and `begin_upload`
  if it exists.
  - On `AdmissionRequired` with a policy set, run the responder **outside** the executor's `block_on`, and filter its
    output.
  - Reuse the same identity if it is still valid with more than 30 s left; otherwise re-sign over the same body.
  - Retry through the normal ladder with the helper headers on every attempt.
  - A second `AdmissionRequired` is terminal: "remote challenged again after the admission helper ran".
  - Helper headers belong to one operation and are never cached.
  - Cap helper runs at **8 per transport**; beyond that, surface `AdmissionRequired` with a message.
- **B10. Exec helper** (`mkit-cli/src/admission_helper.rs`).
  - `admission_helper` must be an absolute path, run with no arguments and no shell.
  - stdin is the exact STC object, written from a thread; stdout is read from a thread with a 128 KiB cap; stderr is
    inherited.
  - A 120 s wall-clock deadline covers the whole run. On expiry, kill, reap and join.
  - stdout is parsed strictly: a JSON object of strings, with exact duplicate keys rejected. An empty object aborts.
  - Error text never contains stdout bytes or values.
- **B11. Config.**
  - `admission_helper` joins `REPO_FORBIDDEN_KEYS`.
  - `remote.<name>.admission_headers` is comma-separated, stored in a **separate map**, so no phantom remote appears in
    listings.
  - Add a predicate `is_repo_forbidden_key` used at every site, `-c` included.
  - `mkit config` routes both keys to the user file and refuses a reserved name.
  - The fixed reserved-entry warning prints once, when the policy is built.
  - The policy is built only when `admission_helper` is set **and** the endpoint equals `trusted_remote_endpoint`.
  - Clone and explicit URLs get the default allowlist only.
- **B12. UX and exit codes.**
  - With no helper, or an untrusted endpoint: 3.10's error plus one hint line.
  - Before spawning: `remote requires admission for <Method> (schemes: …); running admission helper`. Suspend the
    progress line while the helper runs.
  - `--json` gains `"admission_required": true`.
  - **Exit codes:**
    - an unresolved `AdmissionRequired` → `NOPERM` (77);
    - a missing or relative helper path, or a header-filter rejection → `CONFIG_ERROR` (78);
    - other helper failures → the general error.
- **B13. Docs and plan.**
  - `docs/CLI.md` config rows. The helper's stdin is untrusted server content, and spending policy is the helper's job.
  - SPEC-CONFIG-SECURITY: drop "not yet implemented".
  - **R-140 (3.10):** B1–B6.
  - **R-141 (3.11):** B7–B12, plus the breakdown drift resolved in favor of the spec (keys, stdin shape, reserved set),
    and the stricter value charset.
  - A CHANGELOG line per WP. Note `RemoteError`'s unsanitized server text as a follow-up.

## C. Your decisions

- Internal module layout.
- How the retry wrapper threads identity and extra headers through the merged 4.9 `advance_refs` path.
- Test script helpers for the exec responder.

## D. Escalate (stop and report) if

- The status marker can't be implemented without forking connectrpc.
- The retry cannot reuse or renew the identity without changing the merged 4.9 or 2.10 public API in a breaking way.
- Production code passes 3,000 lines. Open the PR with Part 1, and list Part 2 as not done.

## Tests (required)

**Part 1:**
1. **Unit, with hand-built `ConnectError`s:**
   - the 3.1 golden gives 2 challenges in order, and the description;
   - a stamped 402 with no detail gives empty challenges and keeps the headers;
   - two details give `InvalidResponse`;
   - every bound is enforced, with each boundary passing;
   - base64 of 88,837 characters is refused before decoding;
   - bad base64 is refused;
   - the type prefix is accepted;
   - a detail on `unavailable` is ignored and the error stays retryable;
   - `permission_denied` without a detail or 402 gives `AccessDenied`;
   - a `RedactionNotice` detail gives `AccessDenied`;
   - header bounds are enforced, and other headers are dropped.
2. **The status wrapper:** a spoofed marker is stripped on 200 and 403, and set only on 402.
3. **Retry ladder:** exactly one attempt on `AdmissionRequired`, including for a raw non-Connect 402.
4. **Display:** ANSI, CR and bidi characters are escaped; no values are shown; the schemes are listed.
5. **Receipts:** the observer gets both header names; over-limit values are dropped; `Debug` hides values; nothing is
   reported on errors.

**Part 2:**
6. **Filter matrix:**
   - every reserved exact name and prefix, even when allowlisted;
   - `authorization` with and without a bearer token;
   - defaults pass; an allowlisted extension (`X-Payment`) passes; a non-allowlisted name is refused;
   - grammar and bounds: 8 vs 9 headers, 8,192 vs 8,193 bytes, CR/LF/NUL/DEL, non-ASCII;
   - already-carried names.
7. **Retry (fake server):**
   - challenge, then responder, then success on `UpdateRef` and ticketless `AdvanceRefs`, with the same identity and
     byte-identical body, and the responder called once;
   - past the margin, a new nonce over the same body;
   - a 503 after the helper keeps the header on every attempt;
   - a second 402 is terminal after 2 attempts;
   - no policy means 1 attempt;
   - a responder error or a filter rejection sends no retry;
   - a raw 402 gives the responder empty challenges;
   - the per-transport cap.
8. **Exec helper:**
   - the happy path, with a stdin golden;
   - a non-zero exit;
   - a timeout that kills and reaps;
   - stdout over 128 KiB;
   - non-object, empty-object, non-string and duplicate-key output;
   - a relative path refused;
   - a helper that never reads stdin doesn't deadlock.
9. **Config:**
   - repo-config and `-c` refusals, with a warning snapshot;
   - `mkit config` routing and reserved-name refusal;
   - no phantom remote.
10. **The trust gate:** an untrusted endpoint never spawns the helper (a marker file stays absent), and the hint is
    printed.
11. **CLI end-to-end:**
    - push against a fake 402 server with a script helper succeeds;
    - a reserved header from the helper is refused and named;
    - no secret value ever appears in stderr or stdout;
    - the `--json` field;
    - exit codes 77 and 78.

## Gates

- `just ci-scripts` (including `check-cli-baseline.sh`) and `just ci-security`
- `cargo nextest run --locked -p mkit-core -p mkit-transport-connect -p mkit-cli --all-features`, and a
  reverse-dependency build of every transport crate
- workspace clippy, rustdoc and doctests
