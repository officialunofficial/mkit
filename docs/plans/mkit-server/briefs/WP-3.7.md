## Purpose

Deployments can run authorization, admission and outcome delivery in a separate service that speaks
`mkit.server.hooks.v1`, such as the 3.14 mppx reference Worker or a paid-storage business layer.
- mkit signs every hook request.
- Every failure fails closed.
- The adapter is transport-agnostic: a `HookChannel` trait.
- The concrete channels come in 3.8 (native HTTP) and 3.9 (Worker service binding and Queue).

## A. Fixed (do not change)

1. **SPEC-SERVER:**
   - §6: the stages, and §6.6's validation of decisions;
   - **§7.1: request signing.** Eight headers, the `mkit-hook:v1` domain, a key id matching `[A-Za-z0-9._-]{1,64}`,
     a fresh 32-byte nonce on every attempt, a validity greater than 0 and at most 300,000 ms, over the exact body
     bytes;
   - §7.3: isolated bindings may be unsigned;
   - **§8: failure semantics.** Authorize and Admit fail closed as retryable `unavailable` with no state; any
     Outcome non-2xx is a delivery error;
   - **§18:** a core-profile server MUST NOT accept inspector configuration.
2. **`proto/mkit/server/hooks/v1/hooks.proto`** and the goldens in `rust/tests/golden/server-hooks/`, including
   `signature.json`, are the contract.
3. **The existing core seams stay as they are:**
   - the `HookSet`/`Hooks<…>` generic stage traits (`pipeline/hooks.rs`);
   - `validate_decision` (R-138);
   - the `s:` reservation rule;
   - `strip_admission_shape`;
   - `authorizer_role` composition;
   - `OutcomeSink`/`DeliveryError` (R-139).
4. **`mkit-server` stays wasm-clean** with the new feature on.

## B. Decided (do not change)

- **B1. Timeout seam (D1).**
  - Add `mkit_server::rt::Sleep`, a `Send + Sync` trait with `fn sleep(&self, d: Duration) -> BoxFuture<'static, ()>`
    (or the crate's existing future alias), and a `with_timeout(sleep, d, fut)` helper that returns an elapsed error.
  - Ship a tokio impl behind the native-only feature the crate already uses for tokio, if one exists. Otherwise leave
    the native impl to 3.4, and ship only the trait, the helper and a manual test sleeper.
  - **The Worker impl (`worker::Delay`) belongs to 3.5. Don't touch the worker crate.**
  - The remote-hook adapter enforces each call's timeout through this seam **and** passes it in the `HookRequest`,
    so channels can cancel underneath.
- **B2. Feature and codegen (D8).**
  - Add a `remote-hooks` feature to `mkit-server`, default off.
  - It uses buffa-generated `mkit.server.hooks.v1` messages only, with no connectrpc client, vendored under
    `mkit-server/generated/` and staged through `build.rs` like the transport codegen.
  - Add a regeneration entry, either a new `scripts/regen-hooks-proto.sh` or an extension of
    `regen-transport-proto.sh`, plus a freshness check wired like the transport one. `protoc` 29.3 is installed.
  - Generated code is excluded from the line cap.
  - Add a `--features remote-hooks` line to `scripts/check-wasm-dep-graph.sh` and the wasm build.
- **B3. Protocol.** Connect unary, JSON codec: `POST <base>/mkit.server.hooks.v1.HooksService/<Rpc>` with
  `Content-Type: application/json` and `Connect-Protocol-Version: 1`. No binary codec.
- **B4. Channel trait** (`hooks/channel.rs`):
  - `HookChannel` has:
    - `audience() -> Option<&str>`, the canonical hook origin;
    - `isolated() -> bool`, true only for a §7.3 binding;
    - `call(HookRequest { procedure, headers, body, timeout, max_response_bytes }) -> Result<HookResponse { status, content_type, body }, ChannelError>`.
  - `ChannelError` is `#[non_exhaustive]` with `Timeout`, `TooLarge` and `Transport(Redacted)`.
  - Channels must stop reading at `max_response_bytes + 1`, and core re-checks the size.
- **B5. Signing** (`hooks/sign.rs`), exactly §7.1.
  - The clock and the nonce source are injectable, so every `signature.json` Admit and Outcome vector reproduces
    byte for byte.
  - The key is held in `Zeroizing`.
  - Constructing a remote hook **without a signer is refused unless `channel.isolated()`** (D13).
- **B6. Mapping** (`hooks/map.rs`):
  - `Operation`, `AdmissionInput` and `Outcome` map to the proto; responses map to `AuthzFacts`/`AdmissionDecision`.
  - **Authorize Deny:** the code is kept only if it is `permission_denied`, `unauthenticated`, or `not_found` on a
    read. Anything else becomes `permission_denied`. The message is kept only if it is at most 512 bytes with no
    control characters; otherwise it is replaced.
  - **Admit:** a remote Allow **requires** `reservation_id`; an Allow without one is an invalid response. Everything
    else goes through `validate_decision`.
  - **Unknown JSON fields** are ignored (D11). Verify that buffa's JSON decoder does this, and add a test. An absent
    `oneof` is invalid.
- **B7. Per-role types (D10).**
  - `RemoteAuthorizer<C>`, `RemoteAdmission<C>` and `RemoteOutcomes<C>` share an `Arc` client and implement the
    existing stage traits, so a deployment enables any subset through `Hooks<…>`.
  - No `HookSet` change (D14).
- **B8. Failure mapping (§8).**
  - **Authorize/Admit:** each of these gives a retryable `unavailable` with nothing written:
    - a transport error;
    - a timeout;
    - a non-2xx status;
    - a Connect error body;
    - a non-JSON content type;
    - a body over 65,536 bytes;
    - malformed JSON;
    - an absent oneof;
    - a failed §6.6 check.
  - No retries inside a call (D12).
  - **Outcome:** any 2xx acknowledges; anything else is a `DeliveryError`, retried by kind 8's backoff with a fresh
    nonce and validity per attempt.
  - A deliberate Deny in a 2xx response is a decision, not a failure.
- **B9. Timeouts.** Per role, configurable; the default is 5 s.
- **B10. Credential safety.**
  - Never log request or response structs or bodies; buffa's derived `Debug` would print credential values.
  - Hold Admit bodies in `Zeroizing<Vec<u8>>`.
  - `ChannelError` text is `Redacted`.
- **B11. Deferred (D9).** Inspect, Event and CachePurge are out of scope: 5.5, 5.2 and 5.10, all Stage 2.
  - Record that the registry summary's "ContentInspector (call shape)" loses to SPEC-SERVER §18.
  - Record that reservation-id uniqueness is enforced only per partition, while §6.6 asks for it per audience;
    uniqueness is the hook's obligation.
- **B12. Docs and plan.**
  - A rustdoc module overview, and the feature in the `mkit-server` README.
  - **R-162:** B1–B11, the 3.4/3.5/3.8/3.9 hand-offs, and the 3.4+3.5 decisions listed below for the record.
  - A CHANGELOG line.

**Decided for the later 3.4+3.5 prompt; record them in R-162, don't build them:**
- **Kind-8 sink calls:** each gets a timeout; a fire stops after the first failure; `max_rows` is configurable
  (default 16).
- **Native shutdown:** a drain, with `--shutdown-drain-secs` defaulting to 10.
- **Worker Free plan:** at most 16 kind-8 sink calls per alarm.
- **CORS:** allow `Payment-Authorization`, `PAYMENT-SIGNATURE`, `Accept-Payment` and extras; expose
  `ADMISSION_EXPOSE_HEADERS`.
- **The Worker's repeated `WWW-Authenticate` bug** gets fixed.
- **ssh:** `INVALID_REQUEST "payment required: use mkit+https"`, keyed on a typed marker.

## C. Your decisions

- Module layout under `mkit-server/src/hooks/`.
- The configuration struct shapes: base URL/audience, key id, timeouts.
- How `build.rs` stages the generated code.
- The test harness: a mock channel.

## D. Escalate (stop and report) if

- Buffa's JSON codec can't match the canonical JSON in the goldens (int64 as strings, base64 bytes, oneof presence),
  and hand-written serde would pass 500 lines.
- `remote-hooks` can't be made wasm-clean.
- Production code (excluding generated) passes 1,800 lines.

## Tests (required)

- Every `signature.json` Admit and Outcome vector reproduces byte for byte.
- **Requests:** encoded requests are semantically equal to `admit.request.json`, `admit-first-attempt.request.json`,
  `authorize.request.json` and `outcome-*.request.json`.
- **Responses:** every Authorize/Admit/Outcome `*-response.json` decodes to the expected decision.
- **A mock channel for each B8 failure mode,** plus:
  - an Allow without a reservation, or with an `s:` reservation;
  - 9 challenges, or 9 headers;
  - a disallowed header name;
  - a bad scheme;
  - a description over 512 bytes;
  - an `external_ref` over 256 bytes.

  Each gives `unavailable` for Authorize/Admit, driven through a memory pipeline and asserting no writes, and a
  `DeliveryError` for Outcome.
- Deny-code and message sanitization, including `not_found` on a write becoming `permission_denied`.
- An unsigned hook on a non-isolated channel is refused.
- **Timeout** through the manual sleeper.
- **Redaction:** a tracing-capture test shows an Admit round trip, including the timeout and invalid-response paths,
  never emits the credential value.
- Unknown JSON fields are ignored.
- `cargo build --target wasm32-unknown-unknown -p mkit-server --features remote-hooks`, plus the dep-graph entry.

## Gates

- The common gate set.
- `cargo nextest run --locked -p mkit-server --all-features`, plus `-p mkit-server-native -p mkit-server-worker` to
  confirm nothing downstream breaks.
- The wasm32 build and clippy with `remote-hooks`.
- `scripts/check-wasm-dep-graph.sh`.
- The new proto freshness check.
- `just ci-server`, `ci-scripts` and `ci-security`.
