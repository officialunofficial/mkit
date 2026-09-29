## Purpose

Both adapters can plug in a real `OutcomeSink` safely. A slow or failing sink can't stall other timers or blow the
Workers subrequest budget. Outcomes committed during a native shutdown are delivered before exit. Browsers can send
payment credentials and read receipts through CORS. Credentials never reach logs. ssh and enc clients that hit a
payment requirement get one clear, fixed frame.

## A. Fixed (do not change)

1. **STC §5.1:** the header sets, including `Accept-Payment`, and repeated `WWW-Authenticate` fields preserved.
2. **SPEC-SERVER:**
   - §6.3: credential headers;
   - §6.5–§6.6: outcomes;
   - §8: failure semantics.
3. **R-138 and R-139:**
   - kinds 8 and 9 are registered with `NoOutcomes` on both adapters (#1212);
   - `ADMISSION_EXPOSE_HEADERS` in `mkit_server::pipeline`;
   - `OutcomeSink`/`DeliveryError`;
   - the sink timeout was deferred to here.
4. **R-162 (3.7):** the `rt::Sleep`/`with_timeout` seam, the `HookChannel`, and the decisions recorded for this bundle.
5. **ssh `ErrorCode` is frozen.** SPEC-RPC is frozen.
6. **Stage 1:** no indexed mode, leases, GC, takedown, receipts or admin are exposed. Native hook flags (URL, keys)
   are **3.8's**. The Worker binding channel, Queue sink and `HookSet`-generic fetch are **3.9's**.

## B. Decided (do not change)

### Part 1: WP-3.4

- **B1. The kind-8 hardening** (core, `timers/outcome_delivery.rs`):
  - each sink call is wrapped in `with_timeout(sleep, sink_timeout)`, default 5 s, configurable;
  - a fire **stops calling the sink after its first failure or timeout**, and reschedules with the existing backoff;
  - `max_rows` is configurable, default 16;
  - the cursor rotation still guarantees fairness;
  - a timeout is a `DeliveryError`.
- **B2. The native `Sleep`:** a tokio implementation in `mkit-server-native`. Add the tokio `time` feature there if
  needed. Core stays `sync`-only.
- **B3. The native sink seam:**
  - `sqlite_timer_registry<…, O: OutcomeSink + 'static>` plus an embedder entry point (C1). The binary stays on
    `NoOutcomes`; 3.8 adds flags.
  - A non-`NoOutcomes` sink with `--meta fs-layout`, which has no timer driver, is a config error.
- **B4. The shutdown drain:**
  - the timer driver gets a separate drain signal;
  - order: listeners drain, then the driver runs `run_due` for partitions due at or before now, until nothing is due or
    `drain_timeout` passes, then exits;
  - the flag is `--shutdown-drain-secs`: default 10, and 0 disables it.
- **B5. CORS (native):**
  - **Allow:** the current list plus `Payment-Authorization`, `PAYMENT-SIGNATURE`, `Accept-Payment` and the configured
    extra credential headers.
  - **Expose:** `ADMISSION_EXPOSE_HEADERS`.
  - These are always on when CORS is enabled.
  - A preflight never reaches admission. Add a counting-hook test.
- **B6. Redaction (native):** build the router `Redactor` from the same configured extra-credential list. This fixes the
  clone-before-extras order at `config.rs` (~1162 in the fact sheet), so an extra credential header is never printed in
  HTTP traces.
- **B7. The ssh/enc payment frame (D6):**
  - add a typed marker, `ServerError::is_transport_admission_required()`. It is set when a TransportIdentity pipeline
    gets a Challenge (unary or streaming), or a reserved ticketless UploadPack (the `Aborted` row is still written);
  - map it **before** #1210's `permission_denied` → "write not permitted" branch in `ssh/verbs.rs`, to
    `ERROR_CODE_INVALID_REQUEST` with the message `"payment required: use mkit+https"` and empty `details`, so it is
    never read as a ref conflict;
  - for streaming, emit it after the drain, the same timing as today's open failures;
  - the client sees a non-retryable `RemoteError`;
  - pin all three rows with `assert_error` in `mkit-server/src/ssh/tests.rs`, plus an `enc_listener` integration test
    with a challenging in-process `Admission`;
  - add an informative line to `docs/SSH-SECURITY.md`.

### Part 2: WP-3.5

- **B8. The Worker `Sleep`:** a `worker::Delay` race implementation in `mkit-server-worker`.
- **B9. The sink seam:** `with_outcome_timers<S, O: OutcomeSink + 'static>` takes the sink, with `NoOutcomes` as the
  default.
- **B10. The plan budget (D4):**
  - on the **Free** plan, at most **16** kind-8 sink calls per alarm (`max_per_tick` 1 × 16 rows, or 4 × 4);
  - on **Paid**, 4 × 16;
  - always budget by plan;
  - correct the Free-plan comment (relay 32 + backup 1 + rollup + outcome).
- **B11. CORS (Worker):**
  - **Preflight allow:** `CORS_ALLOW_HEADERS` plus `authorization`, `payment-authorization`, `payment-signature` and
    `accept-payment`.
  - **Every response** gets `Access-Control-Expose-Headers` from `ADMISSION_EXPOSE_HEADERS`.
  - Keep the change local to `mkit-server-worker`. Don't change the shared `mkit-worker-common::with_cors`.
- **B12. Repeated headers:** copy multi-valued response headers such as `WWW-Authenticate` with **append**, not
  `Headers::set`. Put this in a new host-testable helper local to `mkit-server-worker`. If the shared
  `copy_response_headers` must change, it may, provided repo-worker keeps working, and you note it.
- **B13. Redaction (Worker):** there is no header logging to fix. Add a capture test that a 402 or deny path emits no
  credential values. Add a README note that platform invocation-log capture must be checked at staging (D15).
- **B14. Tests that need an observable sink:** the wrangler delivery and backpressure cases go to 3.13. Host tests
  here.

### Both parts

- **B15. Docs and plan:**
  - **R-165:** B1–B7.
  - **R-166:** B8–B14.
  - The native and Worker READMEs.
  - A CHANGELOG line per WP.

## C. Your decisions

- **C1:** the embedder entry-point shape (`open_with_sink`, or a generic `Services`).
- **C2:** the drain signal mechanism.
- **C3:** the Free vs Paid split: 1 × 16 or 4 × 4.
- **C4:** the helper and module names.

## D. Escalate (stop and report) if

- The ssh frame can't be emitted without changing the frozen `ErrorCode` set.
- The Worker budget can't be enforced per plan without a DO migration.
- Production code passes 1,500 lines.

## Tests (required)

**3.4:**
- **Kind 8, with a manual sleeper:**
  - a hanging sink is cut at the timeout;
  - the first failure stops the fire and reschedules;
  - `max_rows` is honoured;
  - no row is lost.
- **Native drain:**
  - an outcome committed during listener drain is delivered before exit, with a capturing sink through the embedder
    seam;
  - the drain deadline is respected when the sink hangs.
- A real sink with fs-layout is a config error.
- **CORS:** the preflight allows the payment headers and extras and never calls `Admission`; responses carry the
  expose list. Extend `tests/server_basics.rs`.
- **Tracing capture:** `Payment-Authorization`, `PAYMENT-SIGNATURE`, `Authorization: Payment …` and a configured extra
  never appear.
- **ssh:** the three B7 rows give the exact frame; UpdateRef stays non-CAS on the client; the reserved UploadPack still
  writes one `Aborted`; the enc test passes.

**3.5:**
- `with_outcome_timers` with a capturing or failing sink;
- the per-plan budget: at most 16 sink calls per alarm on Free;
- the timeout via a fake sleeper;
- the CORS header strings;
- repeated `WWW-Authenticate` is preserved;
- the redaction capture.

## Gates

- The common gate set, plus `just ci-server`, `ci-scripts` and `ci-security`.
- `cargo nextest run --locked -p mkit-server -p mkit-server-native -p mkit-server-worker -p mkit-server-conformance --all-features`.
- wasm32 clippy for `mkit-server` and `mkit-server-worker`, and the worker build.
- `scripts/vcs-worker-conformance.sh` default phase, with `VCS_CONFORMANCE_PORT` set to a free port.
