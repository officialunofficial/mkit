# Brief: WP-3.8 + WP-3.9 (bundle 3-8-3-9)

## Purpose

Operators can run authorization, admission and outcome delivery in a separate hook service:
- **Natively,** over HTTPS with signed requests.
- **On Workers,** over an unsigned, isolated service binding.

Both use 3.7's fail-closed remote-hook adapter. That makes the 3.14 mppx reference Worker, and business layers like
it, pluggable without forking the server.

## A. Fixed (do not change)

1. **SPEC-SERVER:**
   - §6.1: https, or loopback-only http;
   - §6.3: remote admission owns abuse quota;
   - §7.1: signing, with key-role separation a MUST;
   - §7.3: isolated bindings may be unsigned;
   - §8: fail closed;
   - §18: no inspector configuration.
2. **R-162 (3.7):**
   - the `HookChannel` contract: `audience()`, `isolated()`, a size cap that returns the status plus `max + 1` bytes,
     and `Transport(Redacted)`;
   - `HookClient::new`'s refusals;
   - a single audience value shared by the hook client and kind 8 (`outcome_audience`).
3. **R-165 and R-166 (#1219):**
   - `open_with_sink`/options;
   - the drain;
   - `with_outcome_timers<S, O>`;
   - the Worker Free-plan subrequest split, fixed at relay 32 + backup 1 + outcome 1×8 + rollup ≤ 8.
4. **R-154:** the Worker fetch becomes generic over `HookSet` (3.9). There are no Stage 2 surfaces.
5. **The 3.14 reference Worker's contract:** binding `ADMISSION_HOOK`, Connect JSON, Admit and Outcome only.

## B. Decided (do not change)

### Core

- **B1.** Add `Choice<L, R>` in `pipeline::hooks`. It implements `Authorizer`, `Admission` and `OutcomeSink`, and
  forwards `is_open` and `is_default`.

### Part 1: WP-3.8 (native)

- **B2. `HttpChannel`** (`mkit-server-native/src/hooks/http.rs`, a new default `hooks` feature pulling
  `mkit-server/remote-hooks` and reqwest):
  - **Client:** reqwest 0.13 rustls with the platform verifier; `redirect(Policy::none())`; no cookies;
    `referer(false)`; one pooled client per `HookClient`.
  - **Timeouts:** a per-request `.timeout(req.timeout)` plus the core `with_timeout`.
  - **Body:** a streamed read with a cap of `max + 1` that returns the real status. Never allocate from
    `Content-Length`. Use `TooLarge` only when no status is known.
  - **Base URL:** `https`, or `http` to loopback only. Refuse userinfo, a query or a fragment. A path prefix is
    allowed. `audience()` is the canonical origin (lowercase host, default port dropped) and must pass
    `validate_audience`.
  - **Proxies (D2):** honour the environment proxy for https. **Never** for loopback http: use `.no_proxy()` and pin
    `localhost` to 127.0.0.1 and ::1 via `.resolve()`.
  - **Body buffer:** `Bytes::from_owner(Zeroizing)`.
  - **Errors:** `Transport(Redacted)`, or `Timeout` when `is_timeout()`.
- **B3. Flags** (`#[command(flatten)] HookArgs` in `hooks/config.rs`; `ServeConfig.hooks: Option<HookSettings>` with
  a redacted `Debug`):
  - **URLs (D3):** `--hook-authorize-url`, `--hook-admit-url` and `--hook-outcome-url`, each optional; a URL enables
    that role. Any of them requires `--auth auth-v2`. The outcome URL also requires `--meta sqlite`.
  - **Key (D4):** `--hook-key-file <PATH>`, one line `<key-id> <64-hex seed>`, read with the `read_secret_file`
    rules, with `MKIT_HOOK_KEY` as the fallback. Required when any URL is set.
  - **Validity:** `--hook-signature-validity-secs`, default 60, at most 300.
  - **Timeout (D5):** `--hook-timeout-secs`, default 5, at least 1, and **less than** `--unary-timeout-secs`. The
    kind-8 sink timeout is set to the hook timeout.
  - **Authorizer role (D7):** `--authorizer-role check|authority`, allowed only with an authorize URL.
- **B4. Key-role separation (D6).**
  - `check_key_separation`: refuse a hook seed equal to any ticket-key secret, the enc server seed (compare inside
    `open`, after `load_server_key`, since it may be created on first run), or the URL-token active seed, plus any
    retired URL-token public key equal to the hook public key.
  - If the URL-token key flag from 1.30b/R-153 exists on the base, include it. If not, leave an explicit `TODO` plus an
    R-167 hand-off.
- **B5. Wiring:**
  - `build_services`, `with_meta` and `open_inner` become generic over `H: HookSet + 'static`.
  - Add `open_with(cfg, hooks, sink, options)`.
  - `open(cfg)` builds from `cfg.hooks` with `Choice`s:
    - `Choice<OpenAuthorizer, RemoteAuthorizer<HttpChannel>>`;
    - `Choice<DefaultAdmission, RemoteAdmission<HttpChannel>>`;
    - the sink `Choice<NoOutcomes, RemoteOutcomes<HttpChannel>>`, with `real_sink = remote`.
  - `server_audience` = `outcome_audience(cfg)`.
  - Roles sharing a base URL share one `Arc<HookClient>`.
  - The enc/ssh sibling inherits the hooks.
  - `open_with_sink` together with `--hook-outcome-url` is a `CONFIG_ERROR`.
- **B6. Key list (D14):** `mkit-server hook-key-list --hook-key-file <PATH>` prints the §7.2 JSON.

### Part 2: WP-3.9 (Worker)

- **B7. `BindingChannel`** (`mkit-server-worker/src/hooks/binding.rs`, over `env.service("ADMISSION_HOOK")`):
  - `audience() = None` and `isolated() = true`;
  - the URL is `https://mkit-hook.invalid` + the procedure;
  - `RequestRedirect::Manual`;
  - a streamed body cap of `max + 1`;
  - the timeout via `WorkerSleep`;
  - URL building and the cap as pure, host-testable helpers.
- **B8. Vars (D10)**, in `hooks/config.rs`:
  - the `ADMISSION_HOOK` binding;
  - `HOOK_ROLES`: a comma list of `authorize`, `admit` and `outcome`, required with the binding and without a
    default. Either one without the other is a `ConfigError`;
  - `HOOK_TIMEOUT_MS`: default 5000;
  - `AUTHORIZER_ROLE`.

  Config errors follow the existing rule: every RPC answers `unavailable`.
- **B9. Generic entry points:**
  - `adapter::fetch_with(req, env, make_hooks)` and `serve_with<H: HookSet + 'static>`;
  - `ns_object_with(state, env, class, make_sink)`;
  - `fetch` and `ns_object` keep their signatures and build from vars;
  - `WorkerPipeline` becomes generic;
  - the outcome sink `Choice<NoOutcomes, RemoteOutcomes<BindingChannel>>` in every outcome class, with
    `audience = cfg.audience`, via the Worker `outcome_audience` helper.
- **B10. Budget (D15):** count one subrequest per binding call.
  - Fetch path: at most +2 per RPC (Authorize + Admit).
  - Alarms: bounded by the fixed Free 1×8 kind-8 split.
  - Document it in the Worker README.
- **B11. Wrangler harness:**
  - `wrangler.hooks.jsonc` (test-only);
  - a small JS stub hook Worker that answers Admit/Outcome and records outcomes;
  - `wrangler.jsonc` gains a commented-out `services` example.
- **B12. Deferred (D11b, D12):**
  - **The Queue outcome sink:** it needs a SPEC-SERVER §7.3/§8 amendment with human review. It becomes a new registry
    row, **3.9b** ("Worker Queue outcome sink + spec"), Stage 2, deps 3.9.
  - **A signed Worker webhook via `fetch`.**
  - Record both in R-168.

### Shared

- **B13. Test stub:** `mkit-server-conformance/src/stubs/hook.rs`, feature `stubs`, like `fake_s3`. It is an axum
  Connect-JSON server with:
  - a §7.1 verifier: key list, audience, window, digest, nonce replay;
  - scripted answers;
  - recorded calls.

  3.12 builds MPP on top of it.
- **B14. Docs:**
  - CONTAINER.md and the native README: hook flags, key file, TLS/no-redirect/loopback rules, and "remote admission
    replaces the default abuse quota".
  - The vcs-worker README: the binding must have no public route (a `workers.dev` or preview route disabled), the
    budget, and `HOOK_ROLES`.
  - **R-167:** B1–B6, plus the key-separation hand-off. **R-168:** B7–B12.
  - Add registry row 3.9b.
  - A CHANGELOG line per WP.

## C. Your decisions

- Module and type names.
- The `open_with` options struct shape.
- How the JS stub Worker records calls for tests.

## D. Escalate (stop and report) if

- reqwest can't do the streamed cap or the proxy/loopback rules without a different client.
- `HookSet`-generic Worker fetch requires a DO class or migration change.
- Production code passes 2,200 lines.

## Tests (required)

**Native `HttpChannel`:**
- http to a non-loopback host is refused;
- userinfo, a query or a fragment is refused;
- a canonical origin;
- a 3xx is not followed (Admit gives `unavailable`);
- an oversize body gives the status plus exactly `max + 1` bytes, and an oversized 2xx Outcome still acknowledges;
- a timeout cancels the call;
- connection refused fails closed;
- a self-signed https fixture fails verification;
- loopback ignores `HTTP_PROXY`.

**Native config:**
- hooks without auth-v2 are refused;
- an outcome URL with fs-layout is refused;
- key file: missing, group-readable, symlinked, or with a bad id, all refused;
- a seed equal to a ticket key, the enc key or the URL-token key is refused;
- a hook timeout ≥ the unary timeout is refused;
- a role flag without an authorize URL is refused;
- `open_with_sink` together with an outcome URL is refused.

**Native e2e with `stubs/hook.rs`:**
- signatures verify;
- the Admit audience;
- Authorize deny and allow;
- Authority role;
- the outcome is delivered after commit;
- with the hook down, retries carry a fresh nonce until a 2xx;
- the drain delivers what is due;
- `Choice` forwards `is_open` and `is_default`;
- the enc sibling hits the hook;
- no credential values in tracing.

**Worker host:**
- the `HOOK_ROLES` matrix;
- the URL and cap helpers;
- an audience mismatch is retained;
- `fetch_with` compiles with a custom `HookSet`;
- wasm32 clippy and build.

**`wrangler dev` with the JS stub:**
- Admit allow is followed by exactly one Outcome for its reservation;
- a challenge gives a 402;
- a stopped stub makes writes answer `unavailable`;
- `vcs-worker-conformance.sh` still passes with hooks off.

## Gates

- The common gate set, plus `just ci-server`, `ci-scripts` (including `check-cli-baseline.sh`; reqwest must stay out
  of the CLI graph) and `ci-security`.
- `cargo nextest run --locked -p mkit-server -p mkit-server-native -p mkit-server-worker -p mkit-server-conformance --all-features`.
- wasm32 clippy for `mkit-server` (`remote-hooks`) and `mkit-server-worker`, the worker build, and
  `check-wasm-dep-graph.sh`.
- `scripts/vcs-worker-conformance.sh` default phase, plus the hook harness, with `VCS_CONFORMANCE_PORT` set to a free
  port.
