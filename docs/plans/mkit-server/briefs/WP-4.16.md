## Purpose

Opt-in adapters mount HTTP object serving on axum and on the Workers fetch path:
- raw escaped paths;
- streaming, Range and HEAD;
- CORS on every response;
- query-free logs;
- the URL-token key document;
- URL-token keys with full key separation.

Everything stays **off** in Stage 1.

## A. Fixed (do not change)

1. **SPEC-HTTP-OBJECTS §2** (the raw path/query, including a trailing empty `?`), **§5, §6 and §8** (CORS, 302).
2. **R-136, R-153 and R-169:** the URL-token flags and vars, and key separation (hook, ticket and enc keys), belong
   here.
3. **Private responses** suppress shared caching (R-178).
4. **Stage 1 inertness.**

## B. Decided (do not change)

- **B1. Default-off adapter features** forward `http-objects`, and are absent from:
  - native defaults;
  - the Worker/app features;
  - `scripts/release/mkit-server-features`.

  Mounts require explicit programmatic indexed + HTTP configuration **and** a mount opt-in.
- **B2. Dispatch:**
  - by `/-/`, with RPC dispatch exact;
  - never in opaque mode;
  - stream bodies without buffering;
  - preserve repeated headers and Content-Length;
  - no HEAD body on any status.
- **B3. CORS on every response** (errors, 304, challenges, preflight):
  - default `*`, or a configured-origin echo plus `Vary: Origin`;
  - no Allow-Credentials;
  - OPTIONS returns 204;
  - the §8 lists plus `ADMISSION_EXPOSE_HEADERS`.
- **B4. Logging:** query-free tracing on native, and redacted Worker URL diagnostics.
- **B5. The key document:** `/.well-known/mkit-url-token-keys.json`, mounted outside the bearer/payment gates:
  - active and retained keys, via `key_set_json`;
  - `public, max-age=300`;
  - read CORS.
- **B6. Keys and configuration:**
  - native, feature-gated `--url-token-key-file` and `--url-token-ttl`;
  - Worker secret `URL_TOKEN_KEYS` (key-file grammar) and `URL_TOKEN_TTL` (seconds);
  - key separation against ticket secrets, hook keys and the native enc key, comparing active and retired public
    keys via narrow public-key introspection, not seed export.
- **B7. 302:** disabled by default. Allowed only for a public ref GET/HEAD without a proof, after the earlier checks,
  as a relative repository-preserving object URL. Disabled whenever admission is configured.
- **B8. Docs and plan:** R-179, the READMEs and a CHANGELOG line. Deployment manifests are unchanged; production
  exposure is 4.18/5.2.

## C. Your decisions

Mount module layout and option-struct shapes.

## D. Escalate (stop and report) if

- Streaming or HEAD can't be bridged on Workers without buffering.
- Production code passes 2,200 lines.

## Tests (required)

The fact sheet's §9 bullets for the adapters, plus the Stage 1 feature/config/route inertness tests and
`IssueObjectUrl = unimplemented`.

## Gates

- The common gate set, plus `just ci-server`, `ci-scripts` and `ci-security`.
- `cargo nextest run --locked -p mkit-server -p mkit-server-native -p mkit-server-worker --all-features`.
- wasm32 clippy and the worker build, with and without the feature.
- `scripts/check-release-artifact-features.sh`.
