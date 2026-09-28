## Purpose

This WP specifies how a browser, a CDN, or a verifier fetches repository content over plain HTTP: the URL forms, the
status order, the caching and security headers, the disclosure proofs (including the new multi-chunk span bundle),
URL-token placement, read admission, and CORS. WP-4.12–4.16 implement it.

## A. Fixed (do not change)

1. **PRD §6.6:**
   - the two URL forms (by object id; by ref and path);
   - 404 before 451;
   - `ETag` = the object id;
   - ref-path responses are `no-cache`;
   - public content is `public, immutable`; private content is `private`;
   - `?proof=1` proves path → tree → commit → signature;
   - every read goes through the Authorizer and, optionally, Admission.
2. **PRD §6.7:** pending content is never served to non-writers over HTTP.
3. **The user's decisions** (2026-09-27):
   - **M4-a:** a byte-range proof is requested by **query**, `?proof=1&range=a-b`, **never** through the `Range`
     header. The proof is its own representation. This deliberately reinterprets the PRD's "a Range request can
     include a byte-range disclosure proof"; state it in the spec's rationale and the PR body.
   - **M4-b:** multi-chunk ranges use an **MKDS container of existing MKDP v2 bundles**, **not** a new MKDP payload
     kind. MKDP v2 and its goldens are unchanged.
4. **SPEC-DISCLOSURE (MKDP v2):**
   - payload kinds 0 `Object`, 1 `Chunk`, 2 `Range`; kind 3 is reserved (#1027);
   - a range can't cross a chunk boundary;
   - the bundle cap is 64 MiB.
   - The builder is `build_disclosure_from` and the verifier is `verify_disclosure` (`mkit-core` `verify.rs`).
5. **SPEC-WRITE-GRANTS §9.4 URL tokens:**
   - the format is `mkit-url-token:v1`;
   - the targets are `object:<hex>` and `path:<ref>:<b64url path>`;
   - every verification failure is `not_found`;
   - tokens resolve in the published view;
   - the URL form, cache headers and key-set publication are delegated to this spec.
6. **SPEC-SERVER §9.6:** extracted copies are keyed by object id and are never observable or used as delta bases.
   Per-repository authorization of HTTP reads is delegated here. §9.1: decoding needs indexed mode.
7. **STC:**
   - §5.1: 402 is `no-store` and receipts are `private`; the credential and payment headers; preflight is never
     charged;
   - §7.4: the repository grammar;
   - new request headers are named `X-Mkit-*`.
8. **SPEC-REFS §3:** a ref segment may be exactly `-`; names are ≤ 512 bytes; only `refs/` names are served.
9. **SPEC-OBJECTS §4.1:** tree entry names may contain `-`, `%`, `?`, `#`, spaces and non-UTF-8 bytes.
10. **No proto changes** (00-plan line ~72: 4.11 isn't a proto WP). Nothing is added to `AdmitRequest` or
    `Principal`.

## B. Decided by the orchestrator (do not change)

### B.1 Placement

- **New:** `docs/specs/SPEC-HTTP-OBJECTS.md`, registered in `docs/specs/README.md`.
- **MKDS:** a new section of SPEC-DISCLOSURE, bumping its doc version 3 → 4.
- **Small amendments:**
  - **SPEC-SERVER §5:** a read-reservation rule. The abandonment bound for HTTP reads isn't keyed on an auth
    validity interval.
  - **SPEC-SERVER §6.2:** HTTP read procedure strings.
  - **STC:**
    - §5.1: a cross-link;
    - §7.4: "Host, path and forwarded headers MUST NOT select the repository" is scoped to Connect RPCs; HTTP
      serving selects the repository by path and ignores `X-Repository`.
  - **SPEC-WRITE-GRANTS §9.4:**
    - the URL form (a `token=` query parameter);
    - the key-set publication;
    - **the token path range becomes 0–1024 bytes, where an empty path is the root tree.** WP-2.11 isn't
      implemented, so no code or goldens change.

### B.2 URL grammar (ABNF in the spec)

```abnf
http-path    = repo-prefix "/-/" ( objects-form / refs-form )
repo-prefix  = "/" repository / ""        ; "" only on single-repository deployments
repository   = <STC §7.4 grammar>         ; lowercase; otherwise 400
objects-form = "objects/" object-id
object-id    = 64HEXLC                    ; uppercase is 400
refs-form    = ref-name "/-/" [ file-path ]   ; second "/-/" mandatory; empty path = root tree
ref-name     = "refs/" ref-seg *( "/" ref-seg )  ; SPEC-REFS §3, <= 512 B, no percent-encoding
file-path    = path-seg *( "/" path-seg ) ; each segment percent-decoded to one entry name, total 1..1024 B
query        = param *( "&" param )
param        = "proof=1" / "range=" 1*DIGIT "-" 1*DIGIT   ; inclusive, like byte-range-spec
             / "commit=" 64HEXLC / "path=" pct-path / "token=" url-token
```

- The ref ends at the first segment that is exactly `-`, so refs with a `-` segment are not addressable. Document
  this limitation.
- Percent-encoding inside a ref → 400.
- An unknown or repeated parameter → 400.
- `range` requires `proof=1`.
- On `objects-form`, `proof=1` requires both `commit` and `path`.
- **Every 400 depends only on the URL text**, never on stored state.
- State why these routes can't collide with `/.well-known/`, `/mkit.transport.v1.*` or `/grpc.*`.

### B.3 Status order (first match wins)

1. `OPTIONS` preflight → 204. It never requires auth or payment.
2. A method other than GET or HEAD → 405, with `Allow`.
3. URL or query syntax → 400.
4. **Bearer gate:** in a bearer-gated deployment, HTTP routes need the bearer like the RPCs do. OPTIONS and the
   key-set document are exempt.
5. **Token:** if present, check its syntax and signature against the key set **before** the repository lookup.
   - A missing repository, or a private repository with a missing or invalid token → 404, byte-identical in status,
     headers and body.
   - A token on a public repository is ignored, and still redacted from logs.
6. **Authorizer:** deny → 403, or 404 if the repository is private or the hook says `not_found`.
7. **Resolve in the published view** (the caller's view is always the published view; signed-read HTTP GETs are
   deferred):
   - peel tags;
   - a missing ref, a non-tree path component, a missing entry, an unreachable commit context, or an id that isn't
     a member or isn't reachable → 404 `no-store`;
   - the global CAS is never consulted.
8. **451 is reserved** for M5 tombstones. The reachability walk MUST NOT descend through a tombstoned object. M4
   never returns 451.
9. `If-None-Match` matches → 304, free of charge.
10. **An unsatisfiable `Range`** → 416 with `Content-Range: bytes */N`.
    - A multi-range request is served as a 200.
    - A proof range that is out of bounds or over the cap → 416.
11. **Admission** (if configured for reads): challenge → 402; deny → 403.
12. Serve 200 or 206. Proofs are 200. A redirect, if enabled, is 302.

### B.4 Headers

Use the research table below as normative content:

| Response | Headers |
|---|---|
| Object 200/206 | <ul><li>`ETag: "<64hex id>"`: the leaf id on ref paths</li><li>`Accept-Ranges: bytes`</li><li>`Content-Range` on 206</li><li>`If-Range` honoured</li><li>Blob and ChunkedBlob content: `application/octet-stream`</li><li>Other object types: canonical bytes, `application/vnd.mkit.object`</li><li>`X-Mkit-Object-Type` and `X-Mkit-Object`, plus `X-Mkit-Commit` on ref paths</li></ul> |
| `Cache-Control` | <ul><li>Public id URL: `public, max-age=31536000, immutable`</li><li>Public ref path: `public, no-cache`</li><li>Private id URL: `private, max-age ≤ token remaining, immutable`</li><li>Private ref path: `private, no-cache`</li><li>**Any response where read admission ran: `private`**</li><li>402 and all errors: `no-store`</li><li>304 repeats the 200's `Cache-Control` and `ETag`</li></ul> |
| Security | <ul><li>`X-Content-Type-Options: nosniff`</li><li>`Content-Security-Policy: sandbox; default-src 'none'`</li><li>`Referrer-Policy: no-referrer`</li><li>Serving from a dedicated origin is a SHOULD</li></ul> |
| Proof 200 | <ul><li>`application/vnd.mkit.disclosure` (MKDP) or `application/vnd.mkit.disclosure-span` (MKDS)</li><li>`Accept-Ranges: none`; any `Range` header is ignored</li><li>`ETag: "<commit>.<leaf>.<selector>"`</li><li>Commit-pinned proofs: `public, immutable`</li><li>Ref-path proofs: `no-cache`</li></ul> |
| 402 | <ul><li>Pass through `WWW-Authenticate` and `PAYMENT-REQUIRED`</li><li>`no-store`</li><li>The body is the `AdmissionChallenge` in canonical protobuf JSON</li><li>Receipts pass through on 200 with `private`</li></ul> |

### B.5 Proofs

- **Ref paths:**
  - `?proof=1` → an MKDP `Object` bundle. For a ChunkedBlob, the payload is the manifest.
  - `?proof=1&range=a-b` → an MKDP `Range` bundle if the range lies within one chunk or plain blob, otherwise
    **MKDS**.
- **Object-id URLs** accept a proof only with `commit` and `path`. The resolved leaf must equal the id and the
  commit must be reachable; otherwise 404. These proofs are immutable.
- **Informative:** the ref → commit binding is the server's claim until M5 receipts.

### B.6 MKDS (SPEC-DISCLOSURE new section)

```text
"MKDS" | version u8 = 1 | commit_id [32] | offset u64 | len u64
anchor: Vec<u8>        ; MKDP Range over chunk `first` (offset 0, len 1) with a complete chunk_len_proofs set
chunks: Vec<Vec<u8>>   ; 2..=N MKDP Chunk bundles, indices first..=last, in order
```

- Encoding follows MKDP conventions (big-endian, varint lengths).
- No trailing bytes are allowed, and the total is capped at 64 MiB.
- A per-deployment proof-range cap is RECOMMENDED (for example 8 MiB).
- **The verifier checks:**
  1. every inner bundle verifies against `commit_id`;
  2. all bundles share the same path, leaf id, `total_size`, `chunk_size` and chunk inner root;
  3. the anchor's absolute offset gives the start of chunk `first`;
  4. chunk lengths come from the canonical bytes;
  5. the range lies inside the span, and the last chunk is actually needed;
  6. the output is the concatenated content sliced to [a, b).
- Give each check its own reject reason.

### B.7 Tokens and the key set

- **The token goes in the `token=` query parameter only.** Header and cookie forms are deferred (a future
  `X-Mkit-Url-Token`).
- **Mapping:** an id URL is `object:<hex>`; a ref path is `path:<ref>:<b64url>` (an empty path is the root tree).
- The `token` parameter MUST be redacted from logs and traces.
- **The key set** uses the SPEC-SERVER §7.2 key-list JSON shape, with `keyId` = the §9.4 32-hex id. It is published
  at `GET /.well-known/mkit-url-token-keys.json` with `max-age=300`.

### B.8 Redirects, admission, reachability and CORS

- **Redirects:**
  - serve directly by default;
  - an option allows a 302 to the relative id URL (`no-cache`) for a **public** ref-path GET or HEAD **without**
    `proof`;
  - private and proof requests are never redirected.
- **Read admission:**
  - the principal is `anonymous`, including token holders;
  - `procedure` is `/mkit.http.v1/GetObject` or `/mkit.http.v1/GetRefPath`;
  - `declared_bytes` = the body bytes after Range; `pack_id` is empty;
  - HEAD is admitted like GET and records `ReadServed{bytes_served: 0}`;
  - `ReadServed.bytes_served` = the bytes actually sent;
  - a failure before the first byte → `Aborted(INTERNAL)`.
- **Reachability:**
  - a ref path is reachable by construction;
  - an id URL: check membership first (a cheap, uniform 404), then reachability from a published ref value;
  - a rewind or delete takes effect within a deployment-configured `reachability_lag`; tombstones take effect
    immediately;
  - **informative:** CDN copies of orphaned objects persist until `max-age`, and purges happen only on takedown,
    suspension and visibility change.
- **Indexed mode is required** for HTTP serving. An opaque deployment doesn't expose these routes (state the status
  code: 404 for everything, or no route; your choice, C).
- **CORS:**
  - `Access-Control-Allow-Origin: *` by default; with configured origins, echo the origin with `Vary: Origin`;
  - never `Access-Control-Allow-Credentials`;
  - methods: GET, HEAD, OPTIONS;
  - allowed request headers: `Range`, `If-None-Match`, `If-Range`, plus the four STC §5.1 credential headers;
  - exposed response headers: `ETag`, `Content-Range`, `Accept-Ranges`, `Content-Length`, `X-Mkit-Commit`,
    `X-Mkit-Object` and `X-Mkit-Object-Type`, plus the four payment headers.

### B.9 Golden vectors

**New: `rust/tests/golden/http-objects/`**
- a URL-parse table (JSON): good cases, `-`-segment refs, percent-encoding, and every 400 rule;
- a response-case table (JSON): status and header expectations per row of the B.3/B.4 matrix;
- proof bodies from `build_disclosure_from` over the existing disclosure fixture repo: an `Object` for a shallow
  file, the root tree, a chunk, a blob range, and an in-chunk range;
- MKDS accept and reject vectors: non-contiguous chunks, mixed commits, a mismatched leaf, a missing or incomplete
  anchor, a range outside the span, a superfluous last chunk, wrong magic or version, a trailing byte, and oversize.
  Build them with a **test-local** encoder and a **test-local reference verifier**; the product verifier is WP-4.14.
- a generator test, gated by `MKIT_WRITE_GOLDEN=1` like `golden_disclosure`, with a `MANIFEST.txt`.

**Deferred:** token-bearing URLs (2.11/4.15), 451 bodies (M5), and the MKDS product verifier (4.14).

### B.10 Plan edits

Add row **R-109**:

> WP-4.11 decisions.
> - **M4-a:** a query-selected proof range; **M4-b:** MKDS over MKDP v2 (user, 2026-09-27).
> - The URL-token path may be empty (the root tree).
> - HTTP serving selects the repository by path (STC §7.4 is scoped to RPCs).
> - Indexed mode only; the bearer gate applies.
> - Deferred:
>   - signed-read HTTP GETs;
>   - an object-id field on `AdmitRequest`, and a token `Principal` (both need a proto WP);
>   - an O(1)-offset proof builder: 4.10 records chunk offsets, and 4.14 adds a boundary-aware builder plus an
>     in-memory `ObjectSource` prefetch on Workers.
> - 4.14's file list gains the mkit-core and mkit-wasm MKDS verifier.
> - 4.16 adds HEAD to the native CORS layer and redacts query strings.

Update the 4.14 and 4.16 rows' notes accordingly.

## C. Your decisions

- The spec's section structure and rationale prose.
- The opaque-mode behaviour (B.8).
- The JSON shape of the golden tables.
- The exact reject-reason names.

## D. Escalate (stop and report) if

- Any B item contradicts a merged normative rule that a citation can't reconcile.
- Producing the goldens needs a non-test code change in `mkit-core`.
- The spec plus amendments exceed ~1,500 changed lines (excluding goldens).

## Gates

- `bash scripts/check-spec-status.sh`
- `cargo nextest run --locked -p mkit-core --all-features` (the golden generator test, in check mode)
- `just ci-server`
- `git diff origin/feat/mkit-server -- proto/` is empty
