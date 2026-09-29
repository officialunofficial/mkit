## Purpose

A runtime-agnostic HTTP handler, `Pipeline::serve_http_object`, serves repository objects and ref paths per
SPEC-HTTP-OBJECTS. It covers:
- the parser;
- precedence;
- resolution and reachability;
- the byte source (extracted objects held by this repository, or the pack-entry fallback);
- Range and conditional requests;
- headers, caching and the uniform 404.

It carries seams for 4.13 (admission), 4.14b (proofs), 4.15 (tokens), 4.16 (mounting) and 5.9a (takedown). It stays
inert in Stage 1.

## A. Fixed (do not change)

1. **SPEC-HTTP-OBJECTS in full:** §2 grammar, §3 precedence, §4 resolution, §5 representations, §8 security headers.
   Where the prompt framing differs, the spec wins. In particular, ordinary content carries `Accept-Ranges: bytes`
   and supports Range, and a multi-range request gets a strict 200.
2. **The goldens** `url-parse.json` (75 rows) and the applicable rows of `response-cases.json`.
3. **SPEC-SERVER §9.6 and R-163:** extracted objects, and the byte-source rule.
4. **The uniform `not_found` of `authorize_read`**, and SPEC-SERVER's HTTP procedure names `/mkit.http.v1/GetObject`
   and `/mkit.http.v1/GetRefPath`, with the anonymous principal.
5. **R-148 and R-154:** programmatic only, and inert in Stage 1.

## B. Decided (do not change)

- **B1.** The module is `src/http_objects/` behind a **default-off `http-objects` feature**, with no new dependencies
  and wasm-clean. It has the entry point, `HttpBody` and `is_http_object_path` as in the fact sheet §2.
- **B2 (D1).** The parser has a `RepoPrefix::{Required, Omitted}` mode, so all 75 vectors run. The handler always
  uses `Required`.
- **B3 (D2). Reachability for id URLs:**
  - a bounded breadth-first walk from published refs, excluding `refs/mkit/packmap/*`, peeling tags;
  - it follows parents, trees, manifest chunks and tag targets; never remix `sources` or delta bases;
  - `max_walk_objects` defaults to 50k, plus the shared decode budget. A capped walk is a 404 with the metric
    `http_reach_capped`;
  - a positive cache lives for `reachability_lag_ms` (default 60 s), and ref-path serves warm it;
  - it sits behind a `Reachability` trait.
- **B4 (D3).** Every `?proof=1` request goes through a `ProofServer` seam that answers 416 for now; 4.14b owns proofs.
  Record in the registry that 4.14b owns all proof representations.
- **B5 (D4).** Amend the SPEC-HTTP-OBJECTS §4 sentence: *"MUST NOT be consulted to decide membership, reachability,
  or existence; it MAY supply bytes for an id already resolved in this repository and held by it."* Add a
  version-history row.
- **B6 (D5–D8). Error mapping:**
  - hook `unauthenticated` on a public read → 403;
  - `TooManyRows` → 404; a residual retryable cap → 503;
  - the pack-entry fallback over `max_inline_object_bytes` (default 64 MiB, at least `extract_min_bytes + 10`) → 503
    with a metric;
  - a ChunkedBlob with no holder → 503 with an error log, and no reassembly.
- **B7 (D9).** Add `Procedure::HttpGetObject`/`HttpGetRefPath` (`connect_path` gives the hook strings; never from
  `from_connect_path`; `is_write` false; a separate test table) and an `OpKind::HttpGet`. Don't touch `hooks/`.
- **B8.** `PipelineConfig.http_objects: Option<HttpObjectsConfig>`, cfg-gated. `Pipeline::new` refuses it without
  `indexed`.
- **B9. The byte source is holder-gated:**
  - serve `get(Object(id), range)` only when `ContentIndex::holder_record(id, (ns, repo))` exists for **this**
    repository, after membership and reachability are decided;
  - otherwise use the pack-entry fallback;
  - enforce exact lengths from `head` and the sidecar;
  - a Delta type → 404.
- **B10. Responses:**
  - the security trio on every response;
  - ETag;
  - the Cache-Control table;
  - 304 repeats the 200's headers;
  - a canned, byte-identical 404;
  - tokens and the query are held `Redacted` and never logged.
- **B11. Seams:**
  - `TokenGate` (4.15), called before the repository lookup;
  - Admission, with an `on_end(bytes, Result)` body hook (4.13);
  - `TakedownGate` (5.9a), a no-op by default;
  - `ProofServer` (4.14b).
- **B12. Inertness (fact sheet §8, all five locks):**
  - the feature is default off and enabled by no adapter or app crate; verify with `cargo tree -e features`;
  - add `cargo check -p mkit-server --features http-objects --target wasm32-unknown-unknown` to the justfile,
    `cloudbuild/ci.yaml` and `check-wasm-dep-graph.sh`;
  - the CHANGELOG and R-169 say "Stage 2, inert".
- **B13. R-169:** B1–B12, the 4.13/4.14b/4.15/4.16/5.9a hand-offs, and the flagged breakdown disagreements (a)–(e).

## C. Your decisions

Internal module shapes, walk data structures, and the harness layout.

## D. Escalate (stop and report) if

- A §3 precedence rule can't be met without touching `hooks/` or the adapters.
- Reachability can't be bounded as B3 describes.
- Production code passes 2,200 lines.

## Tests (required)

The fact sheet's §9 list (items 1–10), in full.

## Gates

- The common gate set, plus `just ci-server`, `ci-scripts` and `ci-security`.
- `cargo nextest run --locked -p mkit-core -p mkit-server --all-features`, plus `-p mkit-server-native` and
  `-p mkit-server-worker` to confirm nothing breaks downstream.
- The wasm32 check with the feature.
- `cargo tree` evidence that no adapter enables `http-objects`.
