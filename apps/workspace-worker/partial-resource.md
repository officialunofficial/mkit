# Public partial resource measurements

Status: **locally measured; deployment enablement remains operator-gated.**
The original 12 MiB bundle / 6 MiB witness / 4 MiB selected-content profile
is not retained. The consumer now admits 4 MiB bundles, 1 MiB deduplicated
witnesses, and 1 MiB selected content, with the existing 256 KiB per-file cap.
It additionally caps raw update packs at 3 MiB, complete updates at 4 MiB,
and replacement JSON at 3 MiB. Rebuilt path occurrences can enlarge output
independently of deduplicated input witnesses, so input limits alone are insufficient.
Portable v1 limits and legacy full-source limits are unchanged.

## Method and limits of the evidence

Measured locally on 2026-09-19, Darwin arm64, Node 24.13.0,
Miniflare 5.20260908.0-alpha / workerd 1.20260908.1, Vitest 5.0.0,
Rust 1.96.0, wasm-pack 0.14.0; optimized compiled wasm from `wasm:build`.
Docker is not needed for this Worker/Wasm/R2 harness. This is not a container
deployment or a Cloudflare production load test.

`partial-resource.test.ts` runs actual public import, wasm verification,
selected-file persistence, byte replacements, signing/export, R2 write and
digest-checked read-back in a fresh Workerd isolate per fixture. It first runs
the real nanocodex bridge against a local synthetic model response, so the
tokenizer and agent runtime are initialized. No external model/network is used.
The separate lifecycle and runner tests cover authorization, Durable Object
transactions and the descriptor-anchored Python filesystem helper.

Measurements are sampled after baseline, import, edit/persistence and read-back:

- Exported wasm memory lengths are allocation high-water marks, not live Rust
  heap or RSS. Test-only instrumentation records mkit, tokenizer and agent memories.
- CDP `Runtime.getHeapUsage` records JS used/capacity, embedder heap and backing
  storage separately. These are stage samples, **not a continuous JS peak**.
  Do not treat their sum with wasm memory as an exact isolate total: accounting
  can overlap, GC timing varies, and transient/native/runtime memory is not bounded
  by these samples. No forced collection was used.
- Host monotonic elapsed times include local scheduling and R2 emulator work.
  CDP CPU profiler samples/non-idle sample time are sampling estimates, not
  billed CPU or a CPU deadline guarantee. The JSON report retains both.
- One in-flight pipeline was measured. Concurrent workspaces, long-lived warm
  isolates, actual containers, deployment middleware and production R2 latency
  require deployment-specific validation. The local runtime does not establish
  enforcement of a production memory quota.

## Results

All four valid fixtures passed import, changed export, persistence and read-back
on the final implementation. MiB means 1,048,576 bytes. Baseline mkit linear
memory was 1.125 MiB; tokenizer 26.938 MiB; agent 1.188 MiB; JS used about 6.35 MiB.

| Fixture | Input bytes | mkit high-water MiB | All wasm MiB | Max sampled JS used MiB | Max sampled backing MiB | Import / edit / read-back ms |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Exact 1 MiB witness + four 256 KiB files | 2,097,726 | 19.813 | 47.938 | 37.17 | 11.72 | 702 / 1,138 / 7 |
| Exact 1 MiB witness + 256 distinct 4 KiB files | 2,111,080 | 18.063 | 46.188 | 13.20 | 12.36 | 1,667 / 3,362 / 10 |
| Exact 4 MiB signed bundle, including legitimate base-message bytes | 4,194,304 | 25.813 | 53.938 | 37.21 | 19.22 | 356 / 379 / 6 |
| Shared 120,000-entry CDC manifest at 256 selected paths | 3,854,081 | 23.250 | 51.375 | 8.49 | 11.25 | 539 / 1,271 / 2 |

Largest sampled JS heap capacity was 57,098,240 bytes; largest sampled embedder
heap was 902,752 bytes. Update artifacts were respectively 2,097,977; 2,116,221;
2,097,977; and 34,692 bytes. Read-back buffers are included in the measured
pipeline, not inferred from a standalone allocation. The four profiler runs
recorded 320/412/393/352 samples and approximately 1.57/4.31/1.01/1.47 seconds
of non-idle sample time, including initialization and inspector overhead.

The metadata-heavy fixture exposed two repeated-work paths, now fixed:
the adapter materializes each representation once (output still accounts per
path), and the core materializes original content once per representation for
byte comparisons. Distinct replacement bytes cannot bypass that cache, whose
content is bounded by the verified selected-byte total. The resource test supplies
256 distinct replacements for the shared representation (one is a legitimate
no-op). Structural regressions assert actual traversal/load counts; timing
is not used as a correctness assertion. Before the equality cache, shared edit
wall time varied from about 3.9 to 23.6 seconds under local load.

For comparison, the original profile, measured **without** the warmed agent and
tokenizer, reached 84,344,832 bytes of mkit linear memory, 83,980,448 bytes of JS
used heap and 94,604,964 bytes of backing storage at read-back for a valid exact
12 MiB bundle. Those observations do not support the original caps. They are
historical measurements, not a claim that the current profile has an exact RSS bound.

## Boundary and recipient checks

The Rust fixture producer calls existing signing and snapshot APIs; it does not
invent a wire grammar. Exact witness/content/file/bundle bounds succeed;
lowering the applicable bound by one rejects the **same valid fixture**. The
many-file case checks its 4 KiB per-file boundary separately. Stream overflow
tests additionally reject oversized fetches before entering wasm; there is no
full-source fallback. JS-to-wasm argument copying still precedes Rust validation;
this is not a claim of zero allocation on malformed inputs.

The downloaded manual-save and real-runner MKWU artifacts are independently
decoded by `partial_consumer_oracle.rs`, imported into pristine complete bases,
and checked with `verify_closure_store().is_complete()` **before** any oracle
writes. Signature, sole parent, changed paths and independently rebuilt root
are checked. Existing goldens are not rewritten.

## Reproduce from the repository root

Generate temporary fixtures, build the actual adapter and run the Workerd cases:

```sh
export MKIT_PARTIAL_RESOURCE_DIR="$(mktemp -d)"
cargo test --manifest-path rust/Cargo.toml -p mkit-core --test partial_consumer_resources
npm --prefix apps/workspace-worker run wasm:build
cd apps/workspace-worker
./node_modules/.bin/vitest run src/partial-resource.test.ts
cd ../..
```

Each `<fixture>.measurement.json` in that directory contains exact stage metrics.
Generated bundles and measurements are opt-in local artifacts, not committed goldens.

Exercise the independent recipient oracle against actual output artifacts:

```sh
export MKIT_PARTIAL_ORACLE_DIR="$(mktemp -d)"
cd apps/workspace-worker
./node_modules/.bin/vitest run src/partial.lifecycle.test.ts src/partial-runner.integration.test.ts
cd ../..
cargo test --manifest-path rust/Cargo.toml -p mkit-core --test partial_consumer_oracle -- --ignored
```

Both `PUBLIC_PARTIAL_BUNDLE_ORIGIN` and `PUBLIC_PARTIAL_RESOURCE_OK=1` are still
required; neither is set in the checked-in deployment configuration. The latter
is an operator assertion, not automatic resource validation. Do not set it until
these workloads and realistic concurrency pass that deployment's budgets.
