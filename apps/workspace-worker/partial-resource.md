# Public partial resource measurements

Status: **unvalidated for enablement.** Setting `PUBLIC_PARTIAL_BUNDLE_ORIGIN`
does not turn the mode on. `PUBLIC_PARTIAL_RESOURCE_OK` must also be `1`, and
that flag is unset in this repository.

## Method

- Runtime: Node (vitest) loading `wasm-pack --target web` output via the
  worker `mkit.ts` init path. This is compiled wasm, not the native Rust
  adapter. It is not a Cloudflare isolate; Worker RSS is not claimed.
- Tooling: see `apps/workspace-worker/package.json` (`vitest`, `wrangler`)
  and `wasm-pack` from the local `wasm:build` script.
- Fixtures: committed `plain_file.bin` (~698 B) under consumer limits;
  `chunked_file.bin` (~3 MiB selected bytes) under v1 limits only (consumer
  per-file cap 256 KiB rejects it). Empty Blob / empty ChunkedBlob fixtures
  in `src/testdata/`.
- Limits: `max_witness_bytes: 8` on `plain_file.bin` is a valid-bundle
  over-witness rejection. Stream oversize uses 12 MiB+1 bytes and is not a
  witness-limit test.

## Observed (Node + built wasm)

Recorded while running `npx vitest run src/partial-wasm.test.ts` after
`npm run wasm:build` on the PR03 review-fix branch. Exact numbers belong in
the follow-up workerd pass; this file exists so enablement cannot hide behind
an origin default.

| Case | Result |
| --- | --- |
| `plain_file` consumer limits | verify succeeds |
| `chunked_file` consumer file cap | `workspace_too_large` (intended) |
| `plain_file` `max_witness_bytes: 8` | typed reject, no full-source fallback |
| 12 MiB+1 fetch stream | reject before verify |
| Workerd isolate peak wasm memory at 12/6 MiB | **not measured** (Docker container image required for full worker dry-run) |

## Caps

Advertised consumer caps remain 12 MiB bundle / 6 MiB witnesses / 256 KiB
file / 4 MiB aggregate. They are **not** justified as isolate-safe until a
workerd run of valid near-limit bundles (large-directory witnesses, 4 MiB
selected files, shared CDC metadata, candidate persist/read-back) records
baseline vs peak wasm memory, JS heap, CPU, and persistence buffers.

Do not set `PUBLIC_PARTIAL_RESOURCE_OK=1` in production without that report.
