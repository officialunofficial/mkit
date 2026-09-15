# mkit-wasm

WebAssembly bindings for mkit &mdash; a content-addressed VCS for creative work. The package exposes the pure byte-format and crypto paths from `mkit-core` and `mkit-attest` so they can run anywhere a modern JS runtime can: browsers, Cloudflare Workers, Bun, Deno, Node.

No filesystem or network access is performed inside the wasm module. It is a stateless library of object encoders, hashers, signers, verifiers, FastCDC chunkers, delta encoders, and Bao streaming primitives.

## Install

```sh
bun add @officialunofficial/mkit-wasm
# or
npm i @officialunofficial/mkit-wasm
# or
pnpm add @officialunofficial/mkit-wasm
```

The published package is built with `wasm-pack --target bundler`. It works out of the box with esbuild, Wrangler, Vite, webpack, and Rollup. For direct `<script type="module">` usage without a bundler, build the crate yourself with `--target web`.

## Usage

The package is built `--target bundler`, so it **auto-initializes on import**
&mdash; there is no default `init` export and nothing to `await`. Just import the
functions you need:

```ts
import {
  blake3_hex,
  commit_verify,
  attest_build,
  attest_verify,
} from "@officialunofficial/mkit-wasm";

const id = blake3_hex(new TextEncoder().encode("hello"));
console.log(id); // 64-char lowercase hex
```

This works out of the box with esbuild, Vite, webpack, Rollup, and Wrangler
(Cloudflare Workers).

### Explicit init (Bun/some Workers setups)

A few bundlers don't auto-instantiate the wasm at import time, leaving every
export throwing `__wbindgen_add_to_stack_pointer is not a function`. For those,
the package also exports `mkit_wasm_init(module)`: compile a
`WebAssembly.Module` yourself and inject it once before the first call.

```ts
import { mkit_wasm_init, blake3_hex } from "@officialunofficial/mkit-wasm";
// `wasmModule` is a WebAssembly.Module you compiled/imported for your runtime.
mkit_wasm_init(wasmModule);

const id = blake3_hex(new TextEncoder().encode("hello"));
```

For direct `<script type="module">` use without a bundler, build the crate
yourself with `wasm-pack --target web` (that variant exports the classic
`await init()` default).

## Exported functions

Content-addressing and objects:
- `blake3_hex(bytes) -> string` &mdash; BLAKE3 of arbitrary bytes as 64-char hex.
- `blob_encode(bytes) -> { bytes, hash_hex }` &mdash; canonical blob object.
- `tree_encode(entries_json) -> { bytes, hash_hex }` &mdash; canonical tree object.
- `commit_encode_and_sign(...)` &mdash; encode and sign a commit object.
- `commit_verify(commit_bytes) -> bool` &mdash; verify a signed commit.

Signing primitives:
- `keypair_from_seed(seed_hex)` / `keypair_generate()` &mdash; Ed25519 keys.
- `sign_bytes_commit_domain(seed_hex, bytes) -> sig_hex`.
- `verify_bytes_commit_domain(pubkey_hex, bytes, sig_hex) -> bool`.

Attestations (in-toto/DSSE-style envelopes):
- `attest_keypair(seed_hex, algo)` &mdash; ed25519, secp256k1, or p256.
- `attest_build(...)` &mdash; build and sign an envelope.
- `attest_verify(envelope_json, pubkey_hex, algo) -> bool`.

Chunking, delta, and streaming:
- `chunk_boundaries(bytes)` &mdash; FastCDC chunk boundary report.
- `chunked_blob_encode(bytes)` &mdash; chunked-blob object construction.
- `chunked_blob_decode(bytes) -> json` &mdash; `{ total_size, chunk_size, chunks }` from a canonical `ChunkedBlob` (16 MiB cap).
- `delta_encode(base, target)` &mdash; produce a delta summary.
- `bao_encode(bytes)` &mdash; Bao outboard over **raw** file bytes (the web streaming demo).
- `bao_slice(...)` / `bao_verify_slice(...)` &mdash; verified streaming of those raw bytes.
- `blob_bao_encode(content)` &mdash; Bao outboard over **canonical blob bytes**; `hash_hex` equals the blob id.
- `blob_bao_slice(outboard, content, content_offset, len)` &mdash; content offsets; the +10 canonical shift is inside.
- `blob_bao_verify_slice(blob_id_hex, slice, content_offset, len)` &mdash; delegates to `mkit_core::verify::verify_blob_slice`.

Disclosure and closure (issue #1015 verifier kit):
- `verify_disclosure(commit_id_hex, bundle) -> json` &mdash; path, leaf, signer, payload summary **without** bytes, plus `step_inner_roots` (hex array) and `chunk_inner_root` (hex or `null`). Bundles are capped at 64 MiB (`MAX_BUNDLE_BYTES`).
- `disclosure_payload_bytes(commit_id_hex, bundle) -> bytes` &mdash; verified payload bytes; re-verifies. Call `verify_disclosure` first; treat a failure of either as a failure.
- `verify_closure_packs(root_hex, mode, packs, pack_lengths_json) -> json` &mdash; `mode` is `"snapshot"` or `"history"`. `packs` is the concatenation of each pack; `pack_lengths_json` is a JSON array of those lengths (for example `"[1024,2048]"`). Concatenated packs are capped independently of a disclosure bundle, at 1 GiB (`MAX_CLOSURE_INPUT_BYTES`, matching the native store's per-object cap) &mdash; a closure is every object reachable from a commit, a realistically much larger shape than a handful of proofs.
- `verify_closure_manifest(expected_root_hex, manifest, packs, pack_lengths_json) -> json` &mdash; same pack framing; the manifest is a locator, never a trust anchor.
- `verify_tree_entry(tree_id_hex, entry_json, position, proof) -> bool` &mdash; `entry_json` is `{ "name" | "name_hex", "mode", "object_hash" }`. Returns `false` when the proof does not fold to the id; throws on malformed input.
- `verify_chunk(chunked_id_hex, chunk_id_hex, position, proof) -> bool` &mdash; same accept/reject split. Position 0 is never a chunk.
- `wrap_object_id(kind, inner_root_hex) -> hex` &mdash; `kind` is `"tree"` or `"chunked_blob"`. Apply after a commonware BMT verifier checked the inner root.

### Verifying a commit hash

A verified disclosure proves the bytes belong to that commit id; `signature_valid` proves the embedded signer produced the commit; binding that signer to a person or org is application policy.

```ts
import {
  verify_disclosure,
  verify_closure_manifest,
} from "@officialunofficial/mkit-wasm";

const commitId = "…64-char hex…"; // the id you already trust
const disclosed = JSON.parse(verify_disclosure(commitId, bundle));
// disclosed.payload has kind/bytes_len/bytes_blake3, not the bytes

const packs = [pack0, pack1];
const concat = new Uint8Array(packs.reduce((n, p) => n + p.byteLength, 0));
let off = 0;
for (const p of packs) {
  concat.set(p, off);
  off += p.byteLength;
}
const report = JSON.parse(
  verify_closure_manifest(
    commitId,
    manifest,
    concat,
    JSON.stringify(packs.map((p) => p.byteLength)),
  ),
);
if (!report.complete) throw new Error("closure is missing or corrupt");
```

The exact JS surface is generated by `wasm-bindgen`; refer to the
TypeScript declarations shipped in the package for full signatures.

## Versioning

This package is generated from the `mkit-wasm` crate inside the mkit Rust
workspace (`rust/crates/mkit-wasm`). Each npm release is built from a tagged
commit, so `@officialunofficial/mkit-wasm@X.Y.Z` on npm corresponds to tag `vX.Y.Z`.

The wasm bundle wraps the same Rust crates the native `mkit` CLI uses,
so on-disk objects produced here are byte-identical to those produced
by the CLI.

## Provenance

Releases are published from GitHub Actions with
[`npm publish --provenance`](https://docs.npmjs.com/generating-provenance-statements),
producing a Sigstore-backed attestation tied to the workflow run.
Verify on the npm package page or with `npm audit signatures`.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](./LICENSE-APACHE))
- MIT license ([LICENSE-MIT](./LICENSE-MIT))

at your option.
