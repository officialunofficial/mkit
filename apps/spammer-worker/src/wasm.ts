// Memoized wasm init for the Cloudflare Workers runtime.
//
// Both vendored crates (`mkit-wasm` — object/commit/remix encode + Ed25519
// signing; `mkit-repo-client` — the ConnectRPC write surface) are
// wasm-bindgen `target=web` builds, same `pkg/` output `apps/web` vendors and
// the same `wasm:build` script writes into (see package.json). Their JS glue
// exports a default async `init()` that, called with no args, `fetch()`es the
// `.wasm` blob relative to its own module URL — fine in a browser, impossible
// in a Worker (no DOM, no same-origin static file to fetch). `init()` also
// accepts a pre-supplied module via `{ module_or_path }`
// (proven by the Node path, `apps/web/src/lib/mkit.node.ts:19`, which reads
// the bytes off disk instead). A Worker's equivalent of "already have the
// bytes" is Wrangler's bundler transform: an `import x from './foo.wasm'`
// specifier is compiled ahead-of-time into a `WebAssembly.Module`, which is
// exactly the shape `module_or_path` wants — no `fetch`, no `nodejs_compat`,
// no DOM.
//
// Both packages publish their `*_bg.wasm` binary at the package root (no
// `exports` map restricting subpath imports — see the `pkg/package.json`
// `files` list), so `mkit-wasm/mkit_wasm_bg.wasm` /
// `mkit-repo-client/mkit_repo_client_bg.wasm` resolve like any other
// dependency subpath. TypeScript has no built-in type for a bare `.wasm`
// import; see `wasm-modules.d.ts` for the ambient module declaration.

import mkitWasmModule from "mkit-wasm/mkit_wasm_bg.wasm";
import initMkit, * as MkitWasm from "mkit-wasm";
import repoClientWasmModule from "mkit-repo-client/mkit_repo_client_bg.wasm";
import initRepoClient, * as RepoWasm from "mkit-repo-client";

/** The `mkit-wasm` surface: `blake3_hex`, `ed25519_sign`, `commit_encode_and_sign`, `tree_encode`, … */
export type MkitApi = typeof MkitWasm;

/** The `mkit-repo-client` surface: `put_object`, `update_ref`, `post_message`, `react`, the unauthenticated reads, … */
export type RepoWasmApi = typeof RepoWasm;

export interface WasmApi {
  mkit: MkitApi;
  repo: RepoWasmApi;
}

// Module-scope, so it survives for the lifetime of the ISOLATE (Workers reuse
// an isolate's global scope across many requests/alarms) — instantiating a
// `WebAssembly.Module` is not free, and both modules are stateless pure
// functions, so one instantiation per isolate is correct and sufficient.
let pending: Promise<WasmApi> | null = null;

/**
 * Initialize both wasm modules exactly once per isolate and return their
 * typed surfaces. Safe to call on every `alarm()` tick or request — every
 * call after the first resolves the same memoized promise without
 * re-instantiating either module. Rejects (and leaves `pending` unset, so a
 * later call retries) if either module fails to instantiate.
 */
export function getWasm(): Promise<WasmApi> {
  if (!pending) {
    pending = Promise.all([
      initMkit({ module_or_path: mkitWasmModule }),
      initRepoClient({ module_or_path: repoClientWasmModule }),
    ])
      .then(() => ({ mkit: MkitWasm, repo: RepoWasm }))
      .catch((err: unknown) => {
        pending = null;
        throw err;
      });
  }
  return pending;
}

// Test-only: override the memoized promise, mirroring apps/web's
// `__setMkitInit`/`__setRepoWasmInit` (`src/lib/mkit.ts`,
// `src/lib/repo-client.ts`). Lets a test hand in an already-resolved
// `WasmApi` without depending on the isolate having freshly evaluated this
// module's top-level `.wasm` imports.
export function __setWasmForTests(p: Promise<WasmApi>): void {
  pending = p;
}

export function __resetWasmForTests(): void {
  pending = null;
}
