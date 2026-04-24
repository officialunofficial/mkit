// Browser-facing wrapper around `mkit-wasm`.
//
// `mkit-wasm` is built with wasm-bindgen's `target=web`: the default
// export is an async init that fetches the .wasm blob relative to its
// own module URL. That works in browsers out of the box, which is the
// only surface this file needs to cover — the matching Node init path
// used by vitest lives in `mkit.node.ts` to keep `node:fs/promises` out
// of the client bundle.

import init, * as Wasm from "mkit-wasm";

export type MkitApi = typeof Wasm;

let pending: Promise<MkitApi> | null = null;

export function mkit(): Promise<MkitApi> {
  if (!pending) {
    pending = init().then(() => Wasm);
  }
  return pending;
}

// Test-only: wires up a caller-provided init promise (e.g. the Node fs
// path) as the single source of truth. Subsequent `mkit()` calls resolve
// against it without attempting to `fetch` the wasm blob.
export function __setMkitInit(p: Promise<MkitApi>): void {
  pending = p;
}

export function __resetMkitForTests(): void {
  pending = null;
}
