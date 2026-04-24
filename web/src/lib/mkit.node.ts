// Node init path for vitest.
//
// wasm-bindgen's `init()` default resolves the .wasm path relative to
// its own module URL, then `fetch`es it. Node doesn't support
// `fetch(file://…)`, so we read the bytes off disk and hand them in.
// This file imports `node:fs/promises` unconditionally and must never
// be pulled into the browser bundle — call `registerNodeInit()` from
// a vitest setup file only.

import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import init, * as Wasm from "mkit-wasm";
import { __setMkitInit, type MkitApi } from "./mkit";

export function registerNodeInit(): void {
  const p: Promise<MkitApi> = (async () => {
    const requireFn = createRequire(import.meta.url);
    const wasmPath = requireFn.resolve("mkit-wasm/mkit_wasm_bg.wasm");
    const bytes = await readFile(wasmPath);
    await init({ module_or_path: bytes });
    return Wasm;
  })();
  __setMkitInit(p);
}
