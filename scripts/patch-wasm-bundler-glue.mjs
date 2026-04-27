#!/usr/bin/env node
/**
 * patch-wasm-bundler-glue.mjs — post-build patcher for `wasm-pack build
 * --target bundler` output.
 *
 * Background: wasm-pack 0.13's bundler glue (`pkg/mkit_wasm.js`) emits an
 * import-time `__wbg_set_wasm(wasm)` call. Bundlers that resolve the
 * `import * as wasm from "./mkit_wasm_bg.wasm"` line correctly (esbuild,
 * webpack, vite-with-wasm-plugin) end up storing the wasm-bindgen exports
 * namespace; bundlers that don't (Bun, Wrangler/Cloudflare Workers) store
 * a `{__esModule, default: <path>}` shim or a `WebAssembly.Module`
 * respectively. Every export then throws
 * `__wbindgen_add_to_stack_pointer is not a function` at first use.
 *
 * Fix: keep the import-time auto-init for working bundlers (so esbuild /
 * webpack / vite consumers see no behavioural change) and additionally
 * export `mkit_wasm_init(module)` that consumers stuck on broken bundlers
 * can call explicitly to inject a `WebAssembly.Module` they instantiate
 * themselves. Strictly additive: existing consumers don't notice;
 * Bun/Workers consumers go from "broken" to "two-line shim".
 *
 * Consumer pattern (Bun / Cloudflare Workers):
 *
 *     import wasmModule from "../node_modules/@makechain/mkit-wasm/mkit_wasm_bg.wasm";
 *     import { mkit_wasm_init, blake3_hex } from "@makechain/mkit-wasm";
 *     mkit_wasm_init(wasmModule);
 *     blake3_hex(new Uint8Array([1,2,3]));   // works
 *
 * See discussion in the downstream consumer's PR #502 and mkit#90.
 */

import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const SENTINEL = "// mkit-wasm: explicit init() shim";

/**
 * Patches the body of `mkit_wasm.js` (wasm-pack bundler-target glue).
 * Pure string transform so it's testable from Rust without spinning up
 * Node.
 *
 * @param {string} source - original `mkit_wasm.js` contents.
 * @returns {string} patched source.
 */
export function patchBundlerGlue(source) {
  if (source.includes(SENTINEL)) {
    // Idempotent — already patched (e.g. CI re-running the post-build).
    return source;
  }

  // wasm-pack 0.13.1 emits exactly:
  //   import * as wasm from "./mkit_wasm_bg.wasm";
  //   import { __wbg_set_wasm } from "./mkit_wasm_bg.js";
  //
  //   __wbg_set_wasm(wasm);
  //
  //   export { ... } from "./mkit_wasm_bg.js";
  //
  // We rewrite the second `import` to bring in the whole namespace so
  // we can both call `__wbg_set_wasm` and re-pass the import object
  // through to a fresh `WebAssembly.Instance` if a consumer drives us
  // with a raw `WebAssembly.Module`.

  const importLine =
    /import\s*\{\s*__wbg_set_wasm\s*\}\s*from\s*"\.\/mkit_wasm_bg\.js"\s*;/;
  if (!importLine.test(source)) {
    throw new Error(
      "patch-wasm-bundler-glue: expected `import { __wbg_set_wasm } from \"./mkit_wasm_bg.js\"` line; wasm-pack output shape changed?"
    );
  }
  let out = source.replace(
    importLine,
    'import * as __mkit_wasm_bg from "./mkit_wasm_bg.js";\nconst { __wbg_set_wasm } = __mkit_wasm_bg;'
  );

  // Append the explicit-init export. Placed after the auto-init call so
  // tree-shakers that drop unused exports see it as a sibling of the
  // existing exports.
  const shim = `
${SENTINEL} (mkit issue #90, downstream consumer PR #502)
//
// Bundlers like Bun and Cloudflare Workers / Wrangler do NOT resolve
// the auto-init \`import * as wasm from "./mkit_wasm_bg.wasm"\` line to
// the wasm-bindgen exports namespace; they hand us a WebAssembly.Module
// or a path-shim, leaving every export broken with
// "__wbindgen_add_to_stack_pointer is not a function".
//
// Consumers on those bundlers should call \`mkit_wasm_init(module)\`
// once at startup with their own WebAssembly.Module. Consumers on
// esbuild / webpack / vite (the bundlers wasm-pack already supports
// cleanly) can ignore this — auto-init still runs at import.
export function mkit_wasm_init(module) {
  if (typeof WebAssembly !== "undefined" && module instanceof WebAssembly.Module) {
    const instance = new WebAssembly.Instance(module, {
      "./mkit_wasm_bg.js": __mkit_wasm_bg,
    });
    __wbg_set_wasm(instance.exports);
    return;
  }
  // Already a WebAssembly.Instance.exports-shaped namespace (or the
  // raw wasm namespace) — pass through.
  __wbg_set_wasm(module);
}
`;
  // Insert before the re-export block so the function declaration is
  // hoisted alongside other top-level decls.
  const reexport = /\nexport \{/;
  if (!reexport.test(out)) {
    throw new Error(
      "patch-wasm-bundler-glue: could not find the re-export block; wasm-pack output shape changed?"
    );
  }
  out = out.replace(reexport, `\n${shim}\nexport {`);
  return out;
}

/**
 * Patches the d.ts to declare the new export.
 *
 * @param {string} source - original `mkit_wasm.d.ts` contents.
 * @returns {string} patched source.
 */
export function patchBundlerDts(source) {
  if (source.includes("export function mkit_wasm_init")) {
    return source;
  }
  const decl = `\n/**\n * Explicit init for bundlers that mis-resolve the auto-import\n * (Bun, Cloudflare Workers / Wrangler). Call once at startup with a\n * \`WebAssembly.Module\` you instantiate yourself.\n *\n * Consumers on esbuild / webpack / vite can ignore this — auto-init\n * still runs at module import.\n */\nexport function mkit_wasm_init(module: WebAssembly.Module | WebAssembly.Exports): void;\n`;
  return source + decl;
}

async function main() {
  const pkgDir = resolve(process.argv[2] ?? "rust/crates/mkit-wasm/pkg");
  const jsPath = resolve(pkgDir, "mkit_wasm.js");
  const dtsPath = resolve(pkgDir, "mkit_wasm.d.ts");

  const js = await readFile(jsPath, "utf8");
  await writeFile(jsPath, patchBundlerGlue(js));
  const dts = await readFile(dtsPath, "utf8");
  await writeFile(dtsPath, patchBundlerDts(dts));

  console.log(`patched ${jsPath}`);
  console.log(`patched ${dtsPath}`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
