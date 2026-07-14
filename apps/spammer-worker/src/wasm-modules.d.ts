// Ambient type for bare `.wasm` import specifiers (e.g.
// `import m from "mkit-wasm/mkit_wasm_bg.wasm"` in `wasm.ts`). Wrangler's
// bundler compiles such an import into a `WebAssembly.Module` ahead of time —
// `@cloudflare/workers-types` doesn't ship this declaration itself, so it's
// declared here. A shorthand ambient module (`declare module "*.wasm"`)
// matches any import specifier ending in `.wasm`, regardless of package path.

declare module "*.wasm" {
  const wasmModule: WebAssembly.Module;
  export default wasmModule;
}
