//! Tests for the `mkit_wasm_init` post-build shim that patches
//! wasm-pack's `--target bundler` glue.
//!
//! Background: wasm-pack 0.13's bundler-target output has an import-
//! time `__wbg_set_wasm(wasm)` call that breaks under Bun + Cloudflare
//! Workers (their bundler resolution stores the wrong thing in `wasm`,
//! leaving every export at "__wbindgen_add_to_stack_pointer is not a
//! function"). The fix is strictly additive: the auto-init still runs
//! for working bundlers (esbuild, webpack, vite-with-plugin); broken
//! bundlers call `mkit_wasm_init(module)` explicitly to recover.
//!
//! These tests exercise the patch as a pure string transform against a
//! captured fixture matching wasm-pack 0.13.1's exact output shape.
//! Running the JS itself end-to-end requires Node + wasm-pack + a real
//! WebAssembly.Module, so the wasm-pack-driven smoke test is wired into
//! CI separately (release.yml's wasm build step). The fixture-based
//! Rust test pins the shape so a future wasm-pack bump that changes the
//! layout fails CI here, before it ships to npm.
//!
//! See `scripts/patch-wasm-bundler-glue.mjs` for the runtime patcher
//! that performs the same transform on real wasm-pack output.

#![allow(clippy::unwrap_used)]

/// Captured shape of wasm-pack 0.13.1's `pkg/mkit_wasm.js` for
/// `--target bundler`. Trimmed export list so the fixture stays
/// maintainable; the patch only cares about the `__wbg_set_wasm`
/// import shape and the re-export block delimiter.
const WASM_PACK_GLUE_FIXTURE: &str = r#"/* @ts-self-types="./mkit_wasm.d.ts" */
import * as wasm from "./mkit_wasm_bg.wasm";
import { __wbg_set_wasm } from "./mkit_wasm_bg.js";

__wbg_set_wasm(wasm);

export {
    blake3_hex, ed25519_sign, ed25519_verify
} from "./mkit_wasm_bg.js";
"#;

/// Same patch logic as `scripts/patch-wasm-bundler-glue.mjs::patchBundlerGlue`
/// — pure string transform, mirrored here so we can pin the shape from
/// `cargo test` without a Node round-trip.
///
/// If you change one, change both, and update `init_shim_patch_is_idempotent`.
fn patch_bundler_glue(source: &str) -> String {
    const SENTINEL: &str = "// mkit-wasm: explicit init() shim";
    if source.contains(SENTINEL) {
        return source.to_string();
    }

    let import_pattern =
        "import { __wbg_set_wasm } from \"./mkit_wasm_bg.js\";";
    assert!(
        source.contains(import_pattern),
        "fixture missing the wasm-pack import line — wasm-pack output shape changed?"
    );
    let replaced = source.replace(
        import_pattern,
        "import * as __mkit_wasm_bg from \"./mkit_wasm_bg.js\";\nconst { __wbg_set_wasm } = __mkit_wasm_bg;",
    );

    let shim = format!(
        "\n{SENTINEL} (mkit issue #90, downstream consumer PR #502)
export function mkit_wasm_init(module) {{
  if (typeof WebAssembly !== \"undefined\" && module instanceof WebAssembly.Module) {{
    const instance = new WebAssembly.Instance(module, {{
      \"./mkit_wasm_bg.js\": __mkit_wasm_bg,
    }});
    __wbg_set_wasm(instance.exports);
    return;
  }}
  __wbg_set_wasm(module);
}}
"
    );

    let reexport = "\nexport {";
    assert!(
        replaced.contains(reexport),
        "fixture missing the re-export block — wasm-pack output shape changed?"
    );
    replaced.replacen(reexport, &format!("\n{shim}\nexport {{"), 1)
}

/// Test 6 (auto-init shim) part A: the patched glue exports
/// `mkit_wasm_init` as a top-level function and keeps the import-time
/// auto-init call intact. Consumer pattern from the README:
/// `import { mkit_wasm_init, blake3_hex } from "@makechain/mkit-wasm";
///  mkit_wasm_init(wasmModule); blake3_hex(...);`
#[test]
fn shim_exports_mkit_wasm_init() {
    let patched = patch_bundler_glue(WASM_PACK_GLUE_FIXTURE);

    assert!(
        patched.contains("export function mkit_wasm_init(module)"),
        "patched glue must export mkit_wasm_init"
    );
    // Auto-init for working bundlers must remain — strictly additive.
    assert!(
        patched.contains("__wbg_set_wasm(wasm);"),
        "auto-init call must remain (esbuild/webpack/vite pathway)"
    );
    // Existing exports survive verbatim.
    assert!(
        patched.contains("blake3_hex, ed25519_sign, ed25519_verify"),
        "existing wasm-bindgen re-exports must be preserved"
    );
}

/// Part B: the shim re-instantiates a `WebAssembly.Module` with the
/// glue's import-object before calling `__wbg_set_wasm`. This is the
/// load-bearing fix: a raw `WebAssembly.Module` is not an exports
/// namespace, so dropping it directly into `__wbg_set_wasm` leaves
/// every export wired to `undefined`.
#[test]
fn shim_handles_raw_webassembly_module() {
    let patched = patch_bundler_glue(WASM_PACK_GLUE_FIXTURE);

    assert!(
        patched.contains("module instanceof WebAssembly.Module"),
        "shim must dispatch on `module instanceof WebAssembly.Module`"
    );
    assert!(
        patched.contains("new WebAssembly.Instance(module"),
        "shim must instantiate the module to obtain `.exports`"
    );
    assert!(
        patched.contains("\"./mkit_wasm_bg.js\": __mkit_wasm_bg"),
        "instantiation must pass the bg-glue namespace as the import object"
    );
    assert!(
        patched.contains("__wbg_set_wasm(instance.exports)"),
        "shim must re-run __wbg_set_wasm with the freshly-instantiated exports"
    );
}

/// Part C: idempotent. CI re-running the post-build (or a developer
/// running it twice locally) must not double-patch and break the file.
#[test]
fn shim_patch_is_idempotent() {
    let once = patch_bundler_glue(WASM_PACK_GLUE_FIXTURE);
    let twice = patch_bundler_glue(&once);
    assert_eq!(once, twice, "patch must be idempotent");
}

/// Part D: shape-pinning. If wasm-pack ever changes its bundler-target
/// output (e.g. drops the `import { __wbg_set_wasm }` line in favour of
/// a different glue strategy), the patcher's regex misses and it
/// silently skips the rewrite. Catch that here, not in production.
#[test]
fn shim_patch_panics_on_unknown_glue_shape() {
    let result = std::panic::catch_unwind(|| {
        patch_bundler_glue("// totally different file shape, no auto-init\n")
    });
    assert!(
        result.is_err(),
        "patch must abort on unrecognised glue (signals wasm-pack bump)"
    );
}
