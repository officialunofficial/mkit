import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

// Two projects (mirrors apps/mcp/vitest.config.ts):
//   - "unit": pure-logic tests (src/scheduler.ts, etc.), run in plain Node —
//     no wasm, no Workers runtime needed.
//   - "integration": tests that need the REAL Workers runtime via
//     @cloudflare/vitest-pool-workers (miniflare/workerd). `src/wasm.ts`
//     imports `.wasm` files directly (`import m from "mkit-wasm/mkit_wasm_bg.wasm"`),
//     a specifier only Wrangler's bundler (used here and in `wrangler dev`/
//     `deploy`) knows how to turn into a `WebAssembly.Module` — plain Node/Vite
//     has no such loader, so anything touching `wasm.ts` MUST run here.
export default defineConfig({
  test: {
    projects: [
      {
        test: {
          name: "unit",
          environment: "node",
          include: ["src/**/*.test.ts", "test/**/*.test.ts"],
          exclude: ["test/integration/**"],
        },
      },
      {
        plugins: [cloudflareTest({ wrangler: { configPath: "./wrangler.jsonc" } })],
        test: {
          name: "integration",
          include: ["test/integration/**/*.test.ts"],
        },
      },
    ],
    // Coverage is scoped to "unit": the "integration" project runs inside the
    // real Workers isolate via @cloudflare/vitest-pool-workers, which doesn't
    // support the v8 coverage provider used here (needs the separate
    // `istanbul` provider) — same tradeoff apps/mcp makes. Concretely:
    // `spammer.ts` (imports `cloudflare:workers`, the DO base class),
    // `wasm.ts` (imports raw `.wasm` specifiers), and `index.ts` (imports
    // both) can only run in "integration" and so show 0% here even though
    // `spammer.ts`'s pure logic was deliberately split out into
    // `control-auth.ts` (unit-tested) precisely to shrink this gap. Thresholds
    // below are real achieved numbers with a few points of margin — not 80,
    // which is unreachable given the above — mirroring apps/mcp's identical
    // tuned-down thresholds for the same structural reason.
    coverage: {
      provider: "v8",
      reporter: ["text", "lcov"],
      include: ["src/**/*.ts"],
      exclude: ["src/**/*.test.ts", "test/**"],
      thresholds: {
        lines: 55,
        statements: 55,
        functions: 48,
        branches: 48,
      },
    },
  },
});
