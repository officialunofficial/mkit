import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    // Pure-logic tests default to `node` (fast, no DOM). Component tests opt into
    // jsdom per-file via a `// @vitest-environment jsdom` docblock at the top of
    // the file — see src/components/*.test.tsx.
    environment: 'node',
    include: ['src/**/*.test.{ts,tsx}'],
    setupFiles: ['./vitest.setup.ts'],
    globals: false,
    // Component tests each pay a cold wasm compile (once per file — see
    // vitest.setup.ts) before their first assertion; the default 5s test
    // timeout can be tight under load. Widened globally rather than per-file.
    testTimeout: 20_000,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
      include: ['src/**/*.{ts,tsx}'],
      exclude: ['src/**/*.test.{ts,tsx}', 'src/**/*.d.ts'],
      // Floor, not a target: pinned a few points below the measured baseline
      // (see PR that introduced this block) so CI catches a regression without
      // being a wishful bar the suite doesn't clear today. `src/components/*`
      // (30 files) and `src/pages/*` are still largely untested — raising this
      // is follow-up work, not a blocker for the render-smoke-test baseline
      // this threshold locks in.
      thresholds: {
        lines: 34,
        statements: 34,
        functions: 33,
        branches: 28,
      },
    },
  },
})
