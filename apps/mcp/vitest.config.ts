import { defineConfig } from "vitest/config";

// Integration tests drive Wrangler's bundled Worker over HTTP with an
// independent Worker and D1 database per test file.
export default defineConfig({
  test: {
    projects: [
      { test: { name: "unit", environment: "node", include: ["test/*.test.ts"] } },
      {
        test: {
          name: "integration",
          environment: "node",
          include: ["test/integration/**/*.test.ts"],
          hookTimeout: 60_000,
        },
      },
    ],
    // V8 coverage measures Node unit tests; the Worker runs separately in workerd.
    coverage: {
      provider: "v8",
      reporter: ["text", "lcov"],
      include: ["src/**/*.ts"],
      exclude: ["src/**/*.test.ts", "test/**"],
      thresholds: {
        lines: 40,
        statements: 40,
        functions: 37,
        branches: 32,
      },
    },
  },
});
