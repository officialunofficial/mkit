import path from "node:path";
import { fileURLToPath } from "node:url";
import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

const dir = path.dirname(fileURLToPath(import.meta.url));

// Two projects:
//   - "unit": the pure-logic tests (utils/parse/seed/guard), run in Node.
//   - "integration": tests that exercise the real Worker + Durable Object + D1
//     through the live MCP endpoint, run inside the Workers runtime via
//     @cloudflare/vitest-pool-workers (miniflare). The integration project loads
//     the D1 migrations as a TEST_MIGRATIONS binding so tests can seed a fresh,
//     deterministic corpus before driving tools/call over streamable-HTTP.
export default defineConfig(async () => {
  const migrations = await readD1Migrations(path.join(dir, "migrations"));
  return {
    test: {
      projects: [
        {
          test: {
            name: "unit",
            environment: "node",
            include: ["test/*.test.ts"],
          },
        },
        {
          plugins: [
            cloudflareTest({
              isolatedStorage: true,
              miniflare: {
                bindings: { TEST_MIGRATIONS: migrations },
              },
              wrangler: { configPath: "./wrangler.jsonc" },
            }),
          ],
          test: {
            name: "integration",
            include: ["test/integration/**/*.test.ts"],
          },
        },
      ],
      // Coverage is scoped to the "unit" project only (`npm run test:coverage`
      // runs `vitest run --project unit --coverage`): the "integration" project
      // executes inside the real Workers runtime via
      // @cloudflare/vitest-pool-workers, whose isolate doesn't support the v8
      // coverage provider used here (it needs the separate `istanbul`
      // provider). Instrumenting only the pure-logic unit project keeps this
      // simple and still gives a real, CI-enforced floor on the
      // parser/guard/seed code that has no Workers-runtime dependency.
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
  };
});
