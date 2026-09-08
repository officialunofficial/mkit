# Vitest 5 and Cloudflare Workers testing

Researched 2026-09-08 against the npm registry, Cloudflare documentation, and
Cloudflare's upstream pull requests. Local references describe checkout
`c39e1792` in the Dependabot worktree. This is a research result; it does not
claim that an unsupported package combination was installed or tested locally.

## Finding

There is no published, supported Vitest 5 upgrade for the current Workers test
plugin as of this check. Cloudflare renamed `@cloudflare/vitest-pool-workers`
to `@cloudflare/vitest-plugin`, but the latest replacement, version `1.1.6`,
still declares `^4.1.0` peers for `vitest`, `@vitest/runner`, and
`@vitest/snapshot`. The old `0.22.0` package declares the same peers.
Those ranges exclude version 5. The previous explanation omitted the rename
and the active upstream work. ([Plugin 1.1.6 registry manifest](https://registry.npmjs.org/@cloudflare%2fvitest-plugin/1.1.6),
[pool 0.22.0 registry manifest](https://registry.npmjs.org/@cloudflare%2fvitest-pool-workers/0.22.0),
[Cloudflare migration guide](https://developers.cloudflare.com/workers/testing/vitest-integration/migration-guides/migrate-to-vitest-plugin/))

Cloudflare's setup guide explicitly installs `vitest@^4.1.0`. Its prose says
“4.1 or later,” but the concrete install command and published peer ranges
are the precise compatibility evidence; that wording alone does not establish
support for another major version. ([Write your first test](https://developers.cloudflare.com/workers/testing/vitest-integration/write-your-first-test/))

## Upstream support is under development

[Cloudflare PR #15500](https://github.com/cloudflare/workers-sdk/pull/15500),
opened September 3, is titled `[vitest-plugin] Support Vitest 5`. The GitHub
API reported it open and unmerged on September 8. The proposal includes runtime
changes for Istanbul coverage forwarding to the Node host, module-evaluator
diagnostics, and enabling WeakRef for older compatibility dates. Its author
reports 108 passing tests and one skip under Vitest 5, plus a Vitest 4.1.11
compatibility run and fixture tests. Those are upstream author-reported results,
not validation of mkit's suites. ([PR details](https://api.github.com/repos/cloudflare/workers-sdk/pulls/15500))

The PR's package-preview bot also provides
`https://pkg.pr.new/@cloudflare/vitest-plugin@15500`. This offers an experimental
way to evaluate the proposed support before release. It remains an unmerged
preview and was not installed or executed for this research.
([Preview publication in the PR conversation](https://github.com/cloudflare/workers-sdk/pull/15500))

Related [PR #15492](https://github.com/cloudflare/workers-sdk/pull/15492)
reports a concrete failure with Vitest `5.0.0-rc.4`: the plugin's text replacement
of `import.meta.url` also changes a diagnostic string, producing invalid
JavaScript during workerd startup. That PR was also open and unmerged at the
time of this check. This supports treating the upgrade as a runtime compatibility
change, beyond relaxing peer dependencies. It does not prove every mkit test
would fail under every Vitest 5 configuration. ([PR details](https://api.github.com/repos/cloudflare/workers-sdk/pulls/15492))

## Package rename and existing migration debt

The package rename preserves the configuration API. Cloudflare's codemod is
`npx @cloudflare/codemods vitest:pool-workers-to-vitest-plugin`; `--dry-run`
previews changes. Manual migration replaces the dependency name, imports,
subpath imports, and TypeScript `types` entries with the new package name.
The guide also points outbound request mocks to `@msw/cloudflare`.
This rename alone does not unlock Vitest 5.
([Rename migration guide](https://developers.cloudflare.com/workers/testing/vitest-integration/migration-guides/migrate-to-vitest-plugin/))

Current Cloudflare documentation describes storage isolation per test file.
Sharing storage across files requires `--max-workers=1 --no-isolate`; individual
tests within a file should not assume automatic storage rollback.
([Isolation and concurrency](https://developers.cloudflare.com/workers/testing/vitest-integration/isolation-and-concurrency/))

Local inspection found `isolatedStorage: true` in
[`apps/mcp/vitest.config.ts`](../../apps/mcp/vitest.config.ts) and legacy
`env`/`SELF` imports from `cloudflare:test` in
[`apps/mcp/test/integration/harness.ts`](../../apps/mcp/test/integration/harness.ts)
and [`modern.test.ts`](../../apps/mcp/test/integration/modern.test.ts).
These deserve a migration review before relying on the latest plugin's
behavior. Cloudflare's current examples import `env` and `exports` from
`cloudflare:workers` and use `exports.default.fetch()`.
([Current test examples](https://developers.cloudflare.com/workers/testing/vitest-integration/write-your-first-test/))

## An alternative can decouple the test runner

Cloudflare now recommends `createTestHarness()` for integration tests and the
Workers Vitest integration for unit tests. The harness runs production Worker
builds and supports any Node.js test runner. Therefore a harness migration is a
plausible route to Vitest 5 without waiting for the in-Worker plugin; this is an
inference from the runner-independent API, not a completed mkit migration.
([Cloudflare testing overview](https://developers.cloudflare.com/workers/testing/))

The documented lifecycle imports `createTestHarness` from `wrangler`, provides
Worker configuration paths, calls `listen()` before tests, `reset()` after tests,
and `close()` after the suite. Requests use `server.fetch()`.
([Harness setup](https://developers.cloudflare.com/workers/testing/test-harness/get-started/))
Bindings are available through `server.getWorker().getEnv()` for seeding state;
after a reset, schema migrations and seed data must be applied again.
([Preparing test state](https://developers.cloudflare.com/workers/testing/test-harness/prepare-test-state/),
[Harness configuration](https://developers.cloudflare.com/workers/testing/test-harness/configure/))

For mkit this would require adapting the existing in-Worker harness, D1 setup,
and any direct runtime imports, then running the integration suites. It is
separate implementation work rather than an ordinary dependency bump.

## Implemented decision

MCP now uses Wrangler's `createTestHarness()` with Vitest 5. Each isolated test
file starts its own bundled Worker and ephemeral D1 database, applies the real
migrations, and retains the existing corpus cleanup between tests. Both MCP
SDK generations connect through Wrangler's local HTTP listener. Suite teardown
closes the harness. No test-only Worker endpoint is needed.

Spammer keeps its four direct Wasm runtime module tests on Vitest 4 and migrates
to the supported `@cloudflare/vitest-plugin` package. Those tests inspect module
exports and initialization promise identity inside workerd. Moving them behind
a bespoke Worker adapter solely to change runner versions adds maintenance
without improving the test boundary. Its Dependabot major-version deferral
remains until the released plugin supports Vitest 5; MCP's deferral is removed.

The obsolete MCP `legacy-peer-deps` setting is removed. Its former agents/zod
conflict no longer applies, and normal peer resolution supplies Vitest 5's
required Vite peer without bypassing compatibility checks.

Validation: all 52 MCP tests pass on Vitest 5, including both protocol versions
and resilience cases. All 195 Spammer tests pass with plugin 1.1.6. Typechecks
pass for both applications; both coverage floors and audits also pass. MCP's
clean `npm ci` passes with normal peer resolution.
