# mkit web

Waku + Cloudflare Workers demo site that runs `mkit-wasm` directly in the
browser. Each page exercises one slice of the mkit data model — hashing,
signing, tree snapshots, and attestation — so visitors can see the
content-addressed pipeline end-to-end without installing the CLI.

Not part of the published `mkit` toolkit; lives here to keep the deploy
config close to the spec and the WASM crate it consumes.

## Local build

Prerequisites: Node.js 22, Bun 1.3.14, Rust 1.95.0, the
`wasm32-unknown-unknown` target, and `wasm-pack` 0.13.1. (`protoc` is no longer
required — `mkit-rpc` builds from its vendored generated sources by default.)

Bun is the package manager and script runner only — waku, vitest, and wrangler
all execute on the Node runtime (their `#!/usr/bin/env node` shebangs are
honored; nothing passes `--bun`). Use `bun run test`, not `bun test`: the
latter invokes Bun's built-in test runner instead of the vitest script.

```sh
bun install --frozen-lockfile
bun run wasm:build
bun run typecheck
bun run test
bun run build
```

`mkit-wasm` resolves through `vendor/mkit-wasm`, a checked-in package shell
declared as a Bun workspace (Bun has no relative `link:` protocol, so the
workspace symlink replaces pnpm's `link:vendor/mkit-wasm`). `bun run
wasm:build` generates the ignored `vendor/mkit-wasm/pkg/` contents from
`../rust/crates/mkit-wasm` with `wasm-pack --target web`.

Postinstall scripts are opt-in via `trustedDependencies` in `package.json`:
`esbuild` and `workerd` (platform binaries) are trusted; `sharp` deliberately
is not — its from-source fallback fails offline and nothing here does
build-time image work.

## Deploy

Production deploys run through **Cloudflare Workers Builds** (the repo's Git
integration): every push to `main` that touches the watched paths builds with
`scripts/cf-build.sh` (which bootstraps rustup + wasm-pack on the build image)
and deploys the Worker; non-production branches get preview versions via
`wrangler versions upload`. The dashboard build variable `BUN_VERSION=1.3.14`
pins Bun on the build image. Manual deploys still work with `bun run deploy`.

Waku generates `dist/server/wrangler.json`; the post-build patcher pins the
Cloudflare compatibility date, enables the required compatibility flags,
observability, routes, preview URLs, and `workers.dev`. After the Waku build,
`scripts/assert-prerender.mjs` fails the build if any page is missing its
prerendered HTML or RSC payload — waku's SSG step otherwise reports success
even when route registration silently breaks (see #305's fsRouter glob-key
regression, which shipped a blank site).

Preview locally with `bun run preview`. Source lives under `src/`.

## Agent skill (`/SKILL.md`)

The site also serves the project's CLI Agent Skill at
[`mkit.sh/SKILL.md`](https://mkit.sh/SKILL.md) so any
agent can fetch it directly. The canonical file is the **repo-root
`SKILL.md`**; `bun run skill:stage` (run automatically by `dev`/`build` via
`scripts/copy-skill.mjs`) copies it into the gitignored `public/SKILL.md` as a
static asset. Edit the repo-root file, never the copy.
