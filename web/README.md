# mkit web

Waku + Cloudflare Workers demo site that runs `mkit-wasm` directly in the
browser. Each page exercises one slice of the mkit data model — hashing,
signing, tree snapshots, and attestation — so visitors can see the
content-addressed pipeline end-to-end without installing the CLI.

Not part of the published `mkit` toolkit; lives here to keep the deploy
config close to the spec and the WASM crate it consumes.

## Local build

Prerequisites: Node.js 22, pnpm 10, Rust 1.95.0, the `wasm32-unknown-unknown`
target, `wasm-pack` 0.13.1, and `protoc` 31.0 or newer.

```sh
pnpm install --frozen-lockfile
pnpm wasm:build
pnpm typecheck
pnpm test
pnpm build
```

`mkit-wasm` is linked through `vendor/mkit-wasm`, which is a checked-in package
shell. `pnpm wasm:build` generates the ignored `vendor/mkit-wasm/pkg/` contents
from `../rust/crates/mkit-wasm` with `wasm-pack --target web`.

## Deploy

Deploy with `pnpm deploy`. Waku generates `dist/server/wrangler.json`; the
post-build patcher pins the Cloudflare compatibility date, enables the required
compatibility flags, observability, routes, preview URLs, and `workers.dev`.

Preview locally with `pnpm preview`. Source lives under `src/`.

## Agent skill (`/SKILL.md`)

The site also serves the project's CLI Agent Skill at
[`mkit.makechain.net/SKILL.md`](https://mkit.makechain.net/SKILL.md) so any
agent can fetch it directly. The canonical file is the **repo-root
`SKILL.md`**; `pnpm skill:stage` (run automatically by `dev`/`build` via
`scripts/copy-skill.mjs`) copies it into the gitignored `public/SKILL.md` as a
static asset. Edit the repo-root file, never the copy.
