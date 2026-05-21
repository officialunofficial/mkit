# mkit web

Waku + Cloudflare Workers demo site that runs `mkit-wasm` directly in the
browser. Each page exercises one slice of the mkit data model — hashing,
signing, tree snapshots, and attestation — so visitors can see the
content-addressed pipeline end-to-end without installing the CLI.

Not part of the published `mkit` toolkit; lives here to keep the deploy
config close to the spec and the WASM crate it consumes.

Deploy: `pnpm deploy` (see `wrangler.toml` / `waku.config.ts`). Source:
`src/`.
