# Migrating mkit's docs and website to Vocs

This document captures the plan, the file-level decisions, and the
execution checklist for porting the mkit documentation (`docs/`) and
the marketing/demo site (`web/` → mkit.makechain.net) onto
[Vocs](https://github.com/wevm/vocs) `next` (v2).

The companion implementation lives in `apps/docs/` once the
migration lands. Until then this is a plan-of-record. After the
migration this document becomes a maintenance guide for authoring
new pages.

## Why Vocs

mkit's docs are currently 19 hand-rolled Markdown files in `docs/`
and a separate Waku/RSC site in `web/`. The two surfaces diverge:
the marketing pages are interactive WASM demos; the docs are
plain Markdown read on GitHub. Vocs `next` collapses the split:

- One Vite + React 19 + Waku app renders both the docs (MDX) and
  the demos (`'use client'` React components with WASM).
- Built-in Shiki + transformers, MiniSearch, dynamic OG, Rust
  twoslash (`@vocs/twoslash-rust`), `:::callout` directives,
  built-in sidebar/topnav primitives.
- Same stack `makechain/apps/docs/` already ships, so the
  Cloudflare deploy path is known-good and reproducible.

## Decisions (locked)

| Decision | Value |
| --- | --- |
| Layout | Workspace-style `apps/docs/` (pnpm workspace at repo root) |
| Deploy | Cloudflare Pages first; add Worker routes for `/api/*` later if MCP/feedback/OG endpoints are wanted |
| Scope | Docs + landing + demos in a single PR; replaces mkit.makechain.net |
| Vocs pin | `pkg.pr.new` commit pin, mirroring `makechain/apps/docs/` |
| Markdown source of truth | Canonical content moves to `apps/docs/src/pages/`; current `docs/*.md` files are rewritten as `.mdx` |

A `docs/README.md` stub remains in the repo so deep links from
GitHub (and from rustdoc `///` cross-references) resolve to the
hosted site.

## Target layout

```
mkit/
├── pnpm-workspace.yaml              # NEW — declares apps/* as workspaces
├── package.json                     # NEW — workspace root (private)
├── apps/
│   └── docs/
│       ├── src/
│       │   ├── pages/
│       │   │   ├── index.mdx                 # landing (replaces web/src/pages/index.tsx)
│       │   │   ├── _root.css
│       │   │   ├── _mdx-wrapper.tsx
│       │   │   ├── _slots.tsx                # header/footer slots
│       │   │   ├── docs/
│       │   │   │   ├── index.mdx
│       │   │   │   ├── architecture.mdx       # ex docs/ARCHITECTURE.md
│       │   │   │   ├── cli.mdx                # ex docs/CLI.md
│       │   │   │   ├── install.mdx            # ex docs/INSTALL.md
│       │   │   │   ├── fuzz.mdx               # ex docs/FUZZ.md
│       │   │   │   ├── release.mdx            # ex docs/RELEASE.md
│       │   │   │   ├── ssh-security.mdx       # ex docs/SSH-SECURITY.md
│       │   │   │   ├── threat-model.mdx       # ex docs/THREAT-MODEL.md
│       │   │   │   ├── style-guide.mdx        # ex docs/STYLE-GUIDE.md
│       │   │   │   ├── spec/
│       │   │   │   │   ├── attestations.mdx   # ex docs/SPEC-ATTESTATIONS.md
│       │   │   │   │   ├── delta.mdx
│       │   │   │   │   ├── external-signer.mdx
│       │   │   │   │   ├── fastcdc.mdx
│       │   │   │   │   ├── index.mdx          # ex docs/SPEC-INDEX.md
│       │   │   │   │   ├── objects.mdx
│       │   │   │   │   ├── packfile.mdx
│       │   │   │   │   ├── refs.mdx
│       │   │   │   │   ├── rpc.mdx
│       │   │   │   │   ├── signing.mdx
│       │   │   │   │   └── transport.mdx
│       │   │   │   └── advisories/
│       │   │   │       ├── index.mdx          # ex docs/advisories/README.md
│       │   │   │       ├── ghsa-001-per-repo-config.mdx
│       │   │   │       ├── ghsa-002-trust-roots-scope.mdx
│       │   │   │       └── ghsa-003-key-file-handling.mdx
│       │   │   └── demos/
│       │   │       ├── hash.mdx
│       │   │       ├── sign.mdx
│       │   │       ├── attest.mdx
│       │   │       ├── tree.mdx
│       │   │       └── streaming.mdx
│       │   ├── components/                    # ported from web/src/components/
│       │   ├── lib/                           # ported from web/src/lib/
│       │   └── env.ts
│       ├── public/                            # ported from web/public/
│       ├── vocs.config.ts
│       ├── vite.config.ts
│       ├── wrangler.jsonc                     # Cloudflare Pages
│       ├── tsconfig.json
│       └── package.json
├── docs/
│   └── README.md                              # stub — points readers to the site
├── rust/                                      # untouched
├── benchmarks/                                # untouched
└── web/                                       # DELETED in same PR
```

## Pinning Vocs

Mirror `makechain/apps/docs/package.json`:

```json
{
  "dependencies": {
    "vocs": "https://pkg.pr.new/wevm/vocs@<sha>",
    "waku": "1.0.0-alpha.2",
    "react": "^19",
    "react-dom": "^19"
  }
}
```

Use the same `<sha>` `makechain/apps/docs/` currently pins
(`e5ad67e` at time of writing) for the first commit so both sites
exercise the same Vocs build. Bump in lockstep after that.

## `vocs.config.ts` template

```ts
import { defineConfig } from "vocs/config";

const brandLogo = {
  light: "/logo-mkit-light.svg",
  dark: "/logo-mkit-dark.svg",
};

export default defineConfig({
  title: "mkit",
  description:
    "A content-addressed VCS in Rust. Git-like commits, refs, and transports, with a native attestation subsystem (in-toto v1 + DSSE).",
  renderStrategy: "full-static",
  rootDir: "src",
  baseUrl: "https://mkit.makechain.net",
  ogImageUrl: "https://og.makechain.net/?title=%title&description=%description",
  colorScheme: "dark",
  accentColor: "light-dark(black, white)",
  logoUrl: brandLogo,
  iconUrl: "/favicon.svg",
  editLink: {
    link: "https://github.com/officialunofficial/mkit/edit/main/apps/docs/src/pages/:path",
    text: "Edit this page on GitHub",
  },
  socials: [
    { icon: "github", link: "https://github.com/officialunofficial/mkit" },
  ],
  topNav: [
    { text: "Docs", link: "/docs", match: "/docs" },
    { text: "Demos", link: "/demos/hash", match: "/demos" },
    { text: "Spec", link: "/docs/spec/objects", match: "/docs/spec" },
  ],
  twoslash: {
    // Rust hovers via @vocs/twoslash-rust, pointed at the Cargo workspace.
    // Enable once Cargo metadata stabilizes in CI.
    // experimental_rust: Twoslash.experimental_rust({
    //   cargoToml: "../../rust/Cargo.toml",
    //   cacheOnly: true,
    // }),
  },
  sidebar: {
    "/docs": [
      {
        text: "Overview",
        items: [
          { text: "Introduction", link: "/docs" },
          { text: "Install", link: "/docs/install" },
          { text: "CLI", link: "/docs/cli" },
          { text: "Architecture", link: "/docs/architecture" },
        ],
      },
      {
        text: "Specifications",
        items: [
          { text: "Objects", link: "/docs/spec/objects" },
          { text: "Index", link: "/docs/spec/index" },
          { text: "Refs", link: "/docs/spec/refs" },
          { text: "Packfile", link: "/docs/spec/packfile" },
          { text: "Delta", link: "/docs/spec/delta" },
          { text: "FastCDC", link: "/docs/spec/fastcdc" },
          { text: "Transport", link: "/docs/spec/transport" },
          { text: "RPC", link: "/docs/spec/rpc" },
          { text: "Signing", link: "/docs/spec/signing" },
          { text: "Attestations", link: "/docs/spec/attestations" },
          { text: "External signer", link: "/docs/spec/external-signer" },
        ],
      },
      {
        text: "Operations",
        items: [
          { text: "Release", link: "/docs/release" },
          { text: "Fuzz", link: "/docs/fuzz" },
          { text: "SSH security", link: "/docs/ssh-security" },
          { text: "Threat model", link: "/docs/threat-model" },
        ],
      },
      {
        text: "Advisories",
        collapsed: true,
        items: [
          { text: "Overview", link: "/docs/advisories" },
          { text: "GHSA-001 — per-repo config", link: "/docs/advisories/ghsa-001-per-repo-config" },
          { text: "GHSA-002 — trust roots scope", link: "/docs/advisories/ghsa-002-trust-roots-scope" },
          { text: "GHSA-003 — key file handling", link: "/docs/advisories/ghsa-003-key-file-handling" },
        ],
      },
      {
        text: "Contributors",
        collapsed: true,
        items: [
          { text: "Writing style guide", link: "/docs/style-guide" },
        ],
      },
    ],
    "/demos": [
      {
        text: "Browser demos",
        items: [
          { text: "Hash", link: "/demos/hash" },
          { text: "Sign", link: "/demos/sign" },
          { text: "Attest", link: "/demos/attest" },
          { text: "Tree", link: "/demos/tree" },
          { text: "Streaming", link: "/demos/streaming" },
        ],
      },
    ],
  },
});
```

## `vite.config.ts` template

Mirrors `makechain/apps/docs/vite.config.ts` and includes the
node-polyfill stack needed for the WASM demos.

```ts
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";
import { nodePolyfills } from "vite-plugin-node-polyfills";
import { vocs } from "vocs/vite";

export default defineConfig({
  plugins: [
    nodePolyfills({
      include: ["buffer", "crypto", "events", "stream", "util"],
      globals: { Buffer: true, global: true, process: true },
      protocolImports: true,
    }),
    vocs(),
    react(),
  ],
});
```

## `wrangler.jsonc` template

```jsonc
{
  "$schema": "node_modules/wrangler/config-schema.json",
  "name": "mkit-docs",
  "compatibility_date": "2025-11-17",
  "pages_build_output_dir": "./dist/public"
}
```

Cloudflare Pages picks up the build via the `pnpm --filter
mkit-docs build` command; preview URLs are auto-generated per PR.
The domain `mkit.makechain.net` swings to the new Pages project
once the smoke test passes.

## Content migration rules

Apply these mechanically to every file moving from `docs/*.md` to
`apps/docs/src/pages/docs/*.mdx`.

### 1. Filename

- Lowercase, kebab-case, drop the `SPEC-` prefix for spec files
  (the URL prefix is already `/docs/spec/`).
- Examples:
  - `docs/SPEC-OBJECTS.md` → `apps/docs/src/pages/docs/spec/objects.mdx`
  - `docs/STYLE-GUIDE.md` → `apps/docs/src/pages/docs/style-guide.mdx`
  - `docs/SSH-SECURITY.md` → `apps/docs/src/pages/docs/ssh-security.mdx`

### 2. Frontmatter

Prepend each MDX file with:

```mdx
---
title: <human-readable page title>
description: <one-sentence summary, used for OG + search>
---
```

`title` becomes the `<title>` and the page's H1 source for the
sidebar default. `description` feeds the OG image and search
index.

### 3. Cross-links

- `[text](SPEC-OBJECTS.md)` → `[text](/docs/spec/objects)`
- `[text](./SPEC-OBJECTS.md)` → `[text](/docs/spec/objects)`
- `[text](../README.md)` → `[text](/)` (or the matching docs page)
- `[text](SPEC-OBJECTS.md#commit-objects)` → `[text](/docs/spec/objects#commit-objects)`

Vocs's `rehypeLinks` runs `checkDeadlinks: true` by default — a
missed rewrite fails the build, which is the intended safety net.

### 4. GitHub alerts → directives

- `> **Warning:** body` → `:::warning\nbody\n:::`
- `> **Note:** body` → `:::note\nbody\n:::`
- `> **Tip:** body` → `:::tip\nbody\n:::`
- `> **Info:** body` → `:::info\nbody\n:::`
- `> **Danger:** body` → `:::danger\nbody\n:::`

### 5. Code fences

- Keep the language tag. Vocs's Shiki transformers add
  `[!code highlight]`, `[!code ++]`, `[!code --]`, `[!code focus]`
  for free; opt in per-line where it adds value.
- Rust code blocks gain hover types once `experimental_rust`
  twoslash is enabled in `vocs.config.ts`. Until then, no change.

### 6. HTML and entities

- `&mdash;` renders to `—` — leave it alone (MDX parses entities).
- `<kbd>` is fine in MDX; no change needed.
- Bare HTML tables work but `remark-gfm` Markdown tables are
  preferred; rewrite tables only when touching surrounding
  content.

### 7. Images

- Move `web/public/*` assets into `apps/docs/public/`.
- Move `benchmarks/charts/*.svg` references unchanged — the
  benchmark generator continues to write into `benchmarks/charts/`
  and `apps/docs/public/benchmarks/` symlinks (or copies) it at
  build time.

## Landing page

The current landing at `web/src/pages/index.tsx` becomes
`apps/docs/src/pages/index.mdx`. It uses the Vocs `HomePage`
primitive plus the existing demo cards as client components.

Skeleton:

```mdx
---
layout: minimal
title: mkit — A content-addressed VCS in Rust
description: BLAKE3-addressed objects, Ed25519-signed commits, portable in-toto v1 attestations.
showAskAi: false
showLogo: false
---

import { HomePage } from "vocs";
import { DemoCards } from "../components/demo-cards.client.tsx";

<HomePage.Root>
  <HomePage.Logo />
  <HomePage.Tagline>A content-addressed VCS.</HomePage.Tagline>
  <HomePage.Description>
    Every file is named by a BLAKE3 hash of its bytes. Every commit
    is signed. Every review is a portable, signed claim anyone can
    verify. Written in Rust — here it runs in your browser.
  </HomePage.Description>
  <HomePage.Buttons>
    <HomePage.Button href="/docs/install" variant="accent">Install</HomePage.Button>
    <HomePage.Button href="/docs">Docs</HomePage.Button>
    <HomePage.Button href="/demos/hash">Try it</HomePage.Button>
  </HomePage.Buttons>
</HomePage.Root>

<DemoCards />
```

## Demo pages

Each WASM demo (`hash`, `sign`, `attest`, `tree`, `streaming`)
becomes a thin MDX wrapper that imports the existing React
component:

```mdx
---
title: Hash — mkit demos
description: Edit a file and watch the BLAKE3 hashes ripple up through every container.
layout: docs
---

import { HashDemo } from "../../components/hash-demo.client.tsx";

# Hash

Edit a file and watch the BLAKE3 hashes of every container that
holds it — folder, parent folder, commit — rewrite live.

<HashDemo />

## How it works

…surrounding prose…
```

The components themselves move from `web/src/components/*.tsx` to
`apps/docs/src/components/*.client.tsx` (with `'use client'` at
the top). The `mkit-wasm` import path stays the same — the
workspace dependency moves from `web/package.json` to
`apps/docs/package.json` verbatim.

## pnpm workspace

`pnpm-workspace.yaml` at the repo root:

```yaml
packages:
  - "apps/*"
```

`package.json` at the repo root (private):

```json
{
  "name": "mkit-monorepo",
  "private": true,
  "scripts": {
    "dev": "pnpm --filter mkit-docs dev",
    "build": "pnpm --filter mkit-docs build",
    "preview": "pnpm --filter mkit-docs preview",
    "deploy": "pnpm --filter mkit-docs deploy"
  },
  "packageManager": "pnpm@10.25.0"
}
```

The Rust workspace at `rust/` is untouched. Cargo and pnpm
coexist at the repo root.

## Deploy

1. Create a Cloudflare Pages project named `mkit-docs` pointing at
   this repo, branch `main`, build command
   `pnpm --filter mkit-docs build`, output directory
   `apps/docs/dist/public`.
2. CNAME `mkit.makechain.net` to the new Pages project.
3. The first deploy runs in shadow at the Pages preview URL.
4. Smoke test (see checklist below) before swinging the CNAME.
5. After the swing, the old Worker behind `web/` is deleted via
   `wrangler delete mkit-demo-web` and `web/` is removed in a
   follow-up commit.

A GitHub Actions workflow runs `pnpm --filter mkit-docs build` on
every PR; Cloudflare Pages handles deploys itself, so CI only
needs to verify the build succeeds.

## Smoke test checklist

Before swinging DNS, verify on the Pages preview URL:

- [ ] `/` renders the landing page with demo cards.
- [ ] `/docs` renders the docs index with sidebar.
- [ ] Every spec page renders, sidebar highlights the current
  page, and no link in the page is dead.
- [ ] All five demos (`/demos/hash`, `/sign`, `/attest`, `/tree`,
  `/streaming`) load the WASM module and respond to input.
- [ ] Search (Ctrl/Cmd-K) returns results for "BLAKE3",
  "attestation", "transport".
- [ ] Dark mode toggle works; `light-dark()` accent renders.
- [ ] OG image renders for `/docs/spec/objects`.
- [ ] `editLink` resolves to the GitHub edit URL.
- [ ] No console errors on first paint of any page.

## docs/ stub

After the migration, `docs/` keeps a single file —
`docs/README.md` — that explains the move and links to the new
locations. This preserves deep links from external sites and from
rustdoc `///` comments that reference `docs/SPEC-OBJECTS.md`.

```markdown
# mkit documentation

The canonical mkit documentation is now hosted at
[mkit.makechain.net](https://mkit.makechain.net).

The source files live under
[`apps/docs/src/pages/`](../apps/docs/src/pages/). Edit them
directly in this repository; Cloudflare Pages picks up changes
on merge to `main`.

| Old path                          | New URL                                    |
| --------------------------------- | ------------------------------------------ |
| `docs/CLI.md`                     | https://mkit.makechain.net/docs/cli        |
| `docs/INSTALL.md`                 | https://mkit.makechain.net/docs/install    |
| `docs/SPEC-OBJECTS.md`            | https://mkit.makechain.net/docs/spec/objects |
| `docs/SPEC-PACKFILE.md`           | https://mkit.makechain.net/docs/spec/packfile |
| `docs/SPEC-ATTESTATIONS.md`       | https://mkit.makechain.net/docs/spec/attestations |
| `docs/STYLE-GUIDE.md`             | https://mkit.makechain.net/docs/style-guide |
| ...                               | ...                                        |
```

The full mapping table covers every relocated file. CI greps for
the old paths and fails the build if any rust source references a
`docs/*.md` path that no longer exists.

## Execution plan (team)

Spawned as parallel subagents off this branch
(`docs/vocs-migration`):

| Agent | Owns | Outputs |
| --- | --- | --- |
| **scaffold** | Workspace + Vocs project skeleton | `pnpm-workspace.yaml`, root `package.json`, `apps/docs/{package.json,vocs.config.ts,vite.config.ts,tsconfig.json,wrangler.jsonc}`, empty `src/` tree, empty `public/`, `apps/docs/src/pages/_root.css`, `_mdx-wrapper.tsx`, `_slots.tsx` |
| **content** | Markdown → MDX for all 19 docs files | `apps/docs/src/pages/docs/**/*.mdx` with frontmatter, link rewrites, alert directives, code-fence transformers. Stub `docs/README.md` with the redirect table. |
| **demos** | Port the five WASM demo pages | `apps/docs/src/components/*.client.tsx` (header, footer, favicon-swapper, pointer-tracker, hash-demo, sign-demo, attest-demo, tree-demo, streaming-demo, merkle-tree, chunk-strip, result-panel, demo-boundary, mkit-preloader, use-mkit); `apps/docs/src/pages/demos/*.mdx`; `apps/docs/public/` (mirrors `web/public/`). Adds `mkit-wasm` dependency to `apps/docs/package.json`. |
| **landing** | Home page + chrome | `apps/docs/src/pages/index.mdx` (replaces `web/src/pages/index.tsx`); wires `_slots.tsx` to use the existing site's header/footer feel where they fit the Vocs chrome. |
| **deploy** | CI + Cloudflare Pages | `.github/workflows/docs.yml` runs build on PR, smoke-test on main. Creates the Cloudflare Pages project shell (manual step documented). |

The agents run in parallel against the same branch; the main
agent (this transcript) merges, resolves conflicts, runs the
smoke test against the Pages preview URL, and opens the PR.

## Rollback

A rollback is one commit: revert the merge that introduced
`apps/docs/` and `pnpm-workspace.yaml`, restore `web/`, and let
the old Worker resume serving `mkit.makechain.net`. Because the
old `web/` deploy is left in place until the smoke test passes,
the worst-case is a CNAME swap back to the old origin, which
takes minutes.

## Out of scope (deferred)

- MCP endpoint, feedback adapter, dynamic OG image at
  `/api/og` — all require Workers Functions; deferred to the
  "Workers + custom edge logic" follow-up.
- Rust twoslash (`@vocs/twoslash-rust`) — toggle on once CI has
  Cargo metadata cached; until then, plain Rust code blocks
  render fine via Shiki.
- Versioned docs — Vocs `next` does not yet ship versioning;
  reassess when upstream ships it.
- Algolia / DocSearch — MiniSearch covers the current corpus
  size comfortably; revisit if the doc set grows past ~100 pages.

## References

- Vocs `next`: https://github.com/wevm/vocs/tree/next
- Reference implementation: `makechain/apps/docs/` (not in this
  repo, but the same maintainer's adjacent project).
- mkit writing conventions: [`STYLE-GUIDE.md`](STYLE-GUIDE.md) —
  applies unchanged inside MDX files.
