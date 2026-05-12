# Deploying `mkit-docs`

Operator runbook for the Vocs-powered docs site that lives at
[`mkit.makechain.net`](https://mkit.makechain.net). The site is
hosted on **Cloudflare Pages** and deploys via the Git integration:
push to `main` ships production, every other branch ships a preview
URL. GitHub Actions only verifies the build succeeds
(`.github/workflows/docs.yml`).

The plan-of-record for the migration itself is
[`docs/VOCS-MIGRATION.md`](../../docs/VOCS-MIGRATION.md). This file
covers the operational side — creating the Pages project, swinging
DNS, smoke-testing, rolling back.

---

## 1. One-time setup (Cloudflare Pages project)

Done once by a Cloudflare account admin. Subsequent deploys are
automatic.

1. **Cloudflare dashboard → Workers & Pages → Create → Pages →
   Connect to Git.** Pick the `officialunofficial/mkit` repo.
2. **Project name:** `mkit-docs`. This becomes the
   `*.pages.dev` preview hostname.
3. **Production branch:** `main`. Preview deploys: **All non-production
   branches** (default).
4. **Build configuration:**
   - **Framework preset:** None (custom).
   - **Build command:**
     ```sh
     bash apps/docs/scripts/cf-pages-build.sh
     ```
     If you don't want a wrapper script, paste the contents inline
     in the dashboard. The build needs three steps in order:
     ```sh
     # 1. Toolchain — Pages base images ship rustup; the wasm32
     #    target is not pre-installed.
     rustup target add wasm32-unknown-unknown
     # 2. wasm-pack — same version as `release.yml` and
     #    `.github/workflows/docs.yml` to avoid drift.
     cargo install wasm-pack --locked --version 0.13.1
     # 3. Build the `mkit-wasm` package the docs site links to via
     #    `file:../../rust/crates/mkit-wasm/pkg`. The docs use the
     #    `web` target (not `bundler`).
     (cd rust/crates/mkit-wasm && wasm-pack build --target web --out-dir pkg --release)
     # 4. Install workspace deps and build the site.
     corepack enable
     pnpm install --frozen-lockfile
     pnpm --filter mkit-docs build
     ```
   - **Build output directory:** `apps/docs/dist/public`.
   - **Root directory (advanced):** leave at repo root (empty).
5. **Environment variables** (Production + Preview):
   - `NODE_VERSION` = `22`
   - `PNPM_VERSION` = `10.25.0`
   - `CARGO_TERM_COLOR` = `always` (optional, for nicer logs)
6. **Save and deploy.** The first build takes ~6–8 min cold (cargo
   registry + wasm-pack install + Vocs build). Subsequent builds
   reuse Cloudflare's per-project build cache and run in ~2 min.

### Tokens and ownership

Nothing in this repo needs a Cloudflare API token — the Git
integration handles auth on Cloudflare's side. A repo admin must
authorize the Cloudflare Pages GitHub App once when creating the
project.

---

## 2. DNS swing to the new project

The current `mkit.makechain.net` is served by the Worker defined in
`web/wrangler.jsonc` (Workers Assets binding). The swing happens in
the Cloudflare dashboard, not in this repo:

1. **Smoke-test on the preview URL first.** The Pages project gets
   a stable hostname (`mkit-docs.pages.dev`). Run the checklist in
   §4 against it before touching DNS.
2. **Pages project → Custom domains → Set up a custom domain →**
   `mkit.makechain.net`. Cloudflare detects that the zone is on the
   same account and offers to update the DNS record in place;
   accept.
3. **Cloudflare updates the CNAME to point at the Pages project.**
   The old Worker remains deployed but stops receiving traffic on
   the custom domain (it keeps serving on its `*.workers.dev`
   subdomain).
4. **Verify** `curl -I https://mkit.makechain.net/` returns
   `cf-ray` headers from the Pages edge (look for
   `server: cloudflare` and a `200` from a Pages asset path).
5. **The old Worker stays deployed for one release cycle.** A
   follow-up PR removes `web/` and runs `wrangler delete
   mkit-demo-web`. Until then, rollback is a CNAME flip away.

---

## 3. Local preview

Workspace install at the repo root:

```sh
pnpm install
```

This builds nothing — it just resolves the workspace. The
`mkit-wasm` package is referenced as a file dep, so make sure
`rust/crates/mkit-wasm/pkg/` exists:

```sh
(cd rust/crates/mkit-wasm && wasm-pack build --target web --out-dir pkg --release)
```

Dev server (HMR, Vocs dev mode):

```sh
pnpm --filter mkit-docs dev
```

Production build + local preview of the built artifact (matches
what Cloudflare Pages serves):

```sh
pnpm --filter mkit-docs build
pnpm --filter mkit-docs preview
```

Type-check without building:

```sh
pnpm --filter mkit-docs typecheck
```

---

## 4. Smoke-test checklist

Copied from `docs/VOCS-MIGRATION.md` so this file is self-contained.
Run against the Pages preview URL before swinging DNS, and again
against `mkit.makechain.net` after.

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

---

## 5. Rollback

The migration is a single merge commit. To roll back:

1. **`git revert -m 1 <merge-sha>`** on `main`, push. The CI
   workflow runs but is now a no-op (no `apps/docs/`); restore
   `web/` from the pre-merge tree if the revert didn't bring it
   back (`git checkout <pre-merge-sha>^ -- web/`).
2. **Cloudflare dashboard → Pages project `mkit-docs` → Custom
   domains → remove `mkit.makechain.net`.** Re-add it to the
   `mkit-demo-web` Worker (Workers → Triggers → Custom Domains).
3. Cloudflare updates the CNAME; propagation is seconds because
   both records terminate inside Cloudflare.
4. The Pages project can be left in place — it costs nothing and
   keeps the build history for the next attempt.

Time-to-recover: under 5 minutes once an operator is in the
dashboard.

---

## 6. Open follow-ups

Deferred from the migration; track these as separate PRs after the
docs site is live. See `docs/VOCS-MIGRATION.md#out-of-scope-deferred`
for context.

- [ ] **MCP endpoint.** Port `web/`'s MCP server to a Pages Function
      or a routed Worker (`/api/mcp`).
- [ ] **Feedback adapter.** Port the feedback handler currently in
      `web/` (writes to a queue / KV).
- [ ] **Dynamic OG image.** Currently the config points at
      `og.makechain.net`. If/when we want repo-local OG generation,
      add a Pages Function at `/api/og`.
- [ ] **Rust twoslash.** Enable `experimental_rust` in
      `vocs.config.ts` once Cargo metadata is cached in CI.
- [ ] **Delete the old worker.** Once the new site has been stable
      on `mkit.makechain.net` for one release cycle, remove `web/`
      from the repo and run `wrangler delete mkit-demo-web`.
- [ ] **Algolia / DocSearch.** Revisit if the doc set grows past
      ~100 pages; MiniSearch is fine until then.
