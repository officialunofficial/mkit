# mkit MCP

A [Model Context Protocol](https://modelcontextprotocol.io/) server for the
**mkit** toolkit, deployed at **https://mcp.mkit.sh**. It gives AI
assistants a version-pinned, searchable index of mkit's crate source, the
`docs/specs/SPEC-*` corpus, and the CLI reference — so they build against the real
API instead of guessing or scraping GitHub.

## Tools

| Tool | Description |
|------|-------------|
| `get_overview` | Top-level repository README. |
| `list_crates` | The workspace crates with descriptions + paths. |
| `get_crate_readme` | A crate's README (e.g. `mkit-keystore`). |
| `list_files` | Files in a crate/dir (omit `crate` for top-level dirs). |
| `get_file` | A file by repo-relative path, optionally a line range. |
| `search_code` | Ranked snippet search over Rust/TOML source. |
| `list_versions` | Indexed mkit versions (newest first). |
| `list_specs` | The `docs/specs/SPEC-*.md` specifications. |
| `get_spec` | One SPEC doc by name (e.g. `ATTESTATIONS`). |
| `get_command` | One CLI subcommand's reference (e.g. `attest`); omit `name` to list all. |
| `get_cli_reference` | The agent-oriented CLI guide (the repo's `SKILL.md`). |
| `search_docs` | Ranked snippet search over the prose docs. |

The first seven mirror the [Commonware MCP](https://mcp.commonware.xyz); the
last five are mkit-specific (SPEC corpus + CLI reference).

## Sibling: the local `mkit mcp` server

This Worker serves mkit's **documentation and source corpus**. To let an agent
**operate a local repository** (status, staging, signed commits, attestation,
verification), use the local stdio MCP server built into the CLI itself —
`mkit mcp [--repository <path>]` — documented in `docs/CLI.md` §"Agent
integration". The two are complementary: connect both.

## Connecting

### Claude Code

```bash
claude mcp add --transport http mkit https://mcp.mkit.sh
```

Or add to `.mcp.json` in your project (see [`.mcp.json`](./.mcp.json)):

```json
{
  "mcpServers": {
    "mkit": { "type": "http", "url": "https://mcp.mkit.sh" }
  }
}
```

### Cursor

```json
{ "mcpServers": { "mkit": { "url": "https://mcp.mkit.sh" } } }
```

## Architecture

Cloudflare Worker using the [Agents SDK](https://developers.cloudflare.com/agents/)
`McpAgent` + `@modelcontextprotocol/sdk`, backed by **D1** (FTS5: trigram for
substring search, unicode61 for word search).

This server **bakes the corpus into D1 at deploy time** from the source tree
(`scripts/build-index.mjs`, run in CI) rather than cron-fetching a live repo at
runtime. The Worker then serves everything from D1 with **no runtime
credentials**. The corpus is version-pinned to the workspace version
(`rust/Cargo.toml`), so multiple releases can coexist.

## Development

Prereqs: Node 18+, Wrangler, a Cloudflare account.

```bash
cd mcp
npm install

# Build the corpus seed from the working tree (writes dist/seed.sql + manifest.json):
npm run index

# One-time: create the D1 database and paste the returned id into wrangler.jsonc:
npm run db:create

# Apply schema + seed to a LOCAL D1, then run the Worker locally:
npm run db:migrate:local
npm run db:seed:local
npm run dev    # MCP inspector: npx @modelcontextprotocol/inspector@latest → Streamable HTTP → http://localhost:8787

npm run ci     # typecheck + tests
./scripts/itest.sh   # optional: load schema+seed into a throwaway SQLite DB and
                     # run the Worker's exact queries (needs sqlite3 w/ FTS5)
```

## Deploy model: release-gated corpus, continuous Worker

The corpus is **version-pinned and immutable**: each indexed version matches
the source tree of its release tag, so what the MCP serves for `v0.2.0` is
exactly what `cargo install mkit-cli` at 0.2.0 builds against. The Worker
**code** and the served **corpus** deploy on separate paths — two GitHub
Actions workflows plus Cloudflare Workers Builds:

| Path | Trigger | Does |
|---|---|---|
| `mcp.yml` | PR / push touching mcp or docs | Validate only (index + typecheck + test). |
| Cloudflare **Workers Builds** (CF dashboard git integration) | Merge to `main` | Build + deploy the Worker **code** only — never seeds. Tool/`instructions` fixes reach agents without waiting for a release. Same model the web app uses; configured in the Cloudflare dashboard, not in this repo. |
| `mcp-release.yml` | Release tag `v*.*.*` (or dispatch) | Check out the **tag**, guard tag == workspace version, **seed that version into D1 if not already indexed**. Already-indexed versions are never touched; `workflow_dispatch` with `force: true` re-seeds a version *from its own tag* (indexer-fix escape hatch). Does **not** deploy the Worker — Workers Builds already shipped the code from `main`. |

Consequence: docs/SPEC/SKILL edits on `main` appear in the MCP **at the next
release** (by design — served docs match the released binary). The Worker code
itself tracks `main` via Workers Builds.

Manual deploy (escape hatch / local):

```bash
npm run index            # rebuild dist/seed.sql from the tree
npm run db:migrate       # apply migrations to remote D1 (idempotent)
npm run db:seed          # load the corpus into remote D1
npm run deploy           # wrangler deploy (custom domain mcp.mkit.sh)
```

> **Seed size limits:** D1 caps a single SQL *statement* at 100 KB. `build-index`
> automatically splits any oversized file into an `INSERT` + `UPDATE … content =
> content || '<chunk>'` appends (the FTS trigger re-syncs after each), and hard-
> fails if any emitted statement would still exceed the cap — so `db:seed` can't
> silently break. Separately, `dist/seed.sql` as a whole is ~3.5 MB at 0.2.0; if a
> future workspace outgrows D1's single-file import limit, split the file and
> `db:seed` each part — the delete-by-version + upsert makes re-seeding idempotent.

Secrets needed in CI: `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID` (D1 edit
scope for the corpus seed), stored in the GitHub **Environment `mcp`**. The
environment's deployment-branch policy must allow tags matching `v*.*.*` —
otherwise `mcp-release.yml` is silently blocked. (Worker-code deploys go through
Cloudflare Workers Builds, which uses CF-side credentials, not these secrets.)
