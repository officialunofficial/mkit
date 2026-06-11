# mkit MCP

A [Model Context Protocol](https://modelcontextprotocol.io/) server for the
**mkit** toolkit, deployed at **https://mcp.mkit.makechain.net**. It gives AI
assistants a version-pinned, searchable index of mkit's crate source, the
`docs/SPEC-*` corpus, and the CLI reference — so they build against the real
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
| `list_specs` | The `docs/SPEC-*.md` specifications. |
| `get_spec` | One SPEC doc by name (e.g. `ATTESTATIONS`). |
| `get_command` | One CLI subcommand's reference (e.g. `attest`); omit `name` to list all. |
| `get_cli_reference` | The agent-oriented CLI guide (the repo's `SKILL.md`). |
| `search_docs` | Ranked snippet search over the prose docs. |

The first seven mirror the [Commonware MCP](https://mcp.commonware.xyz); the
last five are mkit-specific (SPEC corpus + CLI reference).

## Connecting

### Claude Code

```bash
claude mcp add --transport http mkit https://mcp.mkit.makechain.net
```

Or add to `.mcp.json` in your project (see [`.mcp.json`](./.mcp.json)):

```json
{
  "mcpServers": {
    "mkit": { "type": "http", "url": "https://mcp.mkit.makechain.net" }
  }
}
```

### Cursor

```json
{ "mcpServers": { "mkit": { "url": "https://mcp.mkit.makechain.net" } } }
```

## Architecture

Cloudflare Worker using the [Agents SDK](https://developers.cloudflare.com/agents/)
`McpAgent` + `@modelcontextprotocol/sdk`, backed by **D1** (FTS5: trigram for
substring search, unicode61 for word search).

The mkit repo is **private** while its crates are public, so — unlike
Commonware, which cron-fetches its public GitHub — this server **bakes the
corpus into D1 at deploy time** from the source tree (`scripts/build-index.mjs`,
run in CI, which has repo access). The Worker then serves everything from D1
with **no runtime credentials**. The corpus is version-pinned to the workspace
version (`rust/Cargo.toml`), so multiple releases can coexist.

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

## Deploy

Deploy is automated in CI (`.github/workflows/mcp-deploy.yml`), but manually:

```bash
npm run index            # rebuild dist/seed.sql from the tree
npm run db:migrate       # apply migrations to remote D1 (idempotent)
npm run db:seed          # load the corpus into remote D1
npm run deploy           # wrangler deploy (custom domain mcp.mkit.makechain.net)
```

> **Large seeds:** `dist/seed.sql` is the whole workspace (~3.5 MB at 0.2.0). If
> a future workspace outgrows D1's single-file import limit, split the seed into
> chunks and `db:seed` each — the schema's upsert/delete-by-version makes
> re-seeding idempotent.

Secrets needed in CI: `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID` (D1 edit +
Workers deploy scope).
