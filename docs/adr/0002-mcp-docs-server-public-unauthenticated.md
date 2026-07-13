# ADR 0002 &mdash; MCP documentation server is intentionally public and unauthenticated

- Status: Accepted
- Date: 2026-06-22
- Supersedes: n/a

## Context

The crates/docs MCP server (`apps/mcp`, deployed as a Cloudflare Worker) lets
agents search the mkit source, SPEC docs, and CLI reference at a pinned
release. Its entire corpus is version-pinned content built into a D1 database
at deploy time. The data is public information &mdash; the same source and docs are
already in the open repository &mdash; and the server performs only read-only
lookups over it.

## Decision

- The MCP documentation server is **public and unauthenticated**. There is no
  login, API key, or per-caller credential.
- The server is **read-only over a static corpus**: it serves a version-pinned
  snapshot baked into D1 at deploy. It holds **no runtime credentials** and
  performs no writes, network egress, or privileged operations.
- `Access-Control-Allow-Origin: *` (`CORS: *`) is **acceptable** because there
  is no authenticated session or secret to protect from a cross-origin caller.

## Consequences

- No auth surface to operate, rotate, or leak; the only state is a redeployable,
  reproducible D1 index.
- The corpus is exactly as sensitive as the public repository &mdash; already
  published. Releasing a new docs version is a redeploy, not a data-protection
  event.
- If a future tool needs writes, privileged data, or per-caller policy, that
  tool does **not** belong on this server; it requires its own
  authenticated surface and a new ADR.
