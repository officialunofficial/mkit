# mkit workspace service

This Worker serves the same-origin `/api/workspaces` routes on mkit.sh, including the passkey-backed browser session (`/api/workspaces/session`) that the web app's account control uses. The website no longer ships a workspace page; the workspace routes below are API-only. The Worker requires a saved passkey-derived Ed25519 identity to create or change a workspace.

Each workspace has a Durable Object for its owner and file manifest; an isolated Cloudflare Sandbox for files and commands; and content-addressed mkit objects in R2. Signing seeds are never supplied to the Sandbox.

Files and saved versions are public.

## Execution and recovery

The owner signs a 30-day delegation granting the workspace file, command, and version permissions. The owner's signing key stays in browser memory. Saves and restores create versions; restoring copies an older tree into a new version.

Signed `POST /api/workspaces/:id/versions` accepts `{message, edits?: [{path, content, expectedHash}]}`. It stops and captures the terminal, checks every browser edit against the captured file hashes, and publishes all files as one named version. `expectedHash` is `null` for a new file. A conflict publishes no version or browser edits; captured terminal work remains available as working files. Omitting edits creates a checkpoint of the current working files. Messages are limited to 200 characters and the JSON request to 8 MiB; the file limits below still apply.

Workspace views include each file's content hash and `changes` against the current saved head, with added, modified, or deleted status and before/after hashes. Mode changes are modified even when the hashes match. Historical views return the selected version's file hashes while `changes` continues to describe current working files against the current head.

The terminal uses a real Sandbox PTY in `/workspace/project`. It is unavailable after execution permission expires or is revoked. Saving/restoring files, logging out, or revoking access stops the existing PTY session. The browser retries a dropped connection up to three times while the owner view remains open; Reconnect can also open a fresh shell. It stops retrying when the view closes or the identity is locked. Locking an identity invalidates the owner's server session.

## Current limits

| Resource | Limit |
| --- | --- |
| Tracked project | 256 files, 256 KiB per file, 4 MiB total |
| Paths | 32 components; 1,024 UTF-8 bytes; no traversal or symlinks |
| Excluded from capture | `node_modules`, `.git`, `.mkit`, `.venv`, `__pycache__`, `target`, `.DS_Store` |
| New remixes | 3 per identity/day; 50 across the service/day |
| Shell command | 60 seconds; at most 64 KiB returned output |
| Terminal connection | 20 minutes; global browser session expires after seven days |
| Sandbox | Sleeps after 2 minutes idle; deployment allows 3 concurrent containers |

Daily limits use UTC day boundaries. Container hosting is billed by Cloudflare.

Oversized source files fail capture; they are not silently omitted. Binary blobs and executable modes survive capture and recovery. Dependency and cache directories are not durable; recreate them after a cold start when needed.

## Setup and verification

Run from this directory. Install Node.js, Rust with the WebAssembly target, `wasm-pack`, and Docker for local Sandbox execution. Authenticate Wrangler to the Cloudflare account containing the `mkit.sh` zone and `mkit-repo-worker` service.

```sh
npm ci
npm run wasm:build
npm run types
npm run typecheck
npm test
npm run build
```

`build` is a Worker dry run. It does not publish.  Generated WASM and Worker types must be regenerated after dependency or binding changes.

For a local service on port 8788:

```sh
npm run dev -- --port 8788 --local-upstream localhost:8788 --var AUTH_AUDIENCE:http://localhost:8788
```

The repository binding reads the configured remote demo service; workspace state and objects are local to Wrangler during ordinary local development. Docker must be running for terminal/command tests. A live smoke test creates a remix in the target service, edits files, exercises the PTY, and verifies logout:

```sh
node scripts/smoke.mjs http://localhost:8788
```

The smoke's isolated test identity is stored only in ignored `.wrangler` output. The smoke does not perform a WebAuthn ceremony; verify that separately in the browser.

For local browser testing, proxy `/api/workspaces` HTTP and WebSocket traffic through the web app's origin and set `AUTH_AUDIENCE` to that browser origin. A web development server on a different port cannot call the Worker directly: signed audiences, cookies, and WebSocket Origin checks intentionally require one origin.

## Deployment

Provision the `mkit-workspaces` R2 bucket, enable the account's container support, and verify the service binding and route in `wrangler.jsonc`. Deploy with:

```sh
npm run deploy
```

Deploy the web app separately from `../web`. The workspace Worker owns `mkit.sh/api/workspaces*`; the web app uses its session route. Keep `AUTH_AUDIENCE` equal to `https://mkit.sh` in production. Review container concurrency before increasing it.

After deployment, verify sign-in, sign-out, and session renewal from the web app. Confirm a signed-out visitor can read files and versions but cannot open a terminal.
