# mkit workspace service

This Worker powers `/create` on mkit.sh through the same-origin `/api/workspaces` routes. Users remix the `lobby-v2` demo repository's `main` ref, or another public workspace. The browser requires a saved passkey-derived Ed25519 identity to create or change a workspace.

Each workspace has a Durable Object for its owner, task, conversation, and file manifest; an isolated Cloudflare Sandbox for files and commands; and content-addressed mkit objects in R2. Published nanocodex 0.5.0 runs unchanged in the Worker. A private protocol adapter connects it to Groq's `openai/gpt-oss-120b` model. Model credentials and signing seeds are never supplied to the Sandbox.

Files and saved versions are public. Prompts, agent answers, and task details require the owner's session. Public commit messages do not contain private task prompts. Agent output written into project files is public, like every other file.

## Execution and recovery

The owner signs a 30-day delegation granting the workspace agent file, command, and version permissions. The owner's signing key stays in browser memory. The agent signs automatic versions under its own key, so accepted tasks continue after the browser closes. Manual saves and restores also create versions; restoring copies an older tree into a new version.

Signed `POST /api/workspaces/:id/versions` accepts `{message, edits?: [{path, content, expectedHash}]}`. It stops and captures the terminal, checks every browser edit against the captured file hashes, and publishes all files as one named version. `expectedHash` is `null` for a new file. A conflict publishes no version or browser edits; captured terminal work remains available as working files. Omitting edits creates a checkpoint of the current working files. Messages are limited to 200 characters and the JSON request to 8 MiB; the file limits below still apply.

Workspace views include each file's content hash and `changes` against the current saved head, with added, modified, or deleted status and before/after hashes. Mode changes are modified even when the hashes match. Historical views return the selected version's file hashes while `changes` continues to describe current working files against the current head.

Tasks checkpoint file changes after each mutating tool. A successful task atomically saves its version, conversation snapshot, completion state, and final answer. Cancellation or failure retains captured draft files without publishing a completed-task version. If the Worker restarts during a running task, recovery marks it interrupted and preserves its saved draft. It does not replay shell commands whose outcome is uncertain; the user submits a new task to continue.

The terminal uses a real Sandbox PTY in `/workspace/project`. It is unavailable during agent tasks and after execution permission expires or is revoked. Starting a task, saving/restoring files, logging out, or revoking access stops the existing PTY session. The browser retries a dropped connection up to three times while the owner view remains open; Reconnect can also open a fresh shell. It stops retrying when the view closes or the identity is locked. Locking an identity invalidates the owner's server session; it does not cancel an already authorized agent task.

## Current limits

| Resource | Limit |
| --- | --- |
| Tracked project | 256 files, 256 KiB per file, 4 MiB total |
| Paths | 32 components; 1,024 UTF-8 bytes; no traversal or symlinks |
| Excluded from capture | `node_modules`, `.git`, `.mkit`, `.venv`, `__pycache__`, `target`, `.DS_Store` |
| New remixes | 3 per identity/day; 50 across the service/day |
| Agent tasks | 12 per identity/day; one active task per workspace |
| Task execution deadline | 5 minutes, followed by cleanup |
| Shell command | 60 seconds; at most 64 KiB returned output |
| Terminal connection | 20 minutes; global browser session expires after seven days |
| Sandbox | Sleeps after 2 minutes idle; deployment allows 3 concurrent containers |
| Model requests | 12 per task; up to 4,096 output tokens per request, reduced for larger input histories |
| Saved model history | 24,000 bytes |
| Shared model allowance | 900 requests and 180,000 tokens/day by default |
| Minute admission | Continuously refills 25 requests and 7,500 reserved tokens/minute; bounded waits |

Daily limits use UTC day boundaries. Model reservations tokenize the serialized request with the model’s ordinary o200k vocabulary and add a 512-token framing reserve before a request and are adjusted when actual usage arrives. Requests with unknown usage keep their reservation. Groq may enforce additional provider limits; a short provider rate-limit response receives one quota-admitted retry. The model's free allowance does not include Cloudflare container hosting costs.

Oversized source files fail capture; they are not silently omitted. File reads and listings are paginated to keep tool results within model limits. Binary blobs and executable modes survive capture and recovery. Dependency and cache directories are not durable; recreate them after a cold start when needed. When conversation context fills up, select **New conversation** while the agent is idle. This clears model history, chat messages, and the last task while preserving files and saved versions.

## Setup and verification

Run from this directory. Install Node.js, Rust with the WebAssembly target, `wasm-pack`, and Docker for local Sandbox execution. Authenticate Wrangler to the Cloudflare account containing the `mkit.sh` zone and `mkit-repo-worker` service.

```sh
npm ci
npm run wasm:build
npm run runtime:stage
npm run types
npm run typecheck
npm test
npm run build
```

`build` is a Worker dry run. It does not publish. The runtime staging script copies the installed, unmodified nanocodex WASM into the ignored vendor directory. Generated WASM and Worker types must be regenerated after dependency or binding changes.

Set `GROQ_API_KEY` through an ignored local `.dev.vars` file. Do not commit credentials. For a local service on port 8788:

```sh
npm run dev -- --port 8788 --local-upstream localhost:8788 --var AUTH_AUDIENCE:http://localhost:8788
```

The repository binding reads the configured remote demo service; workspace state and objects are local to Wrangler during ordinary local development. Docker must be running for terminal/command tests. A live smoke test creates a remix in the target service, edits files, exercises the PTY, and verifies logout:

```sh
node scripts/smoke.mjs http://localhost:8788
node scripts/smoke.mjs http://localhost:8788 --agent
```

The second command also consumes real Groq model usage and verifies completion after the client disconnects. Its isolated test identity is stored only in ignored `.wrangler` output. The smoke does not perform a WebAuthn ceremony; verify that separately in the browser.

For local browser testing, proxy `/api/workspaces` HTTP and WebSocket traffic through the web app's origin and set `AUTH_AUDIENCE` to that browser origin. A web development server on a different port cannot call the Worker directly: signed audiences, cookies, and WebSocket Origin checks intentionally require one origin.

## Deployment

Provision the `mkit-workspaces` R2 bucket, enable the account's container support, and verify the service binding and route in `wrangler.jsonc`. Configure the production secret through Wrangler's prompt:

```sh
npx wrangler secret put GROQ_API_KEY
npm run deploy
```

Deploy the web app separately from `../web`. The workspace Worker owns `mkit.sh/api/workspaces*`; the web app serves `/create`. Keep `AUTH_AUDIENCE` equal to `https://mkit.sh` in production. Review the model quotas and container concurrency before increasing them.

After deployment, verify a real passkey remix, file save, terminal command, agent task, automatic version, history restore, and logout. Confirm a signed-out visitor can read files and versions but cannot read the conversation or open a terminal. Reopen the workspace after closing its tab to verify durable task completion.
