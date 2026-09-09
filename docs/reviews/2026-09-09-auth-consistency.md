# Authentication consistency verification — 2026-09-09

The shared Account and AuthProvider cover all seven main routes. TanStack Query owns the browser session and session-scoped workspace reads; Zustand holds the transient signing key and public recovery metadata. Successful public name lookups are the only persisted queries. Private workspace mutation variables and query results are removed on sign-out, and push mutation variables contain the public author key rather than its signing seed.

A seven-day root-path HttpOnly session preserves login across refresh. Signing unlock remains separate and is requested by workspace writes when needed. Global sign-out invalidates owner reads and terminal access. Workspace activation and replay cannot recreate a login cookie.

Validation:

- All 309 web tests pass; TypeScript passes; production build, seven-route prerender, headers, and installer checks pass.
- All 154 worker tests passed before the final activation race fix. The final 33 focused browser-session/integration tests pass, including that regression; worker TypeScript passes.
- Independent review found and resolved cross-tab metadata overwrite, logout cache races, mutation retention, failed sign-out retry, and activation recreating login after logout.
- The browser workflow passes against production with the actual session endpoint and native virtual-authenticator PRF: one passkey creation, two explicitly requested recoveries, no extra ceremonies during navigation or refresh, no page errors, and sign-out propagating across tabs.

Deployed worker versions:

- Workspace: `f5e6436e-a37d-4a93-a6a1-30ed3fd399ad`
- Web: `60161350-9992-48f6-96c6-2a4611d1f371`

Reproduce from `apps/web`: `bun run verify:auth https://mkit.sh`. See [the workflow](../workflows/auth-consistency.md) for local setup and test boundaries.

Production output:

```json
{
  "passed": true,
  "mockSession": false,
  "checks": [
    "one native PRF identity created; persisted state contains no signing authority",
    "seven routes and browser history preserve identity and signing unlock without another ceremony",
    "second tab remembers login without unlocking signing or revoking the first tab",
    "explicit lock preserves login; native unlock recovers the same public identity",
    "refresh on all seven routes remembers identity without automatic passkey prompts",
    "reference-page sign-out reaches both tabs and survives refresh; persisted caches are public only"
  ],
  "ceremonies": {
    "created": 1,
    "asserted": 2
  },
  "origin": "https://mkit.sh",
  "browser": "152.0.7977.83"
}
```
