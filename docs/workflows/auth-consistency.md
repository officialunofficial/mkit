# Verify browser authentication

Run this check after changing the shared account header, identity persistence, session lifecycle, navigation, or query-cache privacy. It creates one native WebAuthn PRF identity in an isolated Chromium context, then discards that context. It never creates a workspace, opens a terminal, or submits a model task.

From `apps/web`, with dependencies installed and a local server already running:

```sh
bun run verify:auth http://localhost:4173
```

For a static build without the session backend:

```sh
bun run verify:auth http://localhost:4173 --mock-session
```

For the deployed session endpoint:

```sh
bun run verify:auth https://mkit.sh
```

Set `CHROME_EXECUTABLE` to select an installed Chromium binary. The script also checks Playwright's installed Chromium, the standard macOS Chrome location, and common Linux locations. Use a Chromium build with virtual-authenticator PRF support and `localhost` for local passkeys. Do not use an existing personal browser profile.

| Action | Expected result |
| --- | --- |
| Create one passkey | Signed in; signing unlocked; one credential created |
| Navigate all seven main routes, back, and forward | Same public identity; signing stays unlocked; no additional ceremony |
| Open a second tab | Same login; signing locked in the new tab; first tab unaffected |
| Lock signing, then unlock explicitly | Both tabs retain login; original tab recovers the same signing identity through native PRF |
| Refresh each main route | Same login and public identity; signing locked; no automatic passkey ceremony |
| Explicitly unlock the first tab, then sign out from the second tab's Concepts page | Both tabs signed out and signing locked; refresh remains signed out |
| Inspect local and session storage | Public identity metadata and public name-query data only; no signing authority or persisted mutations |

The shared Account region exposes `data-auth-status`, `data-signing-status`, and `data-public-key`. The workflow waits for these states and visible navigation controls rather than network idleness. Output is sanitized JSON with an exit status suitable for CI; it never prints credentials, PRF output, signing seeds, cookies, request headers, or raw browser exceptions.

`--mock-session` intercepts only `/api/workspaces/session` and simulates shared GET/POST/DELETE session state. POST reads the public signing-key header; this mode does **not** verify its signature, cookie attributes, expiry enforcement, or backend authorization. WebAuthn and PRF remain native through the [Chrome DevTools WebAuthn API](https://chromedevtools.github.io/devtools-protocol/tot/WebAuthn/). Run live mode to exercise the real session endpoint. Keep the original authenticator tab alive throughout: the virtual credential belongs to its CDP target.

This check validates persisted query privacy without creating private workspace data. The second tab starts signing-locked, so also test lock propagation between two unlocked stores in the focused identity/session/query unit tests. Those tests should cover private-cache eviction, delayed owner responses after lock or identity replacement, and session-creation/sign-out races. The browser check proves navigation, refresh, native recovery, and remote sign-out through the rendered app.

The root QueryProvider owns a single AuthProvider and Account region for every route. `['auth', 'session']` represents the server login; only successful `['keys', 'name', publicKey]` queries persist. Workspace reads and mutations use the `['workspaces', sessionId, publicKey, ...]` scope and are cleared on sign-out or account replacement. Signing unlock leaves that server session and its cache intact. Private signing seeds are resolved only when executing signed writes and never enter persisted state.

The server sets a seven-day, root-path HttpOnly cookie. Refresh preserves login and owner access; the signing seed is recovered on the next signed workspace action or through **Unlock signing**. **Lock signing** discards the in-memory key while preserving login. **Sign out** revokes the server session, removes private caches, and locks other tabs. Activation cannot create login cookies.
