# Verify browser authentication

Run this check after changing the shared account header, identity persistence, the sign-in and sign-out lifecycle, navigation, or query-cache privacy. It creates one native WebAuthn PRF identity in an isolated Chromium context, then discards that context. Identity is purely client-side, so the check also asserts that the site makes no same-origin `/api/` requests.

From `apps/web`, with dependencies installed and a local server already running:

```sh
bun run verify:auth http://localhost:4173
```

For a deployed site:

```sh
bun run verify:auth https://mkit.sh
```

Set `CHROME_EXECUTABLE` to select an installed Chromium binary. The script also checks Playwright's installed Chromium, the standard macOS Chrome location, and common Linux locations. Use a Chromium build with virtual-authenticator PRF support and `localhost` for local passkeys. Do not use an existing personal browser profile.

| Action | Expected result |
| --- | --- |
| Create one passkey | Signed in; signing unlocked; one credential created |
| Navigate all seven main routes, back, and forward | Same public identity; signing stays unlocked; no additional ceremony |
| Open a second tab | Same remembered identity; signing locked in the new tab; first tab unaffected |
| Lock signing, then unlock explicitly | Both tabs retain login; original tab recovers the same signing identity through native PRF |
| Refresh each main route | Same login and public identity; signing locked; no automatic passkey ceremony |
| Explicitly unlock the first tab, then sign out from the second tab's Concepts page | Both tabs signed out and signing locked; refresh remains signed out |
| Inspect local and session storage | Public identity metadata and public name-query data only; no signing authority or persisted mutations |

The shared Account region exposes `data-auth-status`, `data-signing-status`, and `data-public-key`. The workflow waits for these states and visible navigation controls rather than network idleness. Output is sanitized JSON with an exit status suitable for CI; it never prints credentials, PRF output, signing seeds, cookies, request headers, or raw browser exceptions.

WebAuthn and PRF remain native through the [Chrome DevTools WebAuthn API](https://chromedevtools.github.io/devtools-protocol/tot/WebAuthn/). Keep the original authenticator tab alive throughout: the virtual credential belongs to its CDP target.

The second tab starts signing-locked, so test lock propagation between two unlocked stores in the focused identity unit tests (`auth-provider.test.tsx`), including a ceremony that is still running when another tab signs out. The browser check proves navigation, refresh, native recovery, and cross-tab sign-out through the rendered app.

The root QueryProvider owns a single AuthProvider and Account region for every route. There is no server session: the remembered identity is the persisted public `knownPublicKey` in the `mkit-identity` store, and only successful `['keys', 'name', publicKey]` queries persist in the query cache. Private signing seeds are held in memory only and never enter persisted state.

Refresh preserves the remembered identity; the signing seed is recovered through **Unlock signing** (a passkey ceremony). **Lock signing** discards the in-memory key while preserving the identity. **Sign out** forgets the identity, wipes the seed, keeps the passkey credential id for the next sign-in, and signs out other tabs.
