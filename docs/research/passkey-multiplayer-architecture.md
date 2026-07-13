# Design: passkey identity → Ed25519 → anonymous multiplayer mkit repo

Status: design note (not a spec). Branch `research/passkey-signing-lifecycle`.

Goal: a demo where a visitor enrolls a **P-256 identity passkey**, derives an
**Ed25519 signing key** from it, and then **anyone can push commits** to a
shared, Cloudflare-hosted mkit repo (D1/KV/R2) &mdash; a *multiplayer sandbox*.
Commits are **anonymous**: a signature proves "the same key made these
commits," not *who*. No accounts, no authorization, no billing.

The happy news: **almost none of this is new.** mkit already specs an
HTTP-transport-to-R2 backend, and an existing internal reference Worker
already ships the exact anonymous-contributor pattern &mdash; verifying signatures
with the same `@makechain/mkit-wasm` package this branch extends. The demo
is a *minimal re-cut* of that reference Worker's anonymous path plus the
passkey→Ed25519 client flow.

---

## 1. The three keys (and why)

| Layer | Key | Role | Where it lives |
|---|---|---|---|
| Identity | **P-256 passkey** | Root identity anchor; biometric gate | Synced (iCloud Keychain/Google Password Manager) |
| Signing | **Ed25519** | Signs mkit commits (core is Ed25519-only) | **Derived from the passkey via PRF &mdash; never stored** |
| (optional) Binding | P-256 passkey | Attests "Ed25519 pubkey X is mine" | DSSE attestation, verified by the WASM path this branch added |

**Passkey → Ed25519 via the WebAuthn PRF extension.** The PRF extension returns
a stable 32-byte secret per `(credential, salt)`; an Ed25519 seed *is* 32 bytes.
So:

```
get({ extensions: { prf: { eval: { first: SHA256("mkit.sh/ed25519-identity/v1") } } } })
  → prf.results.first (32 bytes, deterministic per passkey)
  → HKDF-SHA256(ikm=prf, info="mkit-ed25519-signing-v1")  // domain-separate
  → Ed25519 seed → mkit-wasm `ed25519_pubkey_from_seed`/`commit_encode_and_sign`
```

The Ed25519 is **re-derived each session** from a passkey assertion and held
only in memory &mdash; there is no key file. Same passkey → same Ed25519 pubkey →
the *same anonymous player* persists across devices and sessions (because the
passkey syncs), with no real-world identity attached.

- **Support (2026):** synced Apple Passwords + Google Password Manager ≈100%
  PRF-on-create; Android strongest; Windows Hello caught up Feb 2026. The
  Apple/Google org is well covered.
- **Footgun (moot here):** deleting the passkey loses the derived key. For a
  demo this is fine &mdash; ephemeral identity, no stakes. (For production you'd
  escrow or let users register a second device's passkey under the same player.)

---

## 2. Client flow (browser)

1. **Enroll** &mdash; `navigator.credentials.create({ pubKeyCredParams:[{alg:-7}], rp:{id:"mkit.sh"}, extensions:{prf:{}} })`; confirm `getClientExtensionResults().prf.enabled`.
2. **Derive** &mdash; `navigator.credentials.get({ extensions:{ prf:{ eval:{ first: SALT }}}})` → PRF → HKDF → Ed25519 seed → pubkey. (A `get()` is required to actually obtain PRF output on most platforms.)
3. **Author and sign** &mdash; build the commit in WASM: `blob_encode`/`tree_encode`/`commit_encode_and_sign(tree, parents, msg, ts, seed_hex)` (all already exported). Output = canonical object bytes + commit hash + signature.
4. **(optional) Attest the binding** &mdash; P-256 passkey signs a DSSE attestation over the Ed25519 pubkey; verify via `verify_webauthn_wrapping_with_policy` (added on this branch). Shows the full passkey signing lifecycle.
5. **Push** &mdash; sign the request envelope (Ed25519) and POST objects + CAS-advance the ref (§3).
6. **Watch** &mdash; subscribe to the repo's live ref stream for other players' commits (§5).

Libraries: **`ox` `WebAuthnP256`** (ceremony + COSE→SEC1 + DER→compact) for the
attestation path; a thin PRF helper for derivation (SimpleWebAuthn deliberately
won't wrap PRF, so call the raw API). No Rust HTTP transport in the browser &mdash;
plain `fetch`.

---

## 3. Server: a minimal Cloudflare Worker (mirror of an existing internal reference Worker's anonymous path)

The reference Worker's storage split, adopted verbatim:

| Store | Holds | Key shape | Notes |
|---|---|---|---|
| **R2** (`STORAGE`) | Immutable mkit objects (commits, trees, blobs) | `<repo>/objects/<hash>` | Content-addressed; idempotent write via `onlyIf: If-None-Match: *` |
| **Durable Object and SQLite** | Refs (the only mutable state) | table `refs(path PRIMARY KEY, value)` | One DO per repo = serialization gate; CAS in its serial queue |
| **KV** (optional) | Player presence/"seen pubkeys" for the multiplayer UI | `player:<pubkey_hex>` | Not needed for correctness &mdash; the commit's pubkey *is* the identity |

> The reference Worker puts refs in a DO-hosted SQLite (the "D1-like" store)
> rather than raw D1, precisely because a DO gives single-writer
> linearization for free. KV's identity index there maps pubkey→UUID for
> accounts; **that mapping isn't needed here** &mdash; anonymous means the pubkey is the whole
> identity.

**REST contract** &mdash; converges with both mkit's `SPEC-TRANSPORT` §5 HTTP transport
*and* that reference Worker's VCS API. Loose-object variant (no packfile needed, since
pack-creation isn't WASM-exposed yet):

```
PUT  /v1/repos/{repo}/objects/{hash}   body: raw mkit object bytes   → {ok, hash}
GET  /v1/repos/{repo}/objects/{hash}                                  → raw bytes | 404
PUT  /v1/repos/{repo}/refs/{name}      If-Match:"<hash>" | If-None-Match:*   body: <hash>
GET  /v1/repos/{repo}/refs/{name}                                     → <hash> | 404
GET  /v1/repos/{repo}/refs?prefix=                                    → [{name,hash}]
GET  /v1/repos/{repo}/events            (WebSocket; live ref updates — §5)
```

**Auth = demo mode (open write, verify-only).** Mirror the reference Worker's
signed envelope but with `isDemoMode`-style "accept any key":

- Request headers: `X-Public-Key`, `X-Signature`, `X-Digest`, `X-Created-At` (±5 min freshness), `Idempotency-Key`.
- Canonical string `["mkit-write:v1", method, path, repo, bodyDigest, createdAt, idempotencyKey, ifMatch, ifNoneMatch].join("\n")` → BLAKE3 → **`ed25519_verify`** (mkit-wasm, in the Worker &mdash; already proven in production elsewhere).
- **No allow-list, no ownership check.** The signature only proves request integrity + "same author." Any valid Ed25519 key may write any ref.
- **Object validity:** on `PUT .../objects/{hash}`, the Worker runs `commit_verify` (mkit-wasm) for commit objects and checks `BLAKE3(bytes)==hash`, so the shared repo holds only well-formed, self-consistently-signed commits. Cheap, and it demos mkit verification server-side.

---

## 4. Concurrency and consistency

- **Ref CAS in the DO.** `PUT /refs/main` carries `If-Match: "<parent>"`. The
  per-repo RefStore DO reads the current value in its serial queue and writes
  only on match, else `412`. This is exactly the reference Worker's
  `RefStore.writeRef` (`INSERT ... ON CONFLICT DO UPDATE` guarded by the
  read). Linearizable
  without distributed locks.
- **Object writes are commutative.** Content-addressed + idempotent R2 PUT;
  two players uploading the same object is a no-op, different objects don't
  conflict. Only the ref advance is serialized.
- **Client retry on 412** = fetch new ref → rebase/re-parent the commit →
  re-sign → retry. Standard fast-forward CAS loop. (Multiplayer "merge" is just
  a commit with two parents; no PR machinery.)

---

## 5. Real-time multiplayer

A Durable Object can host WebSockets. The per-repo RefStore DO:
- accepts `GET /events` WS connections,
- on every successful ref advance, broadcasts `{ref, hash, author_pubkey}` to all sockets.

Clients turn that event into a **TanStack Query invalidation** → the commit log
/ branch view refetches → everyone sees the new commit within a frame. This is
the "multiplayer" feel: one shared repo, live updates, anonymous authors.

---

## 6. Frontend state stack

Confirmed fit (an existing internal workbench uses the same shape: Vite + React +
TanStack Router + TanStack Query, Ed25519 in the browser):

- **TanStack Query &mdash; server state.** All Worker reads/writes: ref values,
  object/commit fetches, the commit graph, push mutations. Query keys per
  `["repo", repo, "refs"|"objects", …]`. WS event → `invalidateQueries`.
  *Never* mirror this into a client store.
- **Zustand &mdash; client identity/session only.** The passkey credential id, the
  derived Ed25519 pubkey, "unlocked" (seed in memory) flag, the transient seed
  itself, current repo/branch selection, optimistic local-author state. Small,
  synchronous, UI-owned.
- Boundary rule: Query owns *the repo*; Zustand owns *who I am this session*.

---

## 7. What exists vs. what's new

| Piece | Status |
|---|---|
| Ed25519 commit build+sign in WASM (`commit_encode_and_sign`, `ed25519_pubkey_from_seed`) | ✅ exists |
| `ed25519_verify`/`commit_verify` in WASM (server-side, runs in Workers) | ✅ exists (proven in production elsewhere) |
| P-256 passkey attestation + verify (`verify_webauthn_wrapping[_with_policy]`, `attest_pae`) | ✅ added on this branch |
| mkit HTTP transport REST contract + CAS semantics | ✅ specced (`SPEC-TRANSPORT` §5) |
| Reference Worker: R2 objects + DO refs + signed envelope + demo-mode open write | ✅ exists in an existing internal reference Worker (anonymous path) &mdash; to be re-cut minimally |
| PRF → HKDF → Ed25519 seed (browser) | 🔨 new (small; raw WebAuthn API + WebCrypto HKDF) |
| Passkey ceremony in the demo UI (enroll/derive/sign/push/watch) | 🔨 new (the demo work) |
| WS multiplayer events from the RefStore DO | 🔨 new (small; DO WebSocket fan-out) |
| Packfile creation in WASM | ❌ not exposed &mdash; **avoided** by using loose `PUT /objects/{hash}` |

---

## 8. Open decisions

1. **Reuse the existing internal reference Worker in demo mode, or ship a standalone minimal Worker for mkit.sh?** Standalone is cleaner for a public demo (no cross-repo coupling, no billing tables) and is ~a few hundred lines given the reference. Recommended.
2. **Loose objects vs packfiles.** Loose (recommended for the demo) needs no WASM pack support and keeps the Worker trivial; packs would be more faithful to `mkit push` but require exposing pack-creation in WASM.
3. **Attestation binding on/off.** Optional flourish &mdash; show the P-256 passkey vouching for the Ed25519. Nice for the "full lifecycle" story; not required for contribution.
4. **Repo scope.** One shared global repo (max multiplayer chaos) vs. per-room repos (`/repos/{room}`). Per-room is friendlier for demos and trivial (DO id = room).
5. **Anti-abuse on an open-write public endpoint.** Even anonymous, a public CAS endpoint invites spam. Minimum: per-IP rate limit + object size cap + the `commit_verify` gate. (The reference Worker leans on billing reservations; the demo can't.)
