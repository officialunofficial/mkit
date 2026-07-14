# mkit-spammer

A Cloudflare Worker that drives realistic, validly-signed synthetic activity
into a live [mkit](https://mkit.sh) room served by `mkit-repo-worker`
(`https://api.mkit.sh`).

A single Durable Object (`Spammer`) owns a self-rescheduling `alarm()` loop.
Once every ~1000 ms it emits a small batch of real events — signed chat
messages, signed commits on `main`, occasional remix objects on `forks/…`
refs, and the odd reaction — from a deterministic pool of 64 synthetic
Ed25519 identities. Every event is built with the same vendored wasm
(`mkit-wasm` + `mkit-repo-client`) the web app uses, so each write carries a
genuine `mkit-write:v1` envelope and passes repo-worker's real signature and
content-address verification. Nothing is mocked or bypassed — this is real
traffic against a real room.

See `PLAN.md` (repo root) for the full design: rate-floor math, the
per-identity floor bookkeeping, and the file-by-file breakdown.

## Content: static by default, optionally AI-refreshed

`src/content.ts` ships fixed, deterministic phrase pools (no RNG). If Workers
AI is available (the `AI` binding in `wrangler.jsonc`), the `Spammer` DO also
runs a background refresh — at most once every ~20 minutes, via
`ctx.waitUntil`, never on the hot 1s alarm tick — asking a cheap model
(`@cf/mistral/mistral-7b-instruct-v0.1`) for a fresh batch of chat/commit/remix
phrases (`src/ai-content.ts`). A successful refresh replaces the pool future
ticks pick from; ANY failure (quota, timeout, malformed/empty JSON, an
oversized entry) is caught and logged, and the Worker just keeps using
whatever pool it already had — the static `content.ts` pool if no refresh has
ever succeeded. Reactions are excluded from this entirely: their emoji stay
pinned to the closed, server-verified `REACTION_EMOJI` allowlist.

This is well inside the Workers AI free tier (10,000 neurons/day): one
batched refresh call every ~20 minutes on the cheapest model is on the order
of a few dozen to a couple hundred requests/day, not the ~259,000/day a
per-event call would require at this Worker's ~3 events/s cadence.

## Inert by default

This Worker never starts anything on its own:

- The `Spammer` Durable Object only arms its first alarm when an
  authenticated `POST /control` (`action=enable`) reaches it. Merging this
  code, or deploying it, does nothing by itself.
- `wrangler.jsonc` ships `ENABLED="false"`. That var isn't even read at
  runtime for the gate (the DO's own `enabled` storage flag is the real
  source of truth, defaulting to unset/`false`) — it exists as a visible,
  grep-able reminder that a fresh deploy must not assume otherwise.
- `wrangler.jsonc` also ships `ROOM="spammer-test"` — a throwaway room, not
  the production `lobby-v2` room. See "Go-live procedure" below.
- No `routes` / `custom_domain` are configured — this Worker is
  `workers.dev`-only. It can never intercept `mkit.sh` / `api.mkit.sh`
  traffic; it is purely an outbound client of the real repo-worker API.

## `/control` API

Every `/control` request (any HTTP method) requires:

```
Authorization: Bearer <CONTROL_TOKEN>
```

`CONTROL_TOKEN` is a Worker *secret* (`wrangler secret put CONTROL_TOKEN`),
never a `wrangler.jsonc` var. If the secret is unset, every `/control` call
is rejected with `401` — an unconfigured secret fails closed, never open.

Action is selected via `?action=` (preferred) or a POST JSON body
`{"action": "..."}`; a bare request with neither defaults to `status`.

| Action | Effect |
|---|---|
| `enable` | Sets the DO's `enabled` flag and arms the first alarm (only if none is already pending). Returns the status payload. |
| `disable` | Deletes any pending alarm, then clears the `enabled` flag. Returns the status payload. |
| `status` | Reports `{ enabled, room, poolSize }` read fresh off DO storage. |

`GET /health` needs no token and returns `200 ok` — it only proves the
Worker is deployed and routable; it reveals nothing about spammer state.

## Kill-switch runbook

If this is producing unwanted activity, in order of speed:

1. **Primary — instant, no deploy.**

   ```
   curl -X POST "https://<worker>.workers.dev/control?action=disable" \
     -H "Authorization: Bearer $CONTROL_TOKEN"
   ```

   The DO deletes its pending alarm and clears the `enabled` flag. Because
   `alarm()` re-checks the flag in its `finally` block (not a value it
   cached at the top of the tick), this wins even if `disable` races an
   in-flight tick doing real network I/O — the loop stops within about one
   tick (≤ ~1 s). Confirm with:

   ```
   curl "https://<worker>.workers.dev/control?action=status" \
     -H "Authorization: Bearer $CONTROL_TOKEN"
   ```

   which should report `"enabled":false`.

2. **A fresh deploy is inert by default.** `ENABLED="false"` in
   `wrangler.jsonc` and the DO's own default-off `enabled` storage flag mean
   that redeploying this Worker (e.g. to ship an unrelated fix) never
   restarts spamming on its own — it stays off until someone explicitly
   calls `/control?action=enable` again.

3. **Hard stop.** Delete the Worker (and its Durable Object storage)
   entirely:

   ```
   wrangler delete mkit-spammer
   ```

   Use this if you want the surface gone, not just paused.

## Go-live procedure (staged rollout)

`wrangler.jsonc` ships pointed at a **throwaway room**, `ROOM="spammer-test"`,
on purpose. Do not point this Worker at the real `lobby-v2` room as part of
routine development.

1. **Stage on `spammer-test`.** Deploy with `ROOM="spammer-test"` (the
   checked-in default). Enable via `/control?action=enable` and verify
   real signed activity lands: read it back with the same client
   (`listMessages` / `listCommits` / `listRefs` against `spammer-test`) and
   by opening `https://mkit.sh` with that room selected to watch the live
   feed populate. Because writes go through the real `AuthInterceptor`,
   acceptance by the server *is* proof the signatures and content-addresses
   verified — nothing here is mocked.
2. **Disable** (`/control?action=disable`) once you're satisfied, before
   touching anything else.
3. **Go live deliberately, as a separate reviewed diff.** Only after the
   test room looks correct: open a PR that changes `ROOM` from
   `"spammer-test"` to `"lobby-v2"` in `wrangler.jsonc` — and nothing else.
   Get that diff reviewed and merged/deployed on its own; do not fold a
   `ROOM` flip into an unrelated code change.
4. **Enable against `lobby-v2`** only after that reviewed deploy is live,
   via the same authenticated `/control?action=enable` call. Watch
   `https://mkit.sh`'s `lobby-v2` room: commits appear in the linear feed,
   chat interleaves oldest-first, remixes appear in the refs/branches panel
   via the live `WatchRefs` broadcast.
5. Keep the kill-switch runbook above handy for the whole time this points
   at `lobby-v2` — `/control?action=disable` is the one action that matters
   in production.

## Local development

```
bun install
bun run wasm:build   # builds the vendored mkit-wasm / mkit-repo-client pkg/ dirs
bun run dev          # wrangler dev
bun run test         # vitest — pure-logic + envelope-signature unit tests
bun run build        # wrangler deploy --dry-run
```

`bun run dev` needs a `.dev.vars` (gitignored, never committed) with a
throwaway `CONTROL_TOKEN` to exercise `/control` locally.

## What this is not

- Not a production surface: `workers.dev`-only, no route, no custom domain.
- Not a mock: every write is a real signed `mkit-write:v1` envelope verified
  by the real repo-worker `AuthInterceptor` — there is no bypass or fixture
  mode.
- Every synthetic write is also mirrored into repo-worker's `WRITE_EVENTS`
  Analytics Engine dataset like any other write, inflating write-volume
  metrics for whatever room this points at. Expected and acceptable for a
  demo room; worth remembering if reading room-level analytics dashboards.
