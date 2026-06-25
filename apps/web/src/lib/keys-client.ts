// Client for keys.mkit.sh (apps/keys-worker) — the pubkey→handle registry.
//
// Writes reuse the SAME signed envelope the repo client builds
// (`repo/envelope.ts`): the worker verifies `X-Public-Key`/`X-Signature`/… over
// `BLAKE3(canonical)` and enforces signer == the named pubkey. Reads are open.
//
// The base URL comes from `VITE_KEYS_URL`. When it's unset (offline/mock dev),
// the registry is DISABLED: writes no-op and reads return null, so callers fall
// back to the deterministic `playerName()` and the demo still runs.

import type { MkitApi } from './mkit'
import { buildSignedEnvelope, envelopeHeaders } from './repo/envelope'

const TEXT_ENCODER = new TextEncoder()

/** Envelope `procedure` for a name write — must match keys-worker's constant. */
const SET_NAME_PROCEDURE = '/mkit.keys.v1.Keys/SetName'

/** The deployed production registry (apps/keys-worker). */
const PROD_KEYS_URL = 'https://keys.mkit.sh'

/**
 * Registry base URL (no trailing slash), or null when the registry is disabled.
 *
 * `VITE_KEYS_URL` (a build-time var) wins when set — use it to point at a local worker or a preview deploy. Otherwise
 * we default to the production registry when served from an `mkit.sh` host, so prod works with no build-env wiring.
 * Local dev / SSR / tests (no `window`, or a non-mkit host) stay disabled and fall back to the deterministic
 * `playerName`.
 */
export function keysBaseUrl(): string | null {
  const raw = import.meta.env.VITE_KEYS_URL as string | undefined
  if (raw) return raw.replace(/\/$/, '')
  if (typeof window !== 'undefined') {
    const host = window.location.hostname
    if (host === 'mkit.sh' || host.endsWith('.mkit.sh')) return PROD_KEYS_URL
  }
  return null
}

/** True when a keys.mkit.sh base URL is configured. */
export function keysEnabled(): boolean {
  return keysBaseUrl() !== null
}

export type NameRecord = { pubkey: string; name: string; updated_at: number }

/** GET /name/<pubkey> — the stored handle, or null (unset / disabled / error). */
export async function getName(pubkeyHex: string): Promise<string | null> {
  const base = keysBaseUrl()
  if (!base || !pubkeyHex) return null
  const res = await fetch(`${base}/name/${pubkeyHex.toLowerCase()}`)
  if (res.status === 404) return null
  if (!res.ok) return null
  const rec = (await res.json()) as NameRecord
  return rec.name ?? null
}

/** POST /resolve — batch pubkey→name map for many authors at once. */
export async function resolveNames(pubkeysHex: string[]): Promise<Record<string, string>> {
  const base = keysBaseUrl()
  if (!base || pubkeysHex.length === 0) return {}
  const res = await fetch(`${base}/resolve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ pubkeys: pubkeysHex.map((p) => p.toLowerCase()) }),
  })
  if (!res.ok) return {}
  const body = (await res.json()) as { names?: Record<string, string> }
  return body.names ?? {}
}

/**
 * PUT /name/<pubkey> — set/rename the signer's own handle. Signs the request with `seedHex` over the exact JSON body
 * bytes. Resolves to the stored name, or null when the registry is disabled. Throws on a rejected (non-2xx) write so
 * the caller can surface it.
 */
export async function setName(api: MkitApi, seedHex: string, pubkeyHex: string, name: string): Promise<string | null> {
  const base = keysBaseUrl()
  if (!base) return null

  // The body bytes we hash MUST be the bytes we send — serialize once.
  const bodyStr = JSON.stringify({ name })
  const bodyDigest = api.blake3_hex(TEXT_ENCODER.encode(bodyStr))
  const env = buildSignedEnvelope(api, seedHex, { procedure: SET_NAME_PROCEDURE, bodyDigest })

  const res = await fetch(`${base}/name/${pubkeyHex.toLowerCase()}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', ...envelopeHeaders(env) },
    body: bodyStr,
  })
  if (!res.ok) throw new Error(`keys: set name failed (${res.status})`)
  const rec = (await res.json()) as NameRecord
  return rec.name ?? null
}
