// WebAuthn passkey → Ed25519 signing-seed derivation (design note §1, §2).
//
// A synced P-256 passkey is the *identity* anchor; the Ed25519 *signing* key is
// re-derived from it each session via the WebAuthn PRF extension and held only
// in memory. The PRF extension returns a stable 32-byte secret per
// (credential, salt); HKDF-SHA256 domain-separates it into an Ed25519 seed.
//
//   create({ extensions: { prf: {} } })                         // enroll, probe prf.enabled
//   get({ extensions: { prf: { eval: { first: SHA256(SALT_INFO) } } } })
//     → prf.results.first (32 bytes, deterministic per passkey)
//     → HKDF-SHA256(ikm=prf, info="mkit-ed25519-signing-v1")     // 32-byte seed
//
// SimpleWebAuthn deliberately won't wrap PRF, so we call the raw `navigator`
// API directly. `ox`'s WebAuthnP256 is used only for the optional attestation
// ceremony (see `attestEd25519Binding`).

import { Hex, PublicKey, Signature, WebAuthnP256 } from 'ox'
import { bytesToHex } from '../components/use-mkit'
import type { MkitApi } from './mkit'

/** Per-host PRF salt label. The salt itself is SHA-256 of this string (32 bytes). */
function saltInfo(host: string): string {
  return `${host}/ed25519-identity/v1`
}

/** HKDF info string — domain-separates the PRF output into the signing seed. */
const HKDF_INFO = 'mkit-ed25519-signing-v1'

const TEXT_ENCODER = new TextEncoder()

/** The relying-party id is the registrable domain; in the browser that's the hostname. */
export function rpId(): string {
  return typeof location !== 'undefined' ? location.hostname : 'localhost'
}

/** Base64url-nopad encode, used for the WebAuthn `user.id` / challenge plumbing. */
function b64url(bytes: Uint8Array): string {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** A throwaway random challenge — the enroll/derive ceremonies don't verify it server-side here. */
function randomChallenge(): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(32))
}

export type EnrollResult = {
  /** Base64url credential id, used to scope subsequent `get()` assertions. */
  credentialId: string
  /** Whether the authenticator reported PRF support at creation time. */
  prfEnabled: boolean
}

export class PrfUnsupportedError extends Error {
  constructor(message = 'This passkey/authenticator does not support the PRF extension') {
    super(message)
    this.name = 'PrfUnsupportedError'
  }
}

/** True when the platform exposes the WebAuthn API at all. */
export function webauthnAvailable(): boolean {
  return (
    typeof window !== 'undefined' &&
    typeof navigator !== 'undefined' &&
    typeof PublicKeyCredential !== 'undefined' &&
    !!navigator.credentials
  )
}

/**
 * Enroll an identity passkey (§2 step 1). Creates a P-256 (`alg: -7`) discoverable
 * credential with the PRF extension requested, then reports whether the
 * authenticator confirmed PRF support. A `null` return means PRF is unsupported.
 */
export async function enroll(displayName = 'mkit player'): Promise<EnrollResult> {
  if (!webauthnAvailable()) throw new Error('WebAuthn is not available in this environment')

  const userId = crypto.getRandomValues(new Uint8Array(16))
  const cred = (await navigator.credentials.create({
    publicKey: {
      challenge: randomChallenge(),
      rp: { id: rpId(), name: 'mkit multiplayer' },
      user: { id: userId, name: `${displayName}@${rpId()}`, displayName },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
      timeout: 60_000,
      extensions: { prf: {} } as AuthenticationExtensionsClientInputs,
    },
  })) as PublicKeyCredential | null

  if (!cred) throw new Error('Passkey creation was cancelled')

  const ext = cred.getClientExtensionResults() as { prf?: { enabled?: boolean } }
  return {
    credentialId: b64url(new Uint8Array(cred.rawId)),
    // Some platforms only reveal PRF support on the first `get()`, so an absent
    // `enabled` flag here is not authoritative — `deriveEd25519Seed` is the real test.
    prfEnabled: ext.prf?.enabled === true,
  }
}

/** Decode a base64url (no-pad) string back to bytes. */
function fromB64url(s: string): Uint8Array<ArrayBuffer> {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4))
  const b = atob(s.replace(/-/g, '+').replace(/_/g, '/') + pad)
  const out = new Uint8Array(b.length)
  for (let i = 0; i < b.length; i++) out[i] = b.charCodeAt(i)
  return out
}

/** SHA-256 via WebCrypto → Uint8Array. */
export async function sha256(bytes: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  const buf = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer
  return new Uint8Array(await crypto.subtle.digest('SHA-256', buf))
}

/**
 * HKDF-SHA256 over `ikm` with `info`, fixed empty salt, 32-byte output — exactly the
 * Ed25519 seed length. WebCrypto does extract-and-expand in one `deriveBits` call.
 */
export async function hkdfSha256(ikm: Uint8Array, info: string, length = 32): Promise<Uint8Array> {
  const ikmBuf = ikm.buffer.slice(ikm.byteOffset, ikm.byteOffset + ikm.byteLength) as ArrayBuffer
  const key = await crypto.subtle.importKey('raw', ikmBuf, 'HKDF', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: TEXT_ENCODER.encode(info) },
    key,
    length * 8,
  )
  return new Uint8Array(bits)
}

export type DeriveResult = {
  /** 32-byte Ed25519 seed as 64 hex chars — feeds `commit_encode_and_sign` / `ed25519_pubkey_from_seed`. */
  seedHex: string
  /** The raw 32-byte PRF output, for display/debugging only. */
  prfHex: string
  /**
   * Base64url credential id of the passkey the assertion actually used. For a
   * discoverable (no `allowCredentials`) recovery `get()`, this reveals WHICH
   * resident key the user picked, so the caller can persist it. Absent only
   * from the random `ephemeral` fallback.
   */
  credentialId?: string
}

/**
 * Derive the Ed25519 signing seed from an enrolled passkey (§2 step 2).
 * Performs a `get()` with the PRF salt = SHA-256("<host>/ed25519-identity/v1"),
 * reads `prf.results.first`, then HKDF-expands it under `info=HKDF_INFO`.
 *
 * Throws `PrfUnsupportedError` if the authenticator returned no PRF output, so
 * the caller can fall back to an in-memory random seed with a visible notice.
 */
export async function deriveEd25519Seed(credentialId?: string): Promise<DeriveResult> {
  if (!webauthnAvailable()) throw new Error('WebAuthn is not available in this environment')

  const salt = await sha256(TEXT_ENCODER.encode(saltInfo(rpId())))
  const assertion = (await navigator.credentials.get({
    publicKey: {
      challenge: randomChallenge(),
      rpId: rpId(),
      userVerification: 'preferred',
      timeout: 60_000,
      ...(credentialId
        ? { allowCredentials: [{ type: 'public-key', id: fromB64url(credentialId) }] }
        : {}),
      extensions: { prf: { eval: { first: salt } } } as AuthenticationExtensionsClientInputs,
    },
  })) as PublicKeyCredential | null

  if (!assertion) throw new Error('Passkey assertion was cancelled')

  const ext = assertion.getClientExtensionResults() as {
    prf?: { results?: { first?: BufferSource } }
  }
  const first = ext.prf?.results?.first
  if (!first) throw new PrfUnsupportedError()

  const prf = new Uint8Array(first instanceof ArrayBuffer ? first : (first as ArrayBufferView).buffer)
  const seed = await hkdfSha256(prf, HKDF_INFO)
  // Surface which credential the assertion used — for a discoverable (no
  // `allowCredentials`) recovery, this is how the caller learns which resident
  // passkey was picked, so it can be persisted for next time.
  return { seedHex: bytesToHex(seed), prfHex: bytesToHex(prf), credentialId: b64url(new Uint8Array(assertion.rawId)) }
}

export type IdentityResult = DeriveResult & {
  /** Base64url credential id (empty for the ephemeral fallback). */
  credentialId: string
  /** How the seed was obtained — `prf-create` is the one-prompt path. */
  via: 'prf-create' | 'prf-get' | 'ephemeral'
}

/** Coerce a WebAuthn `BufferSource` PRF result to a `Uint8Array`. */
function toPrfBytes(first: BufferSource): Uint8Array {
  return new Uint8Array(first instanceof ArrayBuffer ? first : (first as ArrayBufferView).buffer)
}

/**
 * Create a passkey identity AND derive its Ed25519 seed in ONE ceremony.
 *
 * Collapses the old enroll()+derive() two-prompt flow: the PRF is evaluated AT
 * creation (`prf.eval` on `create()`), so platforms that support PRF-on-create
 * (synced Apple/Google passkeys, ~100% as of 2026) return the seed material in
 * the single registration prompt — no follow-up `get()`. Falls back to one
 * `get()` if the platform withholds PRF on create, and to a random in-memory
 * seed (`via: 'ephemeral'`) if WebAuthn or PRF is unavailable, so the caller
 * always gets a usable signing key with a `via` it can surface.
 */
export async function createIdentity(displayName = 'mkit player'): Promise<IdentityResult> {
  if (!webauthnAvailable()) {
    return { ...randomSeed(), credentialId: '', via: 'ephemeral' }
  }

  const salt = await sha256(TEXT_ENCODER.encode(saltInfo(rpId())))
  const userId = crypto.getRandomValues(new Uint8Array(16))
  const cred = (await navigator.credentials.create({
    publicKey: {
      challenge: randomChallenge(),
      rp: { id: rpId(), name: 'mkit multiplayer' },
      user: { id: userId, name: `${displayName}@${rpId()}`, displayName },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
      timeout: 60_000,
      // Evaluate the PRF AT creation so PRF-on-create platforms need no get().
      extensions: { prf: { eval: { first: salt } } } as AuthenticationExtensionsClientInputs,
    },
  })) as PublicKeyCredential | null
  if (!cred) throw new Error('Passkey creation was cancelled')

  const credentialId = b64url(new Uint8Array(cred.rawId))
  const ext = cred.getClientExtensionResults() as {
    prf?: { enabled?: boolean; results?: { first?: BufferSource } }
  }

  const first = ext.prf?.results?.first
  if (first) {
    const prf = toPrfBytes(first)
    const seed = await hkdfSha256(prf, HKDF_INFO)
    return { seedHex: bytesToHex(seed), prfHex: bytesToHex(prf), credentialId, via: 'prf-create' }
  }

  // No PRF on create. If the authenticator explicitly lacks PRF, go ephemeral;
  // otherwise pull it with a single follow-up assertion.
  if (ext.prf?.enabled === false) {
    return { ...randomSeed(), credentialId, via: 'ephemeral' }
  }
  try {
    const d = await deriveEd25519Seed(credentialId)
    return { ...d, credentialId, via: 'prf-get' }
  } catch (e) {
    if (e instanceof PrfUnsupportedError) return { ...randomSeed(), credentialId, via: 'ephemeral' }
    throw e
  }
}

/**
 * Fallback when PRF is unavailable: a random in-memory seed. NOT derived from a
 * passkey — it won't persist across sessions or devices. The UI must surface
 * this as a degraded "no hardware identity" mode.
 */
export function randomSeed(): DeriveResult {
  const seed = crypto.getRandomValues(new Uint8Array(32))
  return { seedHex: bytesToHex(seed), prfHex: '' }
}

// ---------------------------------------------------------------------------
// Optional: P-256 passkey attests the Ed25519 binding (design note §2 step 4)
// ---------------------------------------------------------------------------

export type BindingCredential = {
  /** ox credential id (base64url), reused for the assertion. */
  id: string
  /** SEC1 uncompressed P-256 public key as hex (no 0x), the WASM verify input. */
  pubkeyHex: string
}

/**
 * Enroll a *separate* P-256 passkey used only to vouch for an Ed25519 pubkey.
 * Uses `ox`'s WebAuthnP256 (COSE→SEC1 key extraction handled for us). This is
 * the optional "binding" flourish — it shows the full passkey lifecycle, not
 * required for contribution.
 */
export async function enrollBindingPasskey(name = 'mkit binding'): Promise<BindingCredential> {
  const cred = await WebAuthnP256.createCredential({ name })
  // ox returns the public key as {x,y} bigints; serialize to SEC1 uncompressed hex.
  const sec1 = PublicKey.toHex(cred.publicKey, { includePrefix: true })
  return { id: cred.id, pubkeyHex: sec1.replace(/^0x/, '') }
}

function hexToBytesLocal(hex: string): Uint8Array {
  const clean = (hex.startsWith('0x') ? hex.slice(2) : hex)
  const out = new Uint8Array(clean.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16)
  return out
}

/**
 * Sign a DSSE-PAE challenge with the binding passkey and verify the assertion
 * through the WASM WebAuthn verifier (`verify_webauthn_wrapping[_with_policy]`),
 * proving the P-256 passkey vouched for the Ed25519 pubkey. The WebAuthn
 * challenge is the PAE itself (design note §4, option A: keep payloads small).
 *
 * Returns the live `authenticatorData` / `clientDataJSON` so the ceremony is
 * legible in the UI, and a verdict. Throws on a verifier rejection.
 */
export async function attestEd25519Binding(
  api: MkitApi,
  binding: BindingCredential,
  ed25519PubkeyHex: string,
  opts: { policyJson?: string } = {},
): Promise<{ verified: boolean; authenticatorDataHex: string; clientDataJSON: string; paeHex: string }> {
  // A tiny in-toto-style predicate binding the Ed25519 key; commit hash is a
  // placeholder "subject" (the binding is over the predicate, not a real commit).
  const predicate = TEXT_ENCODER.encode(JSON.stringify({ ed25519_pubkey: ed25519PubkeyHex }))
  const commitHash = ed25519PubkeyHex.padEnd(64, '0').slice(0, 64)
  const pae = api.attest_pae(commitHash, 'https://mkit.sh/EdBinding/v1', predicate)

  // The WebAuthn challenge is the raw PAE bytes (the verifier checks
  // clientDataJSON.challenge == base64url-nopad(PAE)).
  const { metadata, signature } = await WebAuthnP256.sign({
    credentialId: binding.id,
    challenge: Hex.fromBytes(pae),
  })

  const authenticatorData = hexToBytesLocal(metadata.authenticatorData)
  const clientDataJSONBytes = TEXT_ENCODER.encode(metadata.clientDataJSON)
  const sigCompact = hexToBytesLocal(Signature.toHex(signature)) // r||s, low-S normalized by ox

  // Throws a typed reason on failure; resolves on success.
  if (opts.policyJson !== undefined) {
    api.verify_webauthn_wrapping_with_policy(
      pae,
      authenticatorData,
      clientDataJSONBytes,
      binding.pubkeyHex,
      sigCompact,
      opts.policyJson,
    )
  } else {
    api.verify_webauthn_wrapping(pae, authenticatorData, clientDataJSONBytes, binding.pubkeyHex, sigCompact)
  }

  return {
    verified: true,
    authenticatorDataHex: metadata.authenticatorData.replace(/^0x/, ''),
    clientDataJSON: metadata.clientDataJSON,
    paeHex: bytesToHex(pae),
  }
}
