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
// API directly. The SAME identity passkey also produces the optional
// attestation binding (see `attestIdentityBinding`): one `get()` carries both
// the PRF eval and the WebAuthn assertion signature, so a single passkey and
// a single prompt vouch for both the seed AND the Ed25519 pubkey it derived.

import { p256 } from '@noble/curves/p256'
import { bytesToHex } from '../components/use-mkit'
import type { MkitApi } from './mkit'

/** Fixed 26-byte DER prefix for a P-256 (secp256r1) SPKI public key, per RFC 5480. */
const P256_SPKI_PREFIX_HEX = '3059301306072a8648ce3d020106082a8648ce3d030107034200'

/**
 * Convert a P-256 SPKI-encoded public key (as returned by `AuthenticatorAttestationResponse.getPublicKey()`) to the
 * SEC1 uncompressed hex format mkit's WASM verifier expects (`verify_webauthn_wrapping`'s `pubkey_hex`).
 *
 * A P-256 SPKI key is always exactly 91 bytes: a fixed 26-byte DER header (algorithm OID etc.) followed by the 65-byte
 * SEC1 uncompressed point (`0x04 || x(32) || y(32)`). We validate the header matches exactly (not just the length) and
 * throw a descriptive error otherwise — a mismatched prefix means the key isn't the P-256 curve we asked for, which
 * should never happen but must not silently produce a bogus pubkey.
 */
export function spkiToSec1Hex(spki: ArrayBuffer): string {
  const bytes = new Uint8Array(spki)
  if (bytes.length !== 91) {
    throw new Error(`Expected a 91-byte P-256 SPKI public key, got ${bytes.length} bytes.`)
  }
  const prefixHex = bytesToHex(bytes.subarray(0, 26))
  if (prefixHex !== P256_SPKI_PREFIX_HEX) {
    throw new Error(`SPKI public key is not P-256 (unexpected DER prefix ${prefixHex}).`)
  }
  const point = bytes.subarray(26)
  if (point[0] !== 0x04) {
    throw new Error(`Expected an uncompressed SEC1 point (0x04 prefix), got 0x${point[0]?.toString(16)}.`)
  }
  return bytesToHex(point)
}

/** Per-host PRF salt label. The salt itself is SHA-256 of this string (32 bytes). */
function saltInfo(host: string): string {
  return `${host}/ed25519-identity/v1`
}

/**
 * The 32-byte PRF salt, SHA-256("<host>/ed25519-identity/v1"). This salt is the linchpin tying attestation to seed
 * derivation: every ceremony — create, unlock, and attest — MUST evaluate the PRF under the SAME salt or they'd derive
 * different seeds. A single helper so a future change to the salt scheme (e.g. a label bump) can't silently desync one
 * call site.
 */
async function prfSalt(): Promise<Uint8Array<ArrayBuffer>> {
  return sha256(TEXT_ENCODER.encode(saltInfo(rpId())))
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
 * HKDF-SHA256 over `ikm` with `info`, fixed empty salt, 32-byte output — exactly the Ed25519 seed length. WebCrypto
 * does extract-and-expand in one `deriveBits` call.
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
   * Base64url credential id of the passkey the assertion actually used. For a discoverable (no `allowCredentials`)
   * recovery `get()`, this reveals WHICH resident key the user picked, so the caller can persist it. Absent only from
   * the random `ephemeral` fallback.
   */
  credentialId?: string
}

/**
 * Derive the Ed25519 signing seed from an enrolled passkey (§2 step 2). Performs a `get()` with the PRF salt =
 * SHA-256("<host>/ed25519-identity/v1"), reads `prf.results.first`, then HKDF-expands it under `info=HKDF_INFO`.
 *
 * Throws `PrfUnsupportedError` if the authenticator returned no PRF output, so the caller can fall back to an in-memory
 * random seed with a visible notice.
 */
export async function deriveEd25519Seed(credentialId?: string): Promise<DeriveResult> {
  if (!webauthnAvailable()) throw new Error("This browser can't use passkeys here.")

  const salt = await prfSalt()
  const assertion = (await navigator.credentials.get({
    publicKey: {
      challenge: randomChallenge(),
      rpId: rpId(),
      userVerification: 'preferred',
      timeout: 60_000,
      ...(credentialId ? { allowCredentials: [{ type: 'public-key', id: fromB64url(credentialId) }] } : {}),
      extensions: { prf: { eval: { first: salt } } } as AuthenticationExtensionsClientInputs,
    },
  })) as PublicKeyCredential | null

  if (!assertion) throw new Error('Sign-in was canceled. Try again.')

  const ext = assertion.getClientExtensionResults() as {
    prf?: { results?: { first?: BufferSource } }
  }
  const first = ext.prf?.results?.first
  if (!first) throw new PrfUnsupportedError()

  const prf = toPrfBytes(first)
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
  /**
   * SEC1 uncompressed hex of the identity credential's own P-256 public key, captured via
   * `AuthenticatorAttestationResponse.getPublicKey()` at creation time — the WASM verify input for
   * `attestIdentityBinding`. `null` when there's no credential at all (the ephemeral, no-WebAuthn fallback) or when the
   * authenticator didn't expose `getPublicKey()` (exotic/legacy authenticators): a `null` here just means the "Link
   * with a passkey" attestation button stays disabled for this identity — it never fails identity creation.
   */
  p256PubkeyHex: string | null
}

/**
 * Best-effort capture of the just-created credential's P-256 public key. Never throws: any failure (missing
 * `getPublicKey`, a null return, or an unexpected key shape) degrades to `null` rather than failing identity creation —
 * capturing the attestation pubkey is a bonus, not a requirement for having a usable signing identity.
 */
function capturePubkeyHex(response: AuthenticatorResponse): string | null {
  try {
    const attestation = response as AuthenticatorAttestationResponse
    if (typeof attestation.getPublicKey !== 'function') return null
    const spki = attestation.getPublicKey()
    if (!spki) return null
    return spkiToSec1Hex(spki)
  } catch (err) {
    // Preserve the never-throw/null contract, but don't swallow the descriptive
    // diagnostics `spkiToSec1Hex` throws ("SPKI public key is not P-256 …"):
    // without this, an authenticator that can't attest just yields a
    // permanently disabled button with zero signal in production.
    console.warn('capturePubkeyHex: could not capture P-256 attestation pubkey', err)
    return null
  }
}

/**
 * Coerce a WebAuthn `BufferSource` PRF result to a `Uint8Array` of EXACTLY the view's bytes. A typed-array view can sit
 * at a non-zero `byteOffset` inside a larger backing `ArrayBuffer` (and span only part of it); reading `.buffer` alone
 * would return the WHOLE buffer, corrupting the derived seed. Slice the view's `[byteOffset, byteOffset + byteLength)`
 * window so only its own bytes are used.
 */
export function toPrfBytes(first: BufferSource): Uint8Array {
  return ArrayBuffer.isView(first)
    ? new Uint8Array(first.buffer.slice(first.byteOffset, first.byteOffset + first.byteLength))
    : new Uint8Array(first)
}

/**
 * Create a passkey identity AND derive its Ed25519 seed in ONE ceremony.
 *
 * Collapses the old enroll()+derive() two-prompt flow: the PRF is evaluated AT creation (`prf.eval` on `create()`), so
 * platforms that support PRF-on-create (synced Apple/Google passkeys, ~100% as of 2026) return the seed material in the
 * single registration prompt — no follow-up `get()`. Falls back to one `get()` if the platform withholds PRF on create,
 * and to a random in-memory seed (`via: 'ephemeral'`) if WebAuthn or PRF is unavailable, so the caller always gets a
 * usable signing key with a `via` it can surface.
 */
export async function createIdentity(displayName = 'mkit player'): Promise<IdentityResult> {
  if (!webauthnAvailable()) {
    return { ...randomSeed(), credentialId: '', via: 'ephemeral', p256PubkeyHex: null }
  }

  const salt = await prfSalt()
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
  if (!cred) throw new Error('Passkey setup was canceled. Try again.')

  const credentialId = b64url(new Uint8Array(cred.rawId))
  // Capture the credential's own P-256 pubkey now — the browser default
  // attestation ("none") still exposes it via getPublicKey(). Best-effort:
  // never throws, so a capture failure can't fail identity creation.
  const p256PubkeyHex = capturePubkeyHex(cred.response)
  const ext = cred.getClientExtensionResults() as {
    prf?: { enabled?: boolean; results?: { first?: BufferSource } }
  }

  const first = ext.prf?.results?.first
  if (first) {
    const prf = toPrfBytes(first)
    const seed = await hkdfSha256(prf, HKDF_INFO)
    return { seedHex: bytesToHex(seed), prfHex: bytesToHex(prf), credentialId, via: 'prf-create', p256PubkeyHex }
  }

  // No PRF on create. If the authenticator explicitly lacks PRF, go ephemeral;
  // otherwise pull it with a single follow-up assertion.
  if (ext.prf?.enabled === false) {
    return { ...randomSeed(), credentialId, via: 'ephemeral', p256PubkeyHex }
  }
  try {
    const d = await deriveEd25519Seed(credentialId)
    return { ...d, credentialId, via: 'prf-get', p256PubkeyHex }
  } catch (e) {
    if (e instanceof PrfUnsupportedError) return { ...randomSeed(), credentialId, via: 'ephemeral', p256PubkeyHex }
    throw e
  }
}

/**
 * Fallback when PRF is unavailable: a random in-memory seed. NOT derived from a passkey — it won't persist across
 * sessions or devices. The UI must surface this as a degraded "no hardware identity" mode.
 */
export function randomSeed(): DeriveResult {
  const seed = crypto.getRandomValues(new Uint8Array(32))
  return { seedHex: bytesToHex(seed), prfHex: '' }
}

// ---------------------------------------------------------------------------
// Optional: the identity passkey attests the Ed25519 binding (design note §2
// step 4, unified per #494) — the SAME P-256 credential the Ed25519 seed is
// derived from also vouches for the derived pubkey, in ONE navigator.get().
// ---------------------------------------------------------------------------

const TEXT_DECODER = new TextDecoder()

/**
 * Sign a DSSE-PAE challenge with the IDENTITY passkey (the same credential `deriveEd25519Seed` uses) and verify the
 * assertion through the WASM WebAuthn verifier (`verify_webauthn_wrapping[_with_policy]`), proving the passkey that
 * derives the Ed25519 signing key ALSO vouches for its pubkey. A single `get()` carries both the PRF eval (same salt as
 * `deriveEd25519Seed`) and the WebAuthn assertion signature over the PAE challenge — one prompt, two proofs — but the
 * PRF result is intentionally discarded here (no seed-refresh wiring; that's a bonus, not required by #494).
 *
 * Returns the live `authenticatorData` / `clientDataJSON` / `pae` so the ceremony is legible in the UI. There is no
 * `verified` field: the WASM verifier THROWS a typed reason on any rejection, so a normal return IS the success verdict
 * — a `verified: false` would be unreachable.
 */
export async function attestIdentityBinding(
  api: MkitApi,
  credentialId: string,
  p256PubkeyHex: string,
  ed25519PubkeyHex: string,
  opts: { policyJson?: string } = {},
): Promise<{ authenticatorDataHex: string; clientDataJSON: string; paeHex: string }> {
  if (!webauthnAvailable()) throw new Error("This browser can't use passkeys here.")

  // A tiny in-toto-style predicate binding the Ed25519 key; commit hash is a
  // placeholder "subject" (the binding is over the predicate, not a real commit).
  const predicate = TEXT_ENCODER.encode(JSON.stringify({ ed25519_pubkey: ed25519PubkeyHex }))
  const commitHash = ed25519PubkeyHex.padEnd(64, '0').slice(0, 64)
  const pae = api.attest_pae(commitHash, 'https://mkit.sh/EdBinding/v1', predicate)

  // Same salt `deriveEd25519Seed` uses — carried purely so this ceremony is
  // indistinguishable from an unlock prompt; the PRF result itself is unused.
  const salt = await prfSalt()

  // ONE get(): the WebAuthn challenge is the raw PAE bytes (the verifier
  // checks clientDataJSON.challenge == base64url-nopad(PAE)), scoped to the
  // identity credential via allowCredentials. UV is 'preferred' to MATCH the
  // create/unlock ceremonies (`createIdentity`, `deriveEd25519Seed`): the
  // credential was enrolled under 'preferred', so nothing guarantees it's
  // UV-capable — requiring UV here would make every attest fail with
  // NotAllowedError on a UV-incapable authenticator (e.g. a PIN-less security
  // key). The authenticatorData UV flag still records whether UV happened.
  const assertion = (await navigator.credentials.get({
    publicKey: {
      // Copy into a fresh ArrayBuffer-backed view: `pae` comes back from wasm-bindgen typed as
      // `Uint8Array<ArrayBufferLike>`, which `PublicKeyCredentialRequestOptions.challenge` (a strict `BufferSource`)
      // doesn't structurally accept.
      challenge: new Uint8Array(pae),
      rpId: rpId(),
      allowCredentials: [{ type: 'public-key', id: fromB64url(credentialId) }],
      userVerification: 'preferred',
      timeout: 60_000,
      extensions: { prf: { eval: { first: salt } } } as AuthenticationExtensionsClientInputs,
    },
  })) as PublicKeyCredential | null
  if (!assertion) throw new Error('Passkey attestation was canceled. Try again.')

  const response = assertion.response as AuthenticatorAssertionResponse
  const authenticatorData = new Uint8Array(response.authenticatorData)
  const clientDataJSONBytes = new Uint8Array(response.clientDataJSON)
  const clientDataJSON = TEXT_DECODER.decode(clientDataJSONBytes)

  // DER → 64-byte low-S compact. Parsed with `@noble/curves`'s P-256 curve
  // (not `ox`'s `Signature`, which is bound to secp256k1: it validates r/s
  // against the WRONG group order and never normalizes S, working on P-256 only
  // by the accident that n_p256 < n_secp256k1). `normalizeS()` applies the
  // low-S canonicalization mkit's Rust verifier enforces (`signer_p256::verify_p256`
  // rejects any high-S signature), against the actual P-256 group order.
  const sigCompact = p256.Signature.fromDER(new Uint8Array(response.signature)).normalizeS().toCompactRawBytes()

  // Throws a typed reason on failure; resolves on success.
  if (opts.policyJson !== undefined) {
    api.verify_webauthn_wrapping_with_policy(
      pae,
      authenticatorData,
      clientDataJSONBytes,
      p256PubkeyHex,
      sigCompact,
      opts.policyJson,
    )
  } else {
    api.verify_webauthn_wrapping(pae, authenticatorData, clientDataJSONBytes, p256PubkeyHex, sigCompact)
  }

  return {
    authenticatorDataHex: bytesToHex(authenticatorData),
    clientDataJSON,
    paeHex: bytesToHex(pae),
  }
}
