import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { MkitApi } from './mkit'
import { mkit } from './mkit'
import {
  PrfUnsupportedError,
  attestIdentityBinding,
  createIdentity,
  deriveEd25519Seed,
  hkdfSha256,
  randomSeed,
  sha256,
  spkiToSec1Hex,
  toPrfBytes,
} from './passkey'
import { bytesToHex } from '../components/use-mkit'

// A fixed 32-byte PRF output → the whole derivation must be deterministic.
const PRF_OUTPUT = new Uint8Array(32).map((_, i) => (i * 7 + 3) & 0xff)

// A real P-256 SPKI DER public key (91 bytes), captured once via WebCrypto
// `exportKey('spki', ...)` — used as the golden `spkiToSec1Hex` vector, and as
// the `getPublicKey()` stand-in for the `createIdentity` capture tests.
const GOLDEN_SPKI_HEX =
  '3059301306072a8648ce3d020106082a8648ce3d03010703420004f66d8f4030e02dae9f44ce276fb96f3e72087f5b6d5a65e0740d5db9d74f7bc9627851962852078556c1b4e5290d31bb48670de18d1dc27988ff48e1ffc2718b'
// The trailing 65-byte SEC1 uncompressed point (the DER's last 130 hex chars) — cross-checked separately via
// WebCrypto's `exportKey('raw', ...)` on the same keypair.
const GOLDEN_SEC1_HEX =
  '04f66d8f4030e02dae9f44ce276fb96f3e72087f5b6d5a65e0740d5db9d74f7bc9627851962852078556c1b4e5290d31bb48670de18d1dc27988ff48e1ffc2718b'

function hexToArrayBuffer(hex: string): ArrayBuffer {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i++) bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return bytes.buffer
}

// Minimal WebAuthn mock: `navigator.credentials.get` returns an assertion whose
// PRF result is whatever `prfResult` is set to. `location.hostname` drives the salt.
function installWebAuthnMock(prfResult: BufferSource | undefined) {
  const cred = {
    rawId: new Uint8Array([1, 2, 3, 4]).buffer,
    getClientExtensionResults: () => ({ prf: { results: { first: prfResult } } }),
  }
  vi.stubGlobal('PublicKeyCredential', function PublicKeyCredentialMock() {})
  vi.stubGlobal('navigator', { credentials: { get: vi.fn().mockResolvedValue(cred) } })
  vi.stubGlobal('location', { hostname: 'mkit.sh' })
}

describe('passkey derivation', () => {
  beforeEach(() => {
    // window must exist for `webauthnAvailable()`.
    vi.stubGlobal('window', {})
  })
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('HKDF-SHA256 of a fixed PRF output is deterministic and 32 bytes', async () => {
    const seedA = await hkdfSha256(PRF_OUTPUT, 'mkit-ed25519-signing-v1')
    const seedB = await hkdfSha256(PRF_OUTPUT, 'mkit-ed25519-signing-v1')
    expect(seedA.length).toBe(32)
    expect(bytesToHex(seedA)).toBe(bytesToHex(seedB))
    // A different info string must produce a different seed (domain separation).
    const other = await hkdfSha256(PRF_OUTPUT, 'some-other-info')
    expect(bytesToHex(other)).not.toBe(bytesToHex(seedA))
  })

  it('SHA-256 salt is the per-host label digest', async () => {
    const digest = await sha256(new TextEncoder().encode('mkit.sh/ed25519-identity/v1'))
    expect(digest.length).toBe(32)
  })

  it('deriveEd25519Seed turns a mocked PRF output into a deterministic seed + valid Ed25519 pubkey', async () => {
    installWebAuthnMock(PRF_OUTPUT.buffer)
    const res1 = await deriveEd25519Seed('AQIDBA')
    const res2 = await deriveEd25519Seed('AQIDBA')
    expect(res1.seedHex).toMatch(/^[0-9a-f]{64}$/)
    expect(res1.seedHex).toBe(res2.seedHex) // same PRF → same seed
    expect(res1.prfHex).toBe(bytesToHex(PRF_OUTPUT))
    // The assertion's rawId ([1,2,3,4]) round-trips to its base64url id, so a
    // discoverable recovery can persist which passkey was used.
    expect(res1.credentialId).toBe('AQIDBA')

    // The derived seed must produce a valid Ed25519 keypair via the WASM path.
    const m = await mkit()
    const pubkey = m.ed25519_pubkey_from_seed(hexToBytes(res1.seedHex))
    expect(bytesToHex(pubkey)).toMatch(/^[0-9a-f]{64}$/)
    // And it must match the seed_hex→pubkey path the commit signer uses.
    const kp = m.keypair_from_seed(res1.seedHex)
    expect(kp.pubkey_hex).toBe(bytesToHex(pubkey))
  })

  it('recovers the credential id from a discoverable get() (no credentialId arg)', async () => {
    installWebAuthnMock(PRF_OUTPUT.buffer)
    // Discoverable recovery: no allowCredentials → the platform picks the
    // resident key and we learn its id from the assertion's rawId.
    const res = await deriveEd25519Seed(undefined)
    expect(res.credentialId).toBe('AQIDBA')
    expect(res.seedHex).toMatch(/^[0-9a-f]{64}$/)
  })

  it('throws PrfUnsupportedError when the authenticator returns no PRF result', async () => {
    installWebAuthnMock(undefined)
    await expect(deriveEd25519Seed('AQIDBA')).rejects.toBeInstanceOf(PrfUnsupportedError)
  })

  it('toPrfBytes reads exactly an offset view, not the whole backing buffer', () => {
    // A 32-byte PRF result sitting at byteOffset 8 inside a 48-byte buffer.
    const backing = new ArrayBuffer(48)
    const whole = new Uint8Array(backing)
    // Fill the whole buffer with a sentinel so a "read the whole buffer" bug
    // would surface extra/non-matching bytes.
    whole.fill(0xee)
    const known = new Uint8Array(32).map((_, i) => (i * 5 + 1) & 0xff)
    const view = new Uint8Array(backing, 8, 32)
    view.set(known)

    const out = toPrfBytes(view)
    expect(out.length).toBe(32)
    expect(bytesToHex(out)).toBe(bytesToHex(known))
  })

  it('toPrfBytes passes a plain ArrayBuffer through as all its bytes', () => {
    const buf = new Uint8Array([1, 2, 3, 4]).buffer
    expect(Array.from(toPrfBytes(buf))).toEqual([1, 2, 3, 4])
  })

  it('randomSeed produces a fresh 32-byte seed each call', () => {
    vi.stubGlobal('crypto', globalThis.crypto)
    const a = randomSeed()
    const b = randomSeed()
    expect(a.seedHex).toMatch(/^[0-9a-f]{64}$/)
    expect(a.seedHex).not.toBe(b.seedHex)
  })
})

function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}

// Mock create() + get() with controllable PRF outputs; expose the spies so a
// test can assert HOW MANY ceremonies (prompts) happened. webauthn:false makes
// the platform report no WebAuthn at all. `spkiHex` controls the mocked
// `response.getPublicKey()`: a hex string returns that SPKI DER, `null` makes
// `getPublicKey()` itself return `null`, and `undefined` (default) omits
// `getPublicKey` entirely — three of the shapes `capturePubkeyHex` must
// tolerate without throwing.
function installCeremonyMock(opts: {
  prfOnCreate?: BufferSource
  prfOnGet?: BufferSource
  prfEnabled?: boolean
  webauthn?: boolean
  spkiHex?: string | null
}) {
  const spkiHex = opts.spkiHex
  const createRes = {
    rawId: new Uint8Array([9, 9, 9, 9]).buffer,
    getClientExtensionResults: () => ({
      prf: {
        enabled: opts.prfEnabled ?? true,
        ...(opts.prfOnCreate ? { results: { first: opts.prfOnCreate } } : {}),
      },
    }),
    response:
      spkiHex === undefined ? {} : { getPublicKey: () => (spkiHex === null ? null : hexToArrayBuffer(spkiHex)) },
  }
  const getRes = {
    rawId: new Uint8Array([9, 9, 9, 9]).buffer,
    getClientExtensionResults: () => ({ prf: { results: { first: opts.prfOnGet } } }),
  }
  const create = vi.fn().mockResolvedValue(createRes)
  const get = vi.fn().mockResolvedValue(getRes)
  if (opts.webauthn === false) {
    vi.stubGlobal('PublicKeyCredential', undefined)
    vi.stubGlobal('navigator', {})
  } else {
    vi.stubGlobal('PublicKeyCredential', function PublicKeyCredentialMock() {})
    vi.stubGlobal('navigator', { credentials: { create, get } })
  }
  vi.stubGlobal('location', { hostname: 'mkit.sh' })
  vi.stubGlobal('crypto', globalThis.crypto)
  return { create, get }
}

describe('createIdentity — one-prompt collapse', () => {
  beforeEach(() => vi.stubGlobal('window', {}))
  afterEach(() => vi.unstubAllGlobals())

  it('derives the seed from create() PRF output in a SINGLE ceremony — no get()', async () => {
    const { create, get } = installCeremonyMock({ prfOnCreate: PRF_OUTPUT.buffer })
    const res = await createIdentity()
    expect(res.via).toBe('prf-create')
    expect(create).toHaveBeenCalledTimes(1)
    expect(get).not.toHaveBeenCalled() // the fewer-prompts guarantee
    expect(res.seedHex).toMatch(/^[0-9a-f]{64}$/)
    const expected = bytesToHex(await hkdfSha256(PRF_OUTPUT, 'mkit-ed25519-signing-v1'))
    expect(res.seedHex).toBe(expected) // same derivation as deriveEd25519Seed
  })

  it('falls back to a single get() when PRF is absent on create — via prf-get', async () => {
    const { create, get } = installCeremonyMock({ prfOnGet: PRF_OUTPUT.buffer })
    const res = await createIdentity()
    expect(res.via).toBe('prf-get')
    expect(create).toHaveBeenCalledTimes(1)
    expect(get).toHaveBeenCalledTimes(1) // exactly one extra prompt, not more
    expect(res.seedHex).toBe(bytesToHex(await hkdfSha256(PRF_OUTPUT, 'mkit-ed25519-signing-v1')))
  })

  it('goes ephemeral (no get()) when the authenticator reports PRF disabled', async () => {
    const { create, get } = installCeremonyMock({ prfEnabled: false })
    const res = await createIdentity()
    expect(res.via).toBe('ephemeral')
    expect(create).toHaveBeenCalledTimes(1)
    expect(get).not.toHaveBeenCalled()
    expect(res.seedHex).toMatch(/^[0-9a-f]{64}$/)
  })

  it('goes ephemeral with no ceremony at all when WebAuthn is unavailable', async () => {
    const { create, get } = installCeremonyMock({ webauthn: false })
    const res = await createIdentity()
    expect(res.via).toBe('ephemeral')
    expect(res.credentialId).toBe('')
    expect(create).not.toHaveBeenCalled()
    expect(get).not.toHaveBeenCalled()
    expect(res.p256PubkeyHex).toBeNull() // no credential at all → no pubkey
  })

  it('captures the identity credential’s P-256 pubkey via getPublicKey() (#494)', async () => {
    installCeremonyMock({ prfOnCreate: PRF_OUTPUT.buffer, spkiHex: GOLDEN_SPKI_HEX })
    const res = await createIdentity()
    expect(res.p256PubkeyHex).toBe(GOLDEN_SEC1_HEX)
  })

  it('returns a null pubkey (not a throw) when getPublicKey() is absent', async () => {
    installCeremonyMock({ prfOnCreate: PRF_OUTPUT.buffer })
    const res = await createIdentity()
    expect(res.p256PubkeyHex).toBeNull()
    expect(res.seedHex).toMatch(/^[0-9a-f]{64}$/) // identity creation still succeeds
  })

  it('returns a null pubkey (not a throw) when getPublicKey() itself returns null', async () => {
    installCeremonyMock({ prfOnCreate: PRF_OUTPUT.buffer, spkiHex: null })
    const res = await createIdentity()
    expect(res.p256PubkeyHex).toBeNull()
    expect(res.seedHex).toMatch(/^[0-9a-f]{64}$/)
  })
})

describe('spkiToSec1Hex', () => {
  it('converts a real P-256 SPKI DER key to its SEC1 uncompressed hex (golden vector)', () => {
    expect(spkiToSec1Hex(hexToArrayBuffer(GOLDEN_SPKI_HEX))).toBe(GOLDEN_SEC1_HEX)
  })

  it('rejects a key with the right length but a mangled DER prefix', () => {
    const bytes = hexToBytes(GOLDEN_SPKI_HEX)
    bytes[0] = 0xff // corrupt the very first prefix byte
    expect(() => spkiToSec1Hex(bytes.buffer)).toThrow(/not P-256/)
  })

  it('rejects a buffer of the wrong length outright', () => {
    expect(() => spkiToSec1Hex(new Uint8Array(64).buffer)).toThrow(/91-byte/)
  })
})

// A real P-256 DER-encoded ECDSA signature with a known HIGH-S value (captured
// once via Node's `crypto.sign(..., { dsaEncoding: 'der' })` over a fixed
// keypair/message) — the golden vector proving `attestIdentityBinding`
// actually normalizes to low-S rather than trusting `ox`'s (secp256k1-bound,
// non-normalizing) DER decode as-is.
const HIGH_S_DER_HEX =
  '3046022100ce80acded03a772a22390651032478f2086d21b4b590e51071b14ca8b0d402b2022100abfc238d3b33ab2ca531b2f38cdf87e7a29f7fab7728acd8df9a1b55afd3cef5'
const EXPECTED_R_HEX = 'ce80acded03a772a22390651032478f2086d21b4b590e51071b14ca8b0d402b2'
const EXPECTED_LOW_S_HEX = '5403dc71c4cc54d45ace4d0c732078181a477b022feef1ac141faf6d4c8f565c'
const EXPECTED_COMPACT_HEX = EXPECTED_R_HEX + EXPECTED_LOW_S_HEX

/**
 * Mock `navigator.credentials.get()` to return a WebAuthn assertion whose `response.signature` is the fixed
 * `HIGH_S_DER_HEX` vector above, so tests can assert on the EXACT bytes handed to the WASM verifier.
 */
function installAttestMock() {
  const authenticatorData = new Uint8Array([1, 2, 3, 4]).buffer
  const clientDataJSON = new TextEncoder().encode('{"type":"webauthn.get"}').buffer
  const assertion = {
    response: {
      authenticatorData,
      clientDataJSON,
      signature: hexToArrayBuffer(HIGH_S_DER_HEX),
    },
  }
  const get = vi.fn().mockResolvedValue(assertion)
  vi.stubGlobal('PublicKeyCredential', function PublicKeyCredentialMock() {})
  vi.stubGlobal('navigator', { credentials: { get } })
  vi.stubGlobal('location', { hostname: 'mkit.sh' })
  vi.stubGlobal('crypto', globalThis.crypto)
  return { get, authenticatorData, clientDataJSON }
}

describe('attestIdentityBinding — unified on the identity passkey (#494)', () => {
  beforeEach(() => vi.stubGlobal('window', {}))
  afterEach(() => vi.unstubAllGlobals())

  it('does ONE get() carrying both the PAE challenge and the PRF extension, scoped via allowCredentials', async () => {
    const { get } = installAttestMock()
    const pae = new Uint8Array([7, 7, 7])
    const api = {
      attest_pae: vi.fn().mockReturnValue(pae),
      verify_webauthn_wrapping: vi.fn(),
      verify_webauthn_wrapping_with_policy: vi.fn(),
    } as unknown as MkitApi

    // credential id "AQIDBA" decodes to bytes [1,2,3,4] — see fromB64url in passkey.ts.
    await attestIdentityBinding(api, 'AQIDBA', 'deadbeef', 'ed25519pubkeyhex')

    expect(get).toHaveBeenCalledTimes(1) // exactly one prompt
    const call = get.mock.calls[0]?.[0] as { publicKey: PublicKeyCredentialRequestOptions }
    expect(new Uint8Array(call.publicKey.challenge as ArrayBuffer)).toEqual(pae) // the PAE IS the challenge
    // 'preferred' matches create/unlock — 'required' would fail on a UV-incapable authenticator.
    expect(call.publicKey.userVerification).toBe('preferred')
    expect(call.publicKey.allowCredentials).toHaveLength(1)
    expect(new Uint8Array(call.publicKey.allowCredentials?.[0]?.id as ArrayBuffer)).toEqual(
      new Uint8Array([1, 2, 3, 4]),
    )
    const ext = call.publicKey.extensions as { prf?: { eval?: { first: BufferSource } } }
    expect(ext.prf?.eval?.first).toBeTruthy() // the PRF salt rides the SAME get()
  })

  it('passes the identity pubkey and the low-S-normalized compact signature to the verifier', async () => {
    installAttestMock()
    const pae = new Uint8Array([7, 7, 7])
    const verifyWithPolicy = vi.fn()
    const api = {
      attest_pae: vi.fn().mockReturnValue(pae),
      verify_webauthn_wrapping: vi.fn(),
      verify_webauthn_wrapping_with_policy: verifyWithPolicy,
    } as unknown as MkitApi

    const res = await attestIdentityBinding(api, 'AQIDBA', 'deadbeef', 'ed25519pubkeyhex', {
      policyJson: '{}',
    })

    // No `verified` field: resolving IS the success verdict (the verifier throws on rejection).
    expect(res.paeHex).toBeTruthy()
    expect(verifyWithPolicy).toHaveBeenCalledTimes(1)
    const [paeArg, authDataArg, clientDataArg, pubkeyArg, sigArg, policyArg] = verifyWithPolicy.mock.calls[0] ?? []
    expect(paeArg).toBe(pae)
    expect(pubkeyArg).toBe('deadbeef') // the IDENTITY pubkey, not a separate binding credential
    expect(bytesToHex(sigArg as Uint8Array)).toBe(EXPECTED_COMPACT_HEX) // DER → low-S compact, verified against a golden high-S vector
    expect(policyArg).toBe('{}')
    expect(authDataArg).toBeInstanceOf(Uint8Array)
    expect(clientDataArg).toBeInstanceOf(Uint8Array)
  })

  it('calls the non-policy verify function when no policyJson is given', async () => {
    installAttestMock()
    const verify = vi.fn()
    const api = {
      attest_pae: vi.fn().mockReturnValue(new Uint8Array([7, 7, 7])),
      verify_webauthn_wrapping: verify,
      verify_webauthn_wrapping_with_policy: vi.fn(),
    } as unknown as MkitApi

    await attestIdentityBinding(api, 'AQIDBA', 'deadbeef', 'ed25519pubkeyhex')

    expect(verify).toHaveBeenCalledTimes(1)
  })
})
