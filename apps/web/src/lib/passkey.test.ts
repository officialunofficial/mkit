import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { mkit } from './mkit'
import {
  PrfUnsupportedError,
  createIdentity,
  deriveEd25519Seed,
  hkdfSha256,
  randomSeed,
  sha256,
  toPrfBytes,
} from './passkey'
import { bytesToHex } from '../components/use-mkit'

// A fixed 32-byte PRF output → the whole derivation must be deterministic.
const PRF_OUTPUT = new Uint8Array(32).map((_, i) => (i * 7 + 3) & 0xff)

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

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}

// Mock create() + get() with controllable PRF outputs; expose the spies so a
// test can assert HOW MANY ceremonies (prompts) happened. webauthn:false makes
// the platform report no WebAuthn at all.
function installCeremonyMock(opts: {
  prfOnCreate?: BufferSource
  prfOnGet?: BufferSource
  prfEnabled?: boolean
  webauthn?: boolean
}) {
  const createRes = {
    rawId: new Uint8Array([9, 9, 9, 9]).buffer,
    getClientExtensionResults: () => ({
      prf: {
        enabled: opts.prfEnabled ?? true,
        ...(opts.prfOnCreate ? { results: { first: opts.prfOnCreate } } : {}),
      },
    }),
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
  })
})
