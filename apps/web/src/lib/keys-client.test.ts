import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { getName, keysBaseUrl, keysEnabled, resolveNames, setName } from './keys-client'
import type { MkitApi } from './mkit'

const BASE = 'https://keys.test'
const SEED = 'bb'.repeat(32)
const PUBKEY = '00'.repeat(32) // bytesToHex of the fake all-zero pubkey

// Minimal fake mkit api: keys-client only needs the envelope-signing surface.
const fakeApi = {
  blake3_hex: (_b: Uint8Array) => 'aa'.repeat(32),
  ed25519_sign: (_m: Uint8Array, _s: Uint8Array) => new Uint8Array(64),
  ed25519_pubkey_from_seed: (_s: Uint8Array) => new Uint8Array(32),
} as unknown as MkitApi

function mockFetch(impl: (url: string, init?: RequestInit) => { status?: number; body?: unknown }) {
  const fn = vi.fn(async (url: string, init?: RequestInit) => {
    const r = impl(url, init)
    const status = r.status ?? 200
    return { ok: status >= 200 && status < 300, status, json: async () => r.body } as Response
  })
  vi.stubGlobal('fetch', fn)
  return fn
}

afterEach(() => {
  vi.unstubAllGlobals()
  vi.unstubAllEnvs()
})

describe('keys-client — registry disabled (no VITE_KEYS_URL)', () => {
  beforeEach(() => vi.stubEnv('VITE_KEYS_URL', ''))

  it('reports disabled', () => {
    expect(keysBaseUrl()).toBeNull()
    expect(keysEnabled()).toBe(false)
  })

  it('getName / setName / resolveNames no-op without fetching', async () => {
    const fn = mockFetch(() => ({ body: {} }))
    expect(await getName(PUBKEY)).toBeNull()
    expect(await setName(fakeApi, SEED, PUBKEY, 'slate-badger')).toBeNull()
    expect(await resolveNames([PUBKEY])).toEqual({})
    expect(fn).not.toHaveBeenCalled()
  })
})

describe('keys-client — production host default (no VITE_KEYS_URL)', () => {
  beforeEach(() => vi.stubEnv('VITE_KEYS_URL', ''))

  it('defaults to https://keys.mkit.sh on the mkit.sh host', () => {
    vi.stubGlobal('window', { location: { hostname: 'mkit.sh' } })
    expect(keysBaseUrl()).toBe('https://keys.mkit.sh')
    expect(keysEnabled()).toBe(true)
  })

  it('defaults on a subdomain of mkit.sh', () => {
    vi.stubGlobal('window', { location: { hostname: 'demo.mkit.sh' } })
    expect(keysBaseUrl()).toBe('https://keys.mkit.sh')
  })

  it('stays disabled on a non-mkit host (and never matches a look-alike)', () => {
    vi.stubGlobal('window', { location: { hostname: 'localhost' } })
    expect(keysBaseUrl()).toBeNull()
    vi.stubGlobal('window', { location: { hostname: 'evil-mkit.sh' } })
    expect(keysBaseUrl()).toBeNull()
  })
})

describe('keys-client — registry enabled', () => {
  beforeEach(() => vi.stubEnv('VITE_KEYS_URL', BASE))

  it('getName GETs /name/<pubkey> and returns the handle', async () => {
    const fn = mockFetch((url) => {
      expect(url).toBe(`${BASE}/name/${PUBKEY}`)
      return { body: { pubkey: PUBKEY, name: 'slate-badger', updated_at: 1 } }
    })
    expect(await getName(PUBKEY)).toBe('slate-badger')
    expect(fn).toHaveBeenCalledOnce()
  })

  it('getName returns null on 404', async () => {
    mockFetch(() => ({ status: 404, body: 'not found' }))
    expect(await getName(PUBKEY)).toBeNull()
  })

  it('setName PUTs the signed envelope + JSON body and returns the handle', async () => {
    const fn = mockFetch((url, init) => {
      expect(url).toBe(`${BASE}/name/${PUBKEY}`)
      expect(init?.method).toBe('PUT')
      const h = init?.headers as Record<string, string>
      expect(h['X-Public-Key']).toBe(PUBKEY)
      expect(h['X-Signature']).toBe('00'.repeat(64))
      expect(h['X-Digest']).toBe('aa'.repeat(32))
      expect(h['X-Created-At']).toBeDefined()
      expect(init?.body).toBe(JSON.stringify({ name: 'slate-badger' }))
      return { body: { pubkey: PUBKEY, name: 'slate-badger', updated_at: 2 } }
    })
    expect(await setName(fakeApi, SEED, PUBKEY, 'slate-badger')).toBe('slate-badger')
    expect(fn).toHaveBeenCalledOnce()
  })

  it('setName throws on a rejected (non-2xx) write', async () => {
    mockFetch(() => ({ status: 403, body: 'signer is not the named key' }))
    await expect(setName(fakeApi, SEED, PUBKEY, 'x')).rejects.toThrow(/403/)
  })

  it('resolveNames POSTs /resolve and returns the names map', async () => {
    const fn = mockFetch((url, init) => {
      expect(url).toBe(`${BASE}/resolve`)
      expect(init?.method).toBe('POST')
      expect(init?.body).toBe(JSON.stringify({ pubkeys: [PUBKEY] }))
      return { body: { names: { [PUBKEY]: 'slate-badger' } } }
    })
    expect(await resolveNames([PUBKEY])).toEqual({ [PUBKEY]: 'slate-badger' })
    expect(fn).toHaveBeenCalledOnce()
  })
})
