// @vitest-environment jsdom
import { act, cleanup, renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { AuthProvider, AUTH_CHANGE_KEY, useAuth } from './auth-provider'
import { useIdentityStore } from '../lib/identity-store'
const fake = vi.hoisted(() => {
  const values = new Map<string, string>()
  const storage: Storage = {
    get length() {
      return values.size
    },
    clear: () => values.clear(),
    key: (index) => [...values.keys()][index] ?? null,
    getItem: (key) => values.get(key) ?? null,
    removeItem: (key) => {
      values.delete(key)
    },
    setItem: (key, value) => {
      values.set(key, value)
    },
  }
  Object.defineProperty(globalThis, 'localStorage', { value: storage, configurable: true, writable: true })
  return { create: vi.fn(), derive: vi.fn(), fetch: vi.fn(), storage }
})
vi.mock('../lib/passkey', () => ({ createIdentity: fake.create, deriveEd25519Seed: fake.derive }))
vi.mock('../lib/mkit', () => ({ mkit: async () => ({ ed25519_pubkey_from_seed: () => new Uint8Array(32).fill(2) }) }))
vi.mock('./multiplayer/player-label', () => ({ useSetName: () => ({ mutate: vi.fn() }) }))
const publicKey = '02'.repeat(32)
let client: QueryClient
function mount() {
  client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  return renderHook(() => ({ one: useAuth(), two: useAuth() }), {
    wrapper: ({ children }: { children: ReactNode }) => (
      <QueryClientProvider client={client}>
        <AuthProvider>{children}</AuthProvider>
      </QueryClientProvider>
    ),
  })
}
function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((done) => {
    resolve = done
  })
  return { promise, resolve }
}
function remember() {
  useIdentityStore.setState({ credentialId: 'credential', knownPublicKey: publicKey })
}
beforeEach(() => {
  vi.clearAllMocks()
  useIdentityStore.getState().reset()
  fake.create.mockResolvedValue({
    seedHex: '01'.repeat(32),
    credentialId: 'credential',
    via: 'prf-create',
    p256PubkeyHex: null,
  })
  fake.derive.mockResolvedValue({ seedHex: '01'.repeat(32), credentialId: 'credential' })
  vi.stubGlobal('fetch', fake.fetch)
})
afterEach(() => {
  cleanup()
  client?.clear()
  vi.unstubAllGlobals()
})
it('remembers one shared identity after refresh without recovering a signing key', async () => {
  remember()
  const { result } = mount()
  await waitFor(() => expect(result.current.one.pending).toBe(false))
  expect(result.current.one.publicKey).toBe(publicKey)
  expect(result.current.two.publicKey).toBe(publicKey)
  expect(result.current.one.unlocked).toBe(false)
  expect(fake.derive).not.toHaveBeenCalled()
  expect(fake.fetch).not.toHaveBeenCalled()
  expect(useIdentityStore.getState().seedHex).toBeNull()
})
it('deduplicates ceremonies and keeps seeds out of Query state', async () => {
  const creation = deferred<unknown>()
  fake.create.mockReturnValue(creation.promise)
  const { result } = mount()
  await waitFor(() => expect(result.current.one.pending).toBe(false))
  let first!: Promise<void>, second!: Promise<void>
  act(() => {
    first = result.current.one.onCreate()
    second = result.current.two.onCreate()
  })
  await waitFor(() => expect(fake.create).toHaveBeenCalledTimes(1))
  await act(async () => {
    creation.resolve({ seedHex: '01'.repeat(32), credentialId: 'credential', via: 'prf-create', p256PubkeyHex: null })
    await Promise.all([first, second])
  })
  expect(result.current.one.publicKey).toBe(publicKey)
  expect(result.current.one.unlocked).toBe(true)
  expect(fake.fetch).not.toHaveBeenCalled()
  expect(
    JSON.stringify(
      client
        .getMutationCache()
        .getAll()
        .map((m) => m.state),
    ),
  ).not.toContain('01'.repeat(32))
})
it('locks signing while preserving login and unlocks lazily', async () => {
  remember()
  const { result } = mount()
  await waitFor(() => expect(result.current.one.pending).toBe(false))
  await act(async () => {
    await result.current.one.ensureSigning(publicKey)
  })
  expect(result.current.one.unlocked).toBe(true)
  expect(fake.derive).toHaveBeenCalledTimes(1)
  await act(async () => {
    await result.current.one.lockSigning()
  })
  expect(result.current.one.publicKey).toBe(publicKey)
  expect(result.current.one.unlocked).toBe(false)
  expect(fake.fetch).not.toHaveBeenCalled()
})
it('refuses to sign for an identity other than the remembered one', async () => {
  remember()
  const { result } = mount()
  await waitFor(() => expect(result.current.one.pending).toBe(false))
  await expect(result.current.one.ensureSigning('03'.repeat(32))).rejects.toThrow('another identity')
  fake.derive.mockResolvedValue({ seedHex: '09'.repeat(32), credentialId: 'credential' })
  useIdentityStore.setState({ knownPublicKey: '03'.repeat(32) })
  await act(async () => {
    await result.current.one.onUnlock()
  })
  expect(result.current.one.status).toContain('another identity')
  expect(result.current.one.unlocked).toBe(false)
})
it('fails a late ceremony after sign-out', async () => {
  const derivation = deferred<unknown>()
  fake.derive.mockReturnValue(derivation.promise)
  useIdentityStore.setState({ credentialId: 'credential' })
  const { result } = mount()
  await waitFor(() => expect(result.current.one.pending).toBe(false))
  let unlocking!: Promise<void>
  act(() => {
    unlocking = result.current.one.onUnlock()
  })
  await waitFor(() => expect(fake.derive).toHaveBeenCalledTimes(1))
  await act(async () => {
    await result.current.one.signOut()
    derivation.resolve({ seedHex: '01'.repeat(32), credentialId: 'credential' })
    await unlocking
  })
  expect(result.current.one.publicKey).toBeNull()
  expect(result.current.one.unlocked).toBe(false)
  expect(useIdentityStore.getState().seedHex).toBeNull()
  expect(result.current.one.status).toContain('changed')
})
it('signs out locally, keeping the passkey for the next sign-in', async () => {
  remember()
  const { result } = mount()
  await waitFor(() => expect(result.current.one.pending).toBe(false))
  await act(async () => {
    await result.current.one.ensureSigning()
    await result.current.one.signOut()
  })
  expect(result.current.one.publicKey).toBeNull()
  expect(result.current.one.unlocked).toBe(false)
  expect(result.current.one.hasPasskey).toBe(true)
  expect(useIdentityStore.getState().seedHex).toBeNull()
  expect(JSON.parse(fake.storage.getItem(AUTH_CHANGE_KEY)!).action).toBe('logout')
  expect(fake.fetch).not.toHaveBeenCalled()
})
it('propagates signing lock and logout from another tab', async () => {
  remember()
  const { result } = mount()
  await waitFor(() => expect(result.current.one.pending).toBe(false))
  await act(async () => {
    await result.current.one.ensureSigning()
  })
  act(() =>
    window.dispatchEvent(
      new StorageEvent('storage', { key: AUTH_CHANGE_KEY, newValue: JSON.stringify({ action: 'lock' }) }),
    ),
  )
  expect(result.current.one.unlocked).toBe(false)
  expect(result.current.one.publicKey).toBe(publicKey)
  fake.storage.setItem(
    'mkit-identity',
    JSON.stringify({ version: 1, state: { credentialId: 'credential', knownPublicKey: null, room: 'lobby-v2' } }),
  )
  act(() =>
    window.dispatchEvent(
      new StorageEvent('storage', { key: AUTH_CHANGE_KEY, newValue: JSON.stringify({ action: 'logout' }) }),
    ),
  )
  await waitFor(() => expect(result.current.one.publicKey).toBeNull())
  expect(result.current.one.unlocked).toBe(false)
})
it('reads another tab recovery metadata before persisting the signing lock', async () => {
  useIdentityStore.getState().setCredentialId('old-credential')
  useIdentityStore.getState().setName('old-name')
  const { result } = mount()
  await waitFor(() => expect(result.current.one.pending).toBe(false))
  fake.storage.setItem(
    'mkit-identity',
    JSON.stringify({
      version: 1,
      state: {
        credentialId: 'new-credential',
        name: 'new-name',
        knownPublicKey: publicKey,
        p256PubkeyHex: null,
        room: 'lobby-v2',
      },
    }),
  )
  act(() =>
    window.dispatchEvent(
      new StorageEvent('storage', { key: AUTH_CHANGE_KEY, newValue: JSON.stringify({ action: 'login' }) }),
    ),
  )
  await waitFor(() => expect(useIdentityStore.getState().credentialId).toBe('new-credential'))
  expect(JSON.parse(fake.storage.getItem('mkit-identity')!).state.name).toBe('new-name')
  expect(useIdentityStore.getState().seedHex).toBeNull()
  expect(result.current.one.publicKey).toBe(publicKey)
})
