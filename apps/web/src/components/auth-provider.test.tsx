// @vitest-environment jsdom
import { act, cleanup, renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { AuthProvider, AUTH_CHANGE_KEY, SESSION_KEY, useAuth } from './auth-provider'
import { useWorkspaceDraftStore } from '../lib/workspace-draft-store'
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
  return { read: vi.fn(), write: vi.fn(), create: vi.fn(), derive: vi.fn(), fetch: vi.fn(), storage }
})
vi.mock('../lib/workspace-client', () => ({
  WORKSPACE_API: '/api/workspaces',
  workspaceRead: fake.read,
  workspaceWrite: fake.write,
}))
vi.mock('../lib/passkey', () => ({ createIdentity: fake.create, deriveEd25519Seed: fake.derive }))
vi.mock('../lib/mkit', () => ({ mkit: async () => ({ ed25519_pubkey_from_seed: () => new Uint8Array(32).fill(2) }) }))
vi.mock('./multiplayer/player-label', () => ({ useSetName: () => ({ mutate: vi.fn() }) }))
const publicKey = '02'.repeat(32)
const session = { id: 'session-one', publicKey, expiresAt: Date.now() + 60_000 }
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
beforeEach(() => {
  vi.clearAllMocks()
  useWorkspaceDraftStore.getState().clearAll()
  useIdentityStore.getState().reset()
  fake.read.mockResolvedValue(null)
  fake.create.mockResolvedValue({
    seedHex: '01'.repeat(32),
    credentialId: 'credential',
    via: 'prf-create',
    p256PubkeyHex: null,
  })
  fake.derive.mockResolvedValue({ seedHex: '01'.repeat(32), credentialId: 'credential' })
  fake.write.mockResolvedValue(session)
  fake.fetch.mockResolvedValue(new Response('null'))
  vi.stubGlobal('fetch', fake.fetch)
})
afterEach(() => {
  cleanup()
  client?.clear()
  vi.unstubAllGlobals()
})
it('restores one shared session after refresh without recovering a signing key', async () => {
  fake.read.mockResolvedValue(session)
  const { result } = mount()
  await waitFor(() => expect(result.current.one.session).toEqual(session))
  expect(result.current.two.session).toEqual(session)
  expect(fake.read).toHaveBeenCalledTimes(1)
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
  expect(fake.write).toHaveBeenCalledTimes(1)
  expect(result.current.one.session).toEqual(session)
  expect(result.current.one.unlocked).toBe(true)
  expect(
    JSON.stringify(
      client
        .getMutationCache()
        .getAll()
        .map((m) => m.state),
    ),
  ).not.toContain('01'.repeat(32))
})
it('locks signing while preserving login and unlocks lazily without rotating the session', async () => {
  fake.read.mockResolvedValue(session)
  const { result } = mount()
  await waitFor(() => expect(result.current.one.session).toEqual(session))
  await act(async () => {
    await result.current.one.ensureSigning(publicKey)
  })
  expect(fake.write).not.toHaveBeenCalled()
  await act(async () => {
    await result.current.one.lockSigning()
  })
  expect(result.current.one.session).toEqual(session)
  expect(result.current.one.unlocked).toBe(false)
  expect(fake.fetch).not.toHaveBeenCalled()
})
it('revokes a late login response after sign-out and clears private cache', async () => {
  const login = deferred<typeof session>()
  fake.write.mockReturnValue(login.promise)
  const { result } = mount()
  await waitFor(() => expect(result.current.one.pending).toBe(false))
  let signing!: Promise<void>, logout!: Promise<void>
  act(() => {
    signing = result.current.one.onCreate()
  })
  await waitFor(() => expect(fake.write).toHaveBeenCalledTimes(1))
  client.setQueryData(['workspaces', 'old-session'], { secret: 'terminal' })
  act(() => {
    logout = result.current.one.signOut()
  })
  await act(async () => {
    login.resolve(session)
    await signing
    await logout
  })
  expect(client.getQueryData(SESSION_KEY)).toBeNull()
  expect(client.getQueriesData({ queryKey: ['workspaces'] })).toEqual([])
  expect(useIdentityStore.getState().seedHex).toBeNull()
  expect(fake.fetch).toHaveBeenCalledWith('/api/workspaces/session', expect.objectContaining({ method: 'DELETE' }))
})
it('propagates signing lock and logout from another tab', async () => {
  fake.read.mockResolvedValue(session)
  const { result } = mount()
  await waitFor(() => expect(result.current.one.session).toEqual(session))
  await act(async () => {
    await result.current.one.ensureSigning()
  })
  act(() =>
    window.dispatchEvent(
      new StorageEvent('storage', { key: AUTH_CHANGE_KEY, newValue: JSON.stringify({ action: 'lock' }) }),
    ),
  )
  expect(result.current.one.unlocked).toBe(false)
  expect(result.current.one.session).toEqual(session)
  client.setQueryData(['workspaces', session.id], 'private')
  act(() =>
    window.dispatchEvent(
      new StorageEvent('storage', { key: AUTH_CHANGE_KEY, newValue: JSON.stringify({ action: 'logout' }) }),
    ),
  )
  await waitFor(() => expect(result.current.one.session).toBeNull())
  expect(client.getQueriesData({ queryKey: ['workspaces'] })).toEqual([])
})
it('preserves a known session through a transport failure', async () => {
  fake.read.mockResolvedValue(session)
  const { result } = mount()
  await waitFor(() => expect(result.current.one.session).toEqual(session))
  fake.read.mockRejectedValue(new Error('offline'))
  await act(async () => {
    await client.invalidateQueries({ queryKey: SESSION_KEY })
  })
  expect(result.current.one.session).toEqual(session)
})

it('reads another tab recovery metadata before persisting the signing lock', async () => {
  useIdentityStore.getState().setCredentialId('old-credential')
  useIdentityStore.getState().setName('old-name')
  fake.read.mockResolvedValue(session)
  const { result } = mount()
  await waitFor(() => expect(result.current.one.session).toEqual(session))
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
      new StorageEvent('storage', { key: AUTH_CHANGE_KEY, newValue: JSON.stringify({ action: 'session' }) }),
    ),
  )
  await waitFor(() => expect(useIdentityStore.getState().credentialId).toBe('new-credential'))
  expect(JSON.parse(fake.storage.getItem('mkit-identity')!).state.name).toBe('new-name')
  expect(useIdentityStore.getState().seedHex).toBeNull()
})
it('holds workspace reads during logout and removes private mutation data', async () => {
  fake.read.mockResolvedValue(session)
  const deletion = deferred<Response>()
  fake.fetch.mockReturnValue(deletion.promise)
  const { result } = mount()
  await waitFor(() => expect(result.current.one.session).toEqual(session))
  const mutation = client.getMutationCache().build(client, {
    mutationKey: ['workspaces', session.id, 'write'],
    mutationFn: async (_input: string) => 'private-response',
  })
  await mutation.execute('private-prompt')
  let logout!: Promise<void>
  act(() => {
    logout = result.current.one.signOut()
  })
  await waitFor(() => expect(result.current.one.session).toBeUndefined())
  expect(result.current.one.pending).toBe(true)
  expect(client.getMutationCache().getAll()).toEqual([])
  client.setQueryData(['workspaces', 'public'], 'late-owner-data')
  await act(async () => {
    deletion.resolve(new Response('null'))
    await logout
  })
  expect(result.current.one.session).toBeNull()
  expect(client.getQueriesData({ queryKey: ['workspaces'] })).toEqual([])
})
it('keeps failed sign-out retryable with signing locked', async () => {
  fake.read.mockResolvedValue(session)
  fake.fetch.mockRejectedValueOnce(new Error('offline')).mockResolvedValue(new Response('null'))
  const { result } = mount()
  await waitFor(() => expect(result.current.one.session).toEqual(session))
  await act(async () => {
    await result.current.one.signOut()
  })
  expect(result.current.one.session).toEqual(session)
  expect(result.current.one.unlocked).toBe(false)
  await act(async () => {
    await result.current.one.signOut()
  })
  expect(result.current.one.session).toBeNull()
  expect(fake.fetch).toHaveBeenCalledTimes(2)
})

it('guards unsaved drafts globally, preserves them while signing locks, and clears them on sign-out', async () => {
  fake.read.mockResolvedValue(session)
  const { result } = mount()
  await waitFor(() => expect(result.current.one.session).toEqual(session))
  useWorkspaceDraftStore.getState().setDraft('session:workspace', {
    path: 'README.md',
    content: 'edited',
    original: '',
    hash: null,
    editable: true,
  })
  const dirtyUnload = new Event('beforeunload', { cancelable: true })
  window.dispatchEvent(dirtyUnload)
  expect(dirtyUnload.defaultPrevented).toBe(true)
  await act(async () => {
    await result.current.one.lockSigning()
  })
  expect(useWorkspaceDraftStore.getState().scopes.size).toBe(1)
  await act(async () => {
    await result.current.one.signOut()
  })
  expect(useWorkspaceDraftStore.getState().scopes.size).toBe(0)
  const cleanUnload = new Event('beforeunload', { cancelable: true })
  window.dispatchEvent(cleanUnload)
  expect(cleanUnload.defaultPrevented).toBe(false)
})

it('clears drafts when the server session is replaced', async () => {
  fake.read.mockResolvedValue(session)
  const { result } = mount()
  await waitFor(() => expect(result.current.one.session).toEqual(session))
  useWorkspaceDraftStore.getState().setDraft('session:workspace', {
    path: 'README.md',
    content: 'edited',
    original: '',
    hash: null,
    editable: true,
  })
  act(() => client.setQueryData(SESSION_KEY, { ...session, id: 'replacement' }))
  await waitFor(() => expect(useWorkspaceDraftStore.getState().scopes.size).toBe(0))
})
