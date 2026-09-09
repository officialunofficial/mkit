// @vitest-environment jsdom
import { QueryClient, QueryClientProvider, onlineManager } from '@tanstack/react-query'
import { act, cleanup, renderHook, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { useIdentityStore } from '../../lib/identity-store'
import { nameKey, useSetName } from './player-label'

const registry = vi.hoisted(() => ({ setName: vi.fn(), mkit: vi.fn(), api: {} }))
vi.mock('../../lib/keys-client', () => ({
  setName: registry.setName,
  getName: vi.fn(),
  keysEnabled: () => true,
}))
vi.mock('../../lib/mkit', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../lib/mkit')>()),
  mkit: registry.mkit,
}))

const seedHex = 'ab'.repeat(32)
const pubkeyHex = 'cd'.repeat(32)
let client: QueryClient

beforeEach(() => {
  client = new QueryClient({ defaultOptions: { mutations: { retry: false } } })
  registry.setName.mockReset().mockResolvedValue('amber-wren')
  registry.mkit.mockReset().mockResolvedValue(registry.api)
  useIdentityStore.getState().setCredentialId('passkey-one')
  useIdentityStore.getState().unlock({ seedHex, ed25519PubkeyHex: pubkeyHex })
})

afterEach(() => {
  cleanup()
  client.clear()
  onlineManager.setOnline(true)
  useIdentityStore.getState().reset()
})

function mountMutation() {
  return renderHook(useSetName, {
    wrapper: ({ children }: { children: ReactNode }) => (
      <QueryClientProvider client={client}>{children}</QueryClientProvider>
    ),
  })
}

it('initializes WASM only on mutation and checks identity after initialization completes', async () => {
  let resolveApi!: (api: object) => void
  registry.mkit.mockReturnValue(
    new Promise((resolve) => {
      resolveApi = resolve
    }),
  )
  const { result } = mountMutation()
  expect(registry.mkit).not.toHaveBeenCalled()

  act(() => result.current.mutate({ pubkeyHex, name: 'amber-wren' }))
  await waitFor(() => expect(registry.mkit).toHaveBeenCalledOnce())
  act(() => {
    useIdentityStore.getState().unlock({ seedHex: 'ef'.repeat(32), ed25519PubkeyHex: '12'.repeat(32) })
    resolveApi(registry.api)
  })
  await waitFor(() => expect(result.current.isError).toBe(true))
  expect(registry.setName).not.toHaveBeenCalled()
})

it('keeps successful name updates cached without retaining signing material in mutation state', async () => {
  const { result } = mountMutation()
  await act(async () => {
    await result.current.mutateAsync({ pubkeyHex, name: 'amber-wren' })
  })
  expect(registry.setName).toHaveBeenCalledWith(registry.api, seedHex, pubkeyHex, 'amber-wren')
  expect(client.getQueryData(nameKey(pubkeyHex))).toBe('amber-wren')

  useIdentityStore.getState().lock()
  const mutations = client.getMutationCache().getAll()
  expect(mutations).toHaveLength(1)
  expect(mutations[0]!.state.variables).toEqual({ pubkeyHex, name: 'amber-wren' })
  expect(JSON.stringify(mutations[0]!.state)).not.toContain(seedHex)
})

it.each(['switch', 'lock', 'ephemeral'] as const)(
  'rejects a queued rename when the identity changes to %s before signing',
  async (change) => {
    onlineManager.setOnline(false)
    const { result } = mountMutation()
    act(() => result.current.mutate({ pubkeyHex, name: 'amber-wren' }))
    await waitFor(() => expect(result.current.isPaused).toBe(true))

    act(() => {
      const identity = useIdentityStore.getState()
      if (change === 'lock') identity.lock()
      else {
        identity.unlock({
          seedHex: 'ef'.repeat(32),
          ed25519PubkeyHex: change === 'switch' ? '12'.repeat(32) : pubkeyHex,
          ephemeral: change === 'ephemeral',
        })
      }
      onlineManager.setOnline(true)
    })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(registry.setName).not.toHaveBeenCalled()
    expect(client.getQueryData(nameKey(pubkeyHex))).toBeUndefined()
  },
)
