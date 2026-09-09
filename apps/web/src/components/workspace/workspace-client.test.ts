import { afterEach, describe, expect, it, vi } from 'vitest'
import { mkit } from '../../lib/mkit'
import { useIdentityStore } from '../../lib/identity-store'
import { remixWorkspace, workspaceWrite } from '../../lib/workspace-client'
import { bytesToHex } from '../use-mkit'

afterEach(() => {
  useIdentityStore.getState().reset()
  vi.unstubAllGlobals()
})
describe('workspace signing authority', () => {
  it('does not sign the agent grant if the owner locks while preparation is in flight', async () => {
    const api = await mkit()
    const seed = new Uint8Array(32).fill(1)
    const seedHex = bytesToHex(seed)
    useIdentityStore.getState().setCredentialId('saved-passkey')
    useIdentityStore.getState().unlock({ seedHex, ed25519PubkeyHex: bytesToHex(api.ed25519_pubkey_from_seed(seed)) })
    vi.stubGlobal('location', { origin: 'https://mkit.sh' })
    let resolve!: (response: Response) => void
    const fetchMock = vi.fn().mockReturnValue(
      new Promise<Response>((r) => {
        resolve = r
      }),
    )
    vi.stubGlobal('fetch', fetchMock)
    const result = remixWorkspace(api, useIdentityStore.getState(), { kind: 'demo' })
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(fetchMock.mock.calls[0]?.[1].body).not.toContain(seedHex)
    useIdentityStore.getState().lock()
    resolve(new Response(JSON.stringify({ id: 'prepared', grant: {} })))
    await expect(result).rejects.toThrow('Identity changed')
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })
  it('rejects an ephemeral identity before any request is sent', async () => {
    const api = await mkit()
    useIdentityStore.getState().setCredentialId('old-saved-passkey')
    useIdentityStore.getState().unlock({ seedHex: '01'.repeat(32), ed25519PubkeyHex: '02'.repeat(32), ephemeral: true })
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
    await expect(
      workspaceWrite(api, useIdentityStore.getState(), 'workspace', '/workspace/tasks', { prompt: 'hello' }),
    ).rejects.toThrow('saved passkey')
    expect(fetchMock).not.toHaveBeenCalled()
  })
})
