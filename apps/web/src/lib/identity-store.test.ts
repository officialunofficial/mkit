import { beforeEach, describe, expect, it } from 'vitest'
import { DEFAULT_ROOM, useIdentityStore } from './identity-store'

describe('identity store', () => {
  beforeEach(() => {
    useIdentityStore.getState().reset()
    useIdentityStore.getState().setRoom(DEFAULT_ROOM)
  })

  it('starts locked with no identity', () => {
    const s = useIdentityStore.getState()
    expect(s.unlocked).toBe(false)
    expect(s.seedHex).toBeNull()
    expect(s.ed25519PubkeyHex).toBeNull()
    expect(s.room).toBe(DEFAULT_ROOM)
  })

  it('unlock sets the seed + pubkey and marks unlocked', () => {
    useIdentityStore.getState().unlock({ seedHex: 'aa'.repeat(32), ed25519PubkeyHex: 'bb'.repeat(32) })
    const s = useIdentityStore.getState()
    expect(s.unlocked).toBe(true)
    expect(s.seedHex).toBe('aa'.repeat(32))
    expect(s.ed25519PubkeyHex).toBe('bb'.repeat(32))
    expect(s.ephemeral).toBe(false)
  })

  it('lock wipes the transient seed but keeps the credential', () => {
    const s = useIdentityStore.getState()
    s.setCredentialId('cred-1')
    s.unlock({ seedHex: 'aa'.repeat(32), ed25519PubkeyHex: 'bb'.repeat(32) })
    s.lock()
    const after = useIdentityStore.getState()
    expect(after.seedHex).toBeNull()
    expect(after.unlocked).toBe(false)
    expect(after.credentialId).toBe('cred-1') // keep so the player can re-derive
  })

  it('ephemeral flag is carried through unlock', () => {
    useIdentityStore.getState().unlock({ seedHex: 'aa'.repeat(32), ed25519PubkeyHex: 'bb'.repeat(32), ephemeral: true })
    expect(useIdentityStore.getState().ephemeral).toBe(true)
  })

  it('setRoom falls back to the default on empty input', () => {
    useIdentityStore.getState().setRoom('   ')
    expect(useIdentityStore.getState().room).toBe(DEFAULT_ROOM)
    useIdentityStore.getState().setRoom('arena')
    expect(useIdentityStore.getState().room).toBe('arena')
  })

  it('reset forgets the passkey too', () => {
    const s = useIdentityStore.getState()
    s.setCredentialId('cred-1')
    s.unlock({ seedHex: 'aa'.repeat(32), ed25519PubkeyHex: 'bb'.repeat(32) })
    s.reset()
    const after = useIdentityStore.getState()
    expect(after.credentialId).toBeNull()
    expect(after.seedHex).toBeNull()
  })
})
