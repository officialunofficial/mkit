import { beforeEach, describe, expect, it } from 'vitest'
import { DEFAULT_ROOM, partializeIdentity, useIdentityStore } from './identity-store'

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

  it('lock clears the ephemeral flag (the in-memory seed it described is gone)', () => {
    const s = useIdentityStore.getState()
    s.unlock({ seedHex: 'aa'.repeat(32), ed25519PubkeyHex: 'bb'.repeat(32), ephemeral: true })
    expect(useIdentityStore.getState().ephemeral).toBe(true)
    s.lock()
    expect(useIdentityStore.getState().ephemeral).toBe(false)
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

  it('lock keeps credentialId (so the player can re-derive on reload)', () => {
    const s = useIdentityStore.getState()
    s.setCredentialId('cred-keep')
    s.unlock({ seedHex: 'aa'.repeat(32), ed25519PubkeyHex: 'bb'.repeat(32) })
    s.lock()
    expect(useIdentityStore.getState().credentialId).toBe('cred-keep')
  })

  it('reset clears credentialId', () => {
    const s = useIdentityStore.getState()
    s.setCredentialId('cred-gone')
    s.reset()
    expect(useIdentityStore.getState().credentialId).toBeNull()
  })

  it('reset returns the room to the default (persist now writes room)', () => {
    const s = useIdentityStore.getState()
    s.setRoom('arena')
    expect(useIdentityStore.getState().room).toBe('arena')
    s.reset()
    expect(useIdentityStore.getState().room).toBe(DEFAULT_ROOM)
  })

  describe('persistence partialize', () => {
    it('persists ONLY credentialId + room', () => {
      const s = useIdentityStore.getState()
      s.setCredentialId('cred-1')
      s.setRoom('arena')
      s.unlock({ seedHex: 'aa'.repeat(32), ed25519PubkeyHex: 'bb'.repeat(32) })
      const persisted = partializeIdentity(useIdentityStore.getState())
      expect(persisted).toEqual({ credentialId: 'cred-1', room: 'arena' })
      expect(Object.keys(persisted).toSorted()).toEqual(['credentialId', 'room'])
    })

    it('NEVER persists seedHex / pubkey / unlocked (no signing material on disk)', () => {
      useIdentityStore.getState().unlock({ seedHex: 'cc'.repeat(32), ed25519PubkeyHex: 'dd'.repeat(32) })
      const persisted = partializeIdentity(useIdentityStore.getState()) as Record<string, unknown>
      expect('seedHex' in persisted).toBe(false)
      expect('ed25519PubkeyHex' in persisted).toBe(false)
      expect('unlocked' in persisted).toBe(false)
      expect('ephemeral' in persisted).toBe(false)
    })
  })
})
