import { beforeEach, describe, expect, it } from 'vitest'
import {
  DEFAULT_ROOM,
  RETIRED_DEFAULT_ROOM,
  migrateIdentity,
  partializeIdentity,
  useIdentityStore,
} from './identity-store'

describe('migrateIdentity resets the retired default lobby', () => {
  it('moves a returning visitor off the retired default room onto the fresh one', () => {
    const migrated = migrateIdentity({ credentialId: 'c', room: RETIRED_DEFAULT_ROOM, name: 'amber-wren' }, 0)
    expect(migrated.room).toBe(DEFAULT_ROOM)
    // non-room fields are preserved
    expect(migrated.credentialId).toBe('c')
    expect(migrated.name).toBe('amber-wren')
  })

  it('leaves a user-chosen room untouched', () => {
    const migrated = migrateIdentity({ credentialId: null, room: 'arena', name: null }, 0)
    expect(migrated.room).toBe('arena')
  })

  it('no-ops once already at the current version', () => {
    const already = { credentialId: null, room: RETIRED_DEFAULT_ROOM, name: null }
    // version >= current: nothing to migrate, retired room left as-is
    expect(migrateIdentity(already, 1).room).toBe(RETIRED_DEFAULT_ROOM)
  })

  it('tolerates empty/undefined persisted state', () => {
    expect(migrateIdentity(undefined, 0)).toEqual({})
  })
})

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
    it('persists ONLY credentialId + p256PubkeyHex + room + name', () => {
      const s = useIdentityStore.getState()
      s.setCredentialId('cred-1')
      s.setP256PubkeyHex('ab'.repeat(65))
      s.setRoom('arena')
      s.setName('amber-wren')
      s.unlock({ seedHex: 'aa'.repeat(32), ed25519PubkeyHex: 'bb'.repeat(32) })
      const persisted = partializeIdentity(useIdentityStore.getState())
      expect(persisted).toEqual({
        credentialId: 'cred-1',
        p256PubkeyHex: 'ab'.repeat(65),
        room: 'arena',
        name: 'amber-wren',
      })
      expect(Object.keys(persisted).toSorted()).toEqual(['credentialId', 'name', 'p256PubkeyHex', 'room'])
    })

    // A public key is safe to cache (unlike the seed/derived Ed25519 material):
    // it's what re-enables the "Link with a passkey" button on a returning
    // visit without another passkey prompt.
    it('DOES persist p256PubkeyHex (a public key, unlike seedHex/ed25519PubkeyHex)', () => {
      const s = useIdentityStore.getState()
      s.setP256PubkeyHex('cd'.repeat(65))
      const persisted = partializeIdentity(useIdentityStore.getState())
      expect(persisted.p256PubkeyHex).toBe('cd'.repeat(65))
    })

    it('p256PubkeyHex round-trips through partialize as null when never set', () => {
      const persisted = partializeIdentity(useIdentityStore.getState())
      expect(persisted.p256PubkeyHex).toBeNull()
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

  it('reset clears p256PubkeyHex too', () => {
    const s = useIdentityStore.getState()
    s.setP256PubkeyHex('ef'.repeat(65))
    s.reset()
    expect(useIdentityStore.getState().p256PubkeyHex).toBeNull()
  })
})
