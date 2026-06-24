// Client identity / session state (design note §6).
//
// Boundary rule: TanStack Query owns *the repo* (server state); this Zustand
// store owns *who I am this session*. Only client-side, UI-owned, synchronous
// identity lives here — never server data (refs, objects, commit logs).
//
// PERSISTENCE INVARIANT: only `{ credentialId, room }` are written to
// localStorage (see `partialize`). The Ed25519 `seedHex` — and the derived
// `ed25519PubkeyHex` / `unlocked` flags — are transient and held in memory
// ONLY: re-derived from the passkey each session, NEVER persisted to disk.
// Persisting the credentialId lets a returning user RECOVER the same player
// (deriveEd25519Seed re-mints the same seed from the same passkey) without
// ever putting signing material on disk.

import { create } from 'zustand'
import { type PersistStorage, createJSONStorage, persist } from 'zustand/middleware'

export type IdentityState = {
  /** Base64url credential id of the enrolled passkey, or null before enrolment. */
  credentialId: string | null
  /** Hex Ed25519 public key derived from the passkey (the anonymous player id). */
  ed25519PubkeyHex: string | null
  /** Transient 32-byte signing seed (64 hex). In-memory only — cleared on lock. */
  seedHex: string | null
  /** True once a seed is in memory and we can sign. */
  unlocked: boolean
  /** True when the seed came from the random fallback (no PRF / no passkey). */
  ephemeral: boolean
  /** Selected room / repo for the multiplayer demo. */
  room: string

  setCredentialId: (id: string | null) => void
  /** Set the derived seed + pubkey together and mark unlocked. */
  unlock: (args: { seedHex: string; ed25519PubkeyHex: string; ephemeral?: boolean }) => void
  /** Wipe the in-memory seed (keeps credentialId so the player can re-derive). */
  lock: () => void
  setRoom: (room: string) => void
  /** Full reset — forget the passkey too. */
  reset: () => void
}

export const DEFAULT_ROOM = 'lobby'

/** localStorage key the persisted slice lives under. */
export const IDENTITY_STORAGE_KEY = 'mkit-identity'

/** The ONLY fields written to disk — never the seed/pubkey/unlock flags. */
export type PersistedIdentity = Pick<IdentityState, 'credentialId' | 'room'>

/** Persisted slice: which passkey to recover + the last room. Exported so the
 * invariant (no seed material on disk) is directly testable. */
export function partializeIdentity(s: IdentityState): PersistedIdentity {
  return { credentialId: s.credentialId, room: s.room }
}

/**
 * localStorage-backed JSON storage that degrades to a no-op when there's no
 * `localStorage` (SSR build, the node test env) — so importing the store never
 * throws and the SSR bundle doesn't break.
 */
function identityStorage(): PersistStorage<PersistedIdentity> | undefined {
  try {
    // Touch it through a probe so a throwing/absent localStorage (SSR, the node
    // test env without --localstorage-file) degrades to no persistence rather
    // than crashing the import.
    const ls = typeof globalThis !== 'undefined' ? globalThis.localStorage : undefined
    if (!ls) return undefined
    const probe = '__mkit_identity_probe__'
    ls.setItem(probe, '1')
    ls.removeItem(probe)
    return createJSONStorage<PersistedIdentity>(() => globalThis.localStorage)
  } catch {
    return undefined
  }
}

export const useIdentityStore = create<IdentityState>()(
  persist(
    (set) => ({
      credentialId: null,
      ed25519PubkeyHex: null,
      seedHex: null,
      unlocked: false,
      ephemeral: false,
      room: DEFAULT_ROOM,

      setCredentialId: (id) => set({ credentialId: id }),
      unlock: ({ seedHex, ed25519PubkeyHex, ephemeral = false }) =>
        set({ seedHex, ed25519PubkeyHex, unlocked: true, ephemeral }),
      // Clearing the seed also clears `ephemeral`: that flag describes the
      // now-gone in-memory seed, so leaving it stuck `true` would mislabel the
      // locked state.
      lock: () => set({ seedHex: null, unlocked: false, ephemeral: false }),
      setRoom: (room) => set({ room: room.trim() || DEFAULT_ROOM }),
      // Full reset — forget the passkey AND return to the default room (persist
      // now writes `room`, so a "forget everything" must reset it too).
      reset: () =>
        set({
          credentialId: null,
          ed25519PubkeyHex: null,
          seedHex: null,
          unlocked: false,
          ephemeral: false,
          room: DEFAULT_ROOM,
        }),
    }),
    {
      name: IDENTITY_STORAGE_KEY,
      // Persist ONLY the recovery anchor + room — never the in-memory seed.
      partialize: partializeIdentity,
      // Degrades to no persistence when localStorage is absent (SSR / tests).
      storage: identityStorage(),
    },
  ),
)
