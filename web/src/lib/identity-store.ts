// Client identity / session state (design note §6).
//
// Boundary rule: TanStack Query owns *the repo* (server state); this Zustand
// store owns *who I am this session*. Only client-side, UI-owned, synchronous
// identity lives here — never server data (refs, objects, commit logs).
//
// The Ed25519 `seedHex` is transient and held in memory only: re-derived from
// the passkey each session, never persisted (no localStorage, no disk).

import { create } from 'zustand'

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

export const useIdentityStore = create<IdentityState>((set) => ({
  credentialId: null,
  ed25519PubkeyHex: null,
  seedHex: null,
  unlocked: false,
  ephemeral: false,
  room: DEFAULT_ROOM,

  setCredentialId: (id) => set({ credentialId: id }),
  unlock: ({ seedHex, ed25519PubkeyHex, ephemeral = false }) =>
    set({ seedHex, ed25519PubkeyHex, unlocked: true, ephemeral }),
  lock: () => set({ seedHex: null, unlocked: false }),
  setRoom: (room) => set({ room: room.trim() || DEFAULT_ROOM }),
  reset: () =>
    set({
      credentialId: null,
      ed25519PubkeyHex: null,
      seedHex: null,
      unlocked: false,
      ephemeral: false,
    }),
}))
