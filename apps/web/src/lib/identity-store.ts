// Client identity / session state (design note §6).
//
// Boundary rule: TanStack Query owns *the repo* (server state); this Zustand
// store owns *who I am this session*. Only client-side, UI-owned, synchronous
// identity lives here — never server data (refs, objects, commit logs).
//
// PERSISTENCE INVARIANT: only `{ credentialId, p256PubkeyHex, room, name }` are
// written to localStorage (see `partialize`) — all non-secret (a P-256 PUBLIC
// key is safe to cache). The Ed25519 `seedHex` — and the derived
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
  /**
   * SEC1 uncompressed hex of the identity passkey's own P-256 public key, captured at creation time (#494). Unlike the
   * seed, a PUBLIC key is safe to persist — it's what `attestIdentityBinding` needs to drive the "Link with a passkey"
   * attestation. `null` for identities created before this field existed, or when `getPublicKey()` wasn't available at
   * creation time; either way the attest button stays disabled (see `identity-panel.tsx`).
   */
  p256PubkeyHex: string | null
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
  /**
   * The chosen petname for THIS player (e.g. "amber-wren"), set at create time — the same handle written to the OS
   * passkey. Persisted so the app displays the SAME name as the passkey manager even without a keys.mkit.sh registry;
   * the registry value (when configured) still takes precedence for display.
   */
  name: string | null

  setCredentialId: (id: string | null) => void
  /** Record the identity credential's own P-256 public key (§1/§2 of #494), or `null` if it couldn't be captured. */
  setP256PubkeyHex: (hex: string | null) => void
  /** Set the derived seed + pubkey together and mark unlocked. */
  unlock: (args: { seedHex: string; ed25519PubkeyHex: string; ephemeral?: boolean }) => void
  /** Record this player's own handle (the petname written to the passkey). */
  setName: (name: string | null) => void
  /** Wipe the in-memory seed (keeps credentialId so the player can re-derive). */
  lock: () => void
  setRoom: (room: string) => void
  /** Full reset — forget the passkey too. */
  reset: () => void
}

export const DEFAULT_ROOM = 'lobby-v2'

/**
 * The prior default room, retired 2026-07-03. Its Durable Object holds chat messages written before the reaction-id fix
 * (#522) — several share a content hash because ids weren't yet unique per post, so reactions collide across them.
 * Rather than a destructive in-place clear, we move everyone to a fresh room; {@link migrateIdentity} rewrites a
 * persisted `lobby` to {@link DEFAULT_ROOM}.
 */
export const RETIRED_DEFAULT_ROOM = 'lobby'

/** LocalStorage key the persisted slice lives under. */
export const IDENTITY_STORAGE_KEY = 'mkit-identity'

/** Persisted-state schema version — bumped to 1 to run {@link migrateIdentity}. */
export const IDENTITY_PERSIST_VERSION = 1

/**
 * The ONLY fields written to disk — never the seed/`ed25519PubkeyHex`/unlock flags. `p256PubkeyHex` IS persisted:
 * unlike the Ed25519 signing material, a P-256 public key reveals nothing secret — it's the whole point of a public key
 * — so caching it means a returning user doesn't need a passkey prompt just to re-enable the attest button.
 */
export type PersistedIdentity = Pick<IdentityState, 'credentialId' | 'p256PubkeyHex' | 'room' | 'name'>

/**
 * Persisted slice: which passkey to recover, the last room, and this player's own handle. Exported so the invariant (no
 * seed material on disk) is directly testable.
 */
export function partializeIdentity(s: IdentityState): PersistedIdentity {
  return { credentialId: s.credentialId, p256PubkeyHex: s.p256PubkeyHex, room: s.room, name: s.name }
}

/**
 * Persist migration. A returning visitor sitting on the retired default room ({@link RETIRED_DEFAULT_ROOM}) is moved to
 * {@link DEFAULT_ROOM} so they land in the fresh lobby instead of the one with the colliding pre-fix message ids. A
 * room the user explicitly chose (anything other than the old default) is left untouched. Pure + exported for direct
 * testing.
 */
export function migrateIdentity(persisted: unknown, version: number): PersistedIdentity {
  const p = (persisted ?? {}) as PersistedIdentity
  if (version < IDENTITY_PERSIST_VERSION && p.room === RETIRED_DEFAULT_ROOM) {
    return { ...p, room: DEFAULT_ROOM }
  }
  return p
}

/**
 * LocalStorage-backed JSON storage that degrades to a no-op when there's no `localStorage` (SSR build, the node test
 * env) — so importing the store never throws and the SSR bundle doesn't break.
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
      p256PubkeyHex: null,
      ed25519PubkeyHex: null,
      seedHex: null,
      unlocked: false,
      ephemeral: false,
      room: DEFAULT_ROOM,
      name: null,

      setCredentialId: (id) => set({ credentialId: id }),
      setP256PubkeyHex: (hex) => set({ p256PubkeyHex: hex }),
      unlock: ({ seedHex, ed25519PubkeyHex, ephemeral = false }) =>
        set({ seedHex, ed25519PubkeyHex, unlocked: true, ephemeral }),
      setName: (name) => set({ name }),
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
          p256PubkeyHex: null,
          ed25519PubkeyHex: null,
          seedHex: null,
          unlocked: false,
          ephemeral: false,
          room: DEFAULT_ROOM,
          name: null,
        }),
    }),
    {
      name: IDENTITY_STORAGE_KEY,
      version: IDENTITY_PERSIST_VERSION,
      // Persist ONLY the recovery anchor + room — never the in-memory seed.
      partialize: partializeIdentity,
      // Move returning visitors off the retired `lobby` room (pre-fix colliding
      // message ids) onto the fresh default; keeps a user-chosen room intact.
      migrate: migrateIdentity,
      // Degrades to no persistence when localStorage is absent (SSR / tests).
      storage: identityStorage(),
    },
  ),
)
