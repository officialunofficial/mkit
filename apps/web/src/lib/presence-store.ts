// Live "who's online" roster, keyed by room.
//
// The watch socket (one per room, opened by `useRepoEvents`) feeds `presence`
// frames in here; the floating presence panel reads them out. Client-only UI
// state — the authoritative roster lives on the RefStore Durable Object.

import { create } from 'zustand'
import { EMPTY_PRESENCE, type PresenceState } from './repo-api'

type PresenceStore = {
  byRoom: Record<string, PresenceState>
  set: (room: string, p: PresenceState) => void
}

export const usePresenceStore = create<PresenceStore>((set) => ({
  byRoom: {},
  set: (room, p) => set((s) => ({ byRoom: { ...s.byRoom, [room]: p } })),
}))

/** Read a room's current roster (empty until the first presence frame arrives). */
export function usePresence(room: string): PresenceState {
  return usePresenceStore((s) => s.byRoom[room] ?? EMPTY_PRESENCE)
}
