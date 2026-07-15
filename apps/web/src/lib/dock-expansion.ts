// Whether the floating-dock's presence panel is expanded. Temporary UI state,
// not persisted.

import { create } from 'zustand'

export type DockExpanded = 'presence' | null

type DockExpansion = {
  expanded: DockExpanded
  open: (which: 'presence') => void
  /** Release the slot only if `which` currently holds it (no-op otherwise). */
  close: (which: 'presence') => void
  toggle: (which: 'presence') => void
}

export const useDockExpansion = create<DockExpansion>((set) => ({
  expanded: null,
  open: (which) => set({ expanded: which }),
  close: (which) => set((s) => (s.expanded === which ? { expanded: null } : s)),
  toggle: (which) => set((s) => ({ expanded: s.expanded === which ? null : which })),
}))
