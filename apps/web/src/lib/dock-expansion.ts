// Which floating-dock panel is expanded — at most ONE at a time (mutual
// exclusion). Temporary UI state, not persisted: both panels derive their
// open/expanded state from this single value, so opening one collapses the
// other for free.

import { create } from 'zustand'

export type DockExpanded = 'activity' | 'presence' | null

type DockExpansion = {
  expanded: DockExpanded
  open: (which: 'activity' | 'presence') => void
  /** Release the slot only if `which` currently holds it (no-op otherwise). */
  close: (which: 'activity' | 'presence') => void
  toggle: (which: 'activity' | 'presence') => void
}

export const useDockExpansion = create<DockExpansion>((set) => ({
  expanded: null,
  open: (which) => set({ expanded: which }),
  close: (which) => set((s) => (s.expanded === which ? { expanded: null } : s)),
  toggle: (which) => set((s) => ({ expanded: s.expanded === which ? null : which })),
}))
