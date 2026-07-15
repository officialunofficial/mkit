// Persisted screen position for the floating dock (the presence circle). One
// of 8 snap anchors; remembered across reloads in localStorage, degrading to
// in-memory state when storage is unavailable (SSR / tests) so importing the
// store never throws.

import { create } from 'zustand'
import { type PersistStorage, createJSONStorage, persist } from 'zustand/middleware'

export type DockCorner =
  | 'top-left'
  | 'top-center'
  | 'top-right'
  | 'center-left'
  | 'center-right'
  | 'bottom-left'
  | 'bottom-center'
  | 'bottom-right'

type DockState = {
  corner: DockCorner
  setCorner: (c: DockCorner) => void
}

type PersistedDock = Pick<DockState, 'corner'>

function dockStorage(): PersistStorage<PersistedDock> | undefined {
  try {
    const ls = typeof globalThis !== 'undefined' ? globalThis.localStorage : undefined
    if (!ls) return undefined
    const probe = '__mkit_dock_probe__'
    ls.setItem(probe, '1')
    ls.removeItem(probe)
    return createJSONStorage<PersistedDock>(() => globalThis.localStorage)
  } catch {
    return undefined
  }
}

export const useDockPosition = create<DockState>()(
  persist(
    (set) => ({
      corner: 'bottom-right',
      setCorner: (corner) => set({ corner }),
    }),
    {
      name: 'mkit-dock-position',
      partialize: (s): PersistedDock => ({ corner: s.corner }),
      storage: dockStorage(),
    },
  ),
)
