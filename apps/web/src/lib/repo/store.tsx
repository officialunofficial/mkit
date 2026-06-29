// The repo backend as a value the React tree OWNS — a context, not a mutable
// module global.
//
// Previously this module held a mutable `activeBackend` global resolved at
// call-time (`getRepoBackend()` threw when unconfigured) plus a
// `useSyncExternalStore` readiness flag. That indirection caused a crash class:
// an ungated `getRepoBackend()` (e.g. in `useRepoEvents`) threw into the
// ErrorBoundary whenever a hook ran before the async backend installed. Owning
// the backend as a context value deletes the global AND the crash: consumers
// read `useRepoBackend()` (nullable) and gate on `!!backend`, so the backend is
// only ever dereferenced when present.

import { type ReactNode, createContext, useContext } from 'react'
import type { RepoBackend } from './backend'

/**
 * The active repo backend, or `null` before one is available (worker mode while the wasm client loads). Defaults to
 * `null` so a hook that reads it outside a provider sees "no backend yet" and stays gated, never a stale instance.
 */
const RepoBackendContext = createContext<RepoBackend | null>(null)

/** Provide the backend to the subtree. `backend` is `null` until ready (→ children gate on it). */
export function RepoBackendProvider({ backend, children }: { backend: RepoBackend | null; children: ReactNode }) {
  return <RepoBackendContext.Provider value={backend}>{children}</RepoBackendContext.Provider>
}

/** Read the active backend (or `null`). Hooks gate every query/effect on `!!backend`. */
export function useRepoBackend(): RepoBackend | null {
  return useContext(RepoBackendContext)
}
