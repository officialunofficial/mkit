// Reactive backend holder (useSyncExternalStore source) + the readiness flag.
//
// Moved VERBATIM out of the former monolithic `repo-api.ts` — no behavior
// change — and re-exported by the `repo-api` barrel.

import { useSyncExternalStore } from 'react'
import type { RepoBackend } from './backend'

// ---------------------------------------------------------------------------
// Backend selection (mock toggle) + query keys
// ---------------------------------------------------------------------------

// The backend holder is a tiny REACTIVE external store (useSyncExternalStore
// source) — not a bare global. The bug it fixes: the hooks read this via
// `getRepoBackend()` with no `enabled` gate, so in worker mode the synchronous
// mock bootstrap let refs/log queries RESOLVE to empty `[]` before the async
// WasmRepoBackend was installed, flipping `isPending → false` and rendering the
// "No refs/commits" empty state on a populated room. Making the holder reactive
// lets `useRepoBackendReady()` gate every query so they stay PENDING (skeleton)
// until a backend is actually installed.
let activeBackend: RepoBackend | null = null
const backendListeners = new Set<() => void>()

/** Install the backend used by the hooks, then notify subscribers so any
 * `useRepoBackendReady()` consumers re-render and gated queries enable. */
export function setRepoBackend(backend: RepoBackend): void {
  activeBackend = backend
  for (const l of backendListeners) l()
}

/** Subscribe to backend changes (useSyncExternalStore subscribe fn). Returns an unsubscribe. */
export function subscribeBackend(cb: () => void): () => void {
  backendListeners.add(cb)
  return () => backendListeners.delete(cb)
}

/** Current backend, or null if none is installed yet (useSyncExternalStore snapshot). */
export function getBackendSnapshot(): RepoBackend | null {
  return activeBackend
}

export function getRepoBackend(): RepoBackend {
  if (!activeBackend) throw new Error('repo backend not configured — call setRepoBackend()')
  return activeBackend
}

/**
 * Reactive readiness flag: `true` once a backend is installed. Drives the
 * `enabled` gate on every repo query (dependent-query pattern) so a query stays
 * `status:'pending'` (→ skeleton) until there is a backend to answer it, instead
 * of resolving empty against a not-yet-replaced mock. The 3rd `useSyncExternalStore`
 * arg is the SERVER snapshot (`false`) for SSR safety — the server never has a
 * backend, so readiness is false there and the queries don't fire during SSR.
 */
export function useRepoBackendReady(): boolean {
  return useSyncExternalStore(
    subscribeBackend,
    () => getBackendSnapshot() != null,
    () => false,
  )
}
