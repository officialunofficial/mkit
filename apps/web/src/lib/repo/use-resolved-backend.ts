// Resolve the active repo backend for a client subtree: the in-memory mock
// offline (no `VITE_REPO_BACKEND_URL`), else the wasm ConnectRPC backend once
// it loads (null until then → consumers gate on it). Extracted so the front-page
// lobby reuses the SAME logic as MultiplayerDemo.
//
// Both backends read the live signing seed from the identity store at call time
// (`() => useIdentityStore.getState().seedHex`) so a signed write — push OR
// chat — uses whatever key is currently unlocked, with no prop threading.
//
// Offline demo data is seeded AT MOCK CREATION (not in an Effect) so the very
// first query read already sees it — no seed→render→invalidate race. See
// https://react.dev/learn/you-might-not-need-an-effect ("Initializing the
// application" / "you don't need Effects to transform data for rendering").

import { useEffect, useMemo, useState } from 'react'
import { useIdentityStore } from '../identity-store'
import type { MkitApi } from '../mkit'
import { repoWasm } from '../repo-client'
import { MockRepoBackend, type RepoBackend, WasmRepoBackend } from './backend'

export function useResolvedRepoBackend(
  api: MkitApi,
  room?: string,
): {
  backend: RepoBackend | null
  useMock: boolean
} {
  const backendUrl = import.meta.env.VITE_REPO_BACKEND_URL as string | undefined
  const useMock = !backendUrl

  // ONE stable mock for the lifetime of the mount (keyed only on `api`), so a
  // room switch reuses it and never wipes the user's session posts.
  const mock = useMemo(() => new MockRepoBackend(api, () => useIdentityStore.getState().seedHex), [api])

  // Lazily seed the CURRENT room's offline demo data, idempotently, during
  // render — so the data is already present before any `commitLog`/`listMessages`
  // query reads it (no empty-first-read → no invalidate race), and a room switch
  // seeds the new room without recreating the instance. `seedDemoOnce` no-ops on
  // a room it has already seeded, so calling it every render (incl. StrictMode's
  // double-invoke) is safe. (Worker mode sources real history from the worker.)
  if (useMock && room) mock.seedDemoOnce(room)

  // Worker mode: load the wasm backend asynchronously (a genuine external-system
  // sync — Effect is the right tool). Queries are `enabled`-gated on the backend,
  // so they fetch automatically the moment it flips from null → ready; no manual
  // invalidate is needed.
  const [wasmBackend, setWasmBackend] = useState<RepoBackend | null>(null)
  useEffect(() => {
    if (!backendUrl) return
    let cancelled = false
    repoWasm()
      .then((wasm) => {
        if (cancelled) return
        setWasmBackend(new WasmRepoBackend(wasm, api, () => useIdentityStore.getState().seedHex, backendUrl))
      })
      .catch(() => {
        // GENUINE FALLBACK: if the wasm client fails to load, fall back to the
        // mock — seeded with this room's demo content so the surface still shows
        // life rather than coming up empty.
        if (!cancelled) {
          if (room) mock.seedDemoOnce(room)
          setWasmBackend(mock)
        }
      })
    return () => {
      cancelled = true
    }
  }, [backendUrl, api, mock, room])

  return { backend: useMock ? mock : wasmBackend, useMock }
}
