'use client'

import { QueryClient } from '@tanstack/react-query'
import { PersistQueryClientProvider } from '@tanstack/react-query-persist-client'
import { createSyncStoragePersister } from '@tanstack/query-sync-storage-persister'
import { type ReactNode, useState } from 'react'
import { PERSIST_BUSTER, PERSIST_MAX_AGE, PERSIST_STORAGE_KEY, shouldPersistQuery } from '../lib/query-persist'

/**
 * App-wide TanStack Query provider (design note §6 — Query owns all repo/server state) with cache persistence for the
 * keys.mkit.sh handle queries.
 *
 * The QueryClient is created once per browser session via `useState` (NOT a bare module singleton — that would share
 * one cache across SSR requests/users on the server). The persister is likewise built lazily and is browser-only:
 * there's no `localStorage` during SSR, so `storage` is `undefined` there and the sync persister no-ops. Only
 * whitelisted queries are persisted (see `query-persist`); mutations never are (the in-memory signing seed can't
 * survive a reload).
 */
export function QueryProvider({ children }: { children: ReactNode }) {
  const [client] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: { staleTime: 5_000, refetchOnWindowFocus: false, retry: false },
        },
      }),
  )

  const [persister] = useState(() =>
    createSyncStoragePersister({
      storage: typeof window !== 'undefined' ? window.localStorage : undefined,
      key: PERSIST_STORAGE_KEY,
    }),
  )

  return (
    <PersistQueryClientProvider
      client={client}
      persistOptions={{
        persister,
        maxAge: PERSIST_MAX_AGE,
        // Invalidate the whole persisted cache when the policy/schema changes.
        buster: PERSIST_BUSTER,
        dehydrateOptions: {
          shouldDehydrateQuery: (q) => shouldPersistQuery(q.queryKey),
          // Never persist mutations: the Ed25519 signing seed lives only in
          // memory, so a persisted write could never be resumed after reload.
          shouldDehydrateMutation: () => false,
        },
      }}
    >
      {children}
    </PersistQueryClientProvider>
  )
}
