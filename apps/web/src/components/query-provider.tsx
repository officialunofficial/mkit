'use client'

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { type ReactNode, useState } from 'react'

/**
 * App-wide TanStack Query provider (design note §6 — Query owns all repo/server
 * state). Wraps the layout so any demo can read refs / objects / the commit log
 * and run the push mutation. The client is created once per browser session via
 * `useState`, never recreated on re-render.
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
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}
