'use client'

import { Suspense, useEffect, useState, type ReactNode } from 'react'

/**
 * Mount gate + Suspense boundary for demos that read wasm via `use(mkit())`. SSR never evaluates the children — Vocs's
 * static prerender would otherwise hang on the never-resolving server-side wasm promise — so the server emits the
 * fallback directly. On hydration the gate flips, Suspense catches the wasm load, and React swaps in the real content
 * as soon as the module resolves.
 */
export function DemoBoundary({ children }: { children: ReactNode }) {
  const [mounted, setMounted] = useState(false)
  useEffect(() => {
    setMounted(true)
  }, [])
  if (!mounted) return <Fallback />
  return <Suspense fallback={<Fallback />}>{children}</Suspense>
}

function Fallback() {
  return <p className='text-sm text-[--color-muted]'>Loading wasm…</p>
}
