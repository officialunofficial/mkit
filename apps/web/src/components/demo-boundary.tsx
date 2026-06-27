'use client'

import { Suspense, useEffect, useState, type ReactNode } from 'react'
import { ErrorBoundary } from './error-boundary'

/**
 * Mount gate + Suspense + error boundary for demos that read wasm via `use(mkit())`. SSR never evaluates the children —
 * Waku's static prerender would otherwise hang on the never-resolving server-side wasm promise — so the server emits
 * the fallback directly. On hydration the gate flips, Suspense catches the wasm _load_, and React swaps in the real
 * content as soon as the module resolves. The outer ErrorBoundary catches the wasm _init failure_ `use(mkit())` throws,
 * so a broken wasm load shows a recoverable fallback instead of a blank demo.
 */
export function DemoBoundary({ children }: { children: ReactNode }) {
  const [mounted, setMounted] = useState(false)
  useEffect(() => {
    setMounted(true)
  }, [])
  if (!mounted) return <Fallback />
  return (
    <ErrorBoundary>
      <Suspense fallback={<Fallback />}>{children}</Suspense>
    </ErrorBoundary>
  )
}

function Fallback() {
  return <p className='text-sm text-muted'>Loading…</p>
}
