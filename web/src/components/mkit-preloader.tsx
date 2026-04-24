'use client'

import { useEffect } from 'react'
import { mkit } from '../lib/mkit'

/**
 * Kicks off wasm init at hydration time. Demos mount later and read from the same cached promise, so by the time they
 * render the module is usually already resolved — no Suspense fallback flash.
 */
export function MkitPreloader() {
  useEffect(() => {
    void mkit()
  }, [])
  return null
}
