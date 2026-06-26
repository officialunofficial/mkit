'use client'

import { useEffect } from 'react'
import { mkit } from '../lib/mkit'
import { repoWasm } from '../lib/repo-client'

/**
 * Kicks off wasm init at hydration time. Demos mount later and read from the same cached promise, so by the time they
 * render the module is usually already resolved — no Suspense fallback flash.
 *
 * Also warms the SEPARATE repo-client wasm when the lobby/demo will talk to the worker backend (`VITE_REPO_BACKEND_URL`
 * set). Without this, the repo wasm can't even start downloading until the main wasm resolves, the lobby renders, and
 * its Effect fires — serializing ~400ms onto the front-page "Loading the lobby…" path. Skipped in mock/offline dev (no
 * backend URL) where the repo wasm is never used.
 */
export function MkitPreloader() {
  useEffect(() => {
    void mkit()
    if (import.meta.env.VITE_REPO_BACKEND_URL) void repoWasm()
  }, [])
  return null
}
