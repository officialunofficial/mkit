// Browser-facing wrapper around the `mkit-repo-client` wasm crate.
//
// Same shape as `mkit.ts`: wasm-bindgen `target=web`, default export is an async
// init that fetches the .wasm relative to its own module URL. Init must never run
// during SSR (no DOM, no fetch target), so we hand back a never-resolving promise
// there and let the client hydrate with the real one.

import init, * as RepoWasm from 'mkit-repo-client'

export type RepoWasmApi = typeof RepoWasm

let pending: Promise<RepoWasmApi> | null = null

const SSR_PENDING: Promise<RepoWasmApi> = new Promise(() => {})

export function repoWasm(): Promise<RepoWasmApi> {
  if (pending) return pending
  if (typeof window === 'undefined') return SSR_PENDING
  pending = init().then(() => RepoWasm)
  return pending
}

// Test-only: wire a caller-provided init promise as the single source of truth.
export function __setRepoWasmInit(p: Promise<RepoWasmApi>): void {
  pending = p
}

export function __resetRepoWasmForTests(): void {
  pending = null
}
