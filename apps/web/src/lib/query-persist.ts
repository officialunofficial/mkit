// TanStack Query cache-persistence policy (apps/web).
//
// We persist ONLY the keys.mkit.sh handle queries — `['keys', 'name', <pubkey>]`:
//   * they're small JSON strings, safe for the sync localStorage persister
//     (which serializes with JSON.stringify — that would CORRUPT the Uint8Array
//     bytes of a persisted repo `object` query into a `{"0":..}` blob), and
//   * persisting them lets a returning player see real handles immediately
//     instead of a flash of the deterministic `playerName` fallback.
//
// Everything else is intentionally NOT persisted:
//   * mutable repo `ref`/`log`/`refs` queries would hydrate stale — the
//     WatchRefs stream + refetch are the source of truth;
//   * immutable repo `object` bytes are binary (see above) — they'd need an
//     IndexedDB/structured-clone persister, a separate change;
//   * mutations are never persisted (the Ed25519 signing seed is in-memory only
//     and gone on reload, so a persisted write could never resume).

/** LocalStorage key the dehydrated cache is written under. */
export const PERSIST_STORAGE_KEY = 'mkit-query-cache'

/** Bump to invalidate every previously-persisted cache (policy/schema change). */
export const PERSIST_BUSTER = 'v1'

/**
 * Discard a persisted cache older than this. The persisted queries' `gcTime` must be >= this value or they're evicted
 * from memory before hydration can surface them — see `useDisplayName`.
 */
export const PERSIST_MAX_AGE = 24 * 60 * 60 * 1000 // 24h

/** True for query keys whose cached value is safe AND worth persisting to disk. */
export function shouldPersistQuery(queryKey: readonly unknown[]): boolean {
  return queryKey[0] === 'keys'
}
