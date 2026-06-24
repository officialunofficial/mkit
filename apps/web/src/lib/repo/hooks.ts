// React Query keys, query hooks, the push mutation (+ optimistic lifecycle),
// and the live-events subscription.
//
// Moved verbatim out of the former monolithic `repo-api.ts`; re-exported by the
// `repo-api` barrel so existing `from '../lib/repo-api'` imports keep working.

import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect } from 'react'
import { bytesToHex, hexToBytes } from '../../components/use-mkit'
import type { MkitApi } from '../mkit'
import {
  BackendNotReadyError,
  type CommitLogEntry,
  type RefExpectation,
  type RemixSourceEntry,
  MockRepoBackend,
  type RepoBackend,
  WasmRepoBackend,
  decodeLogObject,
} from './backend'
import { useRepoBackend } from './store'

export const repoKeys = {
  ref: (room: string, name: string) => ['repo', room, 'ref', name] as const,
  refs: (room: string, prefix: string) => ['repo', room, 'refs', prefix] as const,
  object: (room: string, hash: string) => ['repo', room, 'object', hash] as const,
  log: (room: string, ref: string) => ['repo', room, 'log', ref] as const,
}

// ---------------------------------------------------------------------------
// Query hooks
// ---------------------------------------------------------------------------

export function useRef(room: string, name: string) {
  const backend = useRepoBackend()
  return useQuery({
    queryKey: repoKeys.ref(room, name),
    queryFn: () => backend!.getRef(room, name),
    // Dependent query: don't run (stay pending) until a backend is available,
    // so `backend!` is only ever dereferenced when present.
    enabled: !!backend,
  })
}

export function useObject(room: string, hash: string | null) {
  const backend = useRepoBackend()
  return useQuery({
    queryKey: repoKeys.object(room, hash ?? ''),
    queryFn: () => (hash ? backend!.getObject(room, hash) : Promise.resolve(null)),
    // Preserve the existing hash guard AND gate on backend availability.
    enabled: !!backend && !!hash,
    // Objects are CONTENT-ADDRESSED (immutable): a hash → fixed bytes forever,
    // so a cached object is never stale and never needs eviction. Keep this
    // query permanent (don't touch the global default, which keeps refs/log
    // fresh / WS-invalidated).
    staleTime: Number.POSITIVE_INFINITY,
    gcTime: Number.POSITIVE_INFINITY,
  })
}

export function useCommitLog(room: string, ref = 'main') {
  const backend = useRepoBackend()
  return useQuery({
    queryKey: repoKeys.log(room, ref),
    queryFn: () => backend!.commitLog(room, ref),
    enabled: !!backend,
    // Switching branches keeps the previous ref's list on screen during the
    // fetch (no skeleton/empty flash); replaced once the new ref's log resolves.
    placeholderData: keepPreviousData,
  })
}

/** All refs in the room (optionally prefix-filtered) — drives the branches panel. */
export function useRefs(room: string, prefix = '') {
  const backend = useRepoBackend()
  return useQuery({
    queryKey: repoKeys.refs(room, prefix),
    queryFn: () => backend!.listRefs(room, prefix),
    enabled: !!backend,
    // Keep the prior prefix's refs visible while a new prefix loads.
    placeholderData: keepPreviousData,
  })
}

export type PushArgs = {
  api: MkitApi
  seedHex: string
  room: string
  ref: string
  /**
   * Raw mkit object bytes — a commit (from `commit_encode_and_sign`) or a
   * remix (from `remix_encode_and_sign`). PutObject is content-addressed,
   * so the same push path stores either kind.
   */
  commitBytes: Uint8Array
  commitHash: string
  message: string
  /** Parent the object was built on — the CAS expected id (empty for the first object on the ref). */
  parentHash: string
  /** `'commit'` (default) or `'remix'` — tags the recorded log entry. */
  kind?: 'commit' | 'remix'
  /** For a remix push: the upstream commit(s) it forks from (for the log badge). */
  sources?: RemixSourceEntry[]
}

/**
 * Build the log entry recorded for a locally-originated push, SHAPE-IDENTICAL
 * to what a server ref-walk produces in {@link decodeLogObject}. We decode the
 * commit/remix bytes we already hold so `authorPubkey` (signer), `kind`,
 * `sources` and `createdAt` (ISO from the object's unix-seconds timestamp) all
 * match a walked entry exactly — so the optimistic entry we prepend renders
 * identically to the authoritative one and the later reconcile is a no-op for
 * our own commit. Falls back to args-derived fields if the bytes don't decode
 * (e.g. a test/mock that passes opaque bytes), so the entry is always usable.
 */
export function buildPushLogEntry(args: PushArgs): CommitLogEntry {
  const decoded = decodeLogObject(args.api, args.commitBytes, args.commitHash, args.ref)
  if (decoded) {
    // Prefer the caller's explicit kind/sources/message (the UI's intent),
    // but take signer + timestamp from the signed bytes for walk-parity.
    return {
      ...decoded.entry,
      message: args.message,
      kind: args.kind ?? decoded.entry.kind ?? 'commit',
      ...(args.sources ? { sources: args.sources } : {}),
    }
  }
  // Fallback: derive the author from the in-memory seed; stamp "now" (seconds,
  // rendered ISO) to stay consistent with the walked `createdAt` format.
  const authorPubkey = bytesToHex(args.api.ed25519_pubkey_from_seed(hexToBytes(args.seedHex)))
  return {
    hash: args.commitHash,
    message: args.message,
    authorPubkey,
    ref: args.ref,
    createdAt: new Date(Math.floor(Date.now() / 1000) * 1000).toISOString(),
    kind: args.kind ?? 'commit',
    ...(args.sources ? { sources: args.sources } : {}),
  }
}

/**
 * Mutation options for {@link usePushCommit}, factored out so the optimistic
 * lifecycle (onMutate prepend → onError rollback → onSettled reconcile) is
 * unit-testable against a real QueryClient + MutationObserver without React.
 *
 * The backend is an EXPLICIT parameter (no module global): the mutation writes
 * through exactly the instance passed in — directly testable by injecting a mock.
 */
export function pushCommitMutationOptions(qc: ReturnType<typeof useQueryClient>, backend: RepoBackend) {
  return {
    mutationFn: async (args: PushArgs) => {
      await backend.putObject(args.room, args.commitHash, args.commitBytes)

      const expectation: RefExpectation = args.parentHash ? 'MATCH' : 'MISSING'
      await backend.updateRef(args.room, args.ref, args.commitHash, expectation, args.parentHash || undefined)

      const entry = buildPushLogEntry(args)
      if (backend instanceof MockRepoBackend || backend instanceof WasmRepoBackend) {
        backend.recordCommit(args.room, entry)
      }
      return entry
    },
    // OPTIMISTIC PREPEND: show the user's own commit instantly. Cancel any
    // in-flight log fetch (so a slow walk can't clobber our optimistic value),
    // snapshot the current log for rollback, and prepend the new entry built
    // from the bytes we already hold.
    onMutate: async (args: PushArgs) => {
      const logKey = repoKeys.log(args.room, args.ref)
      await qc.cancelQueries({ queryKey: logKey })
      const previous = qc.getQueryData<CommitLogEntry[]>(logKey)
      const entry = buildPushLogEntry(args)
      qc.setQueryData<CommitLogEntry[]>(logKey, (prev) => {
        const list = prev ?? []
        if (list.some((e) => e.hash === entry.hash)) return list // already present — no dupe
        return [entry, ...list]
      })
      return { previous, logKey }
    },
    // ROLLBACK on a rejected push (e.g. CAS conflict) — restore the snapshot.
    onError: (
      _err: unknown,
      _args: PushArgs,
      context: { previous: CommitLogEntry[] | undefined; logKey: readonly unknown[] } | undefined,
    ) => {
      if (context) qc.setQueryData(context.logKey, context.previous)
    },
    // RECONCILE with the server regardless of outcome: invalidate ref + log +
    // refs so the authoritative walk corrects any divergence (the object cache
    // + incremental walk make this cheap — only new objects are fetched).
    onSettled: (_entry: CommitLogEntry | undefined, _err: unknown, args: PushArgs) => {
      void qc.invalidateQueries({ queryKey: repoKeys.ref(args.room, args.ref) })
      void qc.invalidateQueries({ queryKey: repoKeys.log(args.room, args.ref) })
      // A first push to a new ref makes a new branch appear in the panel.
      void qc.invalidateQueries({ queryKey: ['repo', args.room, 'refs'] })
    },
  }
}

/**
 * Push a signed commit: PutObject (idempotent), then UpdateRef with an in-message
 * CAS expectation (§3 step 5). First commit (no parent) → `MISSING`; otherwise
 * `MATCH` on the parent. A failed precondition surfaces as `CasConflictError`
 * for the caller's fetch→re-parent→re-sign retry loop (§4).
 *
 * The signed-write envelope is NOT built here: each backend owns signing. The
 * `WasmRepoBackend` signs inside its sign-callback over the EXACT serialized
 * protobuf body the transport sends (so `X-Digest` matches the server); the mock
 * verifies the signing path in its own tests. This mutation only orchestrates
 * the two calls and records the commit-log entry.
 */
export function usePushCommit() {
  const qc = useQueryClient()
  const backend = useRepoBackend()
  // In practice push is only reachable once unlocked (backend present). If a
  // null backend ever reaches here, the mutation rejects with a clear typed
  // error rather than dereferencing null. `useMutation` is called
  // unconditionally (rules of hooks); only the options differ.
  const options = backend
    ? pushCommitMutationOptions(qc, backend)
    : { mutationFn: (_args: PushArgs) => Promise.reject<CommitLogEntry>(new BackendNotReadyError()) }
  return useMutation(options)
}

/**
 * Subscribe to live ref updates (WatchRefs server-stream) for a room and
 * invalidate the affected queries (§5) — turns a peer's push into a refetch so
 * the log updates within a frame.
 */
export function useRepoEvents(room: string, prefix = ''): void {
  const qc = useQueryClient()
  // Gate on the backend value from context: in worker mode it's null until the
  // wasm client loads, so the effect simply returns until a backend is present.
  // When the backend instance changes (null → mock/wasm, or mock → wasm), the
  // effect re-runs and (re-)subscribes — `backend!` is never dereferenced null.
  const backend = useRepoBackend()
  useEffect(() => {
    if (!backend) return
    return backend.watchRefs(room, prefix, (u) => {
      void qc.invalidateQueries({ queryKey: repoKeys.ref(room, u.name) })
      void qc.invalidateQueries({ queryKey: repoKeys.log(room, u.name) })
      // The advanced ref may be new (a peer created a branch) → refresh the panel.
      void qc.invalidateQueries({ queryKey: ['repo', room, 'refs'] })
    })
  }, [backend, room, prefix, qc])
}
