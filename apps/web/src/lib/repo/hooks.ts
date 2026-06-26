// React Query keys, query hooks, the push mutation (+ optimistic lifecycle),
// and the live-events subscription.
//
// Moved verbatim out of the former monolithic `repo-api.ts`; re-exported by the
// `repo-api` barrel so existing `from '../lib/repo-api'` imports keep working.

import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useCallback, useEffect, useMemo } from 'react'
import { bytesToHex, hexToBytes } from '../../components/use-mkit'
import type { MkitApi } from '../mkit'
import {
  BackendNotReadyError,
  type ChatMessageEntry,
  type CommitLogEntry,
  type FeedItem,
  type ReactionAgg,
  type ReactionEntry,
  type RefExpectation,
  type RemixSourceEntry,
  MockRepoBackend,
  type RepoBackend,
  WasmRepoBackend,
  aggregateReactions,
  decodeLogObject,
  mergeFeed,
} from './backend'
import { useRepoBackend } from './store'

export const repoKeys = {
  ref: (room: string, name: string) => ['repo', room, 'ref', name] as const,
  refs: (room: string, prefix: string) => ['repo', room, 'refs', prefix] as const,
  object: (room: string, hash: string) => ['repo', room, 'object', hash] as const,
  log: (room: string, ref: string) => ['repo', room, 'log', ref] as const,
  messages: (room: string) => ['repo', room, 'messages'] as const,
  reactions: (room: string) => ['repo', room, 'reactions'] as const,
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
   * Raw mkit object bytes — a commit (from `commit_encode_and_sign`) or a remix (from `remix_encode_and_sign`).
   * PutObject is content-addressed, so the same push path stores either kind.
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
 * Build the log entry recorded for a locally-originated push, SHAPE-IDENTICAL to what a server ref-walk produces in
 * {@link decodeLogObject}. We decode the commit/remix bytes we already hold so `authorPubkey` (signer), `kind`,
 * `sources` and `createdAt` (ISO from the object's unix-seconds timestamp) all match a walked entry exactly — so the
 * optimistic entry we prepend renders identically to the authoritative one and the later reconcile is a no-op for our
 * own commit. Falls back to args-derived fields if the bytes don't decode (e.g. a test/mock that passes opaque bytes),
 * so the entry is always usable.
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
 * Mutation options for {@link usePushCommit}, factored out so the optimistic lifecycle (onMutate prepend → onError
 * rollback → onSettled reconcile) is unit-testable against a real QueryClient + MutationObserver without React.
 *
 * The backend is an EXPLICIT parameter (no module global): the mutation writes through exactly the instance passed in —
 * directly testable by injecting a mock.
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
 * Push a signed commit: PutObject (idempotent), then UpdateRef with an in-message CAS expectation (§3 step 5). First
 * commit (no parent) → `MISSING`; otherwise `MATCH` on the parent. A failed precondition surfaces as `CasConflictError`
 * for the caller's fetch→re-parent→re-sign retry loop (§4).
 *
 * The signed-write envelope is NOT built here: each backend owns signing. The `WasmRepoBackend` signs inside its
 * sign-callback over the EXACT serialized protobuf body the transport sends (so `X-Digest` matches the server); the
 * mock verifies the signing path in its own tests. This mutation only orchestrates the two calls and records the
 * commit-log entry.
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
 * Subscribe to live ref updates (WatchRefs server-stream) for a room and invalidate the affected queries (§5) — turns a
 * peer's push into a refetch so the log updates within a frame.
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

// ---------------------------------------------------------------------------
// Lobby: chat messages + the merged (commits + chat) feed
// ---------------------------------------------------------------------------

/** Recent lobby messages (oldest-first), capped. Gated on a ready backend. */
export function useLobbyMessages(room: string) {
  const backend = useRepoBackend()
  return useQuery({
    queryKey: repoKeys.messages(room),
    queryFn: () => backend!.listMessages(room, 100),
    enabled: !!backend,
  })
}

export type PostMessageResult = { messageIdHex: string; accepted: boolean; rateLimited: boolean }

/**
 * Mutation options for {@link usePostMessage}, factored out (like {@link pushCommitMutationOptions}) so the optimistic
 * lifecycle is testable against a real QueryClient without React. The optimistic echo appends the pending message to
 * the messages cache so it shows instantly; `onSettled` invalidates so the authoritative server list (with the real id
 * + seq + the server `created_at`) replaces it. `myPubkeyHex` attributes the optimistic row to the sender; the temp id
 * keeps it distinct + rollback-able.
 */
export function postMessageMutationOptions(
  qc: ReturnType<typeof useQueryClient>,
  backend: RepoBackend,
  room: string,
  myPubkeyHex?: string,
) {
  // Remove ONLY our optimistic row (by its temp id) rather than restoring a
  // snapshot, so a peer's message that streamed in during the post isn't
  // clobbered on rollback.
  const removeOptimistic = (key: readonly unknown[], id: string) =>
    qc.setQueryData<ChatMessageEntry[]>(key, (prev) => prev?.filter((m) => m.messageIdHex !== id) ?? [])

  return {
    mutationFn: (text: string) => backend.postMessage(room, text),
    onMutate: async (text: string) => {
      const key = repoKeys.messages(room)
      await qc.cancelQueries({ queryKey: key })
      // Temp id (not a content hash) — replaced by the server's real id on the
      // post-settle refetch; `optimistic-` prefix can never collide.
      const optimisticId = `optimistic-${crypto.randomUUID()}`
      const optimistic: ChatMessageEntry = {
        messageIdHex: optimisticId,
        authorPubkeyHex: myPubkeyHex ?? '',
        text: text.trim(),
        createdAt: Date.now(),
        // Sort last (newest) until the server assigns the real seq.
        seq: Number.MAX_SAFE_INTEGER,
      }
      qc.setQueryData<ChatMessageEntry[]>(key, (prev) => [...(prev ?? []), optimistic])
      return { key, optimisticId }
    },
    onError: (_err: unknown, _text: string, context: { key: readonly unknown[]; optimisticId: string } | undefined) => {
      if (context) removeOptimistic(context.key, context.optimisticId)
    },
    // A RATE-LIMITED post resolves `{accepted:false}` rather than throwing, so
    // onError never fires — roll the optimistic echo back here too, otherwise it
    // lingers until the settle refetch and the user sees it appear then vanish.
    onSuccess: (
      result: PostMessageResult,
      _text: string,
      context: { key: readonly unknown[]; optimisticId: string } | undefined,
    ) => {
      if (context && !result.accepted) removeOptimistic(context.key, context.optimisticId)
    },
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: repoKeys.messages(room) })
    },
  }
}

/**
 * Post a signed chat message to the room. The signing identity is the author (server-verified). Optimistically echoes
 * the message into the feed, then reconciles with the server on settle (the broadcast echo also invalidates, so this
 * converges idempotently). Rejects with `BackendNotReadyError` if no backend is ready.
 */
export function usePostMessage(room: string, myPubkeyHex?: string) {
  const qc = useQueryClient()
  const backend = useRepoBackend()
  const options = backend
    ? postMessageMutationOptions(qc, backend, room, myPubkeyHex)
    : { mutationFn: (_text: string) => Promise.reject<PostMessageResult>(new BackendNotReadyError()) }
  return useMutation(options)
}

/**
 * Subscribe to the live room stream (ONE WebSocket) and invalidate the right queries: a ref advance refreshes the
 * log/refs (like {@link useRepoEvents}); a chat frame refreshes the messages query. The merged feed re-renders within a
 * frame of either a peer's commit or a peer's message.
 */
export function useLobbyEvents(room: string): void {
  const qc = useQueryClient()
  const backend = useRepoBackend()
  useEffect(() => {
    if (!backend) return
    return backend.watchRoom(room, '', {
      onRef: (u) => {
        void qc.invalidateQueries({ queryKey: repoKeys.ref(room, u.name) })
        void qc.invalidateQueries({ queryKey: repoKeys.log(room, u.name) })
        void qc.invalidateQueries({ queryKey: ['repo', room, 'refs'] })
      },
      onChat: () => {
        void qc.invalidateQueries({ queryKey: repoKeys.messages(room) })
      },
      onReaction: () => {
        void qc.invalidateQueries({ queryKey: repoKeys.reactions(room) })
      },
    })
  }, [backend, room, qc])
}

/**
 * Reactions for the room, aggregated per feed item: a `reactionsFor(targetId)`
 * lookup returning `{ emoji, count, mine }[]`. Gated on a ready backend.
 */
export function useReactions(room: string, myPubkeyHex?: string): (targetId: string) => ReactionAgg[] {
  const backend = useRepoBackend()
  const q = useQuery({
    queryKey: repoKeys.reactions(room),
    queryFn: () => backend!.listReactions(room),
    enabled: !!backend,
  })
  const byTarget = useMemo(() => aggregateReactions(q.data ?? [], myPubkeyHex), [q.data, myPubkeyHex])
  // Stable identity: only changes when the aggregation does, so callers using it
  // as an effect/memo dependency don't re-run on every render. `NO_REACTIONS` is
  // a shared frozen empty array so the "no reactions" case is referentially
  // stable too (a fresh `[]` per call would defeat downstream memoization).
  return useCallback((targetId: string) => byTarget.get(targetId) ?? NO_REACTIONS, [byTarget])
}

/** Shared empty result for feed items with no reactions — one stable reference
 * so the "no reactions" case doesn't defeat memoization. Frozen so a consumer
 * can't mutate the shared singleton (the cast-through-unknown is the compiler's
 * own escape hatch for assigning `readonly never[]` to the array type). */
const NO_REACTIONS: ReactionAgg[] = Object.freeze([]) as unknown as ReactionAgg[]

/**
 * Toggle the signing identity's emoji reaction on a feed item. Optimistically
 * flips the cached reaction list, then reconciles on settle (the broadcast echo
 * also invalidates). Rejects with `BackendNotReadyError` if no backend is ready.
 */
export function useToggleReaction(room: string, myPubkeyHex?: string) {
  const qc = useQueryClient()
  const backend = useRepoBackend()
  const key = repoKeys.reactions(room)
  const options = backend
    ? {
        mutationFn: ({ targetId, emoji }: { targetId: string; emoji: string }) =>
          backend.react(room, targetId, emoji),
        onMutate: async ({ targetId, emoji }: { targetId: string; emoji: string }) => {
          await qc.cancelQueries({ queryKey: key })
          // Optimistic toggle against my own pubkey row. Remember whether we
          // added or removed so a failure can be undone SURGICALLY (just my row)
          // rather than restoring a whole snapshot — restoring a snapshot would
          // clobber any peer reactions the live stream merged in meanwhile.
          let added = false
          if (myPubkeyHex) {
            qc.setQueryData<ReactionEntry[]>(key, (prev) => {
              const list = prev ?? []
              const i = list.findIndex(
                (r) => r.targetIdHex === targetId && r.emoji === emoji && r.authorPubkeyHex === myPubkeyHex,
              )
              if (i >= 0) return list.filter((_, j) => j !== i)
              added = true
              return [...list, { targetIdHex: targetId, emoji, authorPubkeyHex: myPubkeyHex }]
            })
          }
          return { targetId, emoji, added }
        },
        onError: (
          _e: unknown,
          _v: unknown,
          ctx: { targetId: string; emoji: string; added: boolean } | undefined,
        ) => {
          // Invert ONLY our own optimistic change, leaving peer reactions intact.
          if (!ctx || !myPubkeyHex) return
          qc.setQueryData<ReactionEntry[]>(key, (prev) => {
            const list = prev ?? []
            const isMine = (r: ReactionEntry) =>
              r.targetIdHex === ctx.targetId && r.emoji === ctx.emoji && r.authorPubkeyHex === myPubkeyHex
            if (ctx.added) return list.filter((r) => !isMine(r)) // we added → remove
            if (list.some(isMine)) return list // already back (echo raced us)
            return [...list, { targetIdHex: ctx.targetId, emoji: ctx.emoji, authorPubkeyHex: myPubkeyHex }]
          })
        },
        onSettled: () => {
          void qc.invalidateQueries({ queryKey: key })
        },
      }
    : {
        mutationFn: (_v: { targetId: string; emoji: string }) =>
          Promise.reject<{ active: boolean; count: number }>(new BackendNotReadyError()),
      }
  return useMutation(options)
}

/**
 * The merged lobby feed: the `ref` commit log + room chat, interleaved oldest-first by timestamp. Combines
 * {@link useCommitLog} and {@link useLobbyMessages}; the merge itself is the pure {@link mergeFeed}.
 */
export function useLobbyFeed(room: string, ref = 'main'): { items: FeedItem[]; isLoading: boolean; isError: boolean } {
  const log = useCommitLog(room, ref)
  const messages = useLobbyMessages(room)
  const items = useMemo(() => mergeFeed(log.data ?? [], messages.data ?? []), [log.data, messages.data])
  // `isPending` (not `isLoading`) so the gap where the backend is still null —
  // queries are `enabled:false`, which reports isLoading=false in v5 — still
  // reads as loading, not as an empty room. Only consulted when the feed is
  // empty, so a half-loaded feed with items still renders them.
  return {
    items,
    isLoading: log.isPending || messages.isPending,
    isError: log.isError || messages.isError,
  }
}
