// React Query keys, query hooks, the push mutation (+ optimistic lifecycle),
// and the live-events subscription.
//
// Moved verbatim out of the former monolithic `repo-api.ts`; re-exported by the
// `repo-api` barrel so existing `from '../lib/repo-api'` imports keep working.

import {
  type InfiniteData,
  type QueryClient,
  keepPreviousData,
  useInfiniteQuery,
  useMutation,
  useQuery,
  useQueryClient,
} from '@tanstack/react-query'
import { useCallback, useEffect, useMemo } from 'react'
import { bytesToHex, hexToBytes } from '../../components/use-mkit'
import { useIdentityStore } from '../identity-store'
import { usePresenceStore } from '../presence-store'
import { type MkitApi, mkit } from '../mkit'
import {
  BackendNotReadyError,
  type ChatMessageEntry,
  type CommitLogEntry,
  type FeedItem,
  type ReactionAgg,
  type ReactionEntry,
  type ReactionUpdate,
  type RefEntry,
  type RefExpectation,
  type RefUpdate,
  type RemixSourceEntry,
  type RoomWatchHandlers,
  MockRepoBackend,
  type RepoBackend,
  WasmRepoBackend,
  aggregateReactions,
  decodeLogObject,
  isForkRef,
  mergeFeed,
  subscribeRoom,
} from './backend'
import { useRepoBackend } from './store'

export const repoKeys = {
  ref: (room: string, name: string) => ['repo', room, 'ref', name] as const,
  refs: (room: string, prefix: string) => ['repo', room, 'refs', prefix] as const,
  object: (room: string, hash: string) => ['repo', room, 'object', hash] as const,
  log: (room: string, ref: string) => ['repo', room, 'log', ref] as const,
  messages: (room: string) => ['repo', room, 'messages'] as const,
  reactions: (room: string) => ['repo', room, 'reactions'] as const,
  /** Remix (fork) pushes observed live over the socket — see {@link useRemixes}. */
  remixes: (room: string) => ['repo', room, 'remixes'] as const,
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

export function useCommitLog(room: string, ref = 'main', limit?: number) {
  const backend = useRepoBackend()
  const qc = useQueryClient()
  // A capped walk (the lobby) gets its own cache entry so it never collides with
  // an uncapped reader of the same ref. Invalidation still matches by prefix
  // (`['repo', room, 'log', ref]`), so a push refreshes both.
  const key = limit != null ? ([...repoKeys.log(room, ref), limit] as const) : repoKeys.log(room, ref)
  return useQuery({
    queryKey: key,
    queryFn: () =>
      backend!.commitLog(room, ref, {
        ...(limit != null ? { limit } : {}),
        // Paint commits as the walk fetches them (one round-trip each) instead of
        // blocking the feed on the full chain — this clears the "Loading…" gate at
        // the FIRST commit. The final resolve overwrites with the complete list.
        onProgress: (partial) => qc.setQueryData(key, partial),
      }),
    enabled: !!backend,
    // Switching branches keeps the previous ref's list on screen during the
    // fetch (no skeleton/empty flash); replaced once the new ref's log resolves.
    placeholderData: keepPreviousData,
  })
}

/**
 * One `listRefs` page, as cached by {@link useRefs}'s `useInfiniteQuery` — the pageParam is the keyset cursor (a ref
 * name), typed `string`.
 */
export type RefsPage = { refs: RefEntry[]; nextCursor: string; total: number }

/** How many refs {@link useRefs} fetches per page — matches the panel's virtualized-scroll page granularity. */
const REFS_PAGE_SIZE = 200

/**
 * All refs in the room (optionally prefix-filtered), keyset-paginated via `useInfiniteQuery` — drives the branches
 * panel's virtualized infinite scroll.
 *
 * Returned shape (chosen for a virtualized-infinite-scroll consumer, e.g. `@tanstack/react-virtual`): - `refs`: every
 * ref loaded so far, flattened across pages in keyset order — hand straight to the virtualizer as its item list; grows
 * as `fetchNextPage` resolves more pages. - `total`: total refs matching `prefix`, from the first page (stable across
 * later pages — the count doesn't change mid-listing) — use it to size the virtualizer / show "N of total loaded"
 * without waiting for every page. - `fetchNextPage`/`hasNextPage`/`isFetchingNextPage`: passed straight through from
 * the underlying infinite query, so a virtualizer's "load more" trigger (e.g. the last rendered row becoming visible)
 * can drive pagination directly without re-deriving infinite-query state. - `isLoading`/`isError`: pass through for the
 * initial-load gate (mirrors a plain `useQuery`'s flags).
 */
export function useRefs(room: string, prefix = '') {
  const backend = useRepoBackend()
  const query = useInfiniteQuery({
    queryKey: repoKeys.refs(room, prefix),
    queryFn: ({ pageParam }) => backend!.listRefs(room, prefix, { startAfter: pageParam, pageSize: REFS_PAGE_SIZE }),
    initialPageParam: '',
    getNextPageParam: (last) => last.nextCursor || undefined,
    enabled: !!backend,
    // Keep the prior prefix's pages visible while a new prefix loads.
    placeholderData: keepPreviousData,
  })
  const refs = useMemo(() => query.data?.pages.flatMap((p) => p.refs) ?? [], [query.data])
  return {
    refs,
    total: query.data?.pages[0]?.total ?? 0,
    fetchNextPage: query.fetchNextPage,
    hasNextPage: query.hasNextPage,
    isFetchingNextPage: query.isFetchingNextPage,
    isLoading: query.isLoading,
    isError: query.isError,
  }
}

/**
 * Patch a single ref's `objectIdHex` into the cached {@link useRefs} pages (all of them — a ref name only ever appears
 * in one page, but every page is checked since the caller doesn't know which). Pure and unit-testable, in the same
 * convention as {@link applyChatFrame}/{@link applyReactionFrame}: `prev` in, next state out, no side effects.
 *
 * Returns the SAME `prev` reference (not a copy) when `u.name` isn't found in any loaded page — callers use that
 * referential equality to detect a "miss" (a ref not yet loaded, e.g. a brand-new branch) and fall back to a refetch
 * instead of silently doing nothing. Returns `prev` unchanged (still undefined) when there's no cached data yet.
 */
export function patchRefsPages(
  prev: InfiniteData<RefsPage, string> | undefined,
  u: RefUpdate,
): InfiniteData<RefsPage, string> | undefined {
  if (!prev) return prev
  let found = false
  const pages = prev.pages.map((page) => {
    const idx = page.refs.findIndex((r) => r.name === u.name)
    if (idx === -1) return page
    found = true
    const refs = page.refs.slice()
    refs[idx] = { name: u.name, objectIdHex: u.objectIdHex }
    return { ...page, refs }
  })
  return found ? { ...prev, pages } : prev
}

/**
 * Coalesces repeated calls for the same key into one trailing invocation ~`waitMs` after the LAST call — but caps the
 * delay at `maxWaitMs` after the FIRST call in a burst, so a continuous stream of calls (e.g. a bot pushing every
 * 15-30s, each resetting the trailing timer before it fires) still flushes periodically instead of postponing forever.
 * A plain class (not a closure) so a test can hold its own instance and drive it with fake timers.
 *
 * Used to coalesce the `['repo', room, 'refs']` full-list invalidation that a live ref-advance falls back to when
 * {@link patchRefsPages} can't find the ref in cache — see `useRepoEvents`/`useLobbyEvents`'s `onRef` handlers below.
 * Keyed per room so unrelated rooms never coalesce into each other.
 */
export class TrailingDebouncer {
  private pending = new Map<
    string,
    { trailing: ReturnType<typeof setTimeout>; maxWait: ReturnType<typeof setTimeout> }
  >()

  schedule(key: string, fn: () => void, waitMs = 10_000, maxWaitMs = 10_000): void {
    const existing = this.pending.get(key)
    if (existing) clearTimeout(existing.trailing)
    const fire = () => {
      const entry = this.pending.get(key)
      if (entry) {
        clearTimeout(entry.trailing)
        clearTimeout(entry.maxWait)
      }
      this.pending.delete(key)
      fn()
    }
    const trailing = setTimeout(fire, waitMs)
    // Only armed once per burst — NOT reset on every call — so it fires
    // `maxWaitMs` after the first call regardless of how many more arrive.
    const maxWait = existing?.maxWait ?? setTimeout(fire, maxWaitMs)
    this.pending.set(key, { trailing, maxWait })
  }

  /** Drop any pending invocation for `key` without firing it (e.g. on unmount). */
  cancel(key: string): void {
    const existing = this.pending.get(key)
    if (!existing) return
    clearTimeout(existing.trailing)
    clearTimeout(existing.maxWait)
    this.pending.delete(key)
  }
}

/** Shared instance behind the debounced refs-list invalidation in both live-event hooks below. */
const refsInvalidateDebouncer = new TrailingDebouncer()

/** Debounced fallback for a `['repo', room, 'refs']` invalidation — see {@link TrailingDebouncer}. */
function scheduleRefsInvalidate(qc: QueryClient, room: string): void {
  refsInvalidateDebouncer.schedule(room, () => {
    void qc.invalidateQueries({ queryKey: ['repo', room, 'refs'] })
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
  // wasm client loads, so the effect returns until a backend is present.
  // When the backend instance changes (null → mock/wasm, or mock → wasm), the
  // effect re-runs and (re-)subscribes — `backend!` is never dereferenced null.
  const backend = useRepoBackend()
  // The current key (a member when unlocked, else a signed-out viewer). Changing
  // it re-runs the effect → the socket reconnects with the new `?pubkey`, so
  // lock/unlock moves you between "online" and "viewer" in everyone's roster.
  const myPubkey = useIdentityStore((s) => (s.unlocked ? s.ed25519PubkeyHex : null))
  const setPresence = usePresenceStore((s) => s.set)
  useEffect(() => {
    if (!backend) return
    return backend.watchRoom(
      room,
      prefix,
      {
        onRef: (u) => {
          void qc.invalidateQueries({ queryKey: repoKeys.ref(room, u.name) })
          void qc.invalidateQueries({ queryKey: repoKeys.log(room, u.name) })
          // Patch the advanced ref straight into the cached refs list when it's
          // already loaded (the common case) — O(1), no refetch. Only an
          // unrecognized ref (e.g. a peer created a brand-new branch) falls back
          // to a full list refetch, and even that is debounced so a steady
          // stream of advances on refs we DO have cached doesn't force a
          // continuous unbounded refetch (see `TrailingDebouncer`).
          let found = false
          qc.setQueryData<InfiniteData<RefsPage, string>>(repoKeys.refs(room, prefix), (prev) => {
            const next = patchRefsPages(prev, u)
            found = next !== prev
            return next
          })
          if (!found) scheduleRefsInvalidate(qc, room)
        },
        // Live "who's online" roster → the presence store the panel reads.
        onPresence: (p) => setPresence(room, p),
      },
      myPubkey,
    )
  }, [backend, room, prefix, qc, myPubkey, setPresence])
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
 * Apply a live chat frame to the cached message list (newest appended), deduped by content-addressed id so our own echo
 * or a replay is idempotent. Also drops our optimistic placeholder for the SAME (author, text) that this server echo
 * now supersedes, so the poster never sees a transient duplicate.
 */
export function applyChatFrame(prev: ChatMessageEntry[] | undefined, m: ChatMessageEntry): ChatMessageEntry[] {
  const list = prev ?? []
  if (list.some((x) => x.messageIdHex === m.messageIdHex)) return list
  const deopt = list.filter(
    (x) => !(x.messageIdHex.startsWith('optimistic-') && x.authorPubkeyHex === m.authorPubkeyHex && x.text === m.text),
  )
  return [...deopt, m]
}

/**
 * Apply a live reaction toggle to the cached reaction rows: add the (target, emoji, author) row when active, drop it
 * when inactive. Idempotent — a repeated add/remove is a no-op.
 */
export function applyReactionFrame(prev: ReactionEntry[] | undefined, r: ReactionUpdate): ReactionEntry[] {
  const list = prev ?? []
  const matches = (x: ReactionEntry) =>
    x.targetIdHex === r.targetIdHex && x.emoji === r.emoji && x.authorPubkeyHex === r.authorPubkeyHex
  if (r.active)
    return list.some(matches)
      ? list
      : [...list, { targetIdHex: r.targetIdHex, emoji: r.emoji, authorPubkeyHex: r.authorPubkeyHex }]
  return list.filter((x) => !matches(x))
}

/** Cap on {@link repoKeys.remixes}' cache — live-only (no historical backfill), so this just bounds memory growth. */
const REMIX_FEED_LIMIT = 100

/**
 * Resolve a live fork-ref update into a decoded {@link CommitLogEntry} for the feed: fetches the remix object's raw
 * bytes and decodes via {@link decodeLogObject} (shared with the commit-log walk, so `kind`/`sources` come out the same
 * shape). Returns `null` if the object hasn't landed yet or fails to decode — the caller just drops the frame rather
 * than showing a broken row.
 */
async function resolveRemixEntry(backend: RepoBackend, room: string, u: RefUpdate): Promise<CommitLogEntry | null> {
  const bytes = await backend.getObject(room, u.objectIdHex)
  if (!bytes) return null
  const api = await mkit()
  return decodeLogObject(api, bytes, u.objectIdHex, u.name)?.entry ?? null
}

/** Prepend a newly-resolved remix to the cached list, deduped by hash and capped to {@link REMIX_FEED_LIMIT}. */
export function prependRemix(prev: CommitLogEntry[] | undefined, entry: CommitLogEntry): CommitLogEntry[] {
  const list = prev ?? []
  if (list.some((x) => x.hash === entry.hash)) return list
  return [entry, ...list].slice(0, REMIX_FEED_LIMIT)
}

/**
 * Subscribe to the live room stream (ONE WebSocket) and update the cache. Chat and reaction frames carry their FULL
 * payload, so they're applied straight to the cache — O(1), no refetch round-trip per event. Ref/commit frames carry
 * only id+author, so they trigger the (incremental) log re-walk.
 *
 * In worker mode the socket is opened off the STATIC backend URL on mount, in PARALLEL with the wasm load — the live
 * stream needs no wasm, so it's no longer serialized behind backend readiness (which delayed first delivery ~800ms). In
 * mock/offline mode it drives off the in-memory backend's watcher.
 */
export function useLobbyEvents(room: string): void {
  const qc = useQueryClient()
  const backend = useRepoBackend()
  const backendUrl = import.meta.env.VITE_REPO_BACKEND_URL as string | undefined
  // Attribute this connection to the current key (a member when unlocked, else a
  // signed-out viewer). Changing it reconnects the socket with/without `?pubkey`,
  // so lock/unlock moves the user between "online" and "viewer" in the roster.
  const myPubkey = useIdentityStore((s) => (s.unlocked ? s.ed25519PubkeyHex : null))
  const setPresence = usePresenceStore((s) => s.set)

  const handlers: RoomWatchHandlers = useMemo(
    () => ({
      onChat: (m) => qc.setQueryData<ChatMessageEntry[]>(repoKeys.messages(room), (prev) => applyChatFrame(prev, m)),
      onReaction: (r) =>
        qc.setQueryData<ReactionEntry[]>(repoKeys.reactions(room), (prev) => applyReactionFrame(prev, r)),
      onRef: (u) => {
        // A fork push lands on a `forks/<...>` ref, never `main` — the lobby's
        // commit-log walk only follows `main`, so a fork ref would otherwise never
        // surface anywhere but the refs/branches panel. Resolve it directly and
        // patch it into the remix feed cache instead of invalidating the log.
        if (isForkRef(u.name)) {
          if (backend) {
            void resolveRemixEntry(backend, room, u).then((entry) => {
              if (!entry) return
              qc.setQueryData(repoKeys.remixes(room), (prev: CommitLogEntry[] | undefined) => prependRemix(prev, entry))
            })
          }
          void qc.invalidateQueries({ queryKey: repoKeys.ref(room, u.name) })
          void qc.invalidateQueries({ queryKey: ['repo', room, 'refs'] })
          return
        }
        void qc.invalidateQueries({ queryKey: repoKeys.ref(room, u.name) })
        // Prefix match covers both the uncapped log key and the lobby's capped one.
        void qc.invalidateQueries({ queryKey: repoKeys.log(room, u.name) })
        // Same patch-first, debounced-fallback approach as `useRepoEvents` above
        // — the lobby always watches the unfiltered ('') prefix.
        let found = false
        qc.setQueryData<InfiniteData<RefsPage, string>>(repoKeys.refs(room, ''), (prev) => {
          const next = patchRefsPages(prev, u)
          found = next !== prev
          return next
        })
        if (!found) scheduleRefsInvalidate(qc, room)
      },
      // Live "who's online" roster → the presence store, so the lobby can narrate
      // joins/leaves and show viewer-vs-participant state.
      onPresence: (p) => setPresence(room, p),
    }),
    [qc, room, setPresence, backend],
  )

  // Worker mode: open the socket immediately off the static URL (no wasm dep).
  useEffect(() => {
    if (!backendUrl) return
    return subscribeRoom(backendUrl, room, '', handlers, myPubkey)
  }, [backendUrl, room, handlers, myPubkey])

  // Mock/offline mode: drive updates off the in-memory backend's watcher.
  useEffect(() => {
    if (backendUrl || !backend) return
    return backend.watchRoom(room, '', handlers, myPubkey)
  }, [backendUrl, backend, room, handlers, myPubkey])
}

/**
 * Reactions for the room, aggregated per feed item: a `reactionsFor(targetId)` lookup returning `{ emoji, count, mine
 * }[]`. Gated on a ready backend.
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

/**
 * Shared empty result for feed items with no reactions — one stable reference so the "no reactions" case doesn't defeat
 * memoization. Frozen so a consumer can't mutate the shared singleton (the cast-through-unknown is the compiler's own
 * escape hatch for assigning `readonly never[]` to the array type).
 */
const NO_REACTIONS: ReactionAgg[] = Object.freeze([]) as unknown as ReactionAgg[]

/**
 * Toggle the signing identity's emoji reaction on a feed item. Optimistically flips the cached reaction list, then
 * reconciles on settle (the broadcast echo also invalidates). Rejects with `BackendNotReadyError` if no backend is
 * ready.
 */
export function useToggleReaction(room: string, myPubkeyHex?: string) {
  const qc = useQueryClient()
  const backend = useRepoBackend()
  const key = repoKeys.reactions(room)
  const options = backend
    ? {
        mutationFn: ({ targetId, emoji }: { targetId: string; emoji: string }) => backend.react(room, targetId, emoji),
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
        onError: (_e: unknown, _v: unknown, ctx: { targetId: string; emoji: string; added: boolean } | undefined) => {
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
/**
 * How many commits the front-page lobby walks. It shows RECENT activity, not the whole history, so a cold load is
 * bounded to this many sequential object round-trips instead of up to WALK_CAP (100).
 */
const LOBBY_LOG_LIMIT = 30

/**
 * Remix (fork) pushes seen live over the socket, newest-first-prepended (see {@link prependRemix}). No historical
 * backfill — this is a pure cache read populated entirely by {@link useLobbyEvents}'s `onRef` handler, since forks live
 * on `forks/*` refs the commit-log walk never follows. Always enabled (no network fetch, no backend dependency).
 */
export function useRemixes(room: string) {
  return useQuery({
    queryKey: repoKeys.remixes(room),
    queryFn: (): CommitLogEntry[] => [],
    initialData: [] as CommitLogEntry[],
    staleTime: Number.POSITIVE_INFINITY,
  })
}

export function useLobbyFeed(
  room: string,
  ref = 'main',
  limit = LOBBY_LOG_LIMIT,
): { items: FeedItem[]; isLoading: boolean; isError: boolean } {
  const log = useCommitLog(room, ref, limit)
  const messages = useLobbyMessages(room)
  const remixes = useRemixes(room)
  const items = useMemo(
    () => mergeFeed([...(log.data ?? []), ...remixes.data], messages.data ?? []),
    [log.data, messages.data, remixes.data],
  )
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
