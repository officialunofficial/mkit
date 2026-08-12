'use client'

// Repo views for the multiplayer demo: the branches panel (`RefsPanel`, left
// column) and the live commit log + commit/remix detail (`RepoLog`, right column
// under Compose), plus log rows and the loading skeleton.

import * as ScrollArea from '@radix-ui/react-scroll-area'
import { useVirtualizer } from '@tanstack/react-virtual'
import { useEffect, useMemo, useRef as useReactRef, useState } from 'react'
import {
  CasConflictError,
  type CommitLogEntry,
  IdentityLockedError,
  decodeLogObject,
  isForkRef,
  useCommitLog,
  useObject,
  useRef,
  useRefs,
} from '../../lib/repo-api'
import { Field, FieldList, HashChip } from '../result-panel'
import { Tooltip } from '../tooltip'
import { useMkit } from '../use-mkit'
import { useDerive } from './compose'
import { PlayerLabel } from './player-label'
import { BTN, CAS_CONFLICT_COPY, IDENTITY_LOCKED_COPY, errMsg } from './shared'

/**
 * The two ways to build on a commit, shared down to the rows that trigger them: • Remix — a first-class remix object
 * that RECORDS the source (attribution carried in the object). • Branch — a plain new branch pointing AT the commit
 * (git `branch`), NO attribution.
 */
type DeriveActions = {
  onRemix: (commit: string) => void
  onBranch: (commit: string) => void
  can: boolean
  pending: boolean
}

/**
 * "Time ago" relative to now (a commit log is read for recency, not wall-clock) — "just now" / "5m ago" / "3h ago" /
 * "2d ago", falling back to a short date past a week. Empty for an unparseable `iso`. Pair with {@link fullTime} on a
 * `title` for the exact moment on hover.
 */
function timeAgo(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return ''
  const sec = Math.max(0, Math.floor((Date.now() - d.getTime()) / 1000))
  if (sec < 5) return 'just now'
  if (sec < 60) return `${sec}s ago`
  const min = Math.floor(sec / 60)
  if (min < 60) return `${min}m ago`
  const hr = Math.floor(min / 60)
  if (hr < 24) return `${hr}h ago`
  const day = Math.floor(hr / 24)
  if (day < 7) return `${day}d ago`
  const sameYear = d.getFullYear() === new Date().getFullYear()
  return d.toLocaleDateString(
    undefined,
    sameYear ? { month: 'short', day: 'numeric' } : { month: 'short', day: 'numeric', year: 'numeric' },
  )
}

/** Full absolute date+time for a `title` hover — empty for an unparseable `iso`. */
function fullTime(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return ''
  return d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'medium' })
}

/**
 * The selected branch's history (right column, under Compose): the live commit log, and — when a commit row is clicked
 * — a commit/remix-detail view whose parents (and, for a remix, its upstream sources) are themselves links. The
 * branches panel lives separately in the left column ({@link RefsPanel}). Navigation is component state, no router
 * change.
 */
export function RepoLog({
  api,
  room,
  myPubkey,
  seedHex,
  selectedRef,
  onSelectRef,
  selectedCommit,
  onSelectCommit,
}: {
  api: ReturnType<typeof useMkit>
  room: string
  myPubkey: string | null
  seedHex: string | null
  selectedRef: string
  onSelectRef: (r: string) => void
  selectedCommit: string | null
  onSelectCommit: (h: string | null) => void
}) {
  const { remix, branch, pending, error, ready } = useDerive(api, room, seedHex)
  const [status, setStatus] = useState<string | null>(null)

  // Run a remix (with attribution) or a branch-off (without) on `upstreamCommit`,
  // then select the new branch so it lands visibly in the panel + log.
  const run = async (mode: 'remix' | 'branch', upstreamCommit: string) => {
    setStatus(null)
    try {
      const ref = mode === 'remix' ? await remix(upstreamCommit) : await branch(upstreamCommit)
      if (!ref) return
      onSelectRef(ref)
      onSelectCommit(null)
      setStatus(mode === 'remix' ? `Remixed → ${ref}` : `Branched off → ${ref}`)
    } catch (e) {
      setStatus(
        e instanceof CasConflictError
          ? CAS_CONFLICT_COPY
          : e instanceof IdentityLockedError
            ? IDENTITY_LOCKED_COPY
            : errMsg(e),
      )
    }
  }

  // Both need a seed (to sign) and a backend (to read head + push).
  const derive: DeriveActions = {
    onRemix: (c) => void run('remix', c),
    onBranch: (c) => void run('branch', c),
    can: !!seedHex && ready,
    pending,
  }

  return (
    <div className='space-y-3'>
      {selectedCommit ? (
        <CommitDetail
          room={room}
          hash={selectedCommit}
          onSelectCommit={onSelectCommit}
          onClose={() => onSelectCommit(null)}
          derive={derive}
        />
      ) : (
        <LiveLog
          room={room}
          selectedRef={selectedRef}
          myPubkey={myPubkey}
          onSelectCommit={onSelectCommit}
          derive={derive}
        />
      )}
      {status ? <p className='text-sm text-muted'>{status}</p> : null}
      {error && !status ? <p className='text-sm text-amber-700 dark:text-amber-400'>{errMsg(error)}</p> : null}
    </div>
  )
}

/**
 * Loading placeholder for the refs / commit-log lists. Shown while the first fetch is in flight (`isPending`) so a cold
 * load reads as "loading" rather than an empty "no commits / no refs" state — the bug where a freshly-opened room
 * showed an empty log under a populated `main` ref before the walk resolved.
 */
function SkeletonRows({ rows = 5 }: { rows?: number }) {
  return (
    <ul className='divide-y divide-dashed divide-hairline border-y border-dashed border-hairline' aria-hidden='true'>
      {Array.from({ length: rows }).map((_, i) => (
        // biome-ignore lint/suspicious/noArrayIndexKey: static placeholder rows, no identity
        <li key={i} className='flex items-center gap-3 py-2.5'>
          <span className='h-3.5 w-3.5 shrink-0 animate-pulse rounded-sm bg-fg/10' />
          <span className='h-3 animate-pulse rounded bg-fg/10' style={{ width: `${8 + ((i * 7) % 9)}rem` }} />
          <span className='ml-auto h-3 w-16 shrink-0 animate-pulse rounded bg-fg/10' />
        </li>
      ))}
    </ul>
  )
}

/**
 * Estimated row height (px) for the virtualized branch list — measured off the rendered row (py-2.5 padding + a
 * text-sm/icon-14 line), rounded up a touch so `useVirtualizer` never undershoots real layout.
 */
const REF_ROW_HEIGHT = 44

/**
 * How close (in loaded rows) the last virtual row must get to the end of `entries` before {@link RefsPanel} fetches the
 * next page — small enough to stay ahead of a fast scroll without over-fetching.
 */
const REFS_FETCH_THRESHOLD = 5

/**
 * One branch row's contents — shared between the pinned `main` row and every virtualized row so the two never drift
 * apart visually. `main` never fork-matches (`isForkRef` is always false for it), so the caller doesn't need to guard.
 */
function RefRow({ r, active, onSelect }: { r: RefEntryLike; active: boolean; onSelect: () => void }) {
  return (
    <button
      type='button'
      onClick={onSelect}
      aria-pressed={active}
      className={`flex h-full w-full items-center gap-3 py-2.5 text-left transition-colors ${
        active ? 'text-fg' : 'text-muted hover:text-fg'
      }`}
    >
      <HashChip hash={r.objectIdHex} size={14} />
      <span className={`truncate font-mono text-sm ${active ? 'font-semibold' : 'font-medium'}`}>{r.name}</span>
      {isForkRef(r.name) ? (
        <span
          className='shrink-0 rounded bg-purple-100 px-1.5 text-xs text-purple-700 dark:bg-purple-950 dark:text-purple-300'
          title='A remix branch — its head records the commit it derived from (attribution).'
        >
          remix
        </span>
      ) : null}
      {active ? <span className='shrink-0 text-xs text-blue-600 dark:text-blue-400'>selected</span> : null}
      <code className='ml-auto shrink-0 font-mono text-xs text-muted'>{r.objectIdHex.slice(0, 6)}</code>
    </button>
  )
}

type RefEntryLike = { name: string; objectIdHex: string }

/**
 * All branches in the repo (left column). Each row selects the branch the log/detail view follows.
 *
 * `main` is pinned in its own row ABOVE the virtualized/paged list (sourced from {@link useRef}, the same
 * head-of-`main` query `LiveLog` already runs) and filtered out of the paged rows below it — alphabetically `main`
 * would otherwise sort after every `b/*`/`forks/*` prefix and sit unreachably far down a 30k-row list. Everything else
 * renders through `@tanstack/react-virtual` inside the Radix `ScrollArea` (same idiom as {@link LiveLog}'s commit list)
 * so the DOM only ever holds the rows actually on screen, not all of them — the fix for the mobile Safari freeze a full
 * `30,342`-node `<ul>` caused in production. Server keyset order is preserved (no client re-sort) so paging in more
 * rows never reshuffles what's already rendered.
 */
export function RefsPanel({
  room,
  useMock,
  selectedRef,
  onSelectRef,
}: {
  room: string
  useMock: boolean
  selectedRef: string
  onSelectRef: (r: string) => void
}) {
  const refsQuery = useRefs(room)
  const mainHead = useRef(room, 'main')
  const scrollRef = useReactRef<HTMLDivElement>(null)

  // Server keyset order, `main` filtered out (it's rendered pinned, above).
  const entries = useMemo(() => refsQuery.refs.filter((r) => r.name !== 'main'), [refsQuery.refs])

  const virtualizer = useVirtualizer({
    count: entries.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => REF_ROW_HEIGHT,
    overscan: 8,
    getItemKey: (index) => entries[index]?.name ?? index,
  })
  const virtualItems = virtualizer.getVirtualItems()

  // Fetch the next page once the last virtualized row gets within
  // `REFS_FETCH_THRESHOLD` of the loaded list — keeps scrolling ahead of the
  // fetch instead of hitting a dead stop at the end of each page.
  const lastIndex = virtualItems.at(-1)?.index ?? -1
  const { hasNextPage, isFetchingNextPage, fetchNextPage } = refsQuery
  useEffect(() => {
    if (hasNextPage && !isFetchingNextPage && lastIndex >= entries.length - REFS_FETCH_THRESHOLD) {
      fetchNextPage()
    }
  }, [lastIndex, entries.length, hasNextPage, isFetchingNextPage, fetchNextPage])

  // Show the skeleton while the first page is loading (gated-pending OR no
  // backend yet) — so a populated room never flashes its empty state before
  // the first page resolves. Only render the empty copy once the query has
  // settled with genuinely zero refs (main included).
  const showSkeleton = refsQuery.isLoading || mainHead.isLoading
  const hasMain = !!mainHead.data
  const total = refsQuery.total > 0 ? refsQuery.total : entries.length + (hasMain ? 1 : 0)

  return (
    <section className='space-y-2'>
      <div className='flex items-baseline justify-between'>
        <h2 className='text-sm font-semibold'>
          Branches
          {!showSkeleton ? <span className='ml-1.5 font-normal text-muted'>· {total.toLocaleString()}</span> : null}
        </h2>
        <span className='font-mono text-xs text-muted'>{useMock ? 'mock backend' : 'worker'}</span>
      </div>
      {showSkeleton ? (
        <SkeletonRows rows={1} />
      ) : !hasMain && entries.length === 0 ? (
        <p className='text-sm text-muted'>No branches yet. Push a commit to create one.</p>
      ) : (
        <ScrollArea.Root type='auto' className='relative max-h-80 overflow-hidden'>
          <ScrollArea.Viewport
            ref={scrollRef}
            className='h-full max-h-80 w-full border-y border-dashed border-hairline'
          >
            {/* `main` is pinned OUTSIDE the virtualized region — it's a single
                stable row, not worth virtualizing, and needs to stay visible
                without scrolling. */}
            {hasMain ? (
              <ul className={entries.length > 0 ? 'border-b border-dashed border-hairline' : ''}>
                <li>
                  <RefRow
                    r={{ name: 'main', objectIdHex: mainHead.data ?? '' }}
                    active={selectedRef === 'main'}
                    onSelect={() => onSelectRef('main')}
                  />
                </li>
              </ul>
            ) : null}
            <div style={{ height: virtualizer.getTotalSize(), position: 'relative', width: '100%' }}>
              {virtualItems.map((vrow) => {
                const r = entries[vrow.index]
                if (!r) return null
                const active = r.name === selectedRef
                const isLast = vrow.index === entries.length - 1
                return (
                  <div
                    key={vrow.key}
                    data-index={vrow.index}
                    ref={virtualizer.measureElement}
                    className={isLast ? '' : 'border-b border-dashed border-hairline'}
                    style={{
                      position: 'absolute',
                      top: 0,
                      left: 0,
                      width: '100%',
                      height: vrow.size,
                      transform: `translateY(${vrow.start}px)`,
                    }}
                  >
                    <RefRow r={r} active={active} onSelect={() => onSelectRef(r.name)} />
                  </div>
                )
              })}
            </div>
            {isFetchingNextPage ? <p className='py-2 text-center text-xs text-muted'>loading more…</p> : null}
          </ScrollArea.Viewport>
          <ScrollArea.Scrollbar
            orientation='vertical'
            className='flex w-1.5 touch-none select-none p-px transition-opacity data-[state=hidden]:opacity-0'
          >
            <ScrollArea.Thumb className='flex-1 rounded-full bg-muted/40 hover:bg-muted/60' />
          </ScrollArea.Scrollbar>
        </ScrollArea.Root>
      )}
    </section>
  )
}

/**
 * A single dropdown over every ref (branches + forks). The trigger shows the active ref, so the panel stays one line
 * and the commit log gets the room.
 */
function LiveLog({
  room,
  selectedRef,
  myPubkey,
  onSelectCommit,
  derive,
}: {
  room: string
  selectedRef: string
  myPubkey: string | null
  onSelectCommit: (h: string) => void
  derive: DeriveActions
}) {
  const log = useCommitLog(room, selectedRef)
  const head = useRef(room, selectedRef)
  // Newest on top, oldest on bottom — sort by the commit timestamp so the order
  // always matches the timestamps shown on each row.
  const entries = (log.data ?? []).toSorted((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt))
  // Same skeleton rule as the refs panel: loading, or refetching with nothing to
  // show yet. Keeps a populated ref from flashing "No commits" before the walk.
  const showSkeleton = log.isPending || (log.isFetching && entries.length === 0)

  return (
    <section className='space-y-3'>
      <div className='flex items-baseline justify-between'>
        <h2 className='text-sm font-semibold'>
          {isForkRef(selectedRef) ? 'Remix log' : 'Commit log'} · “{selectedRef}”
          {entries.length > 0 ? <span className='ml-1.5 font-normal text-muted'>{entries.length}</span> : null}
        </h2>
        <span className='font-mono text-xs text-muted'>
          {/* Show "head …" while the head is loading/refetching; only show "none" once
              the query has settled with no head. */}
          head {head.isPending || head.isFetching ? '…' : head.data ? head.data.slice(0, 6) : 'none'}
        </span>
      </div>
      {showSkeleton ? (
        <SkeletonRows rows={5} />
      ) : entries.length === 0 ? (
        <p className='text-sm text-muted'>No commits on this branch yet. Push one above.</p>
      ) : (
        // Bound the log so a long history scrolls inside the panel instead of
        // growing the whole page. Radix ScrollArea gives a consistent, themeable
        // scrollbar across browsers.
        <ScrollArea.Root type='auto' className='relative max-h-[30rem] overflow-hidden'>
          <ScrollArea.Viewport className='h-full max-h-[30rem] w-full'>
            <ul className='divide-y divide-dashed divide-hairline border-y border-dashed border-hairline'>
              {entries.map((e) => (
                <LogRow
                  key={e.hash}
                  entry={e}
                  mine={!!myPubkey && e.authorPubkey === myPubkey}
                  onSelect={() => onSelectCommit(e.hash)}
                  derive={derive}
                />
              ))}
            </ul>
          </ScrollArea.Viewport>
          <ScrollArea.Scrollbar
            orientation='vertical'
            className='flex w-1.5 touch-none select-none p-px transition-opacity data-[state=hidden]:opacity-0'
          >
            <ScrollArea.Thumb className='flex-1 rounded-full bg-muted/40 hover:bg-muted/60' />
          </ScrollArea.Scrollbar>
        </ScrollArea.Root>
      )}
    </section>
  )
}

function LogRow({
  entry,
  mine,
  onSelect,
  derive,
}: {
  entry: CommitLogEntry
  mine: boolean
  onSelect: () => void
  derive: DeriveActions
}) {
  const isRemix = entry.kind === 'remix'
  return (
    <li className='flex items-start gap-2 py-2.5'>
      <button
        type='button'
        onClick={onSelect}
        className='flex min-w-0 flex-1 items-start gap-3 text-left transition-colors hover:text-fg'
      >
        <HashChip hash={entry.hash} size={14} />
        <div className='min-w-0 flex-1'>
          <div className='flex items-baseline gap-2'>
            <span className='truncate text-sm font-medium'>{entry.message}</span>
            {isRemix ? (
              <span className='shrink-0 rounded bg-purple-100 px-1.5 text-xs text-purple-700 dark:bg-purple-950 dark:text-purple-300'>
                remix
              </span>
            ) : null}
            {mine ? <span className='shrink-0 text-xs text-green-700 dark:text-green-400'>you</span> : null}
          </div>
          <div className='text-xs text-muted' title={entry.authorPubkey}>
            <PlayerLabel pubkey={entry.authorPubkey} className='font-medium text-fg' />{' '}
            <code className='font-mono break-all'>
              {entry.authorPubkey.slice(0, 10)}… · {entry.hash.slice(0, 6)}
            </code>{' '}
            ·{' '}
            <time className='font-mono' dateTime={entry.createdAt} title={fullTime(entry.createdAt)}>
              {timeAgo(entry.createdAt)}
            </time>
          </div>
        </div>
      </button>
      {/* Two ways to build on a COMMIT (not on a remix — out of scope for the demo). */}
      {derive.can && !isRemix ? (
        <div className='flex shrink-0 items-center gap-1.5'>
          <button
            type='button'
            onClick={() => derive.onRemix(entry.hash)}
            disabled={derive.pending}
            className={BTN}
            title='Sign a remix object that records this commit as its source (attribution carried along).'
          >
            Remix
          </button>
          <button
            type='button'
            onClick={() => derive.onBranch(entry.hash)}
            disabled={derive.pending}
            className={BTN}
            title='Start a new branch pointing at this commit — no attribution (like git branch).'
          >
            Branch
          </button>
        </div>
      ) : null}
    </li>
  )
}

/**
 * Navigable detail for one commit OR remix: fetched by hash (get_object), routed by `object_kind`, then decoded with
 * `commit_decode` / `remix_decode`. Renders message / signer / timestamp / tree / signature for either kind; parents
 * are links that load THAT object's detail in place. For a remix it additionally renders a "remix / fork of …" block
 * whose upstream `commit_hash` is a link → the upstream commit's detail (reusing the same `onSelectCommit`
 * parent-navigation mechanism). A Fork button on a commit builds + pushes a remix of it.
 */
function CommitDetail({
  room,
  hash,
  onSelectCommit,
  onClose,
  derive,
}: {
  room: string
  hash: string
  onSelectCommit: (h: string) => void
  onClose: () => void
  derive: DeriveActions
}) {
  const api = useMkit()
  const obj = useObject(room, hash)

  const decoded = useMemo(() => {
    if (!obj.data) return null
    // `decodeLogObject` routes via `object_kind` → commit_decode /
    // remix_decode and returns the kind + sources, so the detail view
    // never has to guess which decoder to call.
    const res = decodeLogObject(api, obj.data, hash, '')
    if (!res) return { ok: false as const, error: "This commit is in a format we don't recognize." }
    try {
      const info = res.entry.kind === 'remix' ? api.remix_decode(obj.data) : api.commit_decode(obj.data)
      const parents: string[] = []
      for (let i = 0; i < info.parent_count; i++) {
        const p = info.parent(i)
        if (p) parents.push(p)
      }
      return {
        ok: true as const,
        kind: res.entry.kind ?? 'commit',
        message: info.message,
        signerHex: info.signer_hex,
        timestamp: Number(info.timestamp),
        treeHex: info.tree_hex,
        signatureHex: info.signature_hex,
        parents,
        sources: res.entry.sources ?? [],
      }
    } catch (e) {
      return { ok: false as const, error: e instanceof Error ? e.message : String(e) }
    }
  }, [api, obj.data, hash])

  const isRemix = decoded?.ok && decoded.kind === 'remix'

  return (
    <section className='space-y-3'>
      <div className='flex flex-wrap items-baseline justify-between gap-3'>
        <h2 className='flex items-center gap-2 text-sm font-semibold'>
          <HashChip hash={hash} size={14} />
          {isRemix ? 'Remix detail' : 'Commit detail'}
          {isRemix ? (
            <span className='rounded bg-purple-100 px-1.5 text-xs text-purple-700 dark:bg-purple-950 dark:text-purple-300'>
              remix
            </span>
          ) : null}
        </h2>
        <div className='flex flex-wrap items-center gap-2'>
          {/* Build on a commit (not a remix) straight from its detail. */}
          {derive.can && decoded?.ok && !isRemix ? (
            <>
              <button
                type='button'
                className={BTN}
                onClick={() => derive.onRemix(hash)}
                disabled={derive.pending}
                title='Sign a remix object that records this commit as its source (attribution).'
              >
                Remix
              </button>
              <button
                type='button'
                className={BTN}
                onClick={() => derive.onBranch(hash)}
                disabled={derive.pending}
                title='Start a new branch pointing at this commit — no attribution (like git branch).'
              >
                Branch
              </button>
            </>
          ) : null}
          <button type='button' className={BTN} onClick={onClose}>
            ← Back to log
          </button>
        </div>
      </div>

      {obj.isLoading ? (
        <p className='text-sm text-muted'>Loading…</p>
      ) : !obj.data ? (
        <p className='text-sm text-amber-700 dark:text-amber-400'>We couldn't find this commit.</p>
      ) : !decoded?.ok ? (
        <p className='text-red-600 dark:text-red-400'>We couldn't open this commit. Try again.</p>
      ) : (
        <FieldList>
          <Field label='Hash'>
            <code className='font-mono text-sm break-all'>{hash}</code>
          </Field>
          {isRemix ? (
            <Field label='Remix / fork of'>
              {decoded.sources.length === 0 ? (
                <span className='text-sm text-muted'>No sources</span>
              ) : (
                <ul className='space-y-1.5'>
                  {decoded.sources.map((s) => (
                    <li key={s.commitHashHex} className='flex items-center gap-2'>
                      <HashChip hash={s.commitHashHex} size={12} />
                      <Tooltip content='Open the upstream commit this fork derives from'>
                        <button
                          type='button'
                          onClick={() => onSelectCommit(s.commitHashHex)}
                          className='min-w-0 truncate text-left font-mono text-xs break-all text-blue-600 hover:underline dark:text-blue-400'
                        >
                          {s.commitHashHex}
                        </button>
                      </Tooltip>
                    </li>
                  ))}
                </ul>
              )}
            </Field>
          ) : null}
          <Field label='Message'>
            <span className='text-sm break-words whitespace-pre-wrap'>{decoded.message || '(empty)'}</span>
          </Field>
          <Field label='Author / signer'>
            <div title={decoded.signerHex}>
              <PlayerLabel pubkey={decoded.signerHex} className='text-sm font-medium' />{' '}
              <code className='font-mono text-xs text-muted'>{decoded.signerHex.slice(0, 10)}…</code>
            </div>
            <code className='mt-1 block font-mono text-xs break-all text-muted'>{decoded.signerHex}</code>
          </Field>
          <Field label='Timestamp'>
            <span className='text-sm'>
              {decoded.timestamp ? new Date(decoded.timestamp * 1000).toISOString() : 'unknown'}{' '}
              <span className='text-muted'>({decoded.timestamp} unix s)</span>
            </span>
          </Field>
          <Field label='Tree'>
            <code className='font-mono text-xs break-all'>{decoded.treeHex}</code>
          </Field>
          <Field label='Parents'>
            {decoded.parents.length === 0 ? (
              <span className='text-sm text-muted'>None ({isRemix ? 'root remix' : 'root commit'})</span>
            ) : (
              <ul className='space-y-1.5'>
                {decoded.parents.map((p, i) => (
                  <li key={p} className='flex items-center gap-2'>
                    <HashChip hash={p} size={12} />
                    <button
                      type='button'
                      onClick={() => onSelectCommit(p)}
                      className='min-w-0 truncate text-left font-mono text-xs break-all text-blue-600 hover:underline dark:text-blue-400'
                    >
                      {p}
                    </button>
                    {decoded.parents.length > 1 ? (
                      <span className='shrink-0 text-xs text-muted'>{i === 0 ? '(first)' : `(#${i})`}</span>
                    ) : null}
                  </li>
                ))}
              </ul>
            )}
          </Field>
          <Field label='Signature'>
            <code className='font-mono text-xs break-all'>{decoded.signatureHex}</code>
          </Field>
        </FieldList>
      )}
    </section>
  )
}
