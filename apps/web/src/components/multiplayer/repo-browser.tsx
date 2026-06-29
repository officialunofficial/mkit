'use client'

// Repo views for the multiplayer demo: the branches panel (`RefsPanel`, left
// column) and the live commit log + commit/remix detail (`RepoLog`, right column
// under Compose), plus log rows and the loading skeleton.

import * as ScrollArea from '@radix-ui/react-scroll-area'
import { useMemo, useState } from 'react'
import { recordActivity } from '../../lib/activity-log'
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
import { BTN, errMsg } from './shared'

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

const pad = (n: number, w = 2) => String(n).padStart(w, '0')

/** UTC `HH:MM:SS:mmm` for a commit's ISO `createdAt` (empty if unparseable). */
function utcTime(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return ''
  return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}:${pad(d.getUTCMilliseconds(), 3)}`
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
    const t0 = performance.now()
    try {
      const ref = mode === 'remix' ? await remix(upstreamCommit) : await branch(upstreamCommit)
      if (!ref) return
      onSelectRef(ref)
      onSelectCommit(null)
      setStatus(mode === 'remix' ? `Remixed → ${ref}` : `Branched off → ${ref}`)
      recordActivity({
        kind: 'fork',
        title:
          mode === 'remix'
            ? `Remixed ${upstreamCommit.slice(0, 10)}… → ${ref}`
            : `Branched off ${upstreamCommit.slice(0, 10)}… → ${ref}`,
        durationMs: performance.now() - t0,
        lines:
          mode === 'remix'
            ? [
                'Signed a remix object that RECORDS the upstream commit as its source — attribution is carried along.',
                `remix branch ${ref}`,
              ]
            : [
                'Created a new branch pointing AT the commit — no new object, no attribution. Just a fresh line of history (git branch).',
                `branch ${ref}`,
              ],
      })
    } catch (e) {
      setStatus(
        e instanceof CasConflictError
          ? 'That branch just moved (a concurrent push) — try again.'
          : e instanceof IdentityLockedError
            ? 'Unlock or create an identity first.'
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

/** All branches in the repo (left column). Each row selects the branch the log/detail view follows. */
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
  const refs = useRefs(room)
  // Sort `main` first, then alphabetically — a stable, predictable panel.
  const entries = (refs.data ?? []).toSorted((a, b) =>
    a.name === 'main' ? -1 : b.name === 'main' ? 1 : a.name.localeCompare(b.name),
  )
  // Show the skeleton while loading (gated-pending OR no backend yet) OR while
  // refetching with nothing to show yet — so a populated room never flashes its
  // empty state before the walk resolves. Only render the empty copy once the
  // query has settled with genuinely zero refs.
  const showSkeleton = refs.isPending || (refs.isFetching && (refs.data?.length ?? 0) === 0)

  return (
    <section className='space-y-2'>
      <div className='flex items-baseline justify-between'>
        <h2 className='text-sm font-semibold'>Branches · repo “{room}”</h2>
        <span className='font-mono text-xs text-muted'>{useMock ? 'mock backend' : 'worker'}</span>
      </div>
      {showSkeleton ? (
        <SkeletonRows rows={1} />
      ) : entries.length === 0 ? (
        <p className='text-sm text-muted'>No branches yet. Push a commit to create one.</p>
      ) : (
        <ul className='divide-y divide-dashed divide-hairline border-y border-dashed border-hairline'>
          {entries.map((r) => {
            const active = r.name === selectedRef
            return (
              <li key={r.name}>
                <button
                  type='button'
                  onClick={() => onSelectRef(r.name)}
                  aria-pressed={active}
                  className={`flex w-full items-center gap-3 py-2.5 text-left transition-colors ${
                    active ? 'text-fg' : 'text-muted hover:text-fg'
                  }`}
                >
                  <HashChip hash={r.objectIdHex} size={14} />
                  <span className={`truncate font-mono text-sm ${active ? 'font-semibold' : 'font-medium'}`}>
                    {r.name}
                  </span>
                  {isForkRef(r.name) ? (
                    <span
                      className='shrink-0 rounded bg-purple-100 px-1.5 text-xs text-purple-700 dark:bg-purple-950 dark:text-purple-300'
                      title='A remix branch — its head records the commit it derived from (attribution).'
                    >
                      remix
                    </span>
                  ) : null}
                  {active ? <span className='shrink-0 text-xs text-blue-600 dark:text-blue-400'>selected</span> : null}
                  <code className='ml-auto shrink-0 font-mono text-xs text-muted'>{r.objectIdHex.slice(0, 10)}…</code>
                </button>
              </li>
            )
          })}
        </ul>
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
          {/* Show "head …" while the head is loading/refetching; only show ∅ once
              the query has settled with no head. */}
          head {head.isPending || head.isFetching ? '…' : head.data ? `${head.data.slice(0, 10)}…` : '∅'}
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
              {entry.authorPubkey.slice(0, 10)}… · {entry.hash.slice(0, 16)}…
            </code>{' '}
            ·{' '}
            <time className='font-mono' dateTime={entry.createdAt}>
              {utcTime(entry.createdAt)} UTC
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
                <span className='text-sm text-muted'>∅ (no sources)</span>
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
              {decoded.timestamp ? new Date(decoded.timestamp * 1000).toISOString() : '∅'}{' '}
              <span className='text-muted'>({decoded.timestamp} unix s)</span>
            </span>
          </Field>
          <Field label='Tree'>
            <code className='font-mono text-xs break-all'>{decoded.treeHex}</code>
          </Field>
          <Field label='Parents'>
            {decoded.parents.length === 0 ? (
              <span className='text-sm text-muted'>∅ ({isRemix ? 'root remix' : 'root commit'})</span>
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
