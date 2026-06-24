'use client'

// Right column of the multiplayer demo: the refs panel, the live commit log,
// individual log rows, the commit/remix detail view, and the loading skeleton.
// Moved verbatim out of `multiplayer-demo.tsx`.

import { useMemo, useState } from 'react'
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
import { useMkit } from '../use-mkit'
import { useFork } from './compose'
import { PlayerLabel } from './player-label'
import { BTN, errMsg } from './shared'

/**
 * Navigable repo browser (right column): a refs/branches panel, the selected
 * ref's history, and — when a commit row is clicked — a commit/remix-detail
 * view whose parents (and, for a remix, its upstream sources) are themselves
 * links. All navigation is component state (selectedRef / selectedCommit),
 * no router change.
 */
export function RepoBrowser({
  api,
  room,
  myPubkey,
  seedHex,
  useMock,
  selectedRef,
  onSelectRef,
  selectedCommit,
  onSelectCommit,
}: {
  api: ReturnType<typeof useMkit>
  room: string
  myPubkey: string | null
  seedHex: string | null
  useMock: boolean
  selectedRef: string
  onSelectRef: (r: string) => void
  selectedCommit: string | null
  onSelectCommit: (h: string | null) => void
}) {
  const { fork, pending, error, ready: forkReady } = useFork(api, room, seedHex)
  const [forkStatus, setForkStatus] = useState<string | null>(null)

  // Build + push a fork of `upstreamCommit`, then select its new fork ref so
  // the user sees the remix land in the Refs panel + log.
  const onFork = async (upstreamCommit: string) => {
    setForkStatus(null)
    try {
      const ref = await fork(upstreamCommit)
      if (ref) {
        onSelectRef(ref)
        onSelectCommit(null)
        setForkStatus(`Forked → ${ref}`)
      }
    } catch (e) {
      setForkStatus(
        // The fork ref is unique per (commit, you), so a conflict here means a
        // concurrent re-fork raced your push — your fork chain moved under you.
        e instanceof CasConflictError
          ? 'Your fork ref just moved (a concurrent push) — try forking again.'
          : e instanceof IdentityLockedError
            ? 'Unlock (create an identity) before forking.'
            : errMsg(e),
      )
    }
  }
  // Fork needs both a seed (to sign) and a backend (to read head + push).
  const canFork = !!seedHex && forkReady

  return (
    <div className='space-y-6'>
      <RefsPanel room={room} useMock={useMock} selectedRef={selectedRef} onSelectRef={onSelectRef} />
      {selectedCommit ? (
        <CommitDetail
          room={room}
          hash={selectedCommit}
          onSelectCommit={onSelectCommit}
          onClose={() => onSelectCommit(null)}
          onFork={onFork}
          canFork={canFork}
          forkPending={pending}
        />
      ) : (
        <LiveLog
          room={room}
          selectedRef={selectedRef}
          myPubkey={myPubkey}
          onSelectCommit={onSelectCommit}
          onFork={onFork}
          canFork={canFork}
          forkPending={pending}
        />
      )}
      {forkStatus ? <p className='text-sm text-muted'>{forkStatus}</p> : null}
      {error && !forkStatus ? <p className='text-sm text-amber-700 dark:text-amber-400'>{errMsg(error)}</p> : null}
    </div>
  )
}

/**
 * Loading placeholder for the refs / commit-log lists. Shown while the first
 * fetch is in flight (`isPending`) so a cold load reads as "loading" rather than
 * an empty "no commits / no refs" state — the bug where a freshly-opened room
 * showed an empty log under a populated `main` ref before the walk resolved.
 */
function SkeletonRows({ rows = 5 }: { rows?: number }) {
  return (
    <ul
      className='divide-y divide-dashed divide-hairline border-y border-dashed border-hairline'
      aria-hidden='true'
    >
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

/** All refs in the room. Each row selects the ref the log/detail view follows. */
function RefsPanel({
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
    <section className='space-y-3'>
      <div className='flex items-baseline justify-between'>
        <h2 className='text-sm font-semibold'>Refs · room “{room}”</h2>
        <span className='font-mono text-xs text-muted'>{useMock ? 'mock backend' : 'worker'}</span>
      </div>
      {showSkeleton ? (
        <SkeletonRows rows={3} />
      ) : entries.length === 0 ? (
        <p className='text-sm text-muted'>No refs yet — push a commit to create one.</p>
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
                    <span className='shrink-0 rounded bg-purple-100 px-1.5 text-xs text-purple-700 dark:bg-purple-950 dark:text-purple-300'>
                      fork
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

function LiveLog({
  room,
  selectedRef,
  myPubkey,
  onSelectCommit,
  onFork,
  canFork,
  forkPending,
}: {
  room: string
  selectedRef: string
  myPubkey: string | null
  onSelectCommit: (h: string) => void
  onFork: (upstreamCommit: string) => void
  canFork: boolean
  forkPending: boolean
}) {
  const log = useCommitLog(room, selectedRef)
  const head = useRef(room, selectedRef)
  const entries = log.data ?? []
  // Same skeleton rule as the refs panel: loading, or refetching with nothing to
  // show yet. Keeps a populated ref from flashing "No commits" before the walk.
  const showSkeleton = log.isPending || (log.isFetching && entries.length === 0)

  return (
    <section className='space-y-3'>
      <div className='flex items-baseline justify-between'>
        <h2 className='text-sm font-semibold'>
          {isForkRef(selectedRef) ? 'Fork log' : 'Commit log'} · “{selectedRef}”
        </h2>
        <span className='font-mono text-xs text-muted'>
          {/* Show "head …" while the head is loading/refetching; only show ∅ once
              the query has settled with no head. */}
          head{' '}
          {head.isPending || head.isFetching ? '…' : head.data ? `${head.data.slice(0, 10)}…` : '∅'}
        </span>
      </div>
      {showSkeleton ? (
        <SkeletonRows rows={5} />
      ) : entries.length === 0 ? (
        <p className='text-sm text-muted'>No commits on this ref yet — push one above.</p>
      ) : (
        <ul className='divide-y divide-dashed divide-hairline border-y border-dashed border-hairline'>
          {entries.map((e) => (
            <LogRow
              key={e.hash}
              entry={e}
              mine={!!myPubkey && e.authorPubkey === myPubkey}
              onSelect={() => onSelectCommit(e.hash)}
              onFork={onFork}
              canFork={canFork}
              forkPending={forkPending}
            />
          ))}
        </ul>
      )}
    </section>
  )
}

function LogRow({
  entry,
  mine,
  onSelect,
  onFork,
  canFork,
  forkPending,
}: {
  entry: CommitLogEntry
  mine: boolean
  onSelect: () => void
  onFork: (upstreamCommit: string) => void
  canFork: boolean
  forkPending: boolean
}) {
  const isRemix = entry.kind === 'remix'
  return (
    <li className='flex items-center gap-2 py-2.5'>
      <button
        type='button'
        onClick={onSelect}
        className='flex min-w-0 flex-1 items-center gap-3 text-left transition-colors hover:text-fg'
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
            </code>
          </div>
        </div>
      </button>
      {/* Fork a COMMIT (not a remix — that would fork a fork; out of scope for the demo). */}
      {canFork && !isRemix ? (
        <button
          type='button'
          onClick={() => onFork(entry.hash)}
          disabled={forkPending}
          className={`${BTN} shrink-0`}
          title='Build + sign a remix of this commit and push it to a fork ref'
        >
          Fork
        </button>
      ) : null}
    </li>
  )
}

/**
 * Navigable detail for one commit OR remix: fetched by hash (get_object),
 * routed by `object_kind`, then decoded with `commit_decode` /
 * `remix_decode`. Renders message / signer / timestamp / tree / signature
 * for either kind; parents are links that load THAT object's detail in
 * place. For a remix it additionally renders a "remix / fork of …" block
 * whose upstream `commit_hash` is a link → the upstream commit's detail
 * (reusing the same `onSelectCommit` parent-navigation mechanism). A Fork
 * button on a commit builds + pushes a remix of it.
 */
function CommitDetail({
  room,
  hash,
  onSelectCommit,
  onClose,
  onFork,
  canFork,
  forkPending,
}: {
  room: string
  hash: string
  onSelectCommit: (h: string) => void
  onClose: () => void
  onFork: (upstreamCommit: string) => void
  canFork: boolean
  forkPending: boolean
}) {
  const api = useMkit()
  const obj = useObject(room, hash)

  const decoded = useMemo(() => {
    if (!obj.data) return null
    // `decodeLogObject` routes via `object_kind` → commit_decode /
    // remix_decode and returns the kind + sources, so the detail view
    // never has to guess which decoder to call.
    const res = decodeLogObject(api, obj.data, hash, '')
    if (!res) return { ok: false as const, error: 'unknown object kind' }
    try {
      const info =
        res.entry.kind === 'remix' ? api.remix_decode(obj.data) : api.commit_decode(obj.data)
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
      <div className='flex items-baseline justify-between gap-3'>
        <h2 className='flex items-center gap-2 text-sm font-semibold'>
          <HashChip hash={hash} size={14} />
          {isRemix ? 'Remix detail' : 'Commit detail'}
          {isRemix ? (
            <span className='rounded bg-purple-100 px-1.5 text-xs text-purple-700 dark:bg-purple-950 dark:text-purple-300'>
              fork
            </span>
          ) : null}
        </h2>
        <div className='flex items-center gap-2'>
          {/* Fork a commit (not a remix) straight from its detail. */}
          {canFork && decoded?.ok && !isRemix ? (
            <button type='button' className={BTN} onClick={() => onFork(hash)} disabled={forkPending}>
              {forkPending ? 'Forking…' : 'Fork / Remix'}
            </button>
          ) : null}
          <button type='button' className={BTN} onClick={onClose}>
            ← Back to log
          </button>
        </div>
      </div>

      {obj.isLoading ? (
        <p className='text-sm text-muted'>Loading object…</p>
      ) : !obj.data ? (
        <p className='text-sm text-amber-700 dark:text-amber-400'>Object not found in this room.</p>
      ) : !decoded?.ok ? (
        <p className='text-red-600 dark:text-red-400'>Could not decode object: {decoded?.error}</p>
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
                      <button
                        type='button'
                        onClick={() => onSelectCommit(s.commitHashHex)}
                        className='min-w-0 truncate text-left font-mono text-xs break-all text-blue-600 hover:underline dark:text-blue-400'
                        title='Open the upstream commit this fork derives from'
                      >
                        {s.commitHashHex}
                      </button>
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
          <Field label='Signature (Ed25519)'>
            <code className='font-mono text-xs break-all'>{decoded.signatureHex}</code>
          </Field>
        </FieldList>
      )}
    </section>
  )
}
