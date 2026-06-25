'use client'

// The front-page signed lobby — ONE merged feed of a room's signed activity:
// chat messages AND commits pushed in /multiplayer, both signed by the same
// passkey-derived Ed25519 key and labelled with the player's keys.mkit.sh
// handle. Reading is open to everyone; posting requires an unlocked identity
// (the same global identity the multiplayer demo uses — unlock in either and
// you're unlocked in both). Bound to the same room as the multiplayer demo
// (`identity-store` DEFAULT_ROOM), so commits there surface here.

import { useVirtualizer } from '@tanstack/react-virtual'
import { useEffect, useRef as useReactRef, useState } from 'react'
import { DEFAULT_ROOM, useIdentityStore } from '../../lib/identity-store'
import {
  type FeedItem,
  MAX_MESSAGE_CHARS,
  RepoBackendProvider,
  isForkRef,
  useLobbyEvents,
  useLobbyFeed,
  usePostMessage,
  useResolvedRepoBackend,
} from '../../lib/repo-api'
import { useIdentityActions } from '../use-identity-actions'
import { useMkit } from '../use-mkit'
import { PlayerAvatar, PlayerLabel } from '../multiplayer/player-label'
import { BTN, PRIMARY_BTN, errMsg } from '../multiplayer/shared'

/** Message length cap — the SAME shared constant the server enforces. */
const MAX_CHARS = MAX_MESSAGE_CHARS

/**
 * Owns + provides the repo backend for the lobby subtree (mock offline, wasm
 * once loaded). The mock is seeded with offline demo activity at creation
 * (inside the hook), so no seeding/invalidate Effect is needed here.
 */
export function SignedLobby() {
  const api = useMkit()
  const room = useIdentityStore((s) => s.room) || DEFAULT_ROOM
  const { backend } = useResolvedRepoBackend(api, room)

  return (
    <RepoBackendProvider backend={backend}>
      <LobbyBody room={room} />
    </RepoBackendProvider>
  )
}

function LobbyBody({ room }: { room: string }) {
  useLobbyEvents(room)
  const { items, isLoading } = useLobbyFeed(room, 'main')

  return (
    <section className='space-y-3'>
      <div className='flex items-baseline justify-between gap-3'>
        <h2 className='text-lg font-medium tracking-tight text-balance'>Live lobby</h2>
        <span className='text-xs text-muted'>every message &amp; commit is Ed25519-signed</span>
      </div>
      <div className='overflow-hidden rounded-md border border-hairline'>
        <Feed items={items} isLoading={isLoading} />
        <Composer room={room} />
      </div>
    </section>
  )
}

/**
 * The merged feed, virtualized with TanStack Virtual (headless): the product
 * owns the scroll container + row markup; the virtualizer only computes which
 * rows are visible. Rows are dynamically MEASURED (chat wraps to many lines,
 * commits are one), so `estimateSize` is just a first paint hint and
 * `measureElement` corrects each row's real height. Renders only the visible
 * window + overscan, follows the newest row when pinned to the bottom, and
 * offers a sticky "jump to latest" affordance when scrolled up — all without
 * leaving the design system (empty/loading are plain muted text).
 */
function Feed({ items, isLoading }: { items: FeedItem[]; isLoading: boolean }) {
  const scrollRef = useReactRef<HTMLDivElement>(null)
  // `atBottom` drives the jump-to-latest affordance (state → re-render); the
  // ref mirror lets the follow effect read it without re-subscribing per scroll.
  const [atBottom, setAtBottom] = useState(true)
  const atBottomRef = useReactRef(true)
  // Last observed scrollTop, to tell a user scroll-UP from a programmatic
  // (smooth) scroll DOWN toward the newest row.
  const lastTopRef = useReactRef(0)

  const virtualizer = useVirtualizer({
    count: items.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => 56,
    overscan: 6,
    getItemKey: (index) => items[index]?.key ?? index,
  })

  const setBottom = (v: boolean) => {
    atBottomRef.current = v
    setAtBottom(v)
  }

  const onScroll = () => {
    const el = scrollRef.current
    if (!el) return
    const dist = el.scrollHeight - el.scrollTop - el.clientHeight
    const scrolledUp = el.scrollTop < lastTopRef.current - 2
    lastTopRef.current = el.scrollTop
    // Re-pin when within 24px of the end. Otherwise UNPIN only on a genuine
    // user scroll-up — NOT at the intermediate positions of a programmatic
    // smooth-scroll (scrollTop increasing toward the bottom), so a burst of
    // incoming messages keeps following instead of sticking partway.
    if (dist < 24) setBottom(true)
    else if (scrolledUp) setBottom(false)
  }

  // Follow the newest row ONLY when pinned to the bottom — reading a peer's
  // history (scrolled up) is never yanked away by an incoming message.
  // (`atBottomRef`/`virtualizer` are stable refs; only `items.length` re-runs.)
  useEffect(() => {
    if (items.length > 0 && atBottomRef.current) {
      virtualizer.scrollToIndex(items.length - 1, { align: 'end', behavior: 'smooth' })
    }
  }, [items.length, virtualizer, atBottomRef])

  const jumpToLatest = () => {
    setBottom(true)
    if (items.length > 0) virtualizer.scrollToIndex(items.length - 1, { align: 'end', behavior: 'smooth' })
  }

  const empty = items.length === 0
  return (
    <div className='relative'>
      <div ref={scrollRef} onScroll={onScroll} className='max-h-80 min-h-40 overflow-y-auto bg-muted/5'>
        {empty ? (
          <p className='p-4 text-sm text-muted text-pretty'>
            {isLoading ? 'Loading the lobby…' : 'No activity yet — say hi or push a commit in multiplayer.'}
          </p>
        ) : (
          <div style={{ height: virtualizer.getTotalSize(), position: 'relative', width: '100%' }}>
            {virtualizer.getVirtualItems().map((vrow) => {
              const item = items[vrow.index]
              if (!item) return null
              return (
                <div
                  key={vrow.key}
                  data-index={vrow.index}
                  ref={virtualizer.measureElement}
                  className='px-4 py-2'
                  style={{ position: 'absolute', top: 0, left: 0, width: '100%', transform: `translateY(${vrow.start}px)` }}
                >
                  <Row item={item} />
                </div>
              )
            })}
          </div>
        )}
      </div>
      {/* Always rendered so it can cross-fade in/out (opacity + scale) instead
          of popping; `before:` extends the hit area to 40px tall while the pill
          stays visually compact. Hidden from a11y + tab order when inactive. */}
      <button
        type='button'
        onClick={jumpToLatest}
        aria-hidden={atBottom || empty}
        tabIndex={atBottom || empty ? -1 : 0}
        className={`absolute right-3 bottom-3 inline-flex h-8 items-center rounded-full border border-hairline bg-bg/90 px-3 text-xs shadow-sm backdrop-blur transition-[opacity,scale,border-color] duration-200 ease-[cubic-bezier(0.2,0,0,1)] before:absolute before:inset-x-0 before:-inset-y-1 before:content-[""] hover:border-fg active:scale-[0.96] ${
          atBottom || empty ? 'pointer-events-none scale-95 opacity-0' : 'opacity-100'
        }`}
      >
        ↓ Latest
      </button>
    </div>
  )
}

function Row({ item }: { item: FeedItem }) {
  const pubkey = item.kind === 'chat' ? item.message.authorPubkeyHex : item.entry.authorPubkey
  return (
    <div className='flex gap-2.5 text-sm'>
      <PlayerAvatar pubkey={pubkey} size={26} className='mt-0.5' />
      <div className='min-w-0 flex-1'>
        <div className='flex items-baseline gap-2'>
          <PlayerLabel pubkey={pubkey} className='truncate font-medium' />
          {item.kind === 'commit' ? (
            <span className='rounded-sm border border-hairline px-1 text-[10px] uppercase tracking-wide text-muted'>
              {isForkRef(item.entry.ref) ? 'fork' : 'commit'}
            </span>
          ) : null}
          <span className='ml-auto shrink-0 text-xs text-muted tabular-nums'>{relTime(item.ts)}</span>
        </div>
        {item.kind === 'chat' ? (
          <p className='mt-0.5 break-words whitespace-pre-wrap text-fg'>{item.message.text}</p>
        ) : (
          <p className='mt-0.5 text-muted'>
            pushed <code className='font-mono text-fg'>{item.entry.hash.slice(0, 10)}</code> to{' '}
            <code className='font-mono text-fg'>{item.entry.ref}</code>
            {item.entry.message ? <span className='text-muted'> — “{item.entry.message}”</span> : null}
          </p>
        )}
      </div>
    </div>
  )
}

/**
 * Compose row: a signed-post input when unlocked, else an unlock/create CTA. Reading the lobby never requires an
 * identity.
 */
function Composer({ room }: { room: string }) {
  const unlocked = useIdentityStore((s) => s.unlocked)
  const myPubkey = useIdentityStore((s) => s.ed25519PubkeyHex)
  const post = usePostMessage(room, myPubkey ?? undefined)
  const actions = useIdentityActions()
  const [text, setText] = useState('')

  if (!unlocked) {
    return (
      <div className='flex flex-wrap items-center gap-3 border-t border-hairline px-4 py-3'>
        <button
          type='button'
          className={PRIMARY_BTN}
          disabled={actions.busy}
          onClick={() => void (actions.hasPasskey ? actions.onUnlock() : actions.onCreate())}
        >
          {actions.busy ? 'One moment…' : actions.hasPasskey ? 'Unlock to post' : 'Create an identity to post'}
        </button>
        <span className='text-xs text-muted'>
          {actions.status ?? 'A passkey derives an Ed25519 key in your browser — that key signs every message.'}
        </span>
      </div>
    )
  }

  const trimmed = text.trim()
  const over = [...trimmed].length > MAX_CHARS
  const canSend = !!trimmed && !over && !post.isPending

  const send = () => {
    if (!canSend) return
    post.mutate(text, {
      onSuccess: (r) => {
        if (r.accepted) setText('')
      },
    })
  }

  return (
    <div className='space-y-1 border-t border-hairline px-4 py-3'>
      <div className='flex items-center gap-2'>
        <PlayerAvatar pubkey={myPubkey ?? ''} size={26} />
        <input
          // No `maxLength`: it counts UTF-16 code units and would truncate
          // emoji early, disagreeing with the code-point `over` check + counter
          // below (and the server's scalar-value cap). The over-check governs.
          className='h-10 w-full rounded-lg border border-hairline bg-transparent px-3 text-base outline-none transition-colors duration-200 focus:border-fg sm:h-9 sm:text-sm'
          value={text}
          placeholder='Sign a message to the lobby…'
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') send()
          }}
        />
        <button type='button' className={BTN} onClick={send} disabled={!canSend}>
          {post.isPending ? 'Signing…' : 'Send'}
        </button>
      </div>
      <p className='text-xs text-muted'>
        {over ? (
          <span className='text-amber-700 dark:text-amber-400'>Message is over {MAX_CHARS} characters.</span>
        ) : post.isError ? (
          <span className='text-amber-700 dark:text-amber-400'>{errMsg(post.error)}</span>
        ) : post.data?.rateLimited ? (
          <span className='text-amber-700 dark:text-amber-400'>You’re posting too fast — wait a moment.</span>
        ) : (
          <>
            Signed with your Ed25519 key ·{' '}
            <span className='tabular-nums'>
              {[...trimmed].length}/{MAX_CHARS}
            </span>
          </>
        )}
      </p>
    </div>
  )
}

/** Compact relative time (`just now`, `5m`, `2h`, `3d`) from an epoch-ms stamp. */
function relTime(ms: number): string {
  const s = Math.max(0, Math.floor((Date.now() - ms) / 1000))
  if (s < 5) return 'just now'
  if (s < 60) return `${s}s`
  if (s < 3600) return `${Math.floor(s / 60)}m`
  if (s < 86_400) return `${Math.floor(s / 3600)}h`
  return `${Math.floor(s / 86_400)}d`
}
