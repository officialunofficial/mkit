'use client'

// The front-page signed lobby — ONE merged feed of a room's signed activity:
// chat messages AND commits pushed in /multiplayer, plus signed emoji reactions,
// all keyed to the same passkey-derived Ed25519 identity and labelled with the
// player's keys.mkit.sh handle. Slack-structured (grouped rows, hover actions,
// reactions) but in mkit's white/Geist palette. Reading is open; posting +
// reacting require an unlocked identity (shared with the multiplayer demo).

import { useVirtualizer } from '@tanstack/react-virtual'
import { useEffect, useRef as useReactRef, useState } from 'react'
import { DEFAULT_ROOM, useIdentityStore } from '../../lib/identity-store'
import {
  type FeedItem,
  MAX_MESSAGE_CHARS,
  type ReactionAgg,
  RepoBackendProvider,
  isForkRef,
  useLobbyEvents,
  useLobbyFeed,
  usePostMessage,
  useReactions,
  useResolvedRepoBackend,
  useToggleReaction,
} from '../../lib/repo-api'
import { useIdentityActions } from '../use-identity-actions'
import { useMkit } from '../use-mkit'
import { PlayerAvatar, PlayerLabel } from '../multiplayer/player-label'
import { BTN, PRIMARY_BTN, errMsg } from '../multiplayer/shared'

/** Message length cap — the SAME shared constant the server enforces. */
const MAX_CHARS = MAX_MESSAGE_CHARS

/** Emojis offered in the add-reaction picker. */
const REACTION_EMOJI = ['👍', '❤️', '😂', '🎉', '🚀', '👀', '✅', '🔥']

/** Group a row under the previous one if same author within this window. */
const GROUP_WINDOW_MS = 5 * 60_000

/** The Ed25519 pubkey that authored a feed item (chat author or commit author). */
function authorOf(item: FeedItem): string {
  return item.kind === 'chat' ? item.message.authorPubkeyHex : item.entry.authorPubkey
}

/** The reaction target id for a feed item — its hex id (message id or commit hash). */
function targetIdOf(item: FeedItem): string {
  return item.kind === 'chat' ? item.message.messageIdHex : item.entry.hash
}

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
      <div className='flex items-center gap-2'>
        <span className='relative flex h-2 w-2' aria-hidden>
          <span className='absolute inline-flex h-full w-full animate-ping rounded-full bg-green-500/60' />
          <span className='relative inline-flex h-2 w-2 rounded-full bg-green-500' />
        </span>
        <h2 className='text-lg font-medium tracking-tight'>Live lobby</h2>
      </div>
      <div className='overflow-hidden rounded-md border border-hairline'>
        <Feed room={room} items={items} isLoading={isLoading} />
        <Composer room={room} />
      </div>
    </section>
  )
}

function Feed({ room, items, isLoading }: { room: string; items: FeedItem[]; isLoading: boolean }) {
  const scrollRef = useReactRef<HTMLDivElement>(null)
  const [atBottom, setAtBottom] = useState(true)
  const atBottomRef = useReactRef(true)
  const lastTopRef = useReactRef(0)
  const didInitRef = useReactRef(false)

  // Identity + reactions wiring (live signed reactions on any feed item).
  const myPubkey = useIdentityStore((s) => s.ed25519PubkeyHex)
  const unlocked = useIdentityStore((s) => s.unlocked)
  const actions = useIdentityActions()
  const reactionsFor = useReactions(room, myPubkey ?? undefined)
  const toggle = useToggleReaction(room, myPubkey ?? undefined)
  const onNeedIdentity = () => void (actions.hasPasskey ? actions.onUnlock() : actions.onCreate())

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
    if (dist < 24) setBottom(true)
    else if (scrolledUp) setBottom(false)
  }

  // START pinned to the newest row: the FIRST time the feed has rows, jump
  // instantly (no animation — the user shouldn't watch it scroll). After that,
  // smooth-follow only while pinned to the bottom.
  useEffect(() => {
    if (items.length === 0) return
    if (!didInitRef.current) {
      didInitRef.current = true
      virtualizer.scrollToIndex(items.length - 1, { align: 'end' })
    } else if (atBottomRef.current) {
      virtualizer.scrollToIndex(items.length - 1, { align: 'end', behavior: 'smooth' })
    }
  }, [items.length, virtualizer, atBottomRef, didInitRef])

  const jumpToLatest = () => {
    setBottom(true)
    if (items.length > 0) virtualizer.scrollToIndex(items.length - 1, { align: 'end', behavior: 'smooth' })
  }

  const empty = items.length === 0
  return (
    <div className='relative'>
      <div ref={scrollRef} onScroll={onScroll} className='max-h-96 min-h-44 overflow-y-auto bg-muted/5 py-1'>
        {empty ? (
          <p className='p-4 text-sm text-muted text-pretty'>
            {isLoading ? 'Loading the lobby…' : 'No activity yet — say hi or push a commit in multiplayer.'}
          </p>
        ) : (
          <div style={{ height: virtualizer.getTotalSize(), position: 'relative', width: '100%' }}>
            {virtualizer.getVirtualItems().map((vrow) => {
              const item = items[vrow.index]
              if (!item) return null
              const prev = vrow.index > 0 ? items[vrow.index - 1] : undefined
              const grouped =
                !!prev && authorOf(prev) === authorOf(item) && item.ts >= prev.ts && item.ts - prev.ts < GROUP_WINDOW_MS
              return (
                <div
                  key={vrow.key}
                  data-index={vrow.index}
                  ref={virtualizer.measureElement}
                  style={{ position: 'absolute', top: 0, left: 0, width: '100%', transform: `translateY(${vrow.start}px)` }}
                >
                  <Row
                    item={item}
                    grouped={grouped}
                    reactions={reactionsFor(targetIdOf(item))}
                    canReact={unlocked}
                    onToggle={(emoji) =>
                      unlocked ? toggle.mutate({ targetId: targetIdOf(item), emoji }) : onNeedIdentity()
                    }
                  />
                </div>
              )
            })}
          </div>
        )}
      </div>
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

/** One Slack-style feed row: full header (avatar + name + time) for a run's
 * first message; a tight, indented continuation when `grouped` (timestamp shows
 * on hover). A reaction bar sits under the body. */
function Row({
  item,
  grouped,
  reactions,
  canReact,
  onToggle,
}: {
  item: FeedItem
  grouped: boolean
  reactions: ReactionAgg[]
  canReact: boolean
  onToggle: (emoji: string) => void
}) {
  const pubkey = authorOf(item)
  const time = fmtTime(item.ts)
  const body =
    item.kind === 'chat' ? (
      <p className='break-words whitespace-pre-wrap text-fg'>{item.message.text}</p>
    ) : (
      <p className='text-muted'>
        pushed <code className='font-mono text-fg'>{item.entry.hash.slice(0, 10)}</code> to{' '}
        <code className='font-mono text-fg'>{item.entry.ref}</code>
        {item.entry.message ? <span className='text-muted'> — “{item.entry.message}”</span> : null}
      </p>
    )

  return (
    <div className={`group/row relative flex gap-2.5 px-4 text-sm transition-colors hover:bg-muted/10 ${grouped ? 'py-0.5' : 'mt-1 py-1'}`}>
      {grouped ? (
        // Continuation: reserve the avatar gutter; reveal the time on hover.
        <span className='w-[26px] shrink-0 pt-0.5 text-right text-[10px] text-muted opacity-0 transition-opacity tabular-nums group-hover/row:opacity-100'>
          {time.label}
        </span>
      ) : (
        <PlayerAvatar pubkey={pubkey} size={26} className='mt-0.5' />
      )}
      <div className='min-w-0 flex-1'>
        {grouped ? null : (
          <div className='flex items-baseline gap-2'>
            <PlayerLabel pubkey={pubkey} className='truncate font-medium' />
            {item.kind === 'commit' ? (
              <span className='rounded-sm border border-hairline px-1 text-[10px] uppercase tracking-wide text-muted'>
                {isForkRef(item.entry.ref) ? 'fork' : 'commit'}
              </span>
            ) : null}
            <time
              title={time.title}
              className='ml-auto shrink-0 text-xs text-muted tabular-nums'
            >
              {time.label}
            </time>
          </div>
        )}
        <div className={grouped ? '' : 'mt-0.5'}>{body}</div>
        <ReactionBar reactions={reactions} canReact={canReact} onToggle={onToggle} />
      </div>
    </div>
  )
}

/** The reaction row under a message: existing reaction pills + an add-emoji
 * picker. Pills highlight when you've reacted; clicking toggles. */
function ReactionBar({
  reactions,
  canReact,
  onToggle,
}: {
  reactions: ReactionAgg[]
  canReact: boolean
  onToggle: (emoji: string) => void
}) {
  const [pickerOpen, setPickerOpen] = useState(false)

  return (
    <div className='mt-1 flex flex-wrap items-center gap-1'>
      {reactions.map((r) => (
        <button
          key={r.emoji}
          type='button'
          onClick={() => onToggle(r.emoji)}
          title={canReact ? (r.mine ? 'Remove your reaction' : 'Add your reaction') : 'Unlock to react'}
          className={`inline-flex h-6 items-center gap-1 rounded-full border px-2 text-xs leading-none tabular-nums transition-colors active:scale-[0.96] ${
            r.mine ? 'border-blue-500/60 bg-blue-500/10 text-fg' : 'border-hairline bg-muted/5 text-muted hover:border-fg'
          }`}
        >
          <span className='text-sm'>{r.emoji}</span>
          {r.count}
        </button>
      ))}

      {/* Add-reaction control: a small face that opens a picker. Hidden until
          row hover (Slack-style) once there are already reactions. */}
      <div className='relative'>
        <button
          type='button'
          onClick={() => setPickerOpen((o) => !o)}
          aria-label='Add reaction'
          className={`inline-flex h-6 w-6 items-center justify-center rounded-full border border-hairline bg-muted/5 text-muted transition-all hover:border-fg hover:text-fg active:scale-[0.96] ${
            reactions.length > 0 ? 'opacity-0 group-hover/row:opacity-100 focus-visible:opacity-100' : 'opacity-100'
          }`}
        >
          <svg width='15' height='15' viewBox='0 0 24 24' fill='none' stroke='currentColor' strokeWidth='1.6' aria-hidden>
            {/* smiley face (lower-left) */}
            <circle cx='9.5' cy='13.5' r='7' />
            <circle cx='7' cy='12' r='0.9' fill='currentColor' stroke='none' />
            <circle cx='12' cy='12' r='0.9' fill='currentColor' stroke='none' />
            <path d='M6.6 15.4c1.3 1.5 4 1.5 5.3 0' strokeLinecap='round' />
            {/* plus (upper-right), clear of the face */}
            <path d='M20 3.5v6M17 6.5h6' strokeWidth='2' strokeLinecap='round' />
          </svg>
        </button>
        {pickerOpen ? (
          <div
            className='absolute bottom-7 left-0 z-10 flex gap-0.5 rounded-lg border border-hairline bg-bg p-1 shadow-md'
            onMouseLeave={() => setPickerOpen(false)}
          >
            {REACTION_EMOJI.map((e) => (
              <button
                key={e}
                type='button'
                onClick={() => {
                  setPickerOpen(false)
                  onToggle(e)
                }}
                className='flex h-7 w-7 items-center justify-center rounded-md text-base transition-colors hover:bg-muted/20 active:scale-[0.96]'
              >
                {e}
              </button>
            ))}
          </div>
        ) : null}
      </div>
    </div>
  )
}

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
          {actions.busy ? 'One moment…' : actions.hasPasskey ? 'Unlock to post' : 'Join to post'}
        </button>
        <span className='text-xs text-muted'>
          {actions.status ?? 'Set up a passkey to join — it stays on your device.'}
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
          className='h-10 w-full rounded-lg border border-hairline bg-transparent px-3 text-sm outline-none transition-colors duration-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/25 sm:h-9'
          value={text}
          placeholder='Message the lobby…'
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
            Return to send
            {[...trimmed].length > MAX_CHARS - 40 ? (
              <span className='tabular-nums'>
                {' · '}
                {[...trimmed].length}/{MAX_CHARS}
              </span>
            ) : null}
          </>
        )}
      </p>
    </div>
  )
}

/**
 * Slack-style timestamp from an epoch-ms stamp, with a full-datetime `title` for
 * hover. GUARDS against a bogus `ts` (0 / negative / non-finite — which would
 * otherwise render an absurd "20629d"): such items get an empty label rather
 * than a wrong one. Recent → relative; today → clock time; older → a short date.
 */
function fmtTime(ms: number): { label: string; title: string } {
  if (!Number.isFinite(ms) || ms <= 0) return { label: '', title: '' }
  const now = Date.now()
  const d = new Date(ms)
  const title = d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
  const diff = Math.max(0, now - ms)
  const sec = Math.floor(diff / 1000)
  if (sec < 60) return { label: 'now', title }
  if (sec < 3600) return { label: `${Math.floor(sec / 60)}m`, title }
  const sameDay = new Date(now).toDateString() === d.toDateString()
  if (sameDay) return { label: d.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' }), title }
  const sameYear = new Date(now).getFullYear() === d.getFullYear()
  return {
    label: d.toLocaleDateString(undefined, sameYear ? { month: 'short', day: 'numeric' } : { month: 'short', day: 'numeric', year: 'numeric' }),
    title,
  }
}
