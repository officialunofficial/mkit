'use client'

// The front-page signed lobby — ONE merged feed of a room's signed activity:
// chat messages AND commits pushed in /multiplayer, plus signed emoji reactions,
// all keyed to the same passkey-derived Ed25519 identity and labelled with the
// player's keys.mkit.sh handle. A grouped, chat-style feed (hover actions,
// reactions) in mkit's white/Geist palette. Reading is open; posting +
// reacting require an unlocked identity (shared with the multiplayer demo).

import { useVirtualizer } from '@tanstack/react-virtual'
import * as DropdownMenu from '@radix-ui/react-dropdown-menu'
import * as Popover from '@radix-ui/react-popover'
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
import { BTN, FOCUS_RING, HOVER_BORDER, PRIMARY_BTN, errMsg } from '../multiplayer/shared'

/** Message length cap — the SAME shared constant the server enforces. */
const MAX_CHARS = MAX_MESSAGE_CHARS

/**
 * Emojis offered in the add-reaction picker. MUST stay in sync with the server allowlist `REACTION_EMOJI` in
 * apps/repo-worker/src/chat.rs (the authority — it rejects anything else): a reaction with an emoji missing here can't
 * be sent, and one only listed here would be refused server-side. Edit both together.
 */
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

/**
 * Channels the lobby can switch between — each is its own room (own feed + live stream), so the header reads as a real
 * chat room with channels.
 */
const CHANNELS = ['lobby', 'general', 'random'] as const

export function SignedLobby() {
  const api = useMkit()
  const storeRoom = useIdentityStore((s) => s.room) || DEFAULT_ROOM
  // Channel selection is local to the lobby; switching just re-points the feed +
  // backend at a different room.
  const [room, setRoom] = useState(storeRoom)
  const { backend } = useResolvedRepoBackend(api, room)

  return (
    <RepoBackendProvider backend={backend}>
      <LobbyBody room={room} onSelectChannel={setRoom} />
    </RepoBackendProvider>
  )
}

/** Header dropdown to switch the active channel. */
function ChannelSwitcher({ room, onSelect }: { room: string; onSelect: (channel: string) => void }) {
  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger asChild>
        <button
          type='button'
          title='Switch channel'
          className='group inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 font-mono text-sm text-muted transition-colors hover:bg-muted/10 data-[state=open]:text-fg'
        >
          #{room}
          <span aria-hidden className='text-[10px] opacity-70 transition-transform group-data-[state=open]:rotate-180'>
            ▾
          </span>
        </button>
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content
          align='start'
          sideOffset={4}
          className='z-50 min-w-[9rem] overflow-hidden rounded-lg border border-hairline bg-bg p-1 shadow-md'
        >
          {CHANNELS.map((c) => (
            <DropdownMenu.Item
              key={c}
              onSelect={() => onSelect(c)}
              className={`flex cursor-pointer items-center gap-1.5 rounded-md px-2 py-1 font-mono text-sm outline-none transition-colors data-[highlighted]:bg-muted/10 ${
                c === room ? 'text-fg' : 'text-muted'
              }`}
            >
              #{c}
              {c === room ? (
                <span aria-hidden className='ml-auto text-[10px]'>
                  ✓
                </span>
              ) : null}
            </DropdownMenu.Item>
          ))}
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  )
}

function LobbyBody({ room, onSelectChannel }: { room: string; onSelectChannel: (channel: string) => void }) {
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
        <ChannelSwitcher room={room} onSelect={onSelectChannel} />
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
  const prevLenRef = useReactRef(0)

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

  // Depending on the virtualizer's total size (not just `items.length`) re-runs
  // this when row heights change without the count changing — a reaction
  // expanding the last row, or `measureElement` correcting an estimate.
  const totalSize = virtualizer.getTotalSize()

  // START pinned to the newest row, and STAY pinned. The FIRST time the feed has
  // rows, jump INSTANTLY — and re-assert across the next few frames, because the
  // initial jump runs against ESTIMATED row sizes and `measureElement` corrects
  // them a frame or two later (without the re-assert the feed lands short of the
  // true bottom — the "it scrolls to the end" effect). After init, follow while
  // pinned: a genuinely new row gets a gentle smooth nudge; pure height growth (a
  // reaction, a late measurement) re-pins INSTANTLY so it never animates.
  useEffect(() => {
    if (items.length === 0) return
    const last = items.length - 1
    const grew = items.length > prevLenRef.current
    prevLenRef.current = items.length

    if (!didInitRef.current) {
      didInitRef.current = true
      let n = 0
      let raf = requestAnimationFrame(function pin() {
        virtualizer.scrollToIndex(last, { align: 'end' })
        if (++n < 3) raf = requestAnimationFrame(pin)
      })
      return () => cancelAnimationFrame(raf)
    }
    if (atBottomRef.current) {
      virtualizer.scrollToIndex(last, { align: 'end', behavior: grew ? 'smooth' : 'auto' })
    }
  }, [items.length, totalSize, virtualizer, atBottomRef, didInitRef, prevLenRef])

  const jumpToLatest = () => {
    setBottom(true)
    if (items.length > 0) virtualizer.scrollToIndex(items.length - 1, { align: 'end', behavior: 'smooth' })
  }

  const empty = items.length === 0
  return (
    <div className='relative'>
      <div ref={scrollRef} onScroll={onScroll} className='max-h-96 min-h-44 overflow-y-auto py-1'>
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
                  style={{
                    position: 'absolute',
                    top: 0,
                    left: 0,
                    width: '100%',
                    transform: `translateY(${vrow.start}px)`,
                  }}
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
        className={`absolute right-3 bottom-3 inline-flex h-8 items-center rounded-full border border-hairline bg-bg/90 px-3 text-xs shadow-sm backdrop-blur transition-[opacity,scale,border-color] duration-200 ease-[cubic-bezier(0.2,0,0,1)] before:absolute before:inset-x-0 before:-inset-y-1 before:content-[""] ${HOVER_BORDER} active:scale-[0.96] ${
          atBottom || empty ? 'pointer-events-none scale-95 opacity-0' : 'opacity-100'
        }`}
      >
        ↓ Latest
      </button>
    </div>
  )
}

/**
 * One chat-style feed row: full header (avatar + name + time) for a run's first message; a tight, indented continuation
 * when `grouped` (timestamp shows on hover). The add-reaction trigger sits inline at the end of the content line
 * (hover-revealed); any existing reaction pills sit on their own line below.
 */
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
      // Commit lines read as secondary to chat messages — smaller than the
      // row's base `text-sm`.
      <p className='text-[11px] leading-snug text-muted'>
        pushed <code className='font-mono text-fg'>{item.entry.hash.slice(0, 10)}</code> to{' '}
        <code className='font-mono text-fg'>{item.entry.ref}</code>
        {item.entry.message ? <span className='text-muted'> — “{item.entry.message}”</span> : null}
      </p>
    )

  return (
    <div
      className={`group/row relative flex gap-2.5 px-4 text-sm transition-colors hover:bg-muted/10 ${grouped ? 'py-0.5' : 'mt-1 py-1'}`}
    >
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
            <time title={time.title} className='shrink-0 text-xs text-muted tabular-nums'>
              {time.clock}
            </time>
            {item.kind === 'commit' ? (
              <span className='rounded-sm border border-hairline px-1 text-[10px] uppercase tracking-wide text-muted'>
                {isForkRef(item.entry.ref) ? 'fork' : 'commit'}
              </span>
            ) : null}
          </div>
        )}
        <div className={grouped ? '' : 'mt-0.5'}>
          <div className='flex items-start gap-2'>
            <div className='min-w-0 flex-1'>{body}</div>
            <AddReaction onToggle={onToggle} />
          </div>
        </div>
        {reactions.length > 0 ? <ReactionPills reactions={reactions} canReact={canReact} onToggle={onToggle} /> : null}
      </div>
    </div>
  )
}

/**
 * Existing-reaction pills, shown on their own line BELOW the content when a message has any reactions. Pills highlight
 * when you've reacted; clicking toggles. (The add-emoji trigger lives inline on the content line — see AddReaction —
 * not here.)
 */
function ReactionPills({
  reactions,
  canReact,
  onToggle,
}: {
  reactions: ReactionAgg[]
  canReact: boolean
  onToggle: (emoji: string) => void
}) {
  return (
    <div className='mt-1 flex flex-wrap items-center gap-1'>
      {reactions.map((r) => (
        <button
          key={r.emoji}
          type='button'
          onClick={() => onToggle(r.emoji)}
          title={
            canReact ? (r.mine ? 'Remove your reaction' : 'Add your reaction') : 'Sign in with your passkey to react'
          }
          className={`inline-flex h-6 items-center gap-1 rounded-full border px-2 text-xs leading-none tabular-nums transition-colors active:scale-[0.96] ${
            r.mine
              ? 'border-blue-500/60 bg-blue-500/10 text-fg'
              : `border-hairline bg-muted/5 text-muted ${HOVER_BORDER} hover:text-fg`
          }`}
        >
          <span className='text-sm'>{r.emoji}</span>
          {r.count}
        </button>
      ))}
    </div>
  )
}

/**
 * The add-reaction trigger: a small face that sits INLINE at the end of the content line and opens an emoji picker. On
 * hover-capable pointers it's hidden until row hover (or keyboard focus / an open picker) so it isn't a persistent
 * distraction on every row; on coarse/touch pointers — where there's no hover to reveal it —
 * `pointer-coarse:opacity-100` keeps it always visible so it stays reachable. The picker itself renders in a PORTAL
 * (see EmojiPicker) so the feed's `overflow-y-auto` can't clip it.
 */
function AddReaction({ onToggle }: { onToggle: (emoji: string) => void }) {
  const [open, setOpen] = useState(false)
  return (
    <Popover.Root open={open} onOpenChange={setOpen}>
      <Popover.Trigger asChild>
        <button
          type='button'
          aria-label='Add reaction'
          className={`inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-full border border-hairline bg-muted/5 text-muted opacity-0 transition-all ${HOVER_BORDER} hover:text-fg active:scale-[0.96] focus-visible:opacity-100 group-hover/row:opacity-100 pointer-coarse:opacity-100 data-[state=open]:opacity-100`}
        >
          <svg
            width='15'
            height='15'
            viewBox='0 0 24 24'
            fill='none'
            stroke='currentColor'
            strokeWidth='1.6'
            aria-hidden
          >
            {/* smiley face (lower-left) */}
            <circle cx='9.5' cy='13.5' r='7' />
            <circle cx='7' cy='12' r='0.9' fill='currentColor' stroke='none' />
            <circle cx='12' cy='12' r='0.9' fill='currentColor' stroke='none' />
            <path d='M6.6 15.4c1.3 1.5 4 1.5 5.3 0' strokeLinecap='round' />
            {/* plus (upper-right), clear of the face */}
            <path d='M20 3.5v6M17 6.5h6' strokeWidth='2' strokeLinecap='round' />
          </svg>
        </button>
      </Popover.Trigger>
      {/* Portaled + collision-aware: opens above, flips below when there's no room,
          and follows the anchor through the feed's own scroller — no manual rect
          math. Dismiss on outside-click / Escape is built in. */}
      <Popover.Portal>
        <Popover.Content
          side='top'
          align='start'
          sideOffset={6}
          collisionPadding={8}
          onCloseAutoFocus={(e) => e.preventDefault()}
          className='z-50 flex gap-0.5 rounded-lg border border-hairline bg-bg p-1 shadow-md'
        >
          {REACTION_EMOJI.map((e) => (
            <button
              key={e}
              type='button'
              onClick={() => {
                onToggle(e)
                setOpen(false)
              }}
              className='flex h-7 w-7 items-center justify-center rounded-md text-base transition-colors hover:bg-muted/20 active:scale-[0.96]'
            >
              {e}
            </button>
          ))}
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
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
          {actions.busy ? (
            'One moment…'
          ) : (
            <span className='inline-flex items-center gap-1.5'>
              {/* Fingerprint — the passkey/biometric this action unlocks with
                  (reads as "passkey" better than a generic padlock). */}
              <svg
                width='14'
                height='14'
                viewBox='0 0 24 24'
                fill='none'
                stroke='currentColor'
                strokeWidth='2'
                strokeLinecap='round'
                strokeLinejoin='round'
                aria-hidden
              >
                <path d='M2 12C2 6.5 6.5 2 12 2a10 10 0 0 1 8 4' />
                <path d='M5 19.5C5.5 18 6 15 6 12c0-.7.12-1.37.34-2' />
                <path d='M17.29 21.02c.12-.6.43-2.3.5-3.02' />
                <path d='M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4' />
                <path d='M8.65 22c.21-.66.45-1.32.57-2' />
                <path d='M14 13.12c0 2.38 0 6.38-1 8.88' />
                <path d='M2 16h.01' />
                <path d='M21.8 16c.2-2 .131-5.354 0-6' />
                <path d='M9 6.8a6 6 0 0 1 9 5.2c0 .47 0 1.17-.02 2' />
              </svg>
              {actions.hasPasskey ? 'Unlock to chat' : 'Join to chat'}
            </span>
          )}
        </button>
        <span className='text-xs text-muted'>{actions.status ?? 'Set up a passkey. No email, no passwords.'}</span>
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
          // `text-base` on mobile stops iOS auto-zoom; `sm:text-sm` on desktop.
          className={`h-10 w-full rounded-lg border border-hairline bg-transparent px-3 text-base ${FOCUS_RING} sm:h-9 sm:text-sm`}
          value={text}
          placeholder='Message the lobby…'
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') send()
          }}
        />
        <button type='button' className={BTN} onClick={send} disabled={!canSend}>
          {post.isPending ? 'Sending…' : 'Send'}
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
 * Timestamp from an epoch-ms stamp, in two forms plus a full-datetime `title` for hover: - `label` — compact/relative,
 * for the tight continuation-row gutter: recent → "now"/"Xm"; today → clock time; older → a short date. - `clock` —
 * absolute wall-clock for the row header: today → "2:10 PM"; older → a short date (with year when it differs). GUARDS
 * against a bogus `ts` (0 / negative / non-finite — which would otherwise render an absurd "20629d"): such items get
 * empty strings rather than wrong ones.
 */
function fmtTime(ms: number): { label: string; clock: string; title: string } {
  if (!Number.isFinite(ms) || ms <= 0) return { label: '', clock: '', title: '' }
  const now = Date.now()
  const d = new Date(ms)
  const title = d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
  const sameDay = new Date(now).toDateString() === d.toDateString()
  const sameYear = new Date(now).getFullYear() === d.getFullYear()
  const clockLabel = d.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' })
  const dateLabel = d.toLocaleDateString(
    undefined,
    sameYear ? { month: 'short', day: 'numeric' } : { month: 'short', day: 'numeric', year: 'numeric' },
  )
  const clock = sameDay ? clockLabel : dateLabel
  const diff = Math.max(0, now - ms)
  const sec = Math.floor(diff / 1000)
  if (sec < 60) return { label: 'now', clock, title }
  if (sec < 3600) return { label: `${Math.floor(sec / 60)}m`, clock, title }
  if (sameDay) return { label: clockLabel, clock, title }
  return { label: dateLabel, clock, title }
}
