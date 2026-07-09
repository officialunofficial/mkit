'use client'

// The front-page signed lobby — ONE merged feed of a room's signed activity:
// chat messages AND commits pushed in /multiplayer, plus signed emoji reactions,
// all keyed to the same passkey-derived Ed25519 identity and labelled with the
// player's keys.mkit.sh handle. A grouped, chat-style feed (hover actions,
// reactions) in mkit's white/Geist palette. Reading is open; posting +
// reacting require an unlocked identity (shared with the multiplayer demo).

import { useVirtualizer } from '@tanstack/react-virtual'
import * as Popover from '@radix-ui/react-popover'
import { type ReactNode, useEffect, useLayoutEffect, useMemo, useRef as useReactRef, useState } from 'react'
import { DEFAULT_ROOM, useIdentityStore } from '../../lib/identity-store'
import { usePresence } from '../../lib/presence-store'
import {
  type FeedItem,
  MAX_MESSAGE_CHARS,
  type ReactionAgg,
  RepoBackendProvider,
  isForkRef,
  useLobbyEvents,
  useLobbyFeed,
  useObject,
  usePostMessage,
  useReactions,
  useResolvedRepoBackend,
  useToggleReaction,
} from '../../lib/repo-api'
import { CopyButton } from '../copy-button'
import { useIdentityActions } from '../use-identity-actions'
import { useMkit } from '../use-mkit'
import { PlayerAvatar, PlayerLabel } from '../multiplayer/player-label'
import { BTN, FOCUS_RING, HOVER_BORDER, PRIMARY_BTN, errMsg } from '../multiplayer/shared'

/** A live, client-only presence notice spliced into the feed (not a server object). */
type SystemNoticeItem = { kind: 'system'; sysKind: 'left' | 'viewer'; pubkey: string; ts: number; key: string }
/** The commit variant of a feed item, narrowed for the notice + drawer. */
type CommitItem = Extract<FeedItem, { kind: 'commit' }>
/** Everything the feed renders: real feed items plus ephemeral presence notices. */
type RenderItem = FeedItem | SystemNoticeItem

/** How long to wait after a member drops before classifying it (lock reconnects as a viewer a beat later). */
const PRESENCE_DEBOUNCE_MS = 900

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

/**
 * `useLayoutEffect` on the client, `useEffect` (a no-op-during-SSR-safe stand-in) on the server — avoids React's
 * "useLayoutEffect does nothing on the server" warning. Used for the initial bottom-pin below, which MUST run
 * synchronously before the browser's first paint (see {@link Feed}).
 */
const useIsomorphicLayoutEffect = typeof window === 'undefined' ? useEffect : useLayoutEffect

export function SignedLobby() {
  const api = useMkit()
  // One shared room — the lobby is a single channel.
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
  const presenceNotices = usePresenceNotices(room)
  // The commit whose detail drawer is open (null = closed).
  const [openCommit, setOpenCommit] = useState<CommitItem | null>(null)

  // Splice the live presence notices into the feed and re-sort by timestamp.
  // Notices carry a "now" ts, so they land at the bottom as they happen.
  const rendered = useMemo<RenderItem[]>(
    () => [...items, ...presenceNotices].sort((a, b) => a.ts - b.ts),
    [items, presenceNotices],
  )

  return (
    <section className='space-y-3'>
      {/* Header, feed, and composer share one bordered card. `relative` +
          `overflow-hidden` make this card the positioning + clipping context for
          the commit drawer, so it slides in OVER the lobby only (not the whole
          page) and can't change the card's size. The header bar is the visual
          bookend of the composer footer below it — same `border + px-4 py-3`
          treatment (a `border-b` here mirroring the footer's `border-t`). */}
      <div className='relative overflow-hidden rounded-md border border-hairline'>
        <div className='flex items-center gap-2 border-b border-hairline px-4 py-3'>
          <span className='relative flex h-2 w-2' aria-hidden>
            <span className='absolute inline-flex h-full w-full animate-ping rounded-full bg-green-500/60' />
            <span className='relative inline-flex h-2 w-2 rounded-full bg-green-500' />
          </span>
          <h2 className='text-lg font-medium tracking-tight'>Live lobby</h2>
        </div>
        <Feed room={room} items={rendered} isLoading={isLoading} onOpenCommit={setOpenCommit} />
        <Composer room={room} />
        {openCommit ? <CommitDrawer room={room} item={openCommit} onClose={() => setOpenCommit(null)} /> : null}
      </div>
    </section>
  )
}

/**
 * Watches the room roster and emits ephemeral "left the chat" / "is now viewing only" notices for departing members.
 *
 * Presence only exposes the current roster (named `members` + an anonymous `viewers` count), so a member dropping is
 * detected by diffing successive rosters. Distinguishing a true disconnect from a lock (which reconnects a beat later
 * as a viewer) needs a short debounce: when a member disappears we wait {@link PRESENCE_DEBOUNCE_MS}, then — if they
 * haven't returned as a member — classify by whether the viewer count went UP (→ became viewer-only) or not (→ left).
 * It's a heuristic (viewers are anonymous), good enough for a live feed; our own key is never narrated.
 */
function usePresenceNotices(room: string): SystemNoticeItem[] {
  const presence = usePresence(room)
  const myPubkey = useIdentityStore((s) => s.ed25519PubkeyHex)
  const [notices, setNotices] = useState<SystemNoticeItem[]>([])

  // Latest roster for the timers to read when they fire.
  const presenceRef = useReactRef(presence)
  presenceRef.current = presence
  const prevMembersRef = useReactRef<Set<string> | null>(null)
  const timersRef = useReactRef<Map<string, ReturnType<typeof setTimeout>>>(new Map())

  useEffect(() => {
    const current = new Set(presence.members.map((m) => m.pubkeyHex))
    const prev = prevMembersRef.current
    if (prev) {
      // Anyone who reappeared as a member cancels their pending classification.
      for (const pk of current) {
        const t = timersRef.current.get(pk)
        if (t) {
          clearTimeout(t)
          timersRef.current.delete(pk)
        }
      }
      const viewersAtDeparture = presence.viewers
      for (const pk of prev) {
        if (current.has(pk) || pk === myPubkey || timersRef.current.has(pk)) continue
        const timer = setTimeout(() => {
          timersRef.current.delete(pk)
          const snap = presenceRef.current
          if (snap.members.some((m) => m.pubkeyHex === pk)) return // came back as a member
          const becameViewer = snap.viewers > viewersAtDeparture
          const firedAt = Date.now()
          setNotices((list) =>
            [
              ...list,
              {
                kind: 'system' as const,
                sysKind: becameViewer ? ('viewer' as const) : ('left' as const),
                pubkey: pk,
                ts: firedAt,
                key: `sys:${pk}:${firedAt}`,
              },
            ].slice(-50),
          )
        }, PRESENCE_DEBOUNCE_MS)
        timersRef.current.set(pk, timer)
      }
    }
    prevMembersRef.current = current
  }, [presence, myPubkey, presenceRef, prevMembersRef, timersRef])

  // Clear any pending timers on unmount.
  useEffect(() => {
    const timers = timersRef.current
    return () => {
      for (const t of timers.values()) clearTimeout(t)
      timers.clear()
    }
  }, [timersRef])

  return notices
}

function Feed({
  room,
  items,
  isLoading,
  onOpenCommit,
}: {
  room: string
  items: RenderItem[]
  isLoading: boolean
  onOpenCommit: (item: CommitItem) => void
}) {
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

  // START pinned to the newest row. The FIRST time the feed has rows, pin
  // SYNCHRONOUSLY in a layout effect — before the browser paints — so the very
  // first frame the user sees already sits at the bottom; nothing renders top-
  // first and then visibly scrolls down. Re-assert across the next few frames
  // too, because that initial jump runs against ESTIMATED row sizes and
  // `measureElement` corrects them a frame or two later (without the
  // re-assert the feed lands short of the true bottom). After init, follow
  // ONLY when a new row actually arrives and you're already at the bottom —
  // keyed on `items.length`, NOT the virtualizer's total size, so pure
  // measurement churn (async avatar/name loads, a reaction resizing a row)
  // can never re-pin and fight a manual scroll-up.
  useIsomorphicLayoutEffect(() => {
    if (items.length === 0) return
    const last = items.length - 1
    const grew = items.length > prevLenRef.current
    prevLenRef.current = items.length

    if (!didInitRef.current) {
      didInitRef.current = true
      virtualizer.scrollToIndex(last, { align: 'end' })
      let n = 0
      let raf = requestAnimationFrame(function pin() {
        virtualizer.scrollToIndex(last, { align: 'end' })
        if (++n < 3) raf = requestAnimationFrame(pin)
      })
      return () => cancelAnimationFrame(raf)
    }
    if (grew && atBottomRef.current) {
      virtualizer.scrollToIndex(last, { align: 'end', behavior: 'smooth' })
    }
  }, [items.length, virtualizer, atBottomRef, didInitRef, prevLenRef])

  const jumpToLatest = () => {
    setBottom(true)
    if (items.length > 0) virtualizer.scrollToIndex(items.length - 1, { align: 'end', behavior: 'smooth' })
  }

  const empty = items.length === 0
  return (
    <div className='relative'>
      {/* FIXED height (not max-h): the virtualizer needs a definite viewport, and a
          fixed box means the list scrolls internally instead of growing the page
          as messages arrive. */}
      <div ref={scrollRef} onScroll={onScroll} className='h-96 overflow-y-auto py-1'>
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
                  {item.kind === 'system' ? (
                    <SystemNotice notice={item} />
                  ) : item.kind === 'commit' ? (
                    <CommitNotice item={item} onOpen={() => onOpenCommit(item)} />
                  ) : (
                    <Row
                      item={item}
                      // Group only consecutive chat messages from the same author within the window —
                      // commits and presence notices break a run.
                      grouped={
                        !!prev &&
                        prev.kind === 'chat' &&
                        prev.message.authorPubkeyHex === item.message.authorPubkeyHex &&
                        item.ts >= prev.ts &&
                        item.ts - prev.ts < GROUP_WINDOW_MS
                      }
                      // Reactions key on the message id, which is unique per post (the server folds the
                      // signed idempotency nonce into it), so identical text re-posted gets distinct ids
                      // and a reaction can't leak across the two.
                      reactions={reactionsFor(item.message.messageIdHex)}
                      canReact={unlocked}
                      onToggle={(emoji) =>
                        unlocked ? toggle.mutate({ targetId: item.message.messageIdHex, emoji }) : onNeedIdentity()
                      }
                    />
                  )}
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
 * (hover-revealed); any existing reaction pills sit on their own line below. Commits and presence notices render via
 * their own components ({@link CommitNotice}, {@link SystemNotice}), not here.
 */
function Row({
  item,
  grouped,
  reactions,
  canReact,
  onToggle,
}: {
  item: Extract<FeedItem, { kind: 'chat' }>
  grouped: boolean
  reactions: ReactionAgg[]
  canReact: boolean
  onToggle: (emoji: string) => void
}) {
  const pubkey = item.message.authorPubkeyHex
  const time = fmtTime(item.ts)

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
          </div>
        )}
        <div className={grouped ? '' : 'mt-0.5'}>
          <div className='flex items-start gap-2'>
            <div className='min-w-0 flex-1'>
              <p className='break-words whitespace-pre-wrap text-fg'>{item.message.text}</p>
            </div>
            <AddReaction onToggle={onToggle} />
          </div>
        </div>
        {reactions.length > 0 ? <ReactionPills reactions={reactions} canReact={canReact} onToggle={onToggle} /> : null}
      </div>
    </div>
  )
}

/**
 * A commit/fork in the feed, styled like a chat SYSTEM message: centered, small text, a small avatar — visually
 * distinct from a person's chat message. The whole line is a button that opens the commit-detail drawer.
 */
function CommitNotice({ item, onOpen }: { item: CommitItem; onOpen: () => void }) {
  const e = item.entry
  const time = fmtTime(item.ts)
  const fork = isForkRef(e.ref)
  return (
    <div className='px-4 py-1.5'>
      <button
        type='button'
        onClick={onOpen}
        title='View commit details'
        className='group/sys mx-auto flex max-w-full flex-wrap items-center justify-center gap-x-1.5 gap-y-0.5 rounded-md px-2 py-1 text-center text-[11px] leading-snug text-muted transition-colors hover:bg-muted/10 hover:text-fg'
      >
        <PlayerAvatar pubkey={e.authorPubkey} size={16} />
        <PlayerLabel pubkey={e.authorPubkey} className='font-medium text-fg' />
        <span>{fork ? 'forked' : 'pushed'}</span>
        <code className='font-mono text-fg'>{e.hash.slice(0, 10)}</code>
        <span>to</span>
        <code className='font-mono text-fg'>{e.ref}</code>
        {e.message ? <span className='truncate'>— “{e.message}”</span> : null}
        <time className='tabular-nums opacity-70' title={time.title}>
          {time.clock}
        </time>
        <span aria-hidden className='opacity-0 transition-opacity group-hover/sys:opacity-70'>
          ›
        </span>
      </button>
    </div>
  )
}

/** A live presence notice (left / became viewer-only), centered and quiet — the lightest row in the feed. */
function SystemNotice({ notice }: { notice: SystemNoticeItem }) {
  return (
    <div className='px-4 py-1'>
      <p className='mx-auto flex max-w-full flex-wrap items-center justify-center gap-1.5 text-center text-[11px] text-muted'>
        <PlayerLabel pubkey={notice.pubkey} className='font-medium' />
        {notice.sysKind === 'left' ? 'left the chat' : 'is now viewing only'}
      </p>
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
    // Priority: a live result from an actual attempt, then the proactive in-app-browser
    // notice (shown before any tap), then the default first-time hint.
    const hint =
      actions.status ??
      actions.embeddedBrowserWarning ??
      (actions.hasPasskey ? null : 'Set up a passkey. No email, no passwords.')
    return (
      <div className='flex flex-wrap items-center gap-3 border-t border-hairline px-4 py-3'>
        <button
          type='button'
          className={PRIMARY_BTN}
          disabled={actions.busy}
          onClick={() => void (actions.hasPasskey ? actions.onUnlock() : actions.onCreate())}
        >
          {actions.busy ? (
            'Waiting for your passkey…'
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
        {/* The "set up a passkey" prompt only makes sense for a first-time
            visitor (button reads "Join to chat"). When they already have a
            passkey (button reads "Unlock to chat"), drop the static copy and
            show only a live status message, if any. */}
        {hint ? <span className='text-xs text-muted'>{hint}</span> : null}
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
      {/* Only surface a line when there's something worth saying — a warning, or
          the character counter as you near the cap. (No idle "Return to send".) */}
      {over ? (
        <p className='text-xs text-amber-700 dark:text-amber-400'>Message is over {MAX_CHARS} characters.</p>
      ) : post.isError ? (
        <p className='text-xs text-amber-700 dark:text-amber-400'>{errMsg(post.error)}</p>
      ) : post.data?.rateLimited ? (
        <p className='text-xs text-amber-700 dark:text-amber-400'>You’re posting too fast — wait a moment.</p>
      ) : [...trimmed].length > MAX_CHARS - 40 ? (
        <p className='text-xs text-muted tabular-nums'>
          {[...trimmed].length}/{MAX_CHARS}
        </p>
      ) : null}
    </div>
  )
}

/**
 * Right-sliding drawer with the full commit object: identity, message, branch, hashes, parents, tree, signature, and
 * (for a remix) its sources — plus reactions. The feed entry carries the basics; the richer fields (parents, tree,
 * signature, exact time) come from decoding the raw object bytes (`useObject` → `commit_decode`/`remix_decode`).
 * Rendered through a portal over a backdrop; Escape or a backdrop click closes it.
 */
function CommitDrawer({ room, item, onClose }: { room: string; item: CommitItem; onClose: () => void }) {
  const api = useMkit()
  const e = item.entry
  const obj = useObject(room, e.hash)
  const decoded = useMemo(() => decodeCommitDetails(api, obj.data ?? null), [api, obj.data])

  const unlocked = useIdentityStore((s) => s.unlocked)
  const myPubkey = useIdentityStore((s) => s.ed25519PubkeyHex)
  const actions = useIdentityActions()
  const reactionsFor = useReactions(room, myPubkey ?? undefined)
  const toggle = useToggleReaction(room, myPubkey ?? undefined)
  const reactions = reactionsFor(e.hash)
  const onToggle = (emoji: string) =>
    unlocked
      ? toggle.mutate({ targetId: e.hash, emoji })
      : void (actions.hasPasskey ? actions.onUnlock() : actions.onCreate())

  // `open` drives the slide. Mount → flip to true next tick (slide IN). Closing
  // flips it false (slide OUT); the panel's transform `transitionend` then calls
  // onClose to actually unmount — so the exit animates instead of vanishing.
  const [open, setOpen] = useState(false)
  useEffect(() => {
    const raf = requestAnimationFrame(() => setOpen(true))
    const onKey = (ev: KeyboardEvent) => {
      if (ev.key === 'Escape') setOpen(false)
    }
    window.addEventListener('keydown', onKey)
    return () => {
      cancelAnimationFrame(raf)
      window.removeEventListener('keydown', onKey)
    }
  }, [])

  const fork = isForkRef(e.ref)
  const timestamp = decoded ? decoded.timestampMs : Date.parse(e.createdAt)

  // Rendered INSIDE the lobby card (absolute, not a body portal): the backdrop
  // and panel are confined to the card, so it overlays the lobby only — never
  // the page — and being absolutely positioned it can't change the card's size.
  return (
    <div className='absolute inset-0 z-20'>
      <button
        type='button'
        aria-label='Close commit details'
        onClick={() => setOpen(false)}
        className={`absolute inset-0 bg-black/30 transition-opacity duration-300 ${open ? 'opacity-100' : 'opacity-0'}`}
      />
      <aside
        role='dialog'
        aria-label='Commit details'
        // Unmount only after the SLIDE-OUT finishes — the panel's OWN translate
        // transition ending while closing (ignore bubbled transitions from
        // children). Tailwind's `translate-x-*` utilities animate the CSS
        // `translate` property, NOT `transform` — matching on `'transform'`
        // here meant this NEVER fired, so the drawer (and its full-card
        // backdrop) never unmounted on close, leaving it stuck over the feed
        // blocking scroll and any further clicks.
        onTransitionEnd={(ev) => {
          if (ev.target === ev.currentTarget && ev.propertyName === 'translate' && !open) onClose()
        }}
        className={`absolute inset-y-0 right-0 flex w-[92%] max-w-sm flex-col rounded-l-md border-l border-hairline bg-bg shadow-xl transition-transform duration-300 ease-[cubic-bezier(0.2,0,0,1)] ${open ? 'translate-x-0' : 'translate-x-full'}`}
      >
        <header className='flex items-center justify-between gap-3 border-b border-hairline px-4 py-3'>
          <h2 className='text-sm font-semibold'>{e.kind === 'remix' ? 'Remix' : 'Commit'} details</h2>
          <button
            type='button'
            onClick={() => setOpen(false)}
            aria-label='Close'
            className='-m-1.5 inline-flex size-7 items-center justify-center rounded-md text-muted transition-colors hover:bg-muted/10 hover:text-fg'
          >
            <svg
              width='16'
              height='16'
              viewBox='0 0 16 16'
              fill='none'
              stroke='currentColor'
              strokeWidth='1.5'
              strokeLinecap='round'
              aria-hidden
            >
              <path d='M4 4 L12 12 M12 4 L4 12' />
            </svg>
          </button>
        </header>

        <div className='flex-1 space-y-5 overflow-y-auto px-4 py-4 text-sm'>
          <div className='flex items-center gap-2'>
            <PlayerAvatar pubkey={e.authorPubkey} size={28} />
            <div className='min-w-0'>
              <PlayerLabel pubkey={e.authorPubkey} className='block font-medium' />
              <code className='block truncate font-mono text-xs text-muted'>{e.authorPubkey}</code>
            </div>
          </div>

          <DrawerField label='Message'>
            <p className='whitespace-pre-wrap break-words text-fg'>
              {e.message || <span className='text-muted'>(no message)</span>}
            </p>
          </DrawerField>

          <DrawerField label='Branch'>
            <span className='inline-flex items-center gap-2'>
              <code className='font-mono text-fg'>{e.ref}</code>
              <span className='rounded-sm border border-hairline px-1 text-[10px] uppercase tracking-wide text-muted'>
                {fork ? 'fork' : e.kind === 'remix' ? 'remix' : 'commit'}
              </span>
            </span>
          </DrawerField>

          {Number.isFinite(timestamp) && timestamp > 0 ? (
            <DrawerField label='When'>
              <time>{new Date(timestamp).toLocaleString()}</time>
            </DrawerField>
          ) : null}

          <DrawerHash label='Commit hash' value={e.hash} />
          {decoded?.tree ? <DrawerHash label='Tree' value={decoded.tree} /> : null}
          {decoded && decoded.parents.length > 0 ? (
            <DrawerField label={decoded.parents.length > 1 ? 'Parents' : 'Parent'}>
              <div className='space-y-1'>
                {decoded.parents.map((p) => (
                  <code key={p} className='block break-all font-mono text-xs text-muted'>
                    {p}
                  </code>
                ))}
              </div>
            </DrawerField>
          ) : null}
          {e.sources && e.sources.length > 0 ? (
            <DrawerField label='Remixed from'>
              <div className='space-y-1'>
                {e.sources.map((s) => (
                  <code key={s.commitHashHex} className='block break-all font-mono text-xs text-muted'>
                    {s.commitHashHex}
                  </code>
                ))}
              </div>
            </DrawerField>
          ) : null}
          {decoded?.signature ? <DrawerHash label='Signature' value={decoded.signature} /> : null}

          <DrawerField label='Reactions'>
            <div className='flex flex-wrap items-center gap-1.5'>
              {reactions.length > 0 ? (
                <ReactionPills reactions={reactions} canReact={unlocked} onToggle={onToggle} />
              ) : (
                <span className='text-xs text-muted'>No reactions yet.</span>
              )}
              <DrawerAddReaction onToggle={onToggle} />
            </div>
          </DrawerField>

          {!decoded && obj.isLoading ? <p className='text-xs text-muted'>Loading commit object…</p> : null}
        </div>
      </aside>
    </div>
  )
}

/** Label-over-value block used throughout the commit drawer. */
function DrawerField({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className='space-y-1'>
      <div className='text-xs text-muted'>{label}</div>
      <div>{children}</div>
    </div>
  )
}

/** A drawer field whose value is a full hex id, with a copy button. */
function DrawerHash({ label, value }: { label: string; value: string }) {
  return (
    <div className='space-y-1'>
      <div className='text-xs text-muted'>{label}</div>
      <div className='flex items-start gap-2'>
        <code className='min-w-0 flex-1 break-all font-mono text-xs text-fg'>{value}</code>
        <CopyButton text={value} />
      </div>
    </div>
  )
}

/** Always-visible add-reaction control for the drawer (the feed's hover-only one would be invisible here). */
function DrawerAddReaction({ onToggle }: { onToggle: (emoji: string) => void }) {
  const [open, setOpen] = useState(false)
  return (
    <Popover.Root open={open} onOpenChange={setOpen}>
      <Popover.Trigger asChild>
        <button
          type='button'
          className={`inline-flex h-6 items-center gap-1 rounded-full border border-hairline bg-muted/5 px-2 text-xs text-muted ${HOVER_BORDER} hover:text-fg active:scale-[0.96]`}
        >
          + React
        </button>
      </Popover.Trigger>
      <Popover.Portal>
        <Popover.Content
          side='top'
          align='start'
          sideOffset={6}
          collisionPadding={8}
          onCloseAutoFocus={(ev) => ev.preventDefault()}
          // Above the drawer (z-60).
          className='z-[70] flex gap-0.5 rounded-lg border border-hairline bg-bg p-1 shadow-md'
        >
          {REACTION_EMOJI.map((em) => (
            <button
              key={em}
              type='button'
              onClick={() => {
                onToggle(em)
                setOpen(false)
              }}
              className='flex h-7 w-7 items-center justify-center rounded-md text-base transition-colors hover:bg-muted/20 active:scale-[0.96]'
            >
              {em}
            </button>
          ))}
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  )
}

/** Decode the rich commit/remix fields (parents, tree, signature, timestamp) from raw object bytes; null on any error. */
function decodeCommitDetails(
  api: ReturnType<typeof useMkit>,
  bytes: Uint8Array | null,
): { tree: string; signature: string; parents: string[]; timestampMs: number } | null {
  if (!bytes) return null
  try {
    const kind = api.object_kind(bytes)
    const info = kind === 'remix' ? api.remix_decode(bytes) : kind === 'commit' ? api.commit_decode(bytes) : null
    if (!info) return null
    const parents: string[] = []
    for (let i = 0; i < info.parent_count; i++) {
      const p = info.parent(i)
      if (p) parents.push(p)
    }
    return { tree: info.tree_hex, signature: info.signature_hex, parents, timestampMs: Number(info.timestamp) * 1000 }
  } catch {
    return null
  }
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
