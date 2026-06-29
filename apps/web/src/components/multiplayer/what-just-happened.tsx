'use client'

// The "what just happened" overlay (bottom-right). Hidden until the user takes
// an action, then it EXPANDS to narrate it — real values + a green ⚡ speed
// badge — with a 15s countdown bar clipped to the top edge. Hover (or tap on
// mobile) pauses the countdown so you can read. When the countdown ends (or you
// collapse it) it shrinks to a small pill that PERSISTS, with a separate round
// ✕ button beside it to fully close. The next action re-expands it.

import { useEffect, useRef, useState } from 'react'
import { type ActivityEvent, type ActivityKind, formatMs, useActivityLog } from '../../lib/activity-log'
import { useDockExpansion } from '../../lib/dock-expansion'

// The 15s countdown lives in the CSS `wjh-countdown` animation (styles.css +
// the bar's `[animation:wjh-countdown_15s_…]` class); the bar's `animationend`
// is what collapses the card.

/** Per-kind accent dot — a quiet visual key, no new vocabulary. */
const KIND_DOT: Record<ActivityKind, string> = {
  create: 'bg-blue-500',
  unlock: 'bg-blue-500',
  lock: 'bg-amber-500',
  push: 'bg-green-500',
  fork: 'bg-purple-500',
  peer: 'bg-fuchsia-500',
}

const KIND_LABEL: Record<ActivityKind, string> = {
  create: 'identity',
  unlock: 'identity',
  lock: 'identity',
  push: 'push',
  fork: 'fork',
  peer: 'live',
}

/** Disclosure caret — a real chevron SVG that rotates from ▸ (closed) to ▾ (open). */
function Caret({ open, className = '' }: { open: boolean; className?: string }) {
  return (
    <svg
      viewBox='0 0 16 16'
      aria-hidden
      fill='none'
      stroke='currentColor'
      strokeWidth={2}
      strokeLinecap='round'
      strokeLinejoin='round'
      className={`h-3 w-3 text-muted transition-transform ${open ? 'rotate-90' : ''} ${className}`}
    >
      <path d='M6 4l4 4-4 4' />
    </svg>
  )
}

/** Small green ⚡ duration badge, reused by the card and the collapsed pill. */
function SpeedBadge({ ms }: { ms: number }) {
  return (
    <span className='inline-flex items-center gap-0.5 rounded bg-green-100 px-1.5 font-mono text-[10px] font-medium text-green-700 dark:bg-green-950 dark:text-green-300'>
      <span aria-hidden>⚡</span>
      {formatMs(ms)}
    </span>
  )
}

export function WhatJustHappened() {
  const events = useActivityLog((s) => s.events)
  const clear = useActivityLog((s) => s.clear)
  const latest = events[0]

  const [runId, setRunId] = useState(0) // bump to restart the countdown animation
  // The 15s countdown only runs on a FRESH action. A manual re-expand from the
  // collapsed pill opens the card "sticky" (no bar, no auto-collapse).
  const [countdown, setCountdown] = useState(false)
  const [open, setOpen] = useState(true) // detail lines expanded
  const [hovering, setHovering] = useState(false)
  const [frozen, setFrozen] = useState(false) // mobile tap-to-pause toggle
  const paused = hovering || frozen

  // Mutual exclusion across the dock: the shared store is the SINGLE source of
  // truth for whether our card is open, so opening the other panel collapses us
  // with NO effect race. `dismissed` (local) hides us until the next action.
  const expanded = useDockExpansion((s) => s.expanded)
  const openSlot = useDockExpansion((s) => s.open)
  const closeSlot = useDockExpansion((s) => s.close)
  const isOpen = expanded === 'activity'
  const [dismissed, setDismissed] = useState(false)

  // A FRESH event (its id changes) opens the card and starts the countdown. A
  // clean load stays empty until the first action; closing then re-acting brings
  // it back.
  const lastIdRef = useRef<string | null>(null)
  useEffect(() => {
    if (!latest) return
    if (latest.id === lastIdRef.current) return
    lastIdRef.current = latest.id
    setOpen(true)
    setFrozen(false)
    setRunId((n) => n + 1)
    setCountdown(true)
    setDismissed(false)
    openSlot('activity')
  }, [latest, openSlot])

  if (!latest) return null

  // Re-open from the collapsed circle: NO timer this time — stays open until you
  // collapse or close it.
  const expand = () => {
    setFrozen(false)
    setCountdown(false)
    openSlot('activity')
  }

  if (!isOpen) {
    if (dismissed) return null
    // Collapsed = a single emoji circle in the dock row. Click to reopen; the
    // close (✕) lives inside the expanded card now, not as a separate button.
    return (
      <button
        type='button'
        onClick={expand}
        title='What just happened'
        aria-label='Reopen the “what just happened” panel'
        className='inline-flex h-9 w-9 items-center justify-center rounded-full border border-hairline bg-bg text-base shadow-lg transition-colors hover:border-fg'
      >
        <span aria-hidden>⚡</span>
      </button>
    )
  }

  // isOpen → the card.
  const older = events.slice(1)

  return (
    // role=status + aria-live so the latest narration is announced without
    // stealing focus. Pause the countdown while the pointer is over it (hover),
    // and let a tap toggle a sticky freeze on touch devices (no hover there).
    <div
      role='status'
      aria-live='polite'
      onMouseEnter={() => setHovering(true)}
      onMouseLeave={() => setHovering(false)}
      onTouchStart={() => setFrozen((v) => !v)}
      className='w-[22rem] max-w-[calc(100vw-2rem)] overflow-hidden rounded-xl border border-hairline bg-bg text-sm shadow-xl'
    >
      {/* Countdown bar, clipped to the top edge — only on a fresh action. `key`
          restarts the animation each time; `animationend` collapses the card;
          play-state pauses it on hover/tap. A manual re-expand has no bar. */}
      {countdown ? (
        <span
          key={runId}
          aria-hidden
          onAnimationEnd={() => closeSlot('activity')}
          style={{ animationPlayState: paused ? 'paused' : 'running' }}
          className={`absolute top-0 left-0 h-[3px] w-full origin-left [animation:wjh-countdown_15s_linear_forwards] ${
            paused ? 'bg-amber-400' : 'bg-blue-500'
          }`}
        />
      ) : null}

      <header className='flex items-center gap-2 border-b border-hairline px-3 py-2'>
        <span aria-hidden>⚡</span>
        <span className='font-semibold'>What just happened</span>
        <div className='ml-auto flex items-center gap-0.5'>
          <button
            type='button'
            onClick={() => closeSlot('activity')}
            className='inline-flex h-6 w-6 items-center justify-center rounded-md text-sm leading-none text-muted transition-colors hover:bg-fg/10 hover:text-fg'
            aria-label='Collapse the panel'
          >
            <span aria-hidden>−</span>
          </button>
          <button
            type='button'
            onClick={() => {
              setDismissed(true)
              closeSlot('activity')
            }}
            className='inline-flex h-6 w-6 items-center justify-center rounded-md text-xs leading-none text-muted transition-colors hover:bg-fg/10 hover:text-fg'
            aria-label='Close the panel'
          >
            <span aria-hidden>✕</span>
          </button>
        </div>
      </header>

      <div className='px-3 py-3'>
        <LatestCard event={latest} open={open} onToggle={() => setOpen((v) => !v)} />
      </div>

      {older.length > 0 ? (
        <details className='border-t border-hairline'>
          <summary className='cursor-pointer list-none px-3 py-2 text-xs text-muted select-none hover:text-fg [&::-webkit-details-marker]:hidden'>
            Earlier ({older.length})
          </summary>
          <ul className='max-h-48 overflow-y-auto px-3 pb-2'>
            {older.map((e) => (
              <li key={e.id} className='flex items-center gap-2 py-1 text-xs'>
                <span aria-hidden className={`h-1.5 w-1.5 shrink-0 rounded-full ${KIND_DOT[e.kind]}`} />
                <span className='min-w-0 flex-1 truncate text-muted'>{e.title}</span>
                {e.durationMs !== undefined ? (
                  <span className='shrink-0 font-mono text-[10px] text-green-700 dark:text-green-400'>
                    {formatMs(e.durationMs)}
                  </span>
                ) : null}
              </li>
            ))}
          </ul>
          <div className='px-3 pb-2'>
            <button type='button' onClick={clear} className='text-xs text-muted hover:text-fg'>
              Clear
            </button>
          </div>
        </details>
      ) : null}
    </div>
  )
}

function LatestCard({ event, open, onToggle }: { event: ActivityEvent; open: boolean; onToggle: () => void }) {
  return (
    <div className='space-y-2'>
      <button type='button' onClick={onToggle} className='block w-full min-w-0 text-left'>
        <span className='flex items-baseline gap-2'>
          <span className='font-mono text-[10px] tracking-wide text-muted'>{KIND_LABEL[event.kind]}</span>
          {event.durationMs !== undefined ? <SpeedBadge ms={event.durationMs} /> : null}
          <Caret open={open} className='ml-auto shrink-0' />
        </span>
        <span className='mt-0.5 block font-medium'>{event.title}</span>
      </button>
      {open ? (
        <ul className='space-y-1'>
          {event.lines.map((line, i) => (
            // Lines are static per event and never reorder, so index keys are safe.
            // biome-ignore lint/suspicious/noArrayIndexKey: stable, non-reordering list
            <li key={i} className='text-xs leading-relaxed text-muted'>
              {line}
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  )
}
