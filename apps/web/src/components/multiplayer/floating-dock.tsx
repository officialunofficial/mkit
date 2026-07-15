'use client'

// The bottom-corner dock that holds the floating presence panel. Snaps to one
// of 8 screen anchors; hovering reveals a move handle you drag to re-snap.
// The chosen anchor persists in localStorage.

import { type ReactNode, useRef, useState } from 'react'
import { useDockExpansion } from '../../lib/dock-expansion'
import { type DockCorner, useDockPosition } from '../../lib/dock-position'

/**
 * Tailwind positioning per anchor. The cross-axis alignment makes expanded cards grow the sensible way: down from the
 * top, up from the bottom.
 */
const CORNER_CLASS: Record<DockCorner, string> = {
  'top-left': 'top-4 left-4 items-start',
  'top-center': 'top-4 left-1/2 -translate-x-1/2 items-start',
  'top-right': 'top-4 right-4 items-start',
  'center-left': 'top-1/2 left-4 -translate-y-1/2 items-center',
  'center-right': 'top-1/2 right-4 -translate-y-1/2 items-center',
  'bottom-left': 'bottom-4 left-4 items-end',
  'bottom-center': 'bottom-4 left-1/2 -translate-x-1/2 items-end',
  'bottom-right': 'bottom-4 right-4 items-end',
}

/** Position for the snap-zone markers shown while dragging (same anchors as the dock). */
const ZONE_CLASS: Record<DockCorner, string> = {
  'top-left': 'top-4 left-4',
  'top-center': 'top-4 left-1/2 -translate-x-1/2',
  'top-right': 'top-4 right-4',
  'center-left': 'top-1/2 left-4 -translate-y-1/2',
  'center-right': 'top-1/2 right-4 -translate-y-1/2',
  'bottom-left': 'bottom-4 left-4',
  'bottom-center': 'bottom-4 left-1/2 -translate-x-1/2',
  'bottom-right': 'bottom-4 right-4',
}

const ALL_CORNERS = Object.keys(ZONE_CLASS) as DockCorner[]

/**
 * Full-screen overlay shown while dragging: a marker at each of the 8 anchors, the one you'd snap to (`target`)
 * highlighted in the active colour.
 */
function SnapZones({ target }: { target: DockCorner }) {
  return (
    <div className='fixed inset-0 z-[60] pointer-events-none'>
      {ALL_CORNERS.map((c) => (
        <div
          key={c}
          className={`absolute h-12 w-12 rounded-xl border-2 border-dashed transition-colors ${ZONE_CLASS[c]} ${
            c === target ? 'border-fg bg-fg/10' : 'border-hairline/70'
          }`}
        />
      ))}
    </div>
  )
}

/** Snap a pointer position to the nearest of the 8 edge/corner anchors. */
function nearestCorner(x: number, y: number): DockCorner {
  const w = window.innerWidth
  const h = window.innerHeight
  const anchors: Array<[DockCorner, number, number]> = [
    ['top-left', 0, 0],
    ['top-center', w / 2, 0],
    ['top-right', w, 0],
    ['center-left', 0, h / 2],
    ['center-right', w, h / 2],
    ['bottom-left', 0, h],
    ['bottom-center', w / 2, h],
    ['bottom-right', w, h],
  ]
  let best: DockCorner = 'bottom-right'
  let bestD = Number.POSITIVE_INFINITY
  for (const [corner, ax, ay] of anchors) {
    const d = (x - ax) ** 2 + (y - ay) ** 2
    if (d < bestD) {
      bestD = d
      best = corner
    }
  }
  return best
}

/** Four-way move arrows. */
function MoveIcon() {
  return (
    <svg
      viewBox='0 0 16 16'
      width='12'
      height='12'
      fill='none'
      stroke='currentColor'
      strokeWidth='1.4'
      strokeLinecap='round'
      strokeLinejoin='round'
      aria-hidden
    >
      <path d='M8 1.5v13M1.5 8h13M8 1.5 6.2 3.3M8 1.5l1.8 1.8M8 14.5l-1.8-1.8M8 14.5l1.8-1.8M1.5 8l1.8-1.8M1.5 8l1.8 1.8M14.5 8l-1.8-1.8M14.5 8l-1.8 1.8' />
    </svg>
  )
}

export function FloatingDock({ children }: { children: ReactNode }) {
  const corner = useDockPosition((s) => s.corner)
  const setCorner = useDockPosition((s) => s.setCorner)
  const containerRef = useRef<HTMLDivElement>(null)
  // While dragging: the live pointer position + the grab offset within the dock
  // (so it tracks under the cursor instead of jumping its corner to the pointer).
  const [drag, setDrag] = useState<{ x: number; y: number } | null>(null)
  const offset = useRef({ x: 0, y: 0 })
  // The move handle is only for the collapsed circles — hide it once a panel's
  // card is open (nothing to reposition mid-read, and it'd crowd the card).
  const collapsed = useDockExpansion((s) => s.expanded === null)

  const onDown = (e: React.PointerEvent) => {
    e.preventDefault()
    e.currentTarget.setPointerCapture(e.pointerId)
    const rect = containerRef.current?.getBoundingClientRect()
    offset.current = rect ? { x: e.clientX - rect.left, y: e.clientY - rect.top } : { x: 0, y: 0 }
    setDrag({ x: e.clientX, y: e.clientY })
  }
  const onMove = (e: React.PointerEvent) => {
    if (drag) setDrag({ x: e.clientX, y: e.clientY })
  }
  const onUp = (e: React.PointerEvent) => {
    if (!drag) return
    setCorner(nearestCorner(e.clientX, e.clientY))
    setDrag(null)
  }

  return (
    <>
      {drag ? <SnapZones target={nearestCorner(drag.x, drag.y)} /> : null}
      <div
        ref={containerRef}
        className={`group fixed flex flex-row gap-2 ${drag ? 'z-[70] items-end' : `z-50 ${CORNER_CLASS[corner]}`}`}
        style={
          drag
            ? { left: drag.x - offset.current.x, top: drag.y - offset.current.y, right: 'auto', bottom: 'auto' }
            : undefined
        }
      >
        {collapsed || drag ? (
          <button
            type='button'
            aria-label='Move panel — drag to a corner or edge'
            onPointerDown={onDown}
            onPointerMove={onMove}
            onPointerUp={onUp}
            className={`absolute -top-2.5 -left-2.5 z-10 inline-flex h-6 w-6 touch-none items-center justify-center rounded-full border bg-bg text-muted shadow transition hover:border-fg hover:text-fg ${
              drag
                ? 'cursor-grabbing border-fg text-fg opacity-100'
                : 'cursor-grab border-hairline opacity-0 pointer-events-none group-hover:pointer-events-auto group-hover:opacity-100 focus-visible:pointer-events-auto focus-visible:opacity-100'
            }`}
          >
            <MoveIcon />
          </button>
        ) : null}
        {children}
      </div>
    </>
  )
}
