// "What just happened" activity feed (demo legibility).
//
// A tiny client-only event bus the multiplayer demo writes to after each
// action (create / unlock / lock / push / fork / live peer event). The
// `WhatJustHappened` overlay subscribes and narrates — retrospectively, never
// blocking — what the (fast) action just did behind the scenes. Each event
// carries the REAL values from that action (hashes, player name, ref) plus an
// optional `durationMs` so the overlay can flex how fast the compute was.
//
// This is presentation-only: it owns no repo/identity truth, just a capped
// ring of recent events. The overlay (open/collapsed/closed) is local UI state.

import type { ReactNode } from 'react'
import { create } from 'zustand'

export type ActivityKind = 'create' | 'unlock' | 'lock' | 'push' | 'fork' | 'peer'

export type ActivityEvent = {
  id: string
  kind: ActivityKind
  /**
   * One-line headline (what happened). Any renderable node — pass JSX to style inline values (a `<code>` hash, a linked
   * pubkey, …), not just a string.
   */
  title: ReactNode
  /**
   * Expandable detail lines (why it matters / the real values). Each line is a `ReactNode`, so callers can embed custom
   * elements, not only text.
   */
  lines: ReactNode[]
  /** Compute/round-trip time to highlight as the "speed" badge, if meaningful. */
  durationMs?: number
  ts: number
}

type ActivityStore = {
  /** Newest-first, capped at {@link MAX_EVENTS}. */
  events: ActivityEvent[]
  record: (e: Omit<ActivityEvent, 'id' | 'ts'>) => void
  clear: () => void
}

/** Keep the ring small — this is a live narration, not a history log. */
export const MAX_EVENTS = 30

// Monotonic id source. Module-local so ids are stable + unique without needing
// a clock (and without colliding across rapid pushes).
let seq = 0

export const useActivityLog = create<ActivityStore>((set) => ({
  events: [],
  record: (e) => {
    // Always record — history is cheap, and the overlay owns what/when to show
    // (it only auto-appears for a fresh event, then collapses).
    seq += 1
    const event: ActivityEvent = { ...e, id: `act-${seq}`, ts: Date.now() }
    set((s) => ({ events: [event, ...s.events].slice(0, MAX_EVENTS) }))
  },
  clear: () => set({ events: [] }),
}))

/**
 * Imperative emit for non-component call sites (e.g. the live-events hook). Components may also call
 * `useActivityLog((s) => s.record)`.
 */
export function recordActivity(e: Omit<ActivityEvent, 'id' | 'ts'>): void {
  useActivityLog.getState().record(e)
}

/** Format a duration for the speed badge: sub-ms keeps 2 decimals, else rounds. */
export function formatMs(ms: number): string {
  return ms < 1 ? `${ms.toFixed(2)} ms` : `${Math.round(ms)} ms`
}
