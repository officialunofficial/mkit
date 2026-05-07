'use client'

import { useEffect } from 'react'

/**
 * Writes normalised pointer position (0..1) into `--mouse-x` / `--mouse-y` on `<html>`. One rAF-throttled listener;
 * nothing else in the tree re-renders. CSS consumers (e.g. the top separator's `background-position-x`) read the var
 * directly, so updates stay on the compositor.
 *
 * Rendered once from the root layout. Returns `null` — no DOM.
 */
export function PointerTracker() {
  useEffect(() => {
    const root = document.documentElement

    // Seed a sensible starting position so the gradient isn't pinned to
    // 0 before the first pointer event (which also covers touch devices
    // that never emit a mousemove).
    root.style.setProperty('--mouse-x', '0.5')
    root.style.setProperty('--mouse-y', '0.5')

    let pending = false
    let nextX = 0.5
    let nextY = 0.5

    const onMove = (e: PointerEvent) => {
      nextX = e.clientX / window.innerWidth
      nextY = e.clientY / window.innerHeight
      if (!pending) {
        pending = true
        requestAnimationFrame(() => {
          root.style.setProperty('--mouse-x', nextX.toFixed(3))
          root.style.setProperty('--mouse-y', nextY.toFixed(3))
          pending = false
        })
      }
    }

    window.addEventListener('pointermove', onMove, { passive: true })
    return () => {
      window.removeEventListener('pointermove', onMove)
    }
  }, [])

  return null
}
