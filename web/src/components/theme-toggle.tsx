'use client'

import { useEffect, useState } from 'react'

// Preference is what the user picked; the resolved light/dark value is mirrored
// onto <html data-theme> (see _root.tsx). Cycling order: system -> light -> dark.
type Pref = 'system' | 'light' | 'dark'
const ORDER: Pref[] = ['system', 'light', 'dark']

function resolve(pref: Pref): 'light' | 'dark' {
  if (pref === 'system') {
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
  }
  return pref
}

function Icon({ pref }: { pref: Pref }) {
  const common = {
    width: 18,
    height: 18,
    viewBox: '0 0 24 24',
    fill: 'none',
    stroke: 'currentColor',
    strokeWidth: 1.75,
    strokeLinecap: 'round' as const,
    strokeLinejoin: 'round' as const,
  }
  if (pref === 'light') {
    return (
      <svg {...common} aria-hidden>
        <circle cx='12' cy='12' r='4' />
        <path d='M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4' />
      </svg>
    )
  }
  if (pref === 'dark') {
    return (
      <svg {...common} aria-hidden>
        <path d='M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z' />
      </svg>
    )
  }
  // system
  return (
    <svg {...common} aria-hidden>
      <rect x='3' y='4' width='18' height='12' rx='2' />
      <path d='M8 20h8M12 16v4' />
    </svg>
  )
}

/**
 * Three-state theme toggle (system / light / dark). Persists the preference to localStorage and updates <html
 * data-theme> live. Until mounted it renders the neutral `system` state so server and client markup agree (the real
 * value is read from localStorage after hydration); suppressHydrationWarning covers the one-tick swap of the
 * icon/label.
 */
export function ThemeToggle() {
  const [pref, setPref] = useState<Pref>('system')
  const [mounted, setMounted] = useState(false)

  useEffect(() => {
    const stored = localStorage.getItem('theme')
    setPref(stored === 'light' || stored === 'dark' ? stored : 'system')
    setMounted(true)
  }, [])

  function cycle() {
    const next = ORDER[(ORDER.indexOf(pref) + 1) % ORDER.length]!
    setPref(next)
    localStorage.setItem('theme', next)
    document.documentElement.dataset.theme = resolve(next)
  }

  const shown = mounted ? pref : 'system'
  return (
    <button
      type='button'
      onClick={cycle}
      aria-label={`Theme: ${shown}. Click to change.`}
      title={`Theme: ${shown}`}
      suppressHydrationWarning
      className='-m-1.5 inline-flex size-9 items-center justify-center rounded-md p-1.5 text-fg/80 transition-colors duration-200 hover:bg-muted/10 hover:text-fg'
    >
      <span suppressHydrationWarning>
        <Icon pref={shown} />
      </span>
    </button>
  )
}
