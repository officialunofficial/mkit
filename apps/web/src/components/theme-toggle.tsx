'use client'

import { useEffect, useState } from 'react'
import { Tooltip } from './tooltip'

// The user's explicit choice, mirrored onto <html data-theme> (see _root.tsx).
type Theme = 'light' | 'dark'

function Icon({ theme }: { theme: Theme }) {
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
  if (theme === 'dark') {
    return (
      <svg {...common} aria-hidden>
        <path d='M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z' />
      </svg>
    )
  }
  return (
    <svg {...common} aria-hidden>
      <circle cx='12' cy='12' r='4' />
      <path d='M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4' />
    </svg>
  )
}

/**
 * Two-state theme toggle (light / dark). On first load it adopts whatever the no-flash script resolved onto `<html
 * data-theme>` (which already honours the system preference), then flips between light and dark and persists the
 * choice. Until mounted it renders a neutral light icon so server and client markup agree; suppressHydrationWarning
 * covers the one-tick swap.
 */
export function ThemeToggle() {
  const [theme, setTheme] = useState<Theme>('light')
  const [mounted, setMounted] = useState(false)

  useEffect(() => {
    const stored = localStorage.getItem('theme')
    const initial: Theme =
      stored === 'light' || stored === 'dark'
        ? stored
        : document.documentElement.dataset.theme === 'dark'
          ? 'dark'
          : 'light'
    setTheme(initial)
    setMounted(true)
  }, [])

  function toggle() {
    const next: Theme = theme === 'dark' ? 'light' : 'dark'
    setTheme(next)
    localStorage.setItem('theme', next)
    document.documentElement.dataset.theme = next
  }

  const shown: Theme = mounted ? theme : 'light'
  return (
    <Tooltip content={`Switch to ${shown === 'dark' ? 'light' : 'dark'} theme`} side='bottom'>
      <button
        type='button'
        onClick={toggle}
        aria-label={`${shown === 'dark' ? 'Dark' : 'Light'} theme. Switch to ${shown === 'dark' ? 'light' : 'dark'}.`}
        suppressHydrationWarning
        className='-m-1.5 inline-flex size-9 items-center justify-center rounded-md p-1.5 text-fg/80 transition-colors duration-200 hover:bg-muted/10 hover:text-fg'
      >
        <span suppressHydrationWarning>
          <Icon theme={shown} />
        </span>
      </button>
    </Tooltip>
  )
}
