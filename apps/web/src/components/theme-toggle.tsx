'use client'

import { MoonIcon, SunIcon } from '@phosphor-icons/react/ssr'
import { useEffect, useState } from 'react'
import { Tooltip } from './tooltip'

// The user's explicit choice, mirrored onto <html data-theme> (see _root.tsx).
type Theme = 'light' | 'dark'

/**
 * Two-state theme toggle (light / dark) — an icon button (§4.2) in the ghost variant, with its accessible name repeated
 * in a tooltip (§4.2 rule 4). On first load it adopts whatever the no-flash script resolved onto `<html data-theme>`,
 * then flips between light and dark and persists the choice. Until mounted it renders the light icon so server and
 * client markup agree; suppressHydrationWarning covers the one-tick swap.
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
  const label = `Switch to ${shown === 'dark' ? 'light' : 'dark'} theme`
  return (
    <Tooltip content={label} side='bottom'>
      <button
        type='button'
        onClick={toggle}
        aria-label={label}
        suppressHydrationWarning
        className='inline-flex size-8 items-center justify-center rounded-(--rounded-sm) text-primary transition-colors duration-(--duration-fast) ease-standard hover:bg-(--action-ghost-bg-hover) active:bg-(--action-ghost-bg-active)'
      >
        <span suppressHydrationWarning className='inline-flex'>
          {shown === 'dark' ? <MoonIcon size={16} aria-hidden /> : <SunIcon size={16} aria-hidden />}
        </span>
      </button>
    </Tooltip>
  )
}
