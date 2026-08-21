'use client'

import { ListIcon, XIcon } from '@phosphor-icons/react/ssr'
import { useEffect, useRef, useState } from 'react'
import { Link, useRouter } from 'waku'
import { GridLogo } from './grid-logo'
import { NavList } from './site-nav'
import { ThemeToggle } from './theme-toggle'

/**
 * Page chrome masthead (DESIGN.md §4.27): brand on the left, trailing controls on the right, separated from the content
 * by a solid light rule — peers, not a structure and its start (§2.2A rule 1). Below `wide` the primary nav collapses
 * to the trigger here; the expanded panel pushes the page down rather than covering it (§4.27 rule 8) and closes on
 * selection, returning focus to the trigger (rule 9). Sticky occlusion is handled by an opaque surface-page ground
 * alone — a sticky page header casts no shadow (§2.6 rule 4).
 */
export const Header = () => {
  const [navOpen, setNavOpen] = useState(false)
  const triggerRef = useRef<HTMLButtonElement>(null)
  const router = useRouter()

  // Route changes close the expanded nav (§4.27 rule 9).
  useEffect(() => {
    setNavOpen(false)
  }, [router.path])

  const closeNav = () => {
    setNavOpen(false)
    triggerRef.current?.focus()
  }

  return (
    <header
      className='sticky top-0 z-2 border-b'
      style={{ background: 'var(--surface-page)', borderColor: 'var(--border-color-default)' }}
    >
      <div className='mx-auto flex w-full max-w-6xl items-center gap-2 px-6 py-3'>
        <Link to='/' className='-m-2 flex items-center gap-2 p-2' aria-label='mkit home'>
          <GridLogo className='size-5 rounded-[3px]' />
          <span className='font-semibold tracking-(--header-tracking) text-primary'>mkit</span>
        </Link>
        <div className='ml-auto flex items-center gap-2'>
          <ThemeToggle />
          <button
            ref={triggerRef}
            type='button'
            aria-expanded={navOpen}
            aria-controls='site-nav-panel'
            aria-label={navOpen ? 'Close navigation' : 'Open navigation'}
            onClick={() => setNavOpen((v) => !v)}
            className='inline-flex size-8 items-center justify-center rounded-(--rounded-sm) text-primary transition-colors duration-(--duration-fast) ease-standard hover:bg-(--action-ghost-bg-hover) active:bg-(--action-ghost-bg-active) lg:hidden'
          >
            {navOpen ? <XIcon size={16} aria-hidden /> : <ListIcon size={16} aria-hidden />}
          </button>
        </div>
      </div>
      {navOpen ? (
        <nav
          id='site-nav-panel'
          aria-label='Primary'
          className='border-t lg:hidden'
          style={{ borderColor: 'var(--border-color-subtle)' }}
        >
          <div className='mx-auto w-full max-w-6xl px-6 py-2'>
            <NavList onNavigate={closeNav} />
          </div>
        </nav>
      ) : null}
    </header>
  )
}
