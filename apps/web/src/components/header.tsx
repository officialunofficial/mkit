'use client'

import { ListIcon, XIcon } from '@phosphor-icons/react/ssr'
import { useEffect, useRef, useState } from 'react'
import { Link, useRouter } from 'waku'
import { GridLogo } from './grid-logo'
import { NavList } from './site-nav'
import { ThemeToggle } from './theme-toggle'

/**
 * Page chrome masthead, matching polychrome's PageChrome construction: the whole header — brand row, disclosed nav,
 * closing divider — lives inside the central content column (`--page-column`), so the chrome spans the column, never
 * the viewport, and scrolls with the page. §4.27 rule 3 keeps the divider a solid light rule in border-color-default
 * (peers, not a structure and its start — §2.2A rule 1). Below the rail breakpoint the primary nav collapses to the
 * trigger here; the expanded panel sits between the masthead and the divider and pushes the page down rather than
 * covering it (§4.27 rule 8), closing on selection with focus returned to the trigger (rule 9).
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
    <header>
      <div className='mx-auto w-full max-w-(--page-column) px-6 pt-5'>
        <div className='flex items-center gap-2'>
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
              className='inline-flex size-8 items-center justify-center rounded-(--rounded-sm) text-primary transition-colors duration-(--duration-fast) ease-standard hover:bg-(--action-ghost-bg-hover) active:bg-(--action-ghost-bg-active) min-[1440px]:hidden'
            >
              {navOpen ? <XIcon size={16} aria-hidden /> : <ListIcon size={16} aria-hidden />}
            </button>
          </div>
        </div>
        {navOpen ? (
          <nav id='site-nav-panel' aria-label='Primary' className='mt-2 min-[1440px]:hidden'>
            <NavList onNavigate={closeNav} />
          </nav>
        ) : null}
        {/* The divider is a normal child of the padded column container, so it
            fills the column's content box — never the viewport. */}
        <div className='mt-3 border-b' style={{ borderColor: 'var(--border-color-default)' }} aria-hidden />
      </div>
    </header>
  )
}
