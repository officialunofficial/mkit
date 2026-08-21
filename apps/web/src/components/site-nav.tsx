'use client'

import { FlaskIcon, GaugeIcon, GitDiffIcon, HouseIcon, ScrollIcon, UsersThreeIcon } from '@phosphor-icons/react/ssr'
import type { ComponentType } from 'react'
import { Link, useRouter } from 'waku'

// Primary navigation (DESIGN.md §4.27): one entry per route, each an icon and
// a label. Reordering the site nav is editing this list — nothing else.
type NavRoute = '/' | '/concepts' | '/performance' | '/parity' | '/specs' | '/multiplayer'

type IconComponent = ComponentType<{ size?: number; weight?: 'regular' | 'fill'; 'aria-hidden'?: boolean }>

const NAV_LINKS: ReadonlyArray<{ to: NavRoute; label: string; Icon: IconComponent }> = [
  { to: '/', label: 'Overview', Icon: HouseIcon },
  { to: '/concepts', label: 'Concepts', Icon: FlaskIcon },
  { to: '/performance', label: 'Performance', Icon: GaugeIcon },
  { to: '/parity', label: 'Parity', Icon: GitDiffIcon },
  { to: '/specs', label: 'Specs', Icon: ScrollIcon },
  { to: '/multiplayer', label: 'Multiplayer', Icon: UsersThreeIcon },
]

/**
 * The nav item list, shared by the wide rail and the collapsed panel. Per §4.27 rule 4 the active item takes
 * weight-medium, text-primary, a filled icon, and a medium left border in border-color-selected — never a fill — and
 * per rule 5 it is not a link.
 */
export function NavList({ onNavigate }: { onNavigate?: () => void }) {
  const router = useRouter()
  const current = router.path

  return (
    <ul>
      {NAV_LINKS.map(({ to, label, Icon }) => {
        const active = current === to
        const inner = (
          <>
            <Icon size={16} weight={active ? 'fill' : 'regular'} aria-hidden />
            {label}
          </>
        )
        return (
          <li key={to}>
            {active ? (
              <span
                aria-current='page'
                className='flex items-center gap-1 border-l-2 py-1.5 pl-2.5 font-medium text-primary'
                style={{ borderColor: 'var(--border-color-selected)' }}
              >
                {inner}
              </span>
            ) : (
              <Link
                to={to}
                onClick={onNavigate}
                className='flex items-center gap-1 border-l-2 border-transparent py-1.5 pl-2.5 text-secondary transition-colors duration-(--duration-fast) ease-standard hover:text-primary'
              >
                {inner}
              </Link>
            )}
          </li>
        )
      })}
    </ul>
  )
}

/**
 * The wide-tier navigation rail: the offset left column of §2.7, outside the content measure. Below `wide` the nav
 * collapses to the masthead's trigger (§4.27 rule 7) and this rail is not rendered at all.
 */
export function SiteRail() {
  return (
    <nav aria-label='Primary' className='sticky top-[57px] hidden self-start pt-8 text-[length:var(--t-base)] lg:block'>
      <NavList />
    </nav>
  )
}
