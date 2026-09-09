'use client'

import {
  CodeIcon,
  FlaskIcon,
  GaugeIcon,
  GitDiffIcon,
  HouseIcon,
  ScrollIcon,
  UsersThreeIcon,
} from '@phosphor-icons/react/ssr'
import type { ComponentType } from 'react'
import { Link, useRouter } from 'waku'

// Primary navigation (DESIGN.md §4.27): one entry per route, each an icon and
// a label. Reordering the site nav is editing this list — nothing else.
type NavGroup = 'Learn' | 'Reference'

type NavRoute = '/' | '/create' | '/concepts' | '/performance' | '/parity' | '/specs' | '/multiplayer'

type IconComponent = ComponentType<{ size?: number; weight?: 'regular' | 'fill'; 'aria-hidden'?: boolean }>

const NAV_LINKS: ReadonlyArray<{ to: NavRoute; label: string; Icon: IconComponent; group: NavGroup }> = [
  { to: '/', label: 'Overview', group: 'Learn', Icon: HouseIcon },
  { to: '/create', label: 'Create', group: 'Learn', Icon: CodeIcon },
  { to: '/concepts', label: 'Concepts', group: 'Learn', Icon: FlaskIcon },
  { to: '/performance', label: 'Performance', group: 'Reference', Icon: GaugeIcon },
  { to: '/parity', label: 'Parity', group: 'Reference', Icon: GitDiffIcon },
  { to: '/specs', label: 'Specs', group: 'Reference', Icon: ScrollIcon },
  { to: '/multiplayer', label: 'Multiplayer', group: 'Learn', Icon: UsersThreeIcon },
]

/**
 * The nav item list, shared by the wide rail and the collapsed panel. Per §4.27 rule 4 the active item takes
 * weight-medium, text-primary, a filled icon, and a medium left border in border-color-selected — never a fill — and
 * per rule 5 it is not a link.
 */
export function NavList({
  onNavigate,
  dense = false,
  group,
}: {
  onNavigate?: () => void
  dense?: boolean
  group?: NavGroup
}) {
  const router = useRouter()
  const current = router.path
  const rowClass = dense ? 'py-0.5 pointer-coarse:min-h-11' : 'min-h-11'

  return (
    <ul className='space-y-0.5'>
      {NAV_LINKS.filter((item) => !group || item.group === group).map(({ to, label, Icon }) => {
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
                className={`flex items-center gap-1 border-l-2 pl-2 font-medium text-primary ${rowClass}`}
                style={{ borderColor: 'var(--border-color-selected)' }}
              >
                {inner}
              </span>
            ) : (
              <Link
                to={to}
                onClick={onNavigate}
                className={`flex items-center gap-1 border-l-2 border-transparent pl-2 text-secondary transition-colors duration-(--duration-fast) ease-standard hover:text-primary ${rowClass}`}
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
 * The wide-tier navigation rail, built like polychrome's PageChrome sidebar: a fixed rail hanging in the page margin to
 * the LEFT of the content column — outside the content measure (§2.7), so the column keeps its width whether the rail
 * is there or not (§4.27 rule 10). Below the rail breakpoint the nav collapses to the masthead's trigger and this rail
 * is not rendered at all.
 */
export function SiteRail() {
  return (
    <nav
      aria-label='Primary'
      className='fixed top-24 hidden w-40 min-[1440px]:block'
      style={{ right: 'calc(50% + (var(--page-column) / 2) + 2rem)' }}
    >
      <NavList dense />
    </nav>
  )
}

/** Two short lists keep expanded navigation compact on phones and tablets. */
export function ExpandedNav({ onNavigate }: { onNavigate: () => void }) {
  return (
    <div className='grid grid-cols-2 gap-3 py-2'>
      {(['Learn', 'Reference'] as const).map((group) => (
        <div key={group}>
          <h2 className='px-2 pb-1 text-xs text-secondary'>{group}</h2>
          <NavList group={group} onNavigate={onNavigate} />
        </div>
      ))}
    </div>
  )
}
