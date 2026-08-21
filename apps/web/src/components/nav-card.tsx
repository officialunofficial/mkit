'use client'

import { ArrowRightIcon } from '@phosphor-icons/react/ssr'
import type { ReactNode } from 'react'
import { Link } from 'waku'

/**
 * The one link-card construction (§4.24 rules 5–6): a title band — text-sm semibold, a step below the body copy, over a
 * solid light rule — and the body beneath it in text-primary. The title carries the dotted link mark, since the
 * underline is the system's only link signal (§2.1D rule 1, §4.3 rule 5); a trailing in-app arrow appears only when the
 * click changes location (§4.1 rules 7–8) — a card that swaps content in place carries none.
 */
function CardShell({
  title,
  icon,
  withArrow,
  body,
}: {
  title: string
  // A rendered glyph, not a component: server pages hand this across the
  // client boundary, and a component function cannot cross it.
  icon?: ReactNode | undefined
  withArrow: boolean
  body: string
}) {
  return (
    <>
      <span
        className='flex items-center gap-1 border-b px-3 py-1.5 text-xs leading-4 font-semibold tracking-(--header-tracking)'
        style={{ borderColor: 'var(--border-color-default)' }}
      >
        {icon}
        <span className='ds-link'>{title}</span>
        {withArrow ? <ArrowRightIcon size={12} aria-hidden className='ml-auto text-secondary' /> : null}
      </span>
      <span className='block px-3 py-2 text-left'>{body}</span>
    </>
  )
}

const CARD_CLASS =
  'card flex w-full flex-col p-0 transition-colors duration-(--duration-fast) ease-standard hover:bg-(--surface-hover)'

// Waku's typed Link needs the concrete route literals.
export type NavCardRoute = '/concepts' | '/performance' | '/parity' | '/multiplayer'

/** A card that navigates to another page — an anchor, with the in-app arrow. */
export function NavCardLink({
  to,
  title,
  icon,
  body,
}: {
  to: NavCardRoute
  title: string
  icon?: ReactNode
  body: string
}) {
  return (
    <li className='flex'>
      <Link to={to} className={CARD_CLASS}>
        <CardShell title={title} icon={icon} withArrow body={body} />
      </Link>
    </li>
  )
}

/** A card that acts in place (switching a tab) — a button, no arrow. */
export function NavCardButton({
  onClick,
  title,
  icon,
  body,
  children,
}: {
  onClick: () => void
  title: string
  icon?: ReactNode
  body: string
  children?: ReactNode
}) {
  return (
    <li className='flex'>
      <button type='button' onClick={onClick} className={CARD_CLASS}>
        <CardShell title={title} icon={icon} withArrow={false} body={body} />
        {children}
      </button>
    </li>
  )
}
