'use client'

// A small "ⓘ" affordance next to a field label. Click/tap (or keyboard) opens a
// popover with extra explanation. Built on Radix Popover so positioning,
// collision avoidance, focus management, and dismiss (Esc / outside-click) are
// handled for us. Content is a `ReactNode`, so callers can pass rich markup.

import * as Popover from '@radix-ui/react-popover'
import type { ReactNode } from 'react'

export function InfoTip({
  label,
  children,
}: {
  /** Accessible name for the trigger (e.g. "About rooms"). */
  label: string
  /** Popover content. */
  children: ReactNode
}) {
  return (
    <Popover.Root>
      <Popover.Trigger asChild>
        <button
          type='button'
          aria-label={label}
          className='inline-flex h-4 w-4 shrink-0 items-center justify-center rounded-full border border-hairline align-middle font-mono text-[10px] leading-none text-muted transition-colors hover:border-fg hover:text-fg data-[state=open]:border-fg data-[state=open]:text-fg'
        >
          i
        </button>
      </Popover.Trigger>
      <Popover.Portal>
        <Popover.Content
          side='bottom'
          align='start'
          sideOffset={6}
          collisionPadding={8}
          className='z-[80] w-[min(20rem,calc(100vw-1rem))] rounded-lg border border-hairline bg-bg p-3 text-xs leading-relaxed font-normal text-muted shadow-xl'
        >
          {children}
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  )
}
