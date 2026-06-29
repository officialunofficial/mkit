'use client'

// A small "ⓘ" affordance next to a field label. On devices with a pointer it
// opens on HOVER; everywhere it also opens on click/tap and keyboard focus.
// Built on Radix Popover so positioning, collision avoidance, focus management,
// and dismiss (Esc / outside-click) are handled for us. Popover is click-only by
// itself, so we drive `open` ourselves and add the hover intent on top — with a
// short close delay that bridges the gap between the trigger and the content so
// the pointer can travel into the panel without it snapping shut.

import * as Popover from '@radix-ui/react-popover'
import { type ReactNode, useRef, useState } from 'react'

export function InfoTip({
  label,
  children,
}: {
  /** Accessible name for the trigger (e.g. "About rooms"). */
  label: string
  /** Popover content. */
  children: ReactNode
}) {
  const [open, setOpen] = useState(false)
  const closeTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  const cancelClose = () => {
    if (closeTimer.current) {
      clearTimeout(closeTimer.current)
      closeTimer.current = null
    }
  }
  const openNow = () => {
    cancelClose()
    setOpen(true)
  }
  // Small delay so moving the pointer across the trigger→content gap doesn't
  // close the popover mid-travel.
  const closeSoon = () => {
    cancelClose()
    closeTimer.current = setTimeout(() => setOpen(false), 120)
  }

  return (
    <Popover.Root open={open} onOpenChange={setOpen}>
      <Popover.Trigger asChild>
        <button
          type='button'
          aria-label={label}
          onPointerEnter={(e) => {
            // Touch taps also fire pointerenter; let the click handler own those
            // so we don't double-toggle.
            if (e.pointerType !== 'touch') openNow()
          }}
          onPointerLeave={(e) => {
            if (e.pointerType !== 'touch') closeSoon()
          }}
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
          // Hovering INTO the content keeps it open; leaving closes it. Don't
          // pull focus on hover-open, so the page doesn't scroll to it.
          onPointerEnter={openNow}
          onPointerLeave={closeSoon}
          onOpenAutoFocus={(e) => e.preventDefault()}
          className='z-[80] w-[min(20rem,calc(100vw-1rem))] rounded-lg border border-hairline bg-bg p-3 text-xs leading-relaxed font-normal text-muted shadow-xl'
        >
          {children}
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  )
}
