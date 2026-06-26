'use client'

// A small "ⓘ" affordance next to a field label. Hovering or focusing it (desktop)
// or tapping it (mobile) reveals a popover with extra explanation. Content is a
// `ReactNode`, so callers can pass rich markup (code, emphasis, links).

import { type ReactNode, useId, useState } from 'react'

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
  const id = useId()

  return (
    <span className='relative inline-flex align-middle'>
      <button
        type='button'
        aria-label={label}
        aria-expanded={open}
        aria-describedby={open ? id : undefined}
        onClick={() => setOpen((v) => !v)}
        onMouseEnter={() => setOpen(true)}
        onMouseLeave={() => setOpen(false)}
        onFocus={() => setOpen(true)}
        onBlur={() => setOpen(false)}
        className='inline-flex h-4 w-4 items-center justify-center rounded-full border border-hairline font-mono text-[10px] leading-none text-muted transition-colors hover:border-fg hover:text-fg'
      >
        i
      </button>
      {open ? (
        <span
          id={id}
          role='tooltip'
          // Open below-left of the icon; clamp width so it never overflows a
          // narrow column / small screen. Pointer-events on so it's tappable.
          className='absolute top-6 left-0 z-30 w-[min(20rem,80vw)] rounded-lg border border-hairline bg-bg p-3 text-xs leading-relaxed font-normal text-muted shadow-xl'
        >
          {children}
        </span>
      ) : null}
    </span>
  )
}
