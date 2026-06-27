'use client'

import * as RadixTooltip from '@radix-ui/react-tooltip'
import type { ReactNode } from 'react'

/**
 * Hover/focus tooltip on an interactive element. Self-contained (carries its own
 * provider) so it can be dropped anywhere without an app-level wrapper, and
 * portaled + collision-aware via Radix. Use for buttons/links where a short hint
 * helps; for revealing a full value (e.g. a complete hash) on a non-interactive
 * text node, a native `title` is the right tool instead.
 */
export function Tooltip({
  content,
  children,
  side = 'top',
}: {
  content: ReactNode
  children: ReactNode
  side?: 'top' | 'right' | 'bottom' | 'left'
}) {
  return (
    <RadixTooltip.Provider delayDuration={300} skipDelayDuration={150}>
      <RadixTooltip.Root>
        <RadixTooltip.Trigger asChild>{children}</RadixTooltip.Trigger>
        <RadixTooltip.Portal>
          <RadixTooltip.Content
            side={side}
            sideOffset={6}
            collisionPadding={8}
            className='z-50 max-w-xs rounded-md border border-hairline bg-bg px-2 py-1 text-xs text-fg shadow-md'
          >
            {content}
          </RadixTooltip.Content>
        </RadixTooltip.Portal>
      </RadixTooltip.Root>
    </RadixTooltip.Provider>
  )
}
