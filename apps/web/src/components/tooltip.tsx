'use client'

import * as RadixTooltip from '@radix-ui/react-tooltip'
import type { ReactNode } from 'react'

/**
 * Hover/focus tooltip on an interactive element (§4.20). The panel sits on surface-overlay with a border-color-default
 * hairline and shd-overlay — the shadow is how it says it has left the plane (§2.6 rule 2) — at rounded-md (§2.5 rule
 * 2). Content is text-sm, never smaller: a tooltip's content is a value the reader came for (§4.20 rule 2).
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
            className='max-w-xs rounded-(--rounded-md) border px-2 py-1 text-xs text-primary'
            style={{
              background: 'var(--surface-overlay)',
              borderColor: 'var(--overlay-hairline)',
              boxShadow: 'var(--overlay-shadow)',
              fontSize: 'var(--t-sm)',
              lineHeight: 'var(--t-sm-leading)',
            }}
          >
            {content}
          </RadixTooltip.Content>
        </RadixTooltip.Portal>
      </RadixTooltip.Root>
    </RadixTooltip.Provider>
  )
}
