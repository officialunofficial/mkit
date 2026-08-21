'use client'

import { CheckIcon, CopyIcon, XIcon } from '@phosphor-icons/react/ssr'
import { useState } from 'react'

type CopyState = 'idle' | 'copied' | 'failed'

/**
 * Copy affordance (§4.11): feedback replaces the icon in place without changing the control's width, returns to idle on
 * its own, and failure shows a mark distinct from both idle and success. The glyph is icon-small beside text-sm content
 * (§2.8 rule 3); the invisible padding extends the hit area without growing the mark (§4.1 rule 4).
 */
export function CopyButton({ text, label = 'Copy command' }: { text: string; label?: string }) {
  const [state, setState] = useState<CopyState>('idle')

  const copy = () => {
    void navigator.clipboard
      ?.writeText(text)
      .then(() => setState('copied'))
      .catch(() => setState('failed'))
      .finally(() => {
        setTimeout(() => setState('idle'), 1500)
      })
  }

  return (
    <button
      type='button'
      onClick={copy}
      aria-label={state === 'copied' ? 'Copied' : label}
      className='-m-2 shrink-0 p-2 text-secondary transition-colors duration-(--duration-fast) ease-standard hover:text-primary'
    >
      {state === 'copied' ? (
        <CheckIcon size={12} aria-hidden style={{ color: 'var(--status-success-fg)' }} />
      ) : state === 'failed' ? (
        <XIcon size={12} aria-hidden style={{ color: 'var(--status-error-fg)' }} />
      ) : (
        <CopyIcon size={12} aria-hidden />
      )}
    </button>
  )
}
