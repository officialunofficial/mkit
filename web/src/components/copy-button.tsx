'use client'

import { useState } from 'react'

function CopyIcon() {
  return (
    <svg
      width='14'
      height='14'
      viewBox='0 0 24 24'
      fill='none'
      stroke='currentColor'
      strokeWidth='2'
      strokeLinecap='round'
      strokeLinejoin='round'
      aria-hidden
    >
      <rect x='9' y='9' width='13' height='13' rx='2' />
      <path d='M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1' />
    </svg>
  )
}

function CheckIcon() {
  return (
    <svg
      width='14'
      height='14'
      viewBox='0 0 24 24'
      fill='none'
      stroke='currentColor'
      strokeWidth='2.5'
      strokeLinecap='round'
      strokeLinejoin='round'
      aria-hidden
    >
      <path d='M20 6 9 17l-5-5' />
    </svg>
  )
}

/** Copy-to-clipboard button. Swaps to a green check for ~1.5s after a successful copy. */
export function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)

  const copy = () => {
    void navigator.clipboard?.writeText(text).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    })
  }

  return (
    <button
      type='button'
      onClick={copy}
      aria-label={copied ? 'Copied' : 'Copy command'}
      className='-m-1 shrink-0 p-1 text-muted transition-opacity duration-300 hover:opacity-70'
      style={copied ? { color: '#16a34a' } : undefined}
    >
      {copied ? <CheckIcon /> : <CopyIcon />}
    </button>
  )
}
