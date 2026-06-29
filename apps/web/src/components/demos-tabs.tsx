'use client'

import type { ComponentType, ReactNode } from 'react'
import { useEffect, useState } from 'react'
import { AttestDemo } from './attest-demo'
import { DemoBoundary } from './demo-boundary'
import { HashDemo } from './hash-demo'
import { SignDemo } from './sign-demo'
import { StreamingDemo } from './streaming-demo'

type Tab = { id: string; label: string; title: string; body: ReactNode; Demo: ComponentType }

const TABS: Tab[] = [
  {
    id: 'hash',
    label: 'hash',
    title: 'What’s in a hash?',
    body: (
      <>
        Every file, folder, and commit is named by the BLAKE3 hash of its bytes — change one character and the name
        changes. Edit the text or swap the image below and watch every hash rewrite.
      </>
    ),
    Demo: HashDemo,
  },
  {
    id: 'sign',
    label: 'sign',
    title: 'Who signed this?',
    body: (
      <>
        A private key signs a message; the matching public key verifies it. mkit signs every commit this way, with an
        Ed25519 key. Generate a key, sign a message, then flip one character and watch the verifier reject it.
      </>
    ),
    Demo: SignDemo,
  },
  {
    id: 'streaming',
    label: 'streaming',
    title: 'Verify gigabytes, one chunk at a time',
    body: (
      <>
        <p>
          mkit cuts big files into content-defined chunks (FastCDC), ships only the chunks that changed, and verifies
          each one as it arrives. git re-stores the whole binary on every edit.
        </p>
        <br />
        <p>Watch the auto-editor run, or drop in your own large file.</p>
      </>
    ),
    Demo: StreamingDemo,
  },
  {
    id: 'attest',
    label: 'attest',
    title: 'Statements, signed',
    body: (
      <>
        An attestation is a signed statement about a commit — &ldquo;reviewed&rdquo;, &ldquo;tested&rdquo;,
        &ldquo;deployed&rdquo; — stored as a first-class object. mkit uses standard formats (in-toto + DSSE), so anyone
        with your public key can verify it, in mkit or cosign. Type a claim, pick an algorithm, and watch the envelope
        build and verify.
      </>
    ),
    Demo: AttestDemo,
  },
]

export function DemosTabs() {
  const [active, setActive] = useState(0)

  // Honour a `#hash | #sign | #streaming | #attest` deep link on first load —
  // keeps the old per-page URLs meaningful as anchors into the combined page.
  useEffect(() => {
    const id = window.location.hash.slice(1)
    const i = TABS.findIndex((t) => t.id === id)
    if (i >= 0) setActive(i)
  }, [])

  const select = (i: number) => {
    setActive(i)
    const id = TABS[i]?.id
    if (id) window.history.replaceState(null, '', `#${id}`)
  }

  const tab = TABS[active] ?? TABS[0]!
  const ActiveDemo = tab.Demo

  return (
    <div className='space-y-8'>
      <div role='tablist' aria-label='Demos' className='flex flex-wrap gap-1 border-b border-hairline'>
        {TABS.map((t, i) => (
          <button
            key={t.id}
            type='button'
            role='tab'
            aria-selected={i === active}
            onClick={() => select(i)}
            className={`-mb-px border-b-2 px-3 py-2 text-sm transition-colors ${
              i === active ? 'border-fg font-medium text-fg' : 'border-transparent text-muted hover:text-fg'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      <header className='space-y-3'>
        <h1 className='text-4xl font-semibold tracking-tight'>{tab.title}</h1>
        <p className='max-w-prose text-base text-fg'>{tab.body}</p>
      </header>

      {/* Keyed by tab so the previous demo unmounts (and its wasm work stops)
          and the next one mounts fresh — only the active demo ever runs. */}
      <DemoBoundary key={tab.id}>
        <ActiveDemo />
      </DemoBoundary>
    </div>
  )
}
