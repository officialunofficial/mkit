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
        Every file, folder, and commit is named by the BLAKE3 hash of its bytes — change a single character and the name
        changes too. git does the same with SHA-1; mkit uses BLAKE3, one algorithm everywhere, fast enough to re-hash on
        every keystroke. This page builds a tiny commit out of two files: edit the text or swap the image and watch
        every hash along the way rewrite.
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
        A private key signs a message; the matching public key verifies it — anyone can confirm the message is untouched
        and that you signed it. In mkit this isn&rsquo;t optional: every commit carries an Ed25519 signature, where git
        treats signing as a GPG add-on. Generate a key, sign a message, then flip a single character and watch the
        verifier reject it.
      </>
    ),
    Demo: SignDemo,
  },
  {
    id: 'streaming',
    label: 'streaming',
    title: 'Verifiable at gigabyte scale',
    body: (
      <>
        Content addressing only works on big files if you can chunk, diff, and stream-verify them — git stores a fresh
        copy of a large binary on every edit. mkit cuts files at content-defined boundaries (FastCDC), records the chunk
        list in a ChunkedBlob, ships only the changed chunks as a delta, and verifies each chunk against the root hash
        as it arrives (Bao). Drop a file — or let the auto-editor run — and watch all four below.
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
        An attestation is a signed statement about a commit — &ldquo;reviewed&rdquo;, &ldquo;deployed&rdquo;,
        &ldquo;tested&rdquo; — stored in the repo as a first-class object, not a side-channel. mkit uses the standard
        formats (an in-toto Statement inside a DSSE signing envelope), so anyone holding your public key can verify it
        later — with mkit, cosign, or any compliant verifier. Type a claim, pick a signing algorithm, and watch the
        envelope rebuild and verify.
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
