'use client'

import * as Tabs from '@radix-ui/react-tabs'
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
    title: 'Verifiable at gigabyte scale',
    body: (
      <>
        mkit cuts big files into content-defined chunks (FastCDC), ships only the chunks that changed, and verifies each
        one as it arrives — where git re-stores the whole binary on every edit. Drop a file, or let the auto-editor run,
        and watch it work.
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
  const [active, setActive] = useState(TABS[0]!.id)

  // Honour a `#hash | #sign | #streaming | #attest` deep link on first load —
  // keeps the old per-page URLs meaningful as anchors into the combined page.
  useEffect(() => {
    const id = window.location.hash.slice(1)
    if (TABS.some((t) => t.id === id)) setActive(id)
  }, [])

  const onValueChange = (id: string) => {
    setActive(id)
    window.history.replaceState(null, '', `#${id}`)
  }

  return (
    <Tabs.Root value={active} onValueChange={onValueChange} className='space-y-8'>
      <Tabs.List aria-label='Demos' className='flex flex-wrap gap-1 border-b border-hairline'>
        {TABS.map((t) => (
          <Tabs.Trigger
            key={t.id}
            value={t.id}
            className='-mb-px border-b-2 border-transparent px-3 py-2 text-sm text-muted transition-colors hover:text-fg data-[state=active]:border-fg data-[state=active]:font-medium data-[state=active]:text-fg'
          >
            {t.label}
          </Tabs.Trigger>
        ))}
      </Tabs.List>

      {/* Radix unmounts inactive content, so only the active demo is mounted —
          the previous one's wasm work stops when you switch. */}
      {TABS.map((t) => {
        const Demo = t.Demo
        return (
          <Tabs.Content key={t.id} value={t.id} className='space-y-8 focus-visible:outline-none'>
            <header className='space-y-3'>
              <h1 className='text-4xl font-semibold tracking-tight'>{t.title}</h1>
              <p className='max-w-prose text-base text-fg'>{t.body}</p>
            </header>
            <DemoBoundary>
              <Demo />
            </DemoBoundary>
          </Tabs.Content>
        )
      })}
    </Tabs.Root>
  )
}
