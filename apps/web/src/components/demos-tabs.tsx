'use client'

import * as Tabs from '@radix-ui/react-tabs'
import type { ComponentType, ReactNode } from 'react'
import { useEffect, useState } from 'react'
import { NavCardButton } from './nav-card'
import { AttestDemo } from './attest-demo'
import { DemoBoundary } from './demo-boundary'
import { HashDemo } from './hash-demo'
import { PushDemo } from './push-demo'
import { SignDemo } from './sign-demo'
import { StreamingDemo } from './streaming-demo'
import { TreeDemo } from './tree-demo'

// `blurb` is the one-line card description shown in the "More demos to explore"
// strip at the bottom. `footer` renders below the demo (push uses it for its
// trailing explanation); most tabs omit it.
type Tab = {
  id: string
  label: string
  title: string
  blurb: string
  body: ReactNode
  Demo: ComponentType
  footer?: ReactNode
}

const TABS: Tab[] = [
  {
    id: 'hash',
    label: 'Hash',
    title: 'What’s in a Hash?',
    blurb: 'A hash is the name of some bytes — change one byte and the name changes completely.',
    body: (
      <>
        A hash is a name for bytes: mkit names every object by the BLAKE3 of its contents. Change a single byte and the
        name changes completely.
      </>
    ),
    Demo: HashDemo,
  },
  {
    id: 'tree',
    label: 'Tree',
    title: 'Folders, All the Way Down',
    blurb: 'Folders of hashes fold up into one Merkle root: file → folder → commit.',
    body: (
      <>
        A folder lists its entries by their BLAKE3 hashes and each parent’s hash is built from its children’s, so the
        whole repo is one Merkle tree where editing a file ripples up: file → folder → commit.
      </>
    ),
    Demo: TreeDemo,
  },
  {
    id: 'sign',
    label: 'Sign',
    title: 'Who Signed This?',
    blurb: 'Sign a message with an Ed25519 key; change a byte or the key and verification fails.',
    body: (
      <>
        A private key signs a message; the matching public key verifies it. mkit signs every commit this way, with an
        Ed25519 key. Sign a message, then edit what the verifier received — or check it against the wrong key — and
        watch verification fail.
      </>
    ),
    Demo: SignDemo,
  },
  {
    id: 'streaming',
    label: 'Streaming',
    title: 'Verify Gigabytes, One Chunk at a Time',
    blurb: 'Content-defined chunking ships and verifies only the parts of a file that changed.',
    body: (
      <>
        mkit cuts big files into content-defined chunks (FastCDC) and verifies each one against a Bao root as it arrives
        — corruption is caught mid-stream and re-fetched, not discovered after the download. Watch the file stream in
        verified, or corrupt the connection and see the verifier catch it.
      </>
    ),
    Demo: StreamingDemo,
  },
  {
    id: 'push',
    label: 'Push',
    title: 'Push a File, Any File',
    blurb: 'Split a file into hash-named chunks on push and send only the ones that changed.',
    body: <>When you push a file, mkit sends only what changed — not the whole file.</>,
    Demo: PushDemo,
  },
  {
    id: 'attest',
    label: 'Attest',
    title: 'Statements, Signed',
    blurb: 'A signed, first-class statement about a commit — reviewed, tested, deployed.',
    body: (
      <>
        An attestation is a signed statement about a commit — reviewed, tested, deployed. Verifying it proves who said
        what about which commit. Standard formats (in-toto + DSSE), so cosign can verify it too.
      </>
    ),
    Demo: AttestDemo,
  },
]

export function DemosTabs() {
  const [active, setActive] = useState(TABS[0]!.id)

  // Honour a `#hash | #tree | #sign | #streaming | #push | #attest` deep link —
  // on first load (keeps the old per-page URLs meaningful as anchors into the
  // combined page) and on every later hashchange (so a hash link to a tab
  // activates it).
  useEffect(() => {
    const apply = () => {
      const id = window.location.hash.slice(1)
      if (TABS.some((t) => t.id === id)) setActive(id)
    }
    apply()
    window.addEventListener('hashchange', apply)
    return () => window.removeEventListener('hashchange', apply)
  }, [])

  const onValueChange = (id: string) => {
    setActive(id)
    window.history.replaceState(null, '', `#${id}`)
  }

  // Switch to a tab and jump back to the top so the newly-selected demo is in
  // view (the strip that triggers this sits at the bottom of the page).
  const goToTab = (id: string) => {
    onValueChange(id)
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }

  // Every other concept, starting from the one after the active tab and
  // wrapping — a complete list, so no concept reads as omitted by accident.
  const activeIndex = Math.max(
    0,
    TABS.findIndex((t) => t.id === active),
  )
  const upNext = Array.from({ length: TABS.length - 1 }, (_, i) => TABS[(activeIndex + 1 + i) % TABS.length]!)

  return (
    <div className='space-y-8'>
      <Tabs.Root value={active} onValueChange={onValueChange} className='space-y-8'>
        <Tabs.List
          aria-label='Demos'
          className='flex flex-nowrap gap-0.5 overflow-x-auto border-b max-sm:[mask-image:linear-gradient(to_right,black_calc(100%-24px),transparent)]'
          style={{ borderColor: 'var(--border-color-subtle)' }}
        >
          {TABS.map((t) => (
            <Tabs.Trigger
              key={t.id}
              value={t.id}
              className='-mb-px shrink-0 border-b-2 border-transparent px-3 py-2 whitespace-nowrap text-secondary transition-colors duration-(--duration-fast) ease-standard hover:text-primary data-[state=active]:border-(--border-color-selected) data-[state=active]:font-medium data-[state=active]:text-primary'
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
              <header>
                <h1 className='ds-h1'>{t.title}</h1>
                <p className='mt-2 max-w-prose'>{t.body}</p>
              </header>
              <DemoBoundary>
                <Demo />
              </DemoBoundary>
              {t.footer}
            </Tabs.Content>
          )
        })}
      </Tabs.Root>

      {/* "Up next" — the other demos on this page, starting from the one after
          the active tab (wrapping around). Switches tabs in place rather than
          navigating away. */}
      <section>
        <h2 className='ds-h2 rule-square pb-2'>More Concepts to Explore</h2>
        <ul className='mt-2 grid grid-cols-1 gap-3 sm:grid-cols-3'>
          {upNext.map((t) => (
            <NavCardButton key={t.id} onClick={() => goToTab(t.id)} title={t.label} body={t.blurb} />
          ))}
        </ul>
      </section>
    </div>
  )
}
