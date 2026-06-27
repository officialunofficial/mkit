'use client'

import * as Collapsible from '@radix-ui/react-collapsible'
import { useState } from 'react'
import { DEFAULT_ROOM, type IdentityState, useIdentityStore } from '../lib/identity-store'
import { RepoBackendProvider, useRepoEvents, useResolvedRepoBackend } from '../lib/repo-api'
import { useIdentityActions } from './use-identity-actions'
import { useMkit } from './use-mkit'
import { AttestBinding, LockedView, UnlockedHeader } from './multiplayer/identity-panel'
import { Compose } from './multiplayer/compose'
import { RepoBrowser } from './multiplayer/repo-browser'

/**
 * Owns the repo backend as a VALUE and provides it to the tree. The backend is computed (not imperatively installed):
 * the mock is memoised; the wasm client loads into state. `backend` is `null` in worker mode until wasm resolves, so
 * descendants gate on it (skeleton) — the behavior the old readiness flag gave.
 */
export function MultiplayerDemo() {
  const api = useMkit()
  const id = useIdentityStore()
  const room = id.room || DEFAULT_ROOM

  // Backend (mock offline, wasm once loaded). The mock is seeded with offline
  // demo activity AT CREATION inside the hook, so the first query read already
  // sees it — no seeding/invalidate Effect, no empty-first-render race
  // (https://react.dev/learn/you-might-not-need-an-effect).
  const { backend, useMock } = useResolvedRepoBackend(api, room)

  return (
    <RepoBackendProvider backend={backend}>
      <MultiplayerBody api={api} id={id} room={room} useMock={useMock} />
    </RepoBackendProvider>
  )
}

/**
 * The demo body — a DESCENDANT of the provider so `useRepoEvents` and every panel read the backend from context. (Kept
 * separate from the component that renders the provider: a component can't consume a context it provides.)
 */
function MultiplayerBody({
  api,
  id,
  room,
  useMock,
}: {
  api: ReturnType<typeof useMkit>
  id: IdentityState
  room: string
  useMock: boolean
}) {
  useRepoEvents(room)

  // The passkey create/unlock ceremony — shared with the front-page lobby via
  // `useIdentityActions` so the ceremony + keys.mkit.sh registration live once.
  const { onCreate, onUnlock, busy, status } = useIdentityActions()

  // Repo-browser navigation state (no router change needed): which ref the
  // log/detail view follows, and which commit's detail is open (null = none).
  const [selectedRef, setSelectedRef] = useState('main')
  const [selectedCommit, setSelectedCommit] = useState<string | null>(null)

  // State machine: LOCKED → (one prompt) → UNLOCKED, laid out in two columns with
  // the live log ALWAYS on the right — so you can watch others contribute even
  // before you create an identity ("signed out" mode). The left column swaps
  // between the single create action and the compose/attest surface.
  const browser = (
    <RepoBrowser
      api={api}
      room={room}
      myPubkey={id.unlocked ? id.ed25519PubkeyHex : null}
      seedHex={id.unlocked ? id.seedHex : null}
      useMock={useMock}
      selectedRef={selectedRef}
      onSelectRef={(r) => {
        setSelectedRef(r)
        setSelectedCommit(null) // switching branches closes any open detail
      }}
      selectedCommit={selectedCommit}
      onSelectCommit={setSelectedCommit}
    />
  )

  if (!id.unlocked || !id.seedHex || !id.ed25519PubkeyHex) {
    return (
      <div className='grid grid-cols-1 gap-8 lg:grid-cols-2 lg:items-start'>
        <LockedView
          onCreate={onCreate}
          onUnlock={onUnlock}
          busy={busy}
          status={status}
          hasPasskey={id.credentialId != null}
        />
        {browser}
      </div>
    )
  }
  return (
    <div className='grid grid-cols-1 gap-8 lg:grid-cols-2 lg:items-start'>
      <div className='space-y-4'>
        <UnlockedHeader />
        <Compose api={api} seedHex={id.seedHex} room={room} targetRef={selectedRef} onTargetRef={setSelectedRef} />
        <Collapsible.Root className='group'>
          <Collapsible.Trigger className='flex items-center gap-1 text-sm text-muted transition-colors select-none hover:text-fg'>
            <span className='inline-block transition-transform group-data-[state=open]:rotate-90'>›</span> Attest this
            Ed25519 with a passkey (optional)
          </Collapsible.Trigger>
          <Collapsible.Content className='mt-3'>
            <AttestBinding api={api} ed25519PubkeyHex={id.ed25519PubkeyHex} />
          </Collapsible.Content>
        </Collapsible.Root>
      </div>
      {browser}
    </div>
  )
}
