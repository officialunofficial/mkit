'use client'

import { useState } from 'react'
import { DEFAULT_ROOM, type IdentityState, useIdentityStore } from '../lib/identity-store'
import { RepoBackendProvider, useRepoEvents, useResolvedRepoBackend } from '../lib/repo-api'
import { useIdentityActions } from './use-identity-actions'
import { useMkit } from './use-mkit'
import { AttestBinding, LockedView, RoomSelector, UnlockedHeader } from './multiplayer/identity-panel'
import { Compose, ComposeDisabled } from './multiplayer/compose'
import { RepoBrowser } from './multiplayer/repo-browser'
import { WhatJustHappened } from './multiplayer/what-just-happened'

/**
 * Owns the repo backend as a VALUE and provides it to the tree. `useResolvedRepoBackend` returns the mock offline (seeded
 * with demo activity at creation) or the wasm-backed client once it loads; descendants gate on `backend` being non-null.
 */
export function MultiplayerDemo() {
  const api = useMkit()
  const id = useIdentityStore()
  const room = id.room || DEFAULT_ROOM

  const { backend, useMock } = useResolvedRepoBackend(api, room)

  return (
    <RepoBackendProvider backend={backend}>
      <MultiplayerBody api={api} id={id} room={room} useMock={useMock} />
      {/* Retrospective, non-blocking play-by-play (bottom-right). Reads its own
          global store, so no props — every action emits into it directly. */}
      <WhatJustHappened />
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
  // The "what just happened" narration is emitted from inside that hook.
  const { onCreate, onUnlock, busy, status } = useIdentityActions()

  // Repo-browser navigation state (no router change needed): which ref the
  // log/detail view follows, and which commit's detail is open (null = none).
  const [selectedRef, setSelectedRef] = useState('main')
  const [selectedCommit, setSelectedCommit] = useState<string | null>(null)

  // The repo browser (right column) is rendered the same whether locked or not,
  // so it's built once here and dropped into the layout below. `myPubkey`/
  // `seedHex` are null while locked → it renders read-only (browse, no fork).
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

  return (
    <div className='space-y-8'>
      {/* Identity — its own bordered section spanning both columns. The locked
          create/unlock actions and the unlocked player header share this banner
          so "who am I" reads as one distinct concern above the repo workspace. */}
      <section className='rounded-xl border border-hairline p-4 sm:p-5'>
        {id.unlocked && id.ed25519PubkeyHex ? (
          <div className='space-y-4'>
            <UnlockedHeader />
            <details className='group'>
              <summary className='flex cursor-pointer list-none items-center gap-1 text-sm text-muted select-none hover:text-fg [&::-webkit-details-marker]:hidden'>
                <span className='inline-block transition-transform group-open:rotate-90'>›</span> Attest this Ed25519
                with a passkey (optional)
              </summary>
              <div className='mt-3'>
                <AttestBinding api={api} ed25519PubkeyHex={id.ed25519PubkeyHex} />
              </div>
            </details>
          </div>
        ) : (
          <LockedView
            onCreate={onCreate}
            onUnlock={onUnlock}
            busy={busy}
            status={status}
            hasPasskey={id.credentialId != null}
          />
        )}
      </section>

      {/* Left: the repository you're in + the compose surface. Right: that repo's
          shared commit log / browser. The log is ALWAYS visible — watch others
          contribute even before you unlock an identity ("signed out" mode). */}
      <div className='grid grid-cols-1 gap-8 lg:grid-cols-2 lg:items-start'>
        <div className='space-y-6'>
          <RoomSelector />
          {id.unlocked && id.seedHex ? (
            <Compose api={api} seedHex={id.seedHex} room={room} targetRef={selectedRef} onTargetRef={setSelectedRef} />
          ) : (
            <ComposeDisabled />
          )}
        </div>
        {browser}
      </div>
    </div>
  )
}
