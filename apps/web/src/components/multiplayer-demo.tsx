'use client'

import { useState } from 'react'
import { DEFAULT_ROOM, type IdentityState, useIdentityStore } from '../lib/identity-store'
import { RepoBackendProvider, useRepoEvents, useResolvedRepoBackend } from '../lib/repo-api'
import { useIdentityActions } from './use-identity-actions'
import { useMkit } from './use-mkit'
import { LockedView, UnlockedHeader } from './multiplayer/identity-panel'
import { Compose, ComposeDisabled } from './multiplayer/compose'
import { FloatingDock } from './multiplayer/floating-dock'
import { PresencePanel } from './multiplayer/presence-panel'
import { RefsPanel, RepoLog } from './multiplayer/repo-browser'

/**
 * Owns the repo backend as a VALUE and provides it to the tree. `useResolvedRepoBackend` returns the mock offline
 * (seeded with demo activity at creation) or the wasm-backed client once it loads; descendants gate on `backend` being
 * non-null.
 */
export function MultiplayerDemo() {
  const api = useMkit()
  const id = useIdentityStore()
  // ONE fixed shared repository — everyone contributes here (via branches), no
  // repo switching. See `RoomSelector` (read-only).
  const room = DEFAULT_ROOM

  const { backend, useMock } = useResolvedRepoBackend(api, room)

  return (
    <RepoBackendProvider backend={backend}>
      <MultiplayerBody api={api} id={id} room={room} useMock={useMock} />
      {/* Draggable dock (snaps to one of 8 anchors, persisted). Renders null when empty. */}
      <FloatingDock>
        <PresencePanel room={room} />
      </FloatingDock>
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
  const { onCreate, onUnlock, busy, status, embeddedBrowserWarning } = useIdentityActions()

  // Repo-browser navigation state (no router change needed): which ref the
  // log/detail view follows, and which commit's detail is open (null = none).
  const [selectedRef, setSelectedRef] = useState('main')
  const [selectedCommit, setSelectedCommit] = useState<string | null>(null)

  return (
    <div className='space-y-8'>
      {/* Identity — its own bordered section spanning both columns. The locked
          create/unlock actions and the unlocked player header share this banner
          so "who am I" reads as one distinct concern above the repo workspace. */}
      <section className='rounded-xl border border-hairline p-4 sm:p-5'>
        {id.unlocked && id.ed25519PubkeyHex ? (
          <UnlockedHeader api={api} ed25519PubkeyHex={id.ed25519PubkeyHex} />
        ) : (
          <LockedView
            onCreate={onCreate}
            onUnlock={onUnlock}
            busy={busy}
            status={status}
            hasPasskey={id.credentialId != null}
            embeddedBrowserWarning={embeddedBrowserWarning}
          />
        )}
      </section>

      {/* Left: the repository's branches. Right: compose, then the selected
          branch's commit log. The log is ALWAYS visible — watch others contribute
          even before you unlock an identity ("signed out" mode). */}
      <div className='grid grid-cols-1 gap-8 lg:grid-cols-2 lg:items-start'>
        <div className='space-y-6'>
          <RefsPanel
            room={room}
            useMock={useMock}
            selectedRef={selectedRef}
            onSelectRef={(r) => {
              setSelectedRef(r)
              setSelectedCommit(null) // switching branches closes any open detail
            }}
          />
        </div>
        <div className='space-y-6'>
          {id.unlocked && id.seedHex ? (
            <Compose api={api} seedHex={id.seedHex} room={room} targetRef={selectedRef} onTargetRef={setSelectedRef} />
          ) : (
            <ComposeDisabled />
          )}
          <RepoLog
            api={api}
            room={room}
            myPubkey={id.unlocked ? id.ed25519PubkeyHex : null}
            seedHex={id.unlocked ? id.seedHex : null}
            selectedRef={selectedRef}
            onSelectRef={setSelectedRef}
            selectedCommit={selectedCommit}
            onSelectCommit={setSelectedCommit}
          />
        </div>
      </div>
    </div>
  )
}
