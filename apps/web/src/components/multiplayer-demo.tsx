'use client'

import { useState } from 'react'
import { DEFAULT_ROOM, type IdentityState, useIdentityStore } from '../lib/identity-store'
import { RepoBackendProvider, useRepoEvents, useResolvedRepoBackend } from '../lib/repo-api'
import { useMkit } from './use-mkit'
import { Compose, ComposeDisabled } from './multiplayer/compose'
import { FloatingDock } from './multiplayer/floating-dock'
import { PresencePanel } from './multiplayer/presence-panel'
import { RefsPanel, RepoLog } from './multiplayer/repo-browser'
import { WebMcpTools } from './multiplayer/webmcp-tools'

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

  // Repo-browser navigation state (no router change needed): which ref the
  // log/detail view follows, and which commit's detail is open (null = none).
  const [selectedRef, setSelectedRef] = useState('main')
  const [selectedCommit, setSelectedCommit] = useState<string | null>(null)

  return (
    <div className='space-y-8'>
      {/* WebMCP (https://github.com/webmachinelearning/webmcp) tool registration — renders nothing; lets an in-page
          agent read branches/commits and push/remix/branch through the same signing path as the UI below. */}
      <WebMcpTools
        room={room}
        selectedRef={selectedRef}
        onSelectRef={(r) => {
          setSelectedRef(r)
          setSelectedCommit(null)
        }}
        onSelectCommit={setSelectedCommit}
      />

      {/* Left: the repository's branches. Right: compose, then the selected
          branch's commit log. The log is ALWAYS visible — watch others contribute
          while signing is locked or you are signed out. */}
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
