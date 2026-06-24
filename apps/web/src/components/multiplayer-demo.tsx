'use client'

import { useQueryClient } from '@tanstack/react-query'
import { useEffect, useMemo, useState } from 'react'
import { PrfUnsupportedError, createIdentity, deriveEd25519Seed } from '../lib/passkey'
import { DEFAULT_ROOM, type IdentityState, useIdentityStore } from '../lib/identity-store'
import {
  MockRepoBackend,
  type RepoBackend,
  RepoBackendProvider,
  WasmRepoBackend,
  useRepoEvents,
} from '../lib/repo-api'
import { repoWasm } from '../lib/repo-client'
import { bytesToHex, hexToBytes, useMkit } from './use-mkit'
import { AttestBinding, LockedView, UnlockedHeader } from './multiplayer/identity-panel'
import { Compose } from './multiplayer/compose'
import { RepoBrowser } from './multiplayer/repo-browser'
import { errMsg } from './multiplayer/shared'

/**
 * Owns the repo backend as a VALUE and provides it to the tree. The backend is
 * computed (not imperatively installed): the mock is memoised; the wasm client
 * loads into state. `backend` is `null` in worker mode until wasm resolves, so
 * descendants gate on it (skeleton) — the behavior the old readiness flag gave.
 */
export function MultiplayerDemo() {
  const api = useMkit()
  const id = useIdentityStore()
  const qc = useQueryClient()
  const room = id.room || DEFAULT_ROOM

  // Backend selection: when `VITE_REPO_BACKEND_URL` is set, drive the real
  // ConnectRPC service through the wasm client; otherwise use the in-memory mock
  // (offline dev default).
  const backendUrl = import.meta.env.VITE_REPO_BACKEND_URL as string | undefined
  const useMock = !backendUrl

  // One mock backend per mounted demo, always available as the offline fallback.
  const mock = useMemo(() => new MockRepoBackend(api), [api])

  // Worker mode: the wasm-backed backend loads asynchronously into state. While
  // it's null the children gate on the context (skeleton) instead of resolving
  // empty against the not-yet-ready mock. One effect owns the load + fallback.
  const [wasmBackend, setWasmBackend] = useState<RepoBackend | null>(null)
  useEffect(() => {
    if (!backendUrl) return
    let cancelled = false
    repoWasm()
      .then((wasm) => {
        if (cancelled) return
        // The wasm backend reads the live seed from the identity store at call
        // time so writes sign with whatever key is currently unlocked.
        setWasmBackend(new WasmRepoBackend(wasm, api, () => useIdentityStore.getState().seedHex, backendUrl))
      })
      .catch(() => {
        // GENUINE FALLBACK: if the wasm client fails to load in worker mode, use
        // the mock so the demo still runs (offline-style) rather than leaving
        // every query stuck pending forever.
        if (!cancelled) setWasmBackend(mock)
      })
    return () => {
      cancelled = true
    }
  }, [backendUrl, api, mock])

  // The backend VALUE the tree owns: mock offline, else the wasm backend once it
  // loads (null until then → children gate → skeleton).
  const backend = useMock ? mock : wasmBackend

  useEffect(() => {
    // MOCK MODE ONLY. The foreign-commit/remix seeding is a mock-only demo
    // affordance — in worker mode the room's real shared history comes from the
    // worker, so don't seed. The seeding logic (3 foreign commits + a sample
    // remix) lives on the backend itself.
    if (useMock) mock.seedDemo(room)
  }, [mock, room, useMock])

  // The backend just became available (null → mock/wasm) — refresh the gated
  // queries so they fetch the room's real, shared history. See `repoKeys` (all
  // prefixed `repo`).
  useEffect(() => {
    if (backend) void qc.invalidateQueries({ queryKey: ['repo'] })
  }, [backend, qc])

  return (
    <RepoBackendProvider backend={backend}>
      <MultiplayerBody api={api} id={id} room={room} useMock={useMock} />
    </RepoBackendProvider>
  )
}

/**
 * The demo body — a DESCENDANT of the provider so `useRepoEvents` and every
 * panel read the backend from context. (Kept separate from the component that
 * renders the provider: a component can't consume a context it provides.)
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

  const [status, setStatus] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  // Repo-browser navigation state (no router change needed): which ref the
  // log/detail view follows, and which commit's detail is open (null = none).
  const [selectedRef, setSelectedRef] = useState('main')
  const [selectedCommit, setSelectedCommit] = useState<string | null>(null)

  // One ceremony: create the passkey AND derive the Ed25519 seed (PRF-on-create),
  // falling back to one get() or an ephemeral key inside `createIdentity`. Every
  // push afterwards signs with the in-memory key — no further prompts.
  const onCreate = async () => {
    setStatus(null)
    setBusy(true)
    try {
      const res = await createIdentity()
      // Persist the credentialId ONLY for a real (passkey-backed) identity. The
      // ephemeral fallback returns the created credentialId too, but its seed is
      // RANDOM — not derived from that passkey — so persisting it would flip
      // `hasPasskey` true and surface an "Unlock" that derives a DIFFERENT seed
      // (a non-functional identity). Ephemeral identities can't be recovered, so
      // the locked screen must stay on "Create".
      if (res.credentialId && res.via !== 'ephemeral') id.setCredentialId(res.credentialId)
      const pubkey = bytesToHex(api.ed25519_pubkey_from_seed(hexToBytes(res.seedHex)))
      id.unlock({ seedHex: res.seedHex, ed25519PubkeyHex: pubkey, ephemeral: res.via === 'ephemeral' })
      setStatus(
        res.via === 'prf-create'
          ? 'Identity ready — one passkey prompt, Ed25519 derived via PRF.'
          : res.via === 'prf-get'
            ? 'Identity ready — Ed25519 derived from your passkey via PRF.'
            : 'PRF unavailable — using a random in-memory key (won’t persist across sessions or devices).',
      )
    } catch (e) {
      setStatus(errMsg(e))
    } finally {
      setBusy(false)
    }
  }

  // RECOVER the SAME identity (after a Lock, or on a returning visit). Unlike
  // `onCreate`, this does NOT mint a new passkey: `deriveEd25519Seed` runs a
  // get() that re-derives the SAME PRF → SAME seed → SAME Ed25519 pubkey from
  // the existing (resident) passkey. A discoverable get() (no credentialId)
  // still recovers the same identity and tells us which passkey was used, so we
  // persist it for next time.
  const onUnlock = async () => {
    setStatus(null)
    setBusy(true)
    try {
      const res = await deriveEd25519Seed(id.credentialId ?? undefined)
      if (res.credentialId) id.setCredentialId(res.credentialId)
      const pubkey = bytesToHex(api.ed25519_pubkey_from_seed(hexToBytes(res.seedHex)))
      id.unlock({ seedHex: res.seedHex, ed25519PubkeyHex: pubkey, ephemeral: false })
      setStatus('Unlocked — recovered your existing player from the passkey via PRF.')
    } catch (e) {
      if (e instanceof PrfUnsupportedError) {
        setStatus('This passkey can’t derive a key (no PRF). Create a new identity instead.')
      } else {
        setStatus(errMsg(e))
      }
    } finally {
      setBusy(false)
    }
  }

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
      <div className='grid gap-8 lg:grid-cols-2 lg:items-start'>
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
    <div className='grid gap-8 lg:grid-cols-2 lg:items-start'>
      <div className='space-y-6'>
        <UnlockedHeader />
        <Compose api={api} seedHex={id.seedHex} room={room} targetRef={selectedRef} onTargetRef={setSelectedRef} />
        <details className='group'>
          <summary className='flex cursor-pointer list-none items-center gap-1 text-sm text-muted select-none hover:text-fg [&::-webkit-details-marker]:hidden'>
            <span className='inline-block transition-transform group-open:rotate-90'>›</span> Attest this Ed25519 with a
            passkey (optional)
          </summary>
          <div className='mt-3'>
            <AttestBinding api={api} ed25519PubkeyHex={id.ed25519PubkeyHex} />
          </div>
        </details>
      </div>
      {browser}
    </div>
  )
}
