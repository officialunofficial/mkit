'use client'

import { useQueryClient } from '@tanstack/react-query'
import { useEffect, useMemo, useState } from 'react'
import { PrfUnsupportedError, createIdentity, deriveEd25519Seed } from '../lib/passkey'
import { DEFAULT_ROOM, useIdentityStore } from '../lib/identity-store'
import { MockRepoBackend, WasmRepoBackend, setRepoBackend, useRepoEvents } from '../lib/repo-api'
import { repoWasm } from '../lib/repo-client'
import { bytesToHex, hexToBytes, useMkit } from './use-mkit'
import { AttestBinding, LockedView, UnlockedHeader } from './multiplayer/identity-panel'
import { Compose } from './multiplayer/compose'
import { RepoBrowser } from './multiplayer/repo-browser'
import { errMsg } from './multiplayer/shared'

/** The single source of identity + push + live-log UI (design note §2 steps 1–6). */
export function MultiplayerDemo() {
  const api = useMkit()
  const id = useIdentityStore()
  const qc = useQueryClient()
  const room = id.room || DEFAULT_ROOM

  // Backend selection: when `VITE_REPO_BACKEND_URL` is set, drive the real
  // ConnectRPC service through the wasm client; otherwise use the in-memory mock
  // (offline dev default). The mock is the synchronous fallback; the wasm client
  // initialises asynchronously and replaces it once ready.
  const backendUrl = import.meta.env.VITE_REPO_BACKEND_URL as string | undefined
  const useMock = !backendUrl

  // One mock backend per mounted demo, always available as the offline fallback.
  const mock = useMemo(() => new MockRepoBackend(api), [api])

  // Install the mock as the bootstrap backend — MOCK MODE ONLY. In worker mode
  // we deliberately leave the backend NULL until the wasm effect installs the
  // WasmRepoBackend: gating queries on `useRepoBackendReady()` keeps refs/log
  // PENDING (→ skeleton) instead of letting them resolve empty `[]` against the
  // not-yet-seeded mock and flashing "No refs/commits" on a populated room. The
  // genuine offline fallback lives in the wasm effect's `.catch` (if wasm load
  // rejects). Deps `[mock, useMock]` — NOT `room` (editing the Room must not
  // re-install and clobber the WasmRepoBackend back to mock).
  useEffect(() => {
    if (useMock) setRepoBackend(mock)
  }, [mock, useMock])

  useEffect(() => {
    // MOCK MODE ONLY. The foreign-commit/remix seeding is a mock-only demo
    // affordance — in worker mode the room's real shared history comes from the
    // worker, so don't seed (and don't touch the active backend). Gated on the
    // same `!backendUrl` condition the wasm effect below uses. The seeding logic
    // (3 foreign commits + a sample remix) lives on the backend itself.
    if (useMock) mock.seedDemo(room)
  }, [mock, room, useMock])

  // When a backend URL is configured, install the wasm-backed ConnectRPC client.
  // It reads the live seed from the identity store at call time so writes sign
  // with whatever key is currently unlocked.
  useEffect(() => {
    if (!backendUrl) return
    let cancelled = false
    void repoWasm()
      .then((wasm) => {
        if (cancelled) return
        setRepoBackend(
          new WasmRepoBackend(wasm, api, () => useIdentityStore.getState().seedHex, backendUrl),
        )
        // Installing the backend flips `useRepoBackendReady()` true, enabling the
        // gated refs/head/log queries to fetch against the worker (the room's
        // real, shared history). Invalidate the whole `repo` tree to be safe in
        // case anything was cached. See repo-api `repoKeys` (all prefixed `repo`).
        void qc.invalidateQueries({ queryKey: ['repo'] })
      })
      .catch(() => {
        // GENUINE FALLBACK: if the wasm client fails to load in worker mode,
        // install the mock so the demo still runs (offline-style) rather than
        // leaving every query stuck pending forever.
        if (!cancelled) setRepoBackend(mock)
      })
    return () => {
      cancelled = true
    }
  }, [backendUrl, api, qc, mock])

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
