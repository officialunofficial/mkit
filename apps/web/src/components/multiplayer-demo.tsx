'use client'

import { useQueryClient } from '@tanstack/react-query'
import { useEffect, useMemo, useState } from 'react'
import {
  type BindingCredential,
  PrfUnsupportedError,
  attestEd25519Binding,
  createIdentity,
  deriveEd25519Seed,
  enrollBindingPasskey,
  rpId,
} from '../lib/passkey'
import { playerName } from '../lib/identity-name'
import { DEFAULT_ROOM, useIdentityStore } from '../lib/identity-store'
import {
  CasConflictError,
  IdentityLockedError,
  MockRepoBackend,
  WasmRepoBackend,
  type CommitLogEntry,
  type RemixSourceEntry,
  decodeLogObject,
  forkRefName,
  getRepoBackend,
  isForkRef,
  setRepoBackend,
  useCommitLog,
  useObject,
  usePushCommit,
  useRef,
  useRefs,
  useRepoEvents,
} from '../lib/repo-api'
import { repoWasm } from '../lib/repo-client'
import { Field, FieldList, HashChip, INPUT_CLASSES } from './result-panel'
import { bytesToHex, useMkit } from './use-mkit'

const BTN =
  'inline-flex h-10 shrink-0 items-center justify-center rounded-lg border border-hairline bg-transparent px-3 text-sm font-medium transition-all duration-200 hover:border-fg active:translate-y-px disabled:pointer-events-none disabled:opacity-50 sm:h-9'

// Primary call-to-action: filled blue with white text + a 1px offset dark-blue
// shadow, so the main action (create identity / sign & push) reads as clickable.
const PRIMARY_BTN =
  'inline-flex h-10 shrink-0 items-center justify-center rounded-lg bg-blue-600 px-3 text-sm font-medium text-white shadow-[1px_1px_0_0_#1e3a8a] transition-all duration-200 hover:bg-blue-700 active:translate-y-px active:shadow-none disabled:pointer-events-none disabled:opacity-50 sm:h-9'

// A couple of "other players'" commits, so the live multiplayer log isn't empty
// on first load. Seeded once per mock backend. The third lands on a `feature`
// branch so the refs panel shows more than just `main` offline.
const FOREIGN_SEEDS = ['7'.repeat(64), 'a3'.repeat(32), 'b5'.repeat(32)]
const FOREIGN_MESSAGES = ['hello from another tab', 'ship it 🚀', 'spike on a feature branch']
const FOREIGN_REFS = ['main', 'main', 'feature']

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

  // Install the mock as the SYNCHRONOUS bootstrap backend exactly once per mock
  // instance (deps `[mock]` only — NOT `room`). This is the offline default and,
  // in worker mode, the synchronous fallback the wasm effect replaces once its
  // async init resolves (so head/ref/log queries have a backend to answer before
  // then). Keying this off `room` was the bug: editing the Room re-ran it and
  // clobbered the already-installed WasmRepoBackend, reverting worker → mock.
  useEffect(() => {
    setRepoBackend(mock)
  }, [mock])

  useEffect(() => {
    // MOCK MODE ONLY. The foreign-commit/remix seeding is a mock-only demo
    // affordance — in worker mode the room's real shared history comes from the
    // worker, so don't seed (and don't touch the active backend). Gated on the
    // same `!backendUrl` condition the wasm effect below uses.
    if (!useMock) return
    // Seed foreign commits deterministically so the log shows multiplayer life.
    // Also store the commit object so the offline detail view can decode it.
    // Keep the first foreign commit's hash so we can seed a remix of it.
    let firstCommitHash: string | null = null
    FOREIGN_SEEDS.forEach((seed, i) => {
      const tree = api.tree_encode('[]')
      const commit = api.commit_encode_and_sign(tree.hash_hex, '', FOREIGN_MESSAGES[i]!, BigInt(i), seed)
      if (i === 0) firstCommitHash = commit.hash_hex
      const pubkey = bytesToHex(api.ed25519_pubkey_from_seed(hexToBytes(seed)))
      void mock.putObject(room, commit.hash_hex, commit.bytes)
      mock.seedForeignCommit(room, {
        hash: commit.hash_hex,
        message: FOREIGN_MESSAGES[i]!,
        authorPubkey: pubkey,
        ref: FOREIGN_REFS[i]!,
        createdAt: new Date(Date.now() - (FOREIGN_SEEDS.length - i) * 60_000).toISOString(),
      })
    })
    // Seed a sample remix/fork of the first commit so the fork UI path
    // (badge + navigable upstream link + `forks/` ref) is exercised offline,
    // even before anyone clicks "Fork". The remix decodes through the SAME
    // object_kind → remix_decode walk a real push produces.
    if (firstCommitHash) {
      const upstreamCommit: string = firstCommitHash
      const upstreamId = api.blake3_hex(new TextEncoder().encode(room))
      const sourcesJson = JSON.stringify([
        { upstream_id_hex: upstreamId, commit_hash_hex: upstreamCommit },
      ])
      const tree = api.tree_encode('[]')
      const remix = api.remix_encode_and_sign(
        tree.hash_hex,
        '',
        sourcesJson,
        `fork of ${upstreamCommit.slice(0, 10)}…`,
        4n,
        FOREIGN_SEEDS[0]!,
      )
      const forkRef = forkRefName(upstreamCommit)
      const pubkey = bytesToHex(api.ed25519_pubkey_from_seed(hexToBytes(FOREIGN_SEEDS[0]!)))
      void mock.putObject(room, remix.hash_hex, remix.bytes)
      mock.seedForeignCommit(room, {
        hash: remix.hash_hex,
        message: `fork of ${upstreamCommit.slice(0, 10)}…`,
        authorPubkey: pubkey,
        ref: forkRef,
        createdAt: new Date(Date.now() - 30_000).toISOString(),
        kind: 'remix',
        sources: [{ upstreamIdHex: upstreamId, commitHashHex: upstreamCommit }],
      })
    }
  }, [mock, api, room, useMock])

  // When a backend URL is configured, install the wasm-backed ConnectRPC client.
  // It reads the live seed from the identity store at call time so writes sign
  // with whatever key is currently unlocked.
  useEffect(() => {
    if (!backendUrl) return
    let cancelled = false
    void repoWasm().then((wasm) => {
      if (cancelled) return
      setRepoBackend(
        new WasmRepoBackend(wasm, api, () => useIdentityStore.getState().seedHex, backendUrl),
      )
      // The mock backend answered head/ref/log queries synchronously before
      // the worker-backed client finished initialising; those cached results
      // are stale ("head ∅ / No commits yet"). Invalidate the whole `repo`
      // tree so head/ref/log refetch against the worker (which has the room's
      // real, shared history). See repo-api `repoKeys` (all prefixed `repo`).
      void qc.invalidateQueries({ queryKey: ['repo'] })
    })
    return () => {
      cancelled = true
    }
  }, [backendUrl, api, qc])

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

/**
 * Optional flourish (design note §1, §2 step 4): a P-256 *passkey* vouches that
 * the derived Ed25519 key is the same person's, by signing a DSSE-PAE binding
 * challenge. The assertion is verified in WASM via `verify_webauthn_wrapping`
 * (RP-ID pinned), so the green check proves origin-bound WebAuthn — not just a
 * signature. Anonymous still: the binding ties two keys, not a real identity.
 */
function AttestBinding({
  api,
  ed25519PubkeyHex,
}: {
  api: ReturnType<typeof useMkit>
  ed25519PubkeyHex: string
}) {
  const [binding, setBinding] = useState<BindingCredential | null>(null)
  const [result, setResult] = useState<{ verified: boolean } | null>(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  const onAttest = async () => {
    setErr(null)
    setBusy(true)
    try {
      const b = binding ?? (await enrollBindingPasskey())
      setBinding(b)
      const res = await attestEd25519Binding(api, b, ed25519PubkeyHex, {
        policyJson: JSON.stringify({ expected_rp_id: rpId() }),
      })
      setResult({ verified: res.verified })
    } catch (e) {
      setErr(errMsg(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className='space-y-4'>
      <div className='flex flex-wrap items-center gap-2'>
        <button type='button' className={BTN} onClick={onAttest} disabled={busy}>
          {busy ? 'Attesting…' : 'Attest Ed25519 with a passkey (optional)'}
        </button>
        <span className='text-xs text-muted'>A P-256 passkey vouches this Ed25519 key is yours.</span>
      </div>
      {result || binding ? (
        <FieldList>
          {result ? (
            <Field label='Binding attestation'>
              <span
                className={
                  result.verified ? 'text-green-700 dark:text-green-400' : 'text-red-600 dark:text-red-400'
                }
              >
                {result.verified ? 'verified ✓ (WebAuthn assertion checked in WASM)' : 'failed ✗'}
              </span>
            </Field>
          ) : null}
          {binding ? (
            <Field label='Binding passkey (P-256) public key'>
              <code className='font-mono text-xs break-all'>{binding.pubkeyHex}</code>
            </Field>
          ) : null}
        </FieldList>
      ) : null}
      {err ? <p className='text-sm text-amber-700 dark:text-amber-400'>{err}</p> : null}
    </section>
  )
}

/**
 * LOCKED state: two clearly-labelled actions. When a passkey is already known
 * (after a Lock, or a persisted credential on a fresh load) the primary action
 * RECOVERS the same player (Unlock), with "New identity" as the secondary.
 * Otherwise (first-time) the primary mints a passkey (Create) and the secondary
 * recovers a returning user's existing passkey.
 */
function LockedView({
  onCreate,
  onUnlock,
  busy,
  status,
  hasPasskey,
}: {
  onCreate: () => void
  onUnlock: () => void
  busy: boolean
  status: string | null
  hasPasskey: boolean
}) {
  return (
    <section className='space-y-3'>
      {hasPasskey ? (
        <>
          <div className='flex flex-wrap items-center gap-2'>
            <button type='button' className={PRIMARY_BTN} onClick={onUnlock} disabled={busy}>
              {busy ? 'Unlocking…' : 'Unlock'}
            </button>
            <button type='button' className={BTN} onClick={onCreate} disabled={busy}>
              New identity
            </button>
          </div>
          <p className='max-w-prose text-sm text-muted'>
            Unlock recovers your existing player from the passkey; New identity mints a fresh one.
          </p>
        </>
      ) : (
        <>
          <div className='flex flex-wrap items-center gap-2'>
            <button type='button' className={PRIMARY_BTN} onClick={onCreate} disabled={busy}>
              {busy ? 'Creating…' : 'Create passkey identity'}
            </button>
            <button type='button' className={BTN} onClick={onUnlock} disabled={busy}>
              Unlock existing passkey
            </button>
          </div>
          <p className='max-w-prose text-sm text-muted'>
            One passkey → your Ed25519 player. A single prompt; every push afterwards signs without one.
          </p>
        </>
      )}
      {status ? <p className='text-sm text-muted'>{status}</p> : null}
    </section>
  )
}

/** UNLOCKED header: the player identity, a lock control, and the room selector. */
function UnlockedHeader() {
  const id = useIdentityStore()
  return (
    <section className='space-y-3'>
      <div className='flex flex-wrap items-center gap-2'>
        <span className='min-w-0 flex-1 truncate text-sm font-medium' title={id.ed25519PubkeyHex ?? undefined}>
          <span className='text-muted'>You · </span>
          {playerName(id.ed25519PubkeyHex ?? '')}{' '}
          <code className='font-mono text-xs text-muted'>{(id.ed25519PubkeyHex ?? '').slice(0, 10)}…</code>
        </span>
        <button type='button' className={BTN} onClick={() => id.lock()}>
          Lock
        </button>
        <label className='flex items-center gap-2 text-sm text-muted'>
          Room
          <input
            className='w-32 rounded-md border border-hairline bg-transparent px-2 py-1 text-sm outline-none focus:border-fg'
            value={id.room}
            onChange={(e) => id.setRoom(e.target.value)}
          />
        </label>
      </div>
      {id.ephemeral ? (
        <p className='text-sm text-amber-700 dark:text-amber-400'>
          Ephemeral key: no passkey PRF available, so this identity is random and won&rsquo;t persist.
        </p>
      ) : null}
    </section>
  )
}

function Compose({
  api,
  seedHex,
  room,
  targetRef,
  onTargetRef,
}: {
  api: ReturnType<typeof useMkit>
  seedHex: string
  room: string
  /** Ref the push targets (shared with the browser's selected ref). */
  targetRef: string
  onTargetRef: (r: string) => void
}) {
  const [message, setMessage] = useState('gm, multiplayer mkit')
  const push = usePushCommit()
  // Build on the head of the TARGET ref: pushing to a fresh branch name has no
  // head yet (parentHash = '' → MISSING → first commit), an existing one MATCHes.
  const headRef = useRef(room, targetRef)
  const parentHash = headRef.data ?? ''
  // Live lock state: the backend signs with whatever seed is in memory at call
  // time, so a push can race a Lock. Disable the button + surface a typed error.
  const unlocked = useIdentityStore((s) => s.unlocked)

  // Build + sign the commit in WASM each render for a LIGHTWEIGHT PREVIEW that
  // tracks the message and the current head (re-parents on a peer push). The
  // timestamp here is render-time and is NOT what gets pushed — `onPush`
  // re-builds + re-signs with a fresh wall clock so the SIGNED object stamps
  // push time, not render time. Empty tree keeps the demo tiny.
  const built = useMemo(() => {
    try {
      const tree = api.tree_encode('[]')
      // mkit commit timestamps are unix *seconds*; stamp the wall clock so the
      // preview shows a real time instead of epoch 0.
      const nowSecs = BigInt(Math.floor(Date.now() / 1000))
      const commit = api.commit_encode_and_sign(tree.hash_hex, parentHash, message, nowSecs, seedHex)
      return { ok: true as const, commit }
    } catch (e) {
      return { ok: false as const, error: e instanceof Error ? e.message : String(e) }
    }
  }, [api, message, parentHash, seedHex])

  const onPush = () => {
    if (!built.ok || !targetRef) return
    // Re-build + re-sign AT CLICK TIME so the pushed object's timestamp == push
    // time (the memo above captured render time). Stamp a fresh unix-seconds
    // wall clock and push THESE bytes; behavior is otherwise identical.
    let commitBytes: Uint8Array
    let commitHash: string
    try {
      const tree = api.tree_encode('[]')
      const nowSecs = BigInt(Math.floor(Date.now() / 1000))
      const fresh = api.commit_encode_and_sign(tree.hash_hex, parentHash, message, nowSecs, seedHex)
      commitBytes = fresh.bytes
      commitHash = fresh.hash_hex
    } catch {
      return // a build failure is already surfaced via `built.error`
    }
    push.mutate({
      api,
      seedHex,
      room,
      ref: targetRef,
      commitBytes,
      commitHash,
      message,
      parentHash,
    })
  }

  const pushErr =
    push.error instanceof CasConflictError
      ? 'Someone pushed first — the preview re-parented onto the new head. Push again.'
      : push.error instanceof IdentityLockedError
        ? 'Identity is locked — unlock (derive) before pushing.'
        : push.error
          ? errMsg(push.error)
          : null

  return (
    <section className='space-y-4'>
      <label className='block'>
        <span className='mb-1.5 block text-sm text-muted'>Commit message</span>
        <textarea
          className={INPUT_CLASSES}
          rows={3}
          value={message}
          onChange={(e) => setMessage(e.target.value)}
        />
      </label>
      <label className='block'>
        <span className='mb-1.5 block text-sm text-muted'>
          Branch / ref — type a new name to start a branch
        </span>
        <input
          className={INPUT_CLASSES}
          value={targetRef}
          onChange={(e) => onTargetRef(e.target.value)}
          placeholder='main'
          spellCheck={false}
        />
      </label>
      <button
        type='button'
        className={PRIMARY_BTN}
        onClick={onPush}
        disabled={!built.ok || push.isPending || !unlocked || !targetRef}
      >
        {push.isPending ? 'Pushing…' : !unlocked ? 'Locked' : `Sign & push → ${targetRef || '…'}`}
      </button>

      {built.ok ? (
        <FieldList>
          <Field label='Commit hash'>
            <code className='font-mono text-sm break-all'>{built.commit.hash_hex}</code>
          </Field>
          <Field label='Signature (Ed25519, in WASM)'>
            <code className='font-mono text-xs break-all'>{built.commit.signature_hex}</code>
          </Field>
          <Field label={`Parent (head of “${targetRef || 'main'}”)`}>
            <code className='font-mono text-xs break-all'>{parentHash || '∅ (first commit on this ref)'}</code>
          </Field>
        </FieldList>
      ) : (
        <p className='text-red-600 dark:text-red-400'>{built.error}</p>
      )}

      {pushErr ? <p className='text-sm text-amber-700 dark:text-amber-400'>{pushErr}</p> : null}
    </section>
  )
}

/**
 * A "Fork / Remix" action: builds + signs a remix referencing a given
 * upstream commit (one source = `{ upstream_id = blake3(room), commit_hash
 * = the clicked commit }`), then pushes it onto a per-forker
 * `forks/<upstreamShort>-<forkerShort>` ref so it appears in the Refs panel
 * as a fork. Reuses the same PutObject + CAS UpdateRef + envelope-signing
 * flow commits use (`usePushCommit`).
 *
 * Returns `{ fork, pending, error }`: call `fork(upstreamCommit)` to fork
 * that commit; it resolves to the new fork ref so the caller can select it
 * after a successful push.
 */
function useFork(api: ReturnType<typeof useMkit>, room: string, seedHex: string | null) {
  const push = usePushCommit()

  const fork = async (upstreamCommitHash: string): Promise<string | null> => {
    if (!seedHex) return null
    // The fork ref is unique per (upstream commit, forker): keying on the
    // forker's pubkey too means two users forking the SAME commit get distinct
    // refs (no collision), while the SAME forker re-forking advances ITS ref.
    const forkerPubkey = bytesToHex(api.ed25519_pubkey_from_seed(hexToBytes(seedHex)))
    const ref = forkRefName(upstreamCommitHash, forkerPubkey)
    // Opaque caller-chosen provenance tag — the room id hashed to 32 bytes.
    const upstreamId = api.blake3_hex(new TextEncoder().encode(room))
    const sources: RemixSourceEntry[] = [{ upstreamIdHex: upstreamId, commitHashHex: upstreamCommitHash }]
    const sourcesJson = JSON.stringify(
      sources.map((s) => ({ upstream_id_hex: s.upstreamIdHex, commit_hash_hex: s.commitHashHex })),
    )
    // Read the fork ref's current head FIRST, then embed it as the remix's
    // FIRST PARENT so the chain is correctly linked: a fresh ref → '' → the
    // push picks MISSING (create); an existing ref → head → MATCH advances the
    // SAME ref, chaining onto the prior remix instead of orphaning it (building
    // with an empty parent while pushing parentHash=head would MATCH-overwrite
    // and lose the existing fork on the first-parent walk).
    const head = await getRepoBackend().getRef(room, ref)
    // Empty tree keeps the demo remix tiny; a real fork snapshots its own tree.
    const tree = api.tree_encode('[]')
    const remix = api.remix_encode_and_sign(
      tree.hash_hex,
      head ?? '', // chain onto the fork's current head (fresh ref → root remix)
      sourcesJson,
      `fork of ${upstreamCommitHash.slice(0, 10)}…`,
      BigInt(Math.floor(Date.now() / 1000)),
      seedHex,
    )
    await push.mutateAsync({
      api,
      seedHex,
      room,
      ref,
      commitBytes: remix.bytes,
      commitHash: remix.hash_hex,
      message: `fork of ${upstreamCommitHash.slice(0, 10)}…`,
      parentHash: head ?? '',
      kind: 'remix',
      sources,
    })
    return ref
  }

  return { fork, pending: push.isPending, error: push.error }
}

/**
 * Navigable repo browser (right column): a refs/branches panel, the selected
 * ref's history, and — when a commit row is clicked — a commit/remix-detail
 * view whose parents (and, for a remix, its upstream sources) are themselves
 * links. All navigation is component state (selectedRef / selectedCommit),
 * no router change.
 */
function RepoBrowser({
  api,
  room,
  myPubkey,
  seedHex,
  useMock,
  selectedRef,
  onSelectRef,
  selectedCommit,
  onSelectCommit,
}: {
  api: ReturnType<typeof useMkit>
  room: string
  myPubkey: string | null
  seedHex: string | null
  useMock: boolean
  selectedRef: string
  onSelectRef: (r: string) => void
  selectedCommit: string | null
  onSelectCommit: (h: string | null) => void
}) {
  const { fork, pending, error } = useFork(api, room, seedHex)
  const [forkStatus, setForkStatus] = useState<string | null>(null)

  // Build + push a fork of `upstreamCommit`, then select its new fork ref so
  // the user sees the remix land in the Refs panel + log.
  const onFork = async (upstreamCommit: string) => {
    setForkStatus(null)
    try {
      const ref = await fork(upstreamCommit)
      if (ref) {
        onSelectRef(ref)
        onSelectCommit(null)
        setForkStatus(`Forked → ${ref}`)
      }
    } catch (e) {
      setForkStatus(
        // The fork ref is unique per (commit, you), so a conflict here means a
        // concurrent re-fork raced your push — your fork chain moved under you.
        e instanceof CasConflictError
          ? 'Your fork ref just moved (a concurrent push) — try forking again.'
          : e instanceof IdentityLockedError
            ? 'Unlock (create an identity) before forking.'
            : errMsg(e),
      )
    }
  }
  const canFork = !!seedHex

  return (
    <div className='space-y-6'>
      <RefsPanel room={room} useMock={useMock} selectedRef={selectedRef} onSelectRef={onSelectRef} />
      {selectedCommit ? (
        <CommitDetail
          room={room}
          hash={selectedCommit}
          onSelectCommit={onSelectCommit}
          onClose={() => onSelectCommit(null)}
          onFork={onFork}
          canFork={canFork}
          forkPending={pending}
        />
      ) : (
        <LiveLog
          room={room}
          selectedRef={selectedRef}
          myPubkey={myPubkey}
          onSelectCommit={onSelectCommit}
          onFork={onFork}
          canFork={canFork}
          forkPending={pending}
        />
      )}
      {forkStatus ? <p className='text-sm text-muted'>{forkStatus}</p> : null}
      {error && !forkStatus ? <p className='text-sm text-amber-700 dark:text-amber-400'>{errMsg(error)}</p> : null}
    </div>
  )
}

/** All refs in the room. Each row selects the ref the log/detail view follows. */
function RefsPanel({
  room,
  useMock,
  selectedRef,
  onSelectRef,
}: {
  room: string
  useMock: boolean
  selectedRef: string
  onSelectRef: (r: string) => void
}) {
  const refs = useRefs(room)
  // Sort `main` first, then alphabetically — a stable, predictable panel.
  const entries = (refs.data ?? []).toSorted((a, b) =>
    a.name === 'main' ? -1 : b.name === 'main' ? 1 : a.name.localeCompare(b.name),
  )

  return (
    <section className='space-y-3'>
      <div className='flex items-baseline justify-between'>
        <h2 className='text-sm font-semibold'>Refs · room “{room}”</h2>
        <span className='font-mono text-xs text-muted'>{useMock ? 'mock backend' : 'worker'}</span>
      </div>
      {entries.length === 0 ? (
        <p className='text-sm text-muted'>No refs yet — push a commit to create one.</p>
      ) : (
        <ul className='divide-y divide-dashed divide-hairline border-y border-dashed border-hairline'>
          {entries.map((r) => {
            const active = r.name === selectedRef
            return (
              <li key={r.name}>
                <button
                  type='button'
                  onClick={() => onSelectRef(r.name)}
                  aria-pressed={active}
                  className={`flex w-full items-center gap-3 py-2.5 text-left transition-colors ${
                    active ? 'text-fg' : 'text-muted hover:text-fg'
                  }`}
                >
                  <HashChip hash={r.objectIdHex} size={14} />
                  <span className={`truncate font-mono text-sm ${active ? 'font-semibold' : 'font-medium'}`}>
                    {r.name}
                  </span>
                  {isForkRef(r.name) ? (
                    <span className='shrink-0 rounded bg-purple-100 px-1.5 text-xs text-purple-700 dark:bg-purple-950 dark:text-purple-300'>
                      fork
                    </span>
                  ) : null}
                  {active ? <span className='shrink-0 text-xs text-blue-600 dark:text-blue-400'>selected</span> : null}
                  <code className='ml-auto shrink-0 font-mono text-xs text-muted'>{r.objectIdHex.slice(0, 10)}…</code>
                </button>
              </li>
            )
          })}
        </ul>
      )}
    </section>
  )
}

function LiveLog({
  room,
  selectedRef,
  myPubkey,
  onSelectCommit,
  onFork,
  canFork,
  forkPending,
}: {
  room: string
  selectedRef: string
  myPubkey: string | null
  onSelectCommit: (h: string) => void
  onFork: (upstreamCommit: string) => void
  canFork: boolean
  forkPending: boolean
}) {
  const log = useCommitLog(room, selectedRef)
  const head = useRef(room, selectedRef)
  const entries = log.data ?? []

  return (
    <section className='space-y-3'>
      <div className='flex items-baseline justify-between'>
        <h2 className='text-sm font-semibold'>
          {isForkRef(selectedRef) ? 'Fork log' : 'Commit log'} · “{selectedRef}”
        </h2>
        <span className='font-mono text-xs text-muted'>head {head.data ? head.data.slice(0, 10) : '∅'}…</span>
      </div>
      {entries.length === 0 ? (
        <p className='text-sm text-muted'>No commits on this ref yet — push one above.</p>
      ) : (
        <ul className='divide-y divide-dashed divide-hairline border-y border-dashed border-hairline'>
          {entries.map((e) => (
            <LogRow
              key={e.hash}
              entry={e}
              mine={!!myPubkey && e.authorPubkey === myPubkey}
              onSelect={() => onSelectCommit(e.hash)}
              onFork={onFork}
              canFork={canFork}
              forkPending={forkPending}
            />
          ))}
        </ul>
      )}
    </section>
  )
}

function LogRow({
  entry,
  mine,
  onSelect,
  onFork,
  canFork,
  forkPending,
}: {
  entry: CommitLogEntry
  mine: boolean
  onSelect: () => void
  onFork: (upstreamCommit: string) => void
  canFork: boolean
  forkPending: boolean
}) {
  const isRemix = entry.kind === 'remix'
  return (
    <li className='flex items-center gap-2 py-2.5'>
      <button
        type='button'
        onClick={onSelect}
        className='flex min-w-0 flex-1 items-center gap-3 text-left transition-colors hover:text-fg'
      >
        <HashChip hash={entry.hash} size={14} />
        <div className='min-w-0 flex-1'>
          <div className='flex items-baseline gap-2'>
            <span className='truncate text-sm font-medium'>{entry.message}</span>
            {isRemix ? (
              <span className='shrink-0 rounded bg-purple-100 px-1.5 text-xs text-purple-700 dark:bg-purple-950 dark:text-purple-300'>
                remix
              </span>
            ) : null}
            {mine ? <span className='shrink-0 text-xs text-green-700 dark:text-green-400'>you</span> : null}
          </div>
          <div className='text-xs text-muted' title={entry.authorPubkey}>
            <span className='font-medium text-fg'>{playerName(entry.authorPubkey)}</span>{' '}
            <code className='font-mono break-all'>
              {entry.authorPubkey.slice(0, 10)}… · {entry.hash.slice(0, 16)}…
            </code>
          </div>
        </div>
      </button>
      {/* Fork a COMMIT (not a remix — that would fork a fork; out of scope for the demo). */}
      {canFork && !isRemix ? (
        <button
          type='button'
          onClick={() => onFork(entry.hash)}
          disabled={forkPending}
          className={`${BTN} shrink-0`}
          title='Build + sign a remix of this commit and push it to a fork ref'
        >
          Fork
        </button>
      ) : null}
    </li>
  )
}

/**
 * Navigable detail for one commit OR remix: fetched by hash (get_object),
 * routed by `object_kind`, then decoded with `commit_decode` /
 * `remix_decode`. Renders message / signer / timestamp / tree / signature
 * for either kind; parents are links that load THAT object's detail in
 * place. For a remix it additionally renders a "remix / fork of …" block
 * whose upstream `commit_hash` is a link → the upstream commit's detail
 * (reusing the same `onSelectCommit` parent-navigation mechanism). A Fork
 * button on a commit builds + pushes a remix of it.
 */
function CommitDetail({
  room,
  hash,
  onSelectCommit,
  onClose,
  onFork,
  canFork,
  forkPending,
}: {
  room: string
  hash: string
  onSelectCommit: (h: string) => void
  onClose: () => void
  onFork: (upstreamCommit: string) => void
  canFork: boolean
  forkPending: boolean
}) {
  const api = useMkit()
  const obj = useObject(room, hash)

  const decoded = useMemo(() => {
    if (!obj.data) return null
    // `decodeLogObject` routes via `object_kind` → commit_decode /
    // remix_decode and returns the kind + sources, so the detail view
    // never has to guess which decoder to call.
    const res = decodeLogObject(api, obj.data, hash, '')
    if (!res) return { ok: false as const, error: 'unknown object kind' }
    try {
      const info =
        res.entry.kind === 'remix' ? api.remix_decode(obj.data) : api.commit_decode(obj.data)
      const parents: string[] = []
      for (let i = 0; i < info.parent_count; i++) {
        const p = info.parent(i)
        if (p) parents.push(p)
      }
      return {
        ok: true as const,
        kind: res.entry.kind ?? 'commit',
        message: info.message,
        signerHex: info.signer_hex,
        timestamp: Number(info.timestamp),
        treeHex: info.tree_hex,
        signatureHex: info.signature_hex,
        parents,
        sources: res.entry.sources ?? [],
      }
    } catch (e) {
      return { ok: false as const, error: e instanceof Error ? e.message : String(e) }
    }
  }, [api, obj.data, hash])

  const isRemix = decoded?.ok && decoded.kind === 'remix'

  return (
    <section className='space-y-3'>
      <div className='flex items-baseline justify-between gap-3'>
        <h2 className='flex items-center gap-2 text-sm font-semibold'>
          <HashChip hash={hash} size={14} />
          {isRemix ? 'Remix detail' : 'Commit detail'}
          {isRemix ? (
            <span className='rounded bg-purple-100 px-1.5 text-xs text-purple-700 dark:bg-purple-950 dark:text-purple-300'>
              fork
            </span>
          ) : null}
        </h2>
        <div className='flex items-center gap-2'>
          {/* Fork a commit (not a remix) straight from its detail. */}
          {canFork && decoded?.ok && !isRemix ? (
            <button type='button' className={BTN} onClick={() => onFork(hash)} disabled={forkPending}>
              {forkPending ? 'Forking…' : 'Fork / Remix'}
            </button>
          ) : null}
          <button type='button' className={BTN} onClick={onClose}>
            ← Back to log
          </button>
        </div>
      </div>

      {obj.isLoading ? (
        <p className='text-sm text-muted'>Loading object…</p>
      ) : !obj.data ? (
        <p className='text-sm text-amber-700 dark:text-amber-400'>Object not found in this room.</p>
      ) : !decoded?.ok ? (
        <p className='text-red-600 dark:text-red-400'>Could not decode object: {decoded?.error}</p>
      ) : (
        <FieldList>
          <Field label='Hash'>
            <code className='font-mono text-sm break-all'>{hash}</code>
          </Field>
          {isRemix ? (
            <Field label='Remix / fork of'>
              {decoded.sources.length === 0 ? (
                <span className='text-sm text-muted'>∅ (no sources)</span>
              ) : (
                <ul className='space-y-1.5'>
                  {decoded.sources.map((s) => (
                    <li key={s.commitHashHex} className='flex items-center gap-2'>
                      <HashChip hash={s.commitHashHex} size={12} />
                      <button
                        type='button'
                        onClick={() => onSelectCommit(s.commitHashHex)}
                        className='min-w-0 truncate text-left font-mono text-xs break-all text-blue-600 hover:underline dark:text-blue-400'
                        title='Open the upstream commit this fork derives from'
                      >
                        {s.commitHashHex}
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </Field>
          ) : null}
          <Field label='Message'>
            <span className='text-sm break-words whitespace-pre-wrap'>{decoded.message || '(empty)'}</span>
          </Field>
          <Field label='Author / signer'>
            <div title={decoded.signerHex}>
              <span className='text-sm font-medium'>{playerName(decoded.signerHex)}</span>{' '}
              <code className='font-mono text-xs text-muted'>{decoded.signerHex.slice(0, 10)}…</code>
            </div>
            <code className='mt-1 block font-mono text-xs break-all text-muted'>{decoded.signerHex}</code>
          </Field>
          <Field label='Timestamp'>
            <span className='text-sm'>
              {decoded.timestamp ? new Date(decoded.timestamp * 1000).toISOString() : '∅'}{' '}
              <span className='text-muted'>({decoded.timestamp} unix s)</span>
            </span>
          </Field>
          <Field label='Tree'>
            <code className='font-mono text-xs break-all'>{decoded.treeHex}</code>
          </Field>
          <Field label='Parents'>
            {decoded.parents.length === 0 ? (
              <span className='text-sm text-muted'>∅ ({isRemix ? 'root remix' : 'root commit'})</span>
            ) : (
              <ul className='space-y-1.5'>
                {decoded.parents.map((p, i) => (
                  <li key={p} className='flex items-center gap-2'>
                    <HashChip hash={p} size={12} />
                    <button
                      type='button'
                      onClick={() => onSelectCommit(p)}
                      className='min-w-0 truncate text-left font-mono text-xs break-all text-blue-600 hover:underline dark:text-blue-400'
                    >
                      {p}
                    </button>
                    {decoded.parents.length > 1 ? (
                      <span className='shrink-0 text-xs text-muted'>{i === 0 ? '(first)' : `(#${i})`}</span>
                    ) : null}
                  </li>
                ))}
              </ul>
            )}
          </Field>
          <Field label='Signature (Ed25519)'>
            <code className='font-mono text-xs break-all'>{decoded.signatureHex}</code>
          </Field>
        </FieldList>
      )}
    </section>
  )
}

// Local hex→bytes (kept private; repo-api owns the envelope-side copy).
function hexToBytes(hex: string): Uint8Array {
  const clean = hex.length % 2 === 0 ? hex : `0${hex}`
  const out = new Uint8Array(clean.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16)
  return out
}

function errMsg(e: unknown): string {
  if (e instanceof Error) return e.message
  return String(e)
}
