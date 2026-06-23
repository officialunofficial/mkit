'use client'

import { useEffect, useMemo, useState } from 'react'
import {
  type BindingCredential,
  attestEd25519Binding,
  createIdentity,
  enrollBindingPasskey,
  rpId,
} from '../lib/passkey'
import { DEFAULT_ROOM, useIdentityStore } from '../lib/identity-store'
import {
  CasConflictError,
  IdentityLockedError,
  MockRepoBackend,
  WasmRepoBackend,
  type CommitLogEntry,
  setRepoBackend,
  useCommitLog,
  usePushCommit,
  useRef,
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
// on first load. Seeded once per mock backend.
const FOREIGN_SEEDS = ['7'.repeat(64), 'a3'.repeat(32)]
const FOREIGN_MESSAGES = ['hello from another tab', 'ship it 🚀']

/** The single source of identity + push + live-log UI (design note §2 steps 1–6). */
export function MultiplayerDemo() {
  const api = useMkit()
  const id = useIdentityStore()
  const room = id.room || DEFAULT_ROOM

  // Backend selection: when `VITE_REPO_BACKEND_URL` is set, drive the real
  // ConnectRPC service through the wasm client; otherwise use the in-memory mock
  // (offline dev default). The mock is the synchronous fallback; the wasm client
  // initialises asynchronously and replaces it once ready.
  const backendUrl = import.meta.env.VITE_REPO_BACKEND_URL as string | undefined
  const useMock = !backendUrl

  // One mock backend per mounted demo, always available as the offline fallback.
  const mock = useMemo(() => new MockRepoBackend(api), [api])
  useEffect(() => {
    setRepoBackend(mock)
    // Seed foreign commits deterministically so the log shows multiplayer life.
    FOREIGN_SEEDS.forEach((seed, i) => {
      const tree = api.tree_encode('[]')
      const commit = api.commit_encode_and_sign(tree.hash_hex, '', FOREIGN_MESSAGES[i]!, BigInt(i), seed)
      const pubkey = bytesToHex(api.ed25519_pubkey_from_seed(hexToBytes(seed)))
      mock.seedForeignCommit(room, {
        hash: commit.hash_hex,
        message: FOREIGN_MESSAGES[i]!,
        authorPubkey: pubkey,
        ref: 'main',
        createdAt: new Date(Date.now() - (FOREIGN_SEEDS.length - i) * 60_000).toISOString(),
      })
    })
  }, [mock, api, room])

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
    })
    return () => {
      cancelled = true
    }
  }, [backendUrl, api])

  useRepoEvents(room)

  const [status, setStatus] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  // One ceremony: create the passkey AND derive the Ed25519 seed (PRF-on-create),
  // falling back to one get() or an ephemeral key inside `createIdentity`. Every
  // push afterwards signs with the in-memory key — no further prompts.
  const onCreate = async () => {
    setStatus(null)
    setBusy(true)
    try {
      const res = await createIdentity()
      if (res.credentialId) id.setCredentialId(res.credentialId)
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

  // State machine: LOCKED → (one prompt) → UNLOCKED, laid out in two columns with
  // the live log ALWAYS on the right — so you can watch others contribute even
  // before you create an identity ("signed out" mode). The left column swaps
  // between the single create action and the compose/attest surface.
  if (!id.unlocked || !id.seedHex || !id.ed25519PubkeyHex) {
    return (
      <div className='grid gap-8 lg:grid-cols-2 lg:items-start'>
        <LockedView onCreate={onCreate} busy={busy} status={status} />
        <LiveLog room={room} myPubkey={null} useMock={useMock} />
      </div>
    )
  }
  return (
    <div className='grid gap-8 lg:grid-cols-2 lg:items-start'>
      <div className='space-y-6'>
        <UnlockedHeader />
        <Compose api={api} seedHex={id.seedHex} room={room} />
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
      <LiveLog room={room} myPubkey={id.ed25519PubkeyHex} useMock={useMock} />
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

/** LOCKED state: a single action that creates the passkey + derives the key in one prompt. */
function LockedView({ onCreate, busy, status }: { onCreate: () => void; busy: boolean; status: string | null }) {
  return (
    <section className='space-y-3'>
      <button type='button' className={PRIMARY_BTN} onClick={onCreate} disabled={busy}>
        {busy ? 'Creating…' : 'Create passkey identity'}
      </button>
      <p className='max-w-prose text-sm text-muted'>
        One passkey → your Ed25519 player. A single prompt; every push afterwards signs without one.
      </p>
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
        <span className='shrink-0 text-sm text-muted'>You</span>
        <code className='min-w-0 flex-1 truncate font-mono text-sm'>{id.ed25519PubkeyHex}</code>
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

function Compose({ api, seedHex, room }: { api: ReturnType<typeof useMkit>; seedHex: string; room: string }) {
  const [message, setMessage] = useState('gm, multiplayer mkit')
  const push = usePushCommit()
  const headRef = useRef(room, 'main')
  const parentHash = headRef.data ?? ''
  // Live lock state: the backend signs with whatever seed is in memory at call
  // time, so a push can race a Lock. Disable the button + surface a typed error.
  const unlocked = useIdentityStore((s) => s.unlocked)

  // Build + sign the commit in WASM each render so the preview tracks the message
  // and the current head (re-parents on a peer push). Empty tree keeps the demo tiny.
  const built = useMemo(() => {
    try {
      const tree = api.tree_encode('[]')
      const commit = api.commit_encode_and_sign(tree.hash_hex, parentHash, message, 0n, seedHex)
      return { ok: true as const, commit }
    } catch (e) {
      return { ok: false as const, error: e instanceof Error ? e.message : String(e) }
    }
  }, [api, message, parentHash, seedHex])

  const onPush = () => {
    if (!built.ok) return
    push.mutate({
      api,
      seedHex,
      room,
      ref: 'main',
      commitBytes: built.commit.bytes,
      commitHash: built.commit.hash_hex,
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
      <button
        type='button'
        className={PRIMARY_BTN}
        onClick={onPush}
        disabled={!built.ok || push.isPending || !unlocked}
      >
        {push.isPending ? 'Pushing…' : !unlocked ? 'Locked' : 'Sign & push'}
      </button>

      {built.ok ? (
        <FieldList>
          <Field label='Commit hash'>
            <code className='font-mono text-sm break-all'>{built.commit.hash_hex}</code>
          </Field>
          <Field label='Signature (Ed25519, in WASM)'>
            <code className='font-mono text-xs break-all'>{built.commit.signature_hex}</code>
          </Field>
          <Field label='Parent (current head)'>
            <code className='font-mono text-xs break-all'>{parentHash || '∅ (first commit)'}</code>
          </Field>
        </FieldList>
      ) : (
        <p className='text-red-600 dark:text-red-400'>{built.error}</p>
      )}

      {pushErr ? <p className='text-sm text-amber-700 dark:text-amber-400'>{pushErr}</p> : null}
    </section>
  )
}

function LiveLog({
  room,
  myPubkey,
  useMock,
}: {
  room: string
  myPubkey: string | null
  useMock: boolean
}) {
  const log = useCommitLog(room)
  const head = useRef(room, 'main')
  const entries = log.data ?? []

  return (
    <section className='space-y-3'>
      <div className='flex items-baseline justify-between'>
        <h2 className='text-sm font-semibold'>Live commit log · room “{room}”</h2>
        <span className='font-mono text-xs text-muted'>
          {useMock ? 'mock backend' : 'worker'} · head {head.data ? head.data.slice(0, 10) : '∅'}…
        </span>
      </div>
      {entries.length === 0 ? (
        <p className='text-sm text-muted'>No commits yet — push one above.</p>
      ) : (
        <ul className='divide-y divide-dashed divide-hairline border-y border-dashed border-hairline'>
          {entries.map((e) => (
            <LogRow key={e.hash} entry={e} mine={!!myPubkey && e.authorPubkey === myPubkey} />
          ))}
        </ul>
      )}
    </section>
  )
}

function LogRow({ entry, mine }: { entry: CommitLogEntry; mine: boolean }) {
  return (
    <li className='flex items-center gap-3 py-2.5'>
      <HashChip hash={entry.hash} size={14} />
      <div className='min-w-0 flex-1'>
        <div className='flex items-baseline gap-2'>
          <span className='truncate text-sm font-medium'>{entry.message}</span>
          {mine ? <span className='shrink-0 text-xs text-green-700 dark:text-green-400'>you</span> : null}
        </div>
        <code className='block font-mono text-xs break-all text-muted'>
          {entry.authorPubkey.slice(0, 16)}… · {entry.hash.slice(0, 16)}…
        </code>
      </div>
    </li>
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
