'use client'

// Compose surface (build + sign + push a commit) and the fork/remix hook.
// Moved verbatim out of `multiplayer-demo.tsx`.

import { useMemo, useState } from 'react'
import { useIdentityStore } from '../../lib/identity-store'
import {
  CasConflictError,
  IdentityLockedError,
  type RemixSourceEntry,
  forkRefName,
  usePushCommit,
  useRef,
  useRepoBackend,
} from '../../lib/repo-api'
import { Field, FieldList, INPUT_CLASSES } from '../result-panel'
import { bytesToHex, hexToBytes, useMkit } from '../use-mkit'
import { PRIMARY_BTN, errMsg } from './shared'

export function Compose({
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
  const [message, setMessage] = useState('gm')
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
        ? 'Your identity is locked. Unlock it before pushing.'
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
          <Field label='Signature'>
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
export function useFork(api: ReturnType<typeof useMkit>, room: string, seedHex: string | null) {
  const push = usePushCommit()
  const backend = useRepoBackend()

  const fork = async (upstreamCommitHash: string): Promise<string | null> => {
    if (!seedHex || !backend) return null
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
    const head = await backend.getRef(room, ref)
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

  // `ready` lets the UI disable the Fork action until a backend is present (and
  // a seed is in memory) — forking needs both to read the head and push.
  return { fork, pending: push.isPending, error: push.error, ready: !!backend && !!seedHex }
}
