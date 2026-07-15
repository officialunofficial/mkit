'use client'

// Compose surface (build + sign + push a commit) and the fork/remix hook.
// Moved verbatim out of `multiplayer-demo.tsx`.

import * as Collapsible from '@radix-ui/react-collapsible'
import { useQueryClient } from '@tanstack/react-query'
import { useId, useMemo, useState } from 'react'
import { useIdentityStore } from '../../lib/identity-store'
import {
  CasConflictError,
  IdentityLockedError,
  type RemixSourceEntry,
  branchRefName,
  forkRefName,
  usePushCommit,
  useRef,
  useRefs,
  useRepoBackend,
} from '../../lib/repo-api'
import { INPUT_CLASSES } from '../result-panel'
import { bytesToHex, hexToBytes, useMkit } from '../use-mkit'
import { InfoTip } from './info-tip'
import { CAS_CONFLICT_COPY, IDENTITY_LOCKED_COPY, PRIMARY_BTN, errMsg } from './shared'

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
  const [message, setMessage] = useState('gm, multiplayer mkit')
  const messageId = useId()
  const refId = useId()
  const push = usePushCommit()
  // Existing refs in the room drive the dropdown. `main` is always offered even
  // before the room has any refs, so there's always a sensible default target.
  const refsQuery = useRefs(room)
  const refOptions = useMemo(() => {
    const names = (refsQuery.data ?? []).map((r) => r.name)
    return [...new Set(['main', ...names])]
  }, [refsQuery.data])
  // The select sits on `__new__` whenever the target isn't an existing ref —
  // which is exactly the case while typing a brand-new branch name, so the
  // free-text input stays visible without any extra mode state.
  const NEW_REF = '__new__'
  const selectValue = refOptions.includes(targetRef) ? targetRef : NEW_REF
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

  const onPush = async () => {
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
    try {
      await push.mutateAsync({ api, seedHex, room, ref: targetRef, commitBytes, commitHash, message, parentHash })
    } catch {
      // A rejected push (e.g. a CAS conflict) already surfaces via `push.error` below and the optimistic entry rolled back.
    }
  }

  const pushErr =
    push.error instanceof CasConflictError
      ? `${CAS_CONFLICT_COPY} The preview already re-parented onto the new head.`
      : push.error instanceof IdentityLockedError
        ? IDENTITY_LOCKED_COPY
        : push.error
          ? errMsg(push.error)
          : null

  return (
    <section className='space-y-4'>
      <div className='space-y-1.5'>
        <div className='flex items-center gap-1.5'>
          <label htmlFor={messageId} className='text-sm text-muted'>
            Commit message
          </label>
          <InfoTip label='About the commit message'>
            <p>
              The text you’re signing. In this demo the commit points at an{' '}
              <strong className='text-fg'>empty tree</strong> (no files), so a push is really a{' '}
              <strong className='text-fg'>signed message</strong>.
            </p>
            <p className='mt-2'>
              Your Ed25519 key vouches that this exact text came from you — the signature proves “same key”, not who you
              are.
            </p>
          </InfoTip>
        </div>
        <textarea
          id={messageId}
          className={INPUT_CLASSES}
          rows={3}
          value={message}
          onChange={(e) => setMessage(e.target.value)}
        />
      </div>
      <div className='space-y-1.5'>
        <div className='flex items-center gap-1.5'>
          <label htmlFor={refId} className='text-sm text-muted'>
            Branch
          </label>
          <InfoTip label='About branches'>
            <p>
              A <strong className='text-fg'>branch</strong> is a line of history, as in git. Pushing advances it under a{' '}
              <strong className='text-fg'>compare-and-set</strong>, so concurrent pushes serialize cleanly.
            </p>
            <p className='mt-2'>
              Pick an existing branch to add onto it, or start a new one. Remixing a commit makes its own branch under{' '}
              <code className='font-mono'>forks/…</code>; branching off a commit makes one under{' '}
              <code className='font-mono'>b/…</code>.
            </p>
          </InfoTip>
        </div>
        <select
          id={refId}
          className={`${INPUT_CLASSES} pr-9`}
          value={selectValue}
          onChange={(e) => onTargetRef(e.target.value === NEW_REF ? '' : e.target.value)}
        >
          <option value={NEW_REF}>New branch…</option>
          {refOptions.map((name) => (
            <option key={name} value={name}>
              {name}
            </option>
          ))}
        </select>
        {selectValue === NEW_REF ? (
          <input
            className={INPUT_CLASSES}
            value={targetRef}
            onChange={(e) => onTargetRef(e.target.value)}
            placeholder='new-branch-name'
            spellCheck={false}
            // biome-ignore lint/a11y/noAutofocus: focus follows the explicit "New branch" choice
            autoFocus
          />
        ) : null}
      </div>
      <div className='flex justify-end'>
        <button
          type='button'
          className={PRIMARY_BTN}
          onClick={onPush}
          disabled={!built.ok || push.isPending || !unlocked || !targetRef}
        >
          {push.isPending ? 'Pushing…' : !unlocked ? 'Locked' : 'Sign & push'}
        </button>
      </div>

      {built.ok ? (
        <Collapsible.Root>
          <Collapsible.Trigger className='group flex w-full cursor-pointer items-center gap-1 text-sm text-muted transition-colors select-none hover:text-fg'>
            <span className='inline-block transition-transform group-data-[state=open]:rotate-90'>›</span> Signed-commit
            details
          </Collapsible.Trigger>
          {/* Fixed-width label column so every row's value lines up; the qualifier
              for each field lives in an info tooltip, not in the label text. */}
          <Collapsible.Content asChild>
            <dl className='mt-2 grid grid-cols-[5rem_minmax(0,1fr)] items-baseline gap-x-3 gap-y-1.5 text-xs'>
              <dt className='flex items-center gap-1 text-muted'>
                Commit
                <InfoTip label='About the commit hash'>
                  <p>The BLAKE3 content hash that addresses this commit object.</p>
                </InfoTip>
              </dt>
              <dd className='min-w-0 font-mono break-all'>{built.commit.hash_hex}</dd>

              <dt className='flex items-center gap-1 text-muted'>
                Signature
                <InfoTip label='About the signature'>
                  <p>The Ed25519 signature over the commit, produced in your browser by your passkey-derived key.</p>
                </InfoTip>
              </dt>
              <dd className='min-w-0 font-mono break-all'>{built.commit.signature_hex}</dd>

              <dt className='flex items-center gap-1 text-muted'>
                Parent
                <InfoTip label='About the parent'>
                  <p>
                    The current head of “{targetRef || 'main'}” — the commit this one builds on (none for the first
                    commit on a branch).
                  </p>
                </InfoTip>
              </dt>
              <dd className='min-w-0 font-mono break-all'>{parentHash || 'none (first commit on this branch)'}</dd>
            </dl>
          </Collapsible.Content>
        </Collapsible.Root>
      ) : (
        <p className='text-red-600 dark:text-red-400'>{built.error}</p>
      )}

      {pushErr ? <p className='text-sm text-amber-700 dark:text-amber-400'>{pushErr}</p> : null}
    </section>
  )
}

/**
 * The compose surface in its NOT-AVAILABLE-YET state, shown before an identity is unlocked. It mirrors {@link Compose}'s
 * layout (message + branch + push) but every control is inert and dimmed, so the section keeps its shape and the user
 * can see what they'll be able to do once they create or unlock a passkey identity.
 */
export function ComposeDisabled() {
  return (
    <section className='space-y-4 opacity-60' aria-disabled>
      <div className='space-y-1.5'>
        <span className='block text-sm text-muted'>Commit message</span>
        <textarea
          className={INPUT_CLASSES}
          rows={3}
          disabled
          value=''
          placeholder='Create or unlock an identity to write commits.'
        />
      </div>
      <div className='space-y-1.5'>
        <span className='block text-sm text-muted'>Branch</span>
        <select className={`${INPUT_CLASSES} pr-9`} disabled value='main'>
          <option value='main'>main</option>
        </select>
      </div>
      <button type='button' className={PRIMARY_BTN} disabled>
        Sign & push
      </button>
      <p className='text-sm text-muted'>
        Create or unlock an identity above to write commits. You can still browse this repository’s shared history on
        the right.
      </p>
    </section>
  )
}

/**
 * The two ways to build on a commit. Both are per-key + per-commit so two people acting on the same commit get distinct
 * branches.
 *
 * • `remix` — signs a first-class REMIX object that records the upstream commit as its `source` (attribution carried IN
 * the object), pushed onto a `forks/<short>-<short>` branch via the same sign + CAS path commits use. • `branch` —
 * creates a plain `b/<short>-<short>` branch pointing AT the commit (git `branch <name> <commit>`): NO new object and
 * NO recorded attribution, just a fresh line of history.
 *
 * Each resolves to the new branch ref so the caller can select it.
 */
export function useDerive(api: ReturnType<typeof useMkit>, room: string, seedHex: string | null) {
  const push = usePushCommit()
  const backend = useRepoBackend()
  const qc = useQueryClient()
  const [branching, setBranching] = useState(false)

  const forkerPubkey = () => bytesToHex(api.ed25519_pubkey_from_seed(hexToBytes(seedHex as string)))

  const remix = async (upstreamCommitHash: string): Promise<string | null> => {
    if (!seedHex || !backend) return null
    const ref = forkRefName(upstreamCommitHash, forkerPubkey())
    // Opaque provenance tag — the room id hashed to 32 bytes.
    const upstreamId = api.blake3_hex(new TextEncoder().encode(room))
    const sources: RemixSourceEntry[] = [{ upstreamIdHex: upstreamId, commitHashHex: upstreamCommitHash }]
    const sourcesJson = JSON.stringify(
      sources.map((s) => ({ upstream_id_hex: s.upstreamIdHex, commit_hash_hex: s.commitHashHex })),
    )
    // Chain onto the remix branch's current head (fresh ref → '' → MISSING create).
    const head = await backend.getRef(room, ref)
    const tree = api.tree_encode('[]')
    const message = `remix of ${upstreamCommitHash.slice(0, 10)}…`
    const obj = api.remix_encode_and_sign(
      tree.hash_hex,
      head ?? '',
      sourcesJson,
      message,
      BigInt(Math.floor(Date.now() / 1000)),
      seedHex,
    )
    await push.mutateAsync({
      api,
      seedHex,
      room,
      ref,
      commitBytes: obj.bytes,
      commitHash: obj.hash_hex,
      message,
      parentHash: head ?? '',
      kind: 'remix',
      sources,
    })
    return ref
  }

  const branch = async (upstreamCommitHash: string): Promise<string | null> => {
    if (!seedHex || !backend) return null
    setBranching(true)
    try {
      const ref = branchRefName(upstreamCommitHash, forkerPubkey())
      try {
        // Create-only: a fresh branch pointing AT the commit. No new object, no
        // attribution — the branch just continues history from here.
        await backend.updateRef(room, ref, upstreamCommitHash, 'MISSING')
      } catch (e) {
        if (!(e instanceof CasConflictError)) throw e // already branched here → reuse it
      }
      void qc.invalidateQueries({ queryKey: ['repo', room, 'refs'] })
      return ref
    } finally {
      setBranching(false)
    }
  }

  // `ready` gates both actions until a backend + a seed are present.
  return { remix, branch, pending: push.isPending || branching, error: push.error, ready: !!backend && !!seedHex }
}
