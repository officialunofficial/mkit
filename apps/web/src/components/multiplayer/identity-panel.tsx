'use client'

// Identity column of the multiplayer demo: the optional passkey-attestation
// flourish, the locked create/unlock actions, and the unlocked player header.
// Moved verbatim out of `multiplayer-demo.tsx`.

import { useId, useState } from 'react'
import { type BindingCredential, attestEd25519Binding, enrollBindingPasskey, rpId } from '../../lib/passkey'
import { recordActivity } from '../../lib/activity-log'
import { useIdentityStore } from '../../lib/identity-store'
import { Field, FieldList, INPUT_CLASSES } from '../result-panel'
import { useMkit } from '../use-mkit'
import { InfoTip } from './info-tip'
import { OwnPlayerName } from './player-label'
import { BTN, PRIMARY_BTN, errMsg } from './shared'

/**
 * Optional flourish (design note §1, §2 step 4): a P-256 _passkey_ vouches that the derived Ed25519 key is the same
 * person's, by signing a DSSE-PAE binding challenge. The assertion is verified in WASM via `verify_webauthn_wrapping`
 * (RP-ID pinned), so the green check proves origin-bound WebAuthn — not just a signature. Anonymous still: the binding
 * ties two keys, not a real identity.
 */
export function AttestBinding({
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
      <div className='flex flex-wrap items-center gap-1.5'>
        <button type='button' className={BTN} onClick={onAttest} disabled={busy}>
          {busy ? 'Attesting…' : 'Attest with a passkey'}
        </button>
        <InfoTip label='About attesting'>
          <p>
            <strong className='text-fg'>Attesting</strong> has a P-256 passkey sign a challenge vouching that this
            Ed25519 signing key is yours — cryptographically linking the two keys.
          </p>
          <p className='mt-2'>
            It’s optional. The binding is verified in WASM with the RP-ID pinned, so a green check proves the two keys
            belong together — a stronger “same person” signal than the signing key alone.
          </p>
        </InfoTip>
      </div>
      {result || binding ? (
        <FieldList>
          {result ? (
            <Field label='Binding attestation'>
              <span
                className={result.verified ? 'text-green-700 dark:text-green-400' : 'text-red-600 dark:text-red-400'}
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
 * LOCKED state: two clearly-labelled actions. When a passkey is already known (after a Lock, or a persisted credential
 * on a fresh load) the primary action RECOVERS the same player (Unlock), with "New identity" as the secondary.
 * Otherwise (first-time) the primary mints a passkey (Create) and the secondary recovers a returning user's existing
 * passkey.
 */
export function LockedView({
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

/**
 * UNLOCKED header: the player identity + a lock control. (The room selector now lives in the left column — see
 * {@link RoomSelector}.)
 */
export function UnlockedHeader() {
  const id = useIdentityStore()

  // Narrate the lock so the "I can wipe my key and re-derive it" property is
  // legible — capture the player name before clearing for the detail line.
  const onLock = () => {
    recordActivity({
      kind: 'lock',
      title: 'Signing key wiped from memory',
      lines: [
        'The in-memory Ed25519 seed is gone — you can still read the repository, but can’t sign a push until you Unlock.',
        'Your passkey and pubkey stay, so Unlock re-derives the SAME player. No key was ever written to disk.',
      ],
    })
    id.lock()
  }

  return (
    <section className='space-y-3'>
      {/* Stacks on mobile (the identity gets its own full-width line so the name
          isn't crushed by the Lock/Room controls); single row on sm+. No
          `truncate` — it would clip the inline rename editor in OwnPlayerName. */}
      <div className='flex flex-col gap-2 sm:flex-row sm:flex-wrap sm:items-center'>
        <span className='min-w-0 text-sm font-medium sm:flex-1' title={id.ed25519PubkeyHex ?? undefined}>
          <span className='text-muted'>You · </span>
          <OwnPlayerName />{' '}
          <code className='font-mono text-xs break-all text-muted'>{(id.ed25519PubkeyHex ?? '').slice(0, 10)}…</code>
        </span>
        <button type='button' className={BTN} onClick={onLock}>
          Lock
        </button>
      </div>
      {id.ephemeral ? (
        <p className='text-sm text-amber-700 dark:text-amber-400'>
          Ephemeral key: no passkey PRF available, so this identity is random and won&rsquo;t persist.
        </p>
      ) : null}
    </section>
  )
}

/**
 * Room selector — which shared repo you're pointed at. Lives in the left column (alongside compose), independent of
 * identity: you can switch rooms and browse their shared history whether or not you've unlocked a signing key.
 */
export function RoomSelector() {
  const room = useIdentityStore((s) => s.room)
  const setRoom = useIdentityStore((s) => s.setRoom)
  const fieldId = useId()
  return (
    <div className='space-y-1.5'>
      <div className='flex items-center gap-1.5'>
        <label htmlFor={fieldId} className='text-sm text-muted'>
          Repository
        </label>
        <InfoTip label='About the repository'>
          <p>
            <strong className='text-fg'>Everyone here shares one repository.</strong> It’s identified only by its name —
            anyone with the name can read and write it. No accounts: your anonymous key <em>is</em> your identity.
          </p>
          <p className='mt-2'>
            Any number of keys contribute to the same <strong className='text-fg'>shared history</strong>. Because the
            key is derived from your passkey, the same contributor comes back on any device.
          </p>
        </InfoTip>
      </div>
      <input
        id={fieldId}
        className={INPUT_CLASSES}
        value={room}
        onChange={(e) => setRoom(e.target.value)}
        placeholder='lobby'
        spellCheck={false}
      />
    </div>
  )
}
