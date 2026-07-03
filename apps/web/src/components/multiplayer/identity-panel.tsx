'use client'

// Identity column of the multiplayer demo: the optional passkey-attestation
// flourish, the locked create/unlock actions, and the unlocked player header.
// Moved verbatim out of `multiplayer-demo.tsx`.

import { useState } from 'react'
import { attestIdentityBinding, rpId } from '../../lib/passkey'
import { recordActivity } from '../../lib/activity-log'
import { useIdentityStore } from '../../lib/identity-store'
import { Field, FieldList } from '../result-panel'
import { useMkit } from '../use-mkit'
import { InfoTip } from './info-tip'
import { OwnPlayerName } from './player-label'
import { BTN, PRIMARY_BTN, errMsg } from './shared'

/**
 * Optional flourish: the IDENTITY passkey (the same one the Ed25519 key is derived from) vouches for the derived
 * pubkey, by signing a DSSE-PAE binding challenge, verified in-browser (RP-ID pinned). A hook so the trigger can sit
 * inline in the unlocked header row while the results render below it.
 */
function useAttest(
  api: ReturnType<typeof useMkit>,
  credentialId: string | null,
  p256PubkeyHex: string | null,
  ed25519PubkeyHex: string,
) {
  const [result, setResult] = useState<{ verified: boolean } | null>(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  const onAttest = async () => {
    // No credential/pubkey to vouch with (legacy identity or an authenticator
    // that didn't expose getPublicKey()) — the caller already gates the
    // trigger on this via `canAttest`; this guard just makes null
    // unrepresentable downstream instead of relying on that alone.
    if (credentialId == null || p256PubkeyHex == null) return
    setErr(null)
    setBusy(true)
    try {
      const res = await attestIdentityBinding(api, credentialId, p256PubkeyHex, ed25519PubkeyHex, {
        policyJson: JSON.stringify({ expected_rp_id: rpId() }),
      })
      setResult({ verified: res.verified })
    } catch (e) {
      setErr(errMsg(e))
    } finally {
      setBusy(false)
    }
  }

  return { onAttest, busy, result, err }
}

/** Fingerprint glyph — signals that the button triggers a biometric passkey prompt. */
function Fingerprint({ className = '' }: { className?: string }) {
  return (
    <svg
      viewBox='0 0 24 24'
      width='15'
      height='15'
      fill='none'
      stroke='currentColor'
      strokeWidth='1.7'
      strokeLinecap='round'
      strokeLinejoin='round'
      aria-hidden
      className={`shrink-0 ${className}`}
    >
      <path d='M2 12C2 6.5 6.5 2 12 2a10 10 0 0 1 8 4' />
      <path d='M5 19.5C5.5 18 6 15 6 12c0-.7.12-1.37.34-2' />
      <path d='M17.29 21.02c.12-.6.43-2.3.5-3.02' />
      <path d='M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4' />
      <path d='M8.65 22c.21-.66.45-1.32.57-2' />
      <path d='M14 13.12c0 2.38 0 6.38-1 8.88' />
      <path d='M2 16h.01' />
      <path d='M21.8 16c.2-2 .131-5.354 0-6' />
      <path d='M9 6.8a6 6 0 0 1 9 5.2c0 .47 0 1.17-.02 2' />
    </svg>
  )
}

/**
 * LOCKED state: two actions, with the recover/Unlock button kept on the RIGHT — the same spot the Lock button takes
 * once unlocked, so it doesn't jump across the state change. Unlock carries a fingerprint glyph (it triggers a
 * biometric passkey prompt). When a passkey is already known: New identity (left) ↔ Unlock (right). First-time: Create
 * (left, primary) ↔ Unlock existing (right).
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
          <div className='flex flex-wrap items-center justify-between gap-2'>
            <button type='button' className={BTN} onClick={onCreate} disabled={busy}>
              New identity
            </button>
            <button type='button' className={`${PRIMARY_BTN} gap-1.5`} onClick={onUnlock} disabled={busy}>
              <Fingerprint />
              {busy ? 'Unlocking…' : 'Unlock'}
            </button>
          </div>
        </>
      ) : (
        <>
          <div className='flex flex-wrap items-center justify-between gap-2'>
            <button type='button' className={PRIMARY_BTN} onClick={onCreate} disabled={busy}>
              {busy ? 'Creating…' : 'Create passkey identity'}
            </button>
            <button type='button' className={`${BTN} gap-1.5`} onClick={onUnlock} disabled={busy}>
              <Fingerprint />
              Unlock existing passkey
            </button>
          </div>
          <p className='max-w-prose text-sm text-muted'>
            One passkey becomes your Ed25519 player. A single prompt, then every push signs without another.
          </p>
        </>
      )}
      {status ? <p className='text-sm text-muted'>{status}</p> : null}
    </section>
  )
}

/**
 * UNLOCKED header: the player identity + a lock control. (The shared repository is described in the page subcopy above
 * the workspace, not selected here.)
 */
export function UnlockedHeader({
  api,
  ed25519PubkeyHex,
}: {
  api: ReturnType<typeof useMkit>
  ed25519PubkeyHex: string
}) {
  const id = useIdentityStore()
  const attest = useAttest(api, id.credentialId, id.p256PubkeyHex, ed25519PubkeyHex)
  // A legacy identity (created before #494) or an authenticator that didn't
  // expose getPublicKey() at creation time has no captured pubkey — the
  // attest ceremony has no key to hand the verifier, so disable rather than
  // fail on click.
  const canAttest = id.p256PubkeyHex != null

  // Narrate the lock so the "I can wipe my key and re-derive it" property is
  // legible.
  const onLock = () => {
    recordActivity({
      kind: 'lock',
      title: 'Signing key wiped from memory',
      lines: [
        'Your Ed25519 seed is gone from memory. You can still read the repository, but you can’t sign a push until you unlock.',
        'Your passkey and public key remain, so unlocking re-derives the same player. Nothing was ever written to disk.',
      ],
    })
    id.lock()
  }

  return (
    <section className='space-y-3'>
      {/* Player name + key and the attest trigger sit together on the LEFT; Lock
          stays at the far right — the same spot Unlock occupies while locked.
          Stacks on mobile, single row on sm+. */}
      <div className='flex flex-col gap-2 sm:flex-row sm:flex-wrap sm:items-center'>
        <span className='min-w-0' title={ed25519PubkeyHex}>
          <span className='text-lg'>
            <OwnPlayerName />
          </span>{' '}
          <code className='font-mono text-xs break-all text-muted'>{ed25519PubkeyHex.slice(0, 10)}…</code>
        </span>
        <span className='flex items-center gap-1.5'>
          <button
            type='button'
            className={BTN}
            onClick={attest.onAttest}
            disabled={attest.busy || !canAttest}
            title={canAttest ? undefined : 'Re-create your identity to enable passkey attestation.'}
          >
            {attest.busy ? 'Linking…' : 'Link with a passkey'}
          </button>
          <InfoTip label='About linking'>
            <p>
              On its own, your signing key is anonymous. It’s derived from your passkey, but that link is{' '}
              <strong className='text-fg'>private</strong> — no one else can see it or prove it.
            </p>
            <p className='mt-2'>
              <strong className='text-fg'>Linking</strong> has your passkey publicly vouch for your signing key, turning
              that private link into a proof anyone can verify in their browser. It’s the same passkey your signing key
              is derived from — your passkey vouches for your signing key — and your signing key never leaves your
              browser.
            </p>
            <p className='mt-2'>It’s optional, and pinned to this site.</p>
          </InfoTip>
        </span>
        <button
          type='button'
          className={`${BTN} sm:ml-auto`}
          onClick={onLock}
          title='Wipes your signing key from memory; unlock re-derives it from your passkey.'
        >
          Lock
        </button>
      </div>
      {attest.result ? (
        <FieldList>
          <Field label='Binding attestation' compact>
            <span
              className={
                attest.result.verified ? 'text-green-700 dark:text-green-400' : 'text-red-600 dark:text-red-400'
              }
            >
              {attest.result.verified ? 'verified ✓ (checked in your browser)' : 'failed ✗'}
            </span>
          </Field>
          {id.p256PubkeyHex ? (
            <Field label='Identity passkey (P-256) public key' compact>
              <code className='font-mono break-all'>{id.p256PubkeyHex}</code>
            </Field>
          ) : null}
        </FieldList>
      ) : null}
      {attest.err ? <p className='text-sm text-amber-700 dark:text-amber-400'>{attest.err}</p> : null}
      {id.ephemeral ? (
        <p className='text-sm text-amber-700 dark:text-amber-400'>
          This browser can&rsquo;t save your passkey, so this is a temporary identity that won&rsquo;t be here next
          time.
        </p>
      ) : null}
    </section>
  )
}
