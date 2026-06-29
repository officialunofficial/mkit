'use client'

// Identity column of the multiplayer demo: the optional passkey-attestation
// flourish, the locked create/unlock actions, and the unlocked player header.
// Moved verbatim out of `multiplayer-demo.tsx`.

import { useState } from 'react'
import { type BindingCredential, attestEd25519Binding, enrollBindingPasskey, rpId } from '../../lib/passkey'
import { recordActivity } from '../../lib/activity-log'
import { DEFAULT_ROOM, useIdentityStore } from '../../lib/identity-store'
import { Field, FieldList } from '../result-panel'
import { useMkit } from '../use-mkit'
import { InfoTip } from './info-tip'
import { OwnPlayerName } from './player-label'
import { BTN, PRIMARY_BTN, errMsg } from './shared'

/**
 * Optional flourish: a P-256 _passkey_ vouches that the derived Ed25519 key is the same person's, by signing a DSSE-PAE
 * binding challenge, verified in-browser (RP-ID pinned). A hook so the trigger can sit inline in the unlocked header
 * row while the results render below it.
 */
function useAttest(api: ReturnType<typeof useMkit>, ed25519PubkeyHex: string) {
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

  return { onAttest, busy, binding, result, err }
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
            Unlock recovers your existing player from the passkey. New identity creates a fresh one.
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
            One passkey becomes your Ed25519 player. A single prompt, then every push signs without another.
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
export function UnlockedHeader({
  api,
  ed25519PubkeyHex,
}: {
  api: ReturnType<typeof useMkit>
  ed25519PubkeyHex: string
}) {
  const id = useIdentityStore()
  const attest = useAttest(api, ed25519PubkeyHex)

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
      {/* Player name + key, Lock, and the attest trigger all share one row (the
          attest results render below). Stacks on mobile, single row on sm+. */}
      <div className='flex flex-col gap-2 sm:flex-row sm:flex-wrap sm:items-center'>
        <span className='min-w-0 sm:flex-1' title={ed25519PubkeyHex}>
          <span className='text-lg'>
            <OwnPlayerName />
          </span>{' '}
          <code className='font-mono text-xs break-all text-muted'>{ed25519PubkeyHex.slice(0, 10)}…</code>
        </span>
        <button
          type='button'
          className={BTN}
          onClick={onLock}
          title='Wipes your signing key from memory; unlock re-derives it from your passkey.'
        >
          Lock
        </button>
        <button type='button' className={BTN} onClick={attest.onAttest} disabled={attest.busy}>
          {attest.busy ? 'Attesting…' : 'Attest with a passkey'}
        </button>
        <InfoTip label='About attesting'>
          <p>
            <strong className='text-fg'>Attesting</strong> has a P-256 passkey sign a challenge that vouches this
            Ed25519 key is yours, tying the two keys together.
          </p>
          <p className='mt-2'>
            It’s optional. The binding is verified in your browser with the passkey’s origin pinned, so a green check is
            a stronger “same person” signal than the signing key alone.
          </p>
        </InfoTip>
      </div>
      {attest.result || attest.binding ? (
        <FieldList>
          {attest.result ? (
            <Field label='Binding attestation' compact>
              <span
                className={
                  attest.result.verified ? 'text-green-700 dark:text-green-400' : 'text-red-600 dark:text-red-400'
                }
              >
                {attest.result.verified ? 'verified ✓ (checked in your browser)' : 'failed ✗'}
              </span>
            </Field>
          ) : null}
          {attest.binding ? (
            <Field label='Binding passkey (P-256) public key' compact>
              <code className='font-mono break-all'>{attest.binding.pubkeyHex}</code>
            </Field>
          ) : null}
        </FieldList>
      ) : null}
      {attest.err ? <p className='text-sm text-amber-700 dark:text-amber-400'>{attest.err}</p> : null}
      {id.ephemeral ? (
        <p className='text-sm text-amber-700 dark:text-amber-400'>
          No passkey PRF here, so this identity is a random in-memory key that won&rsquo;t persist.
        </p>
      ) : null}
    </section>
  )
}

/**
 * The repository name. There is ONE fixed shared repository everyone contributes to — you don't switch repos, you push
 * to branches — so this renders read-only rather than as an editable field.
 */
export function RoomSelector() {
  return (
    <div className='space-y-1.5'>
      <div className='flex items-center gap-1.5'>
        <span className='text-sm text-muted'>Repository</span>
        <InfoTip label='About the repository'>
          <p>
            <strong className='text-fg'>Everyone shares this one repository</strong> — there's no switching. You
            contribute by pushing commits to a <strong className='text-fg'>branch</strong> (or starting a new one).
          </p>
          <p className='mt-2'>
            No accounts: your anonymous key <em>is</em> your identity, and any number of keys write the same shared
            history. The same passkey brings the same contributor back on any device.
          </p>
        </InfoTip>
      </div>
      <div className='flex items-center justify-between rounded-md border border-hairline bg-fg/[0.03] px-3 py-2 text-sm'>
        <span className='font-mono'>{DEFAULT_ROOM}</span>
        <span className='text-xs text-muted'>one shared repo</span>
      </div>
    </div>
  )
}
