'use client'

import { useMemo, useState } from 'react'
import { HashChip, INPUT_CLASSES } from './result-panel'
import { DEMO_SEED, TEXT_ENCODER, useMkit } from './use-mkit'

// Two stock identities. `alice` is the signer (her seed signs); `mallory` is a
// second party whose key we verify against to show a signature also proves WHO
// signed — verifying alice's signature with mallory's key fails. mallory's seed
// is never needed (we never sign as her), only her public key.
const ALICE = 'alice'
const MALLORY = 'mallory'

export function SignDemo() {
  const api = useMkit()

  // alice's private key (seed) — hidden from the UI; her public key is derived
  // from it and shown as a fingerprint. "New identity" rerolls it.
  const [aliceSeed, setAliceSeed] = useState(DEMO_SEED)
  const alicePubkey = useMemo(() => api.keypair_from_seed(aliceSeed).pubkey_hex, [api, aliceSeed])
  // Generated once on mount; only the public key matters here.
  const [malloryPubkey] = useState(() => api.keypair_from_seed(api.keypair_generate().seed_hex).pubkey_hex)

  const [draft, setDraft] = useState('Fix auth bypass in login')
  // null until signed; freezes the exact message + signature at signing time.
  const [signed, setSigned] = useState<{ message: string; sig: string } | null>(null)
  const [received, setReceived] = useState('')
  const [verifyAs, setVerifyAs] = useState<typeof ALICE | typeof MALLORY>(ALICE)

  const verifyPubkey = verifyAs === ALICE ? alicePubkey : malloryPubkey

  // Re-verify on every keystroke / key switch — the same call mkit makes for a
  // real commit. A single differing byte, or the wrong key, returns false.
  const verdict = useMemo(() => {
    if (!signed) return null
    return api.verify_bytes_commit_domain(verifyPubkey, TEXT_ENCODER.encode(received), signed.sig)
  }, [api, signed, received, verifyPubkey])

  const sign = () => {
    const sig = api.sign_bytes_commit_domain(aliceSeed, TEXT_ENCODER.encode(draft))
    setSigned({ message: draft, sig })
    setReceived(draft)
    setVerifyAs(ALICE)
  }

  const newIdentity = () => {
    setAliceSeed(api.keypair_generate().seed_hex)
    setSigned(null)
  }

  const tampered = signed ? received !== signed.message : false
  const diff = signed ? diffParts(signed.message, received) : null

  return (
    <div className='space-y-6'>
      {/* Who's signing — an identity, not a wall of hex. */}
      <div className='flex flex-wrap items-center justify-between gap-3'>
        <span className='inline-flex items-center gap-2 text-sm text-muted'>
          Signing as
          <Identity pubkey={alicePubkey} name={ALICE} />
        </span>
        <Button onClick={newIdentity}>New identity</Button>
      </div>

      {!signed ? (
        <div className='flex items-end gap-2'>
          <label className='block flex-1'>
            <span className='mb-1.5 block text-sm text-muted'>Message to sign</span>
            <input className={INPUT_CLASSES} value={draft} onChange={(e) => setDraft(e.target.value)} />
          </label>
          <Button onClick={sign} disabled={!draft.trim()}>
            Sign
          </Button>
        </div>
      ) : (
        <div className='space-y-6'>
          {/* The signed record — a disabled field so it reads as locked: the exact
              bytes alice signed can't be edited (faded background + text). */}
          <div className='space-y-1.5'>
            <span className='text-sm font-semibold text-fg'>Signed by {ALICE}</span>
            <input
              className={`${INPUT_CLASSES} disabled:cursor-not-allowed disabled:bg-muted/10 disabled:text-muted`}
              value={signed.message}
              disabled
              aria-label='Signed message (locked)'
            />
            <details className='text-xs text-muted'>
              <summary className='cursor-pointer select-none'>signature</summary>
              <code className='mt-1 block break-all font-mono'>{signed.sig}</code>
            </details>
          </div>

          {/* The verifier's copy — editable. Change one character and watch it break. */}
          <div className='space-y-2'>
            <div className='flex flex-wrap items-start justify-between gap-2'>
              <div className='space-y-0.5'>
                <span className='block text-sm font-semibold text-fg'>The message the verifier received</span>
                {/* Nudge the user to break it themselves — drops away once they
                    start editing, when the live verdict takes over. */}
                {!tampered ? (
                  <span className='block text-xs text-muted'>
                    Try changing a character — does the signature still verify?
                  </span>
                ) : null}
              </div>
              <label className='inline-flex items-center gap-1.5 text-sm text-muted'>
                Check against
                <span className='relative inline-flex'>
                  <select
                    value={verifyAs}
                    onChange={(e) => setVerifyAs(e.target.value as typeof ALICE | typeof MALLORY)}
                    className='appearance-none rounded-md border border-hairline bg-bg py-1 pl-2 pr-7 text-sm text-fg outline-none transition-colors hover:border-blue-500/50 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/25'
                  >
                    <option value={ALICE}>{ALICE}’s key</option>
                    <option value={MALLORY}>{MALLORY}’s key</option>
                  </select>
                  <span
                    aria-hidden
                    className='pointer-events-none absolute inset-y-0 right-2 flex items-center text-muted'
                  >
                    <DownChevron />
                  </span>
                </span>
              </label>
            </div>
            <input
              className={INPUT_CLASSES}
              value={received}
              onChange={(e) => setReceived(e.target.value)}
              aria-label='Received message'
            />

            {verdict ? (
              <p className='flex items-center gap-2 text-sm text-green-700 dark:text-green-400'>
                <span aria-hidden>✓</span>
                Verified — the signature matches this message and {ALICE}’s key.
              </p>
            ) : (
              <div className='space-y-2'>
                <p className='flex items-center gap-2 text-sm text-red-600 dark:text-red-400'>
                  <span aria-hidden>✗</span>
                  {tampered
                    ? 'Tampered — this is not what was signed.'
                    : `Wrong signer — this signature is not ${MALLORY}’s. It’s ${ALICE}’s.`}
                </p>
                {tampered && diff ? (
                  <p className='rounded-md border border-hairline px-3 py-2 font-mono text-sm break-all'>
                    {diff.before}
                    {diff.removed ? (
                      <del className='bg-red-500/15 text-red-600 line-through decoration-red-500 dark:text-red-400'>
                        {diff.removed}
                      </del>
                    ) : null}
                    {diff.added ? <mark className='rounded-sm bg-red-500/20 text-fg'>{diff.added}</mark> : null}
                    {diff.after}
                    <span className='mt-1 block text-xs text-muted not-italic'>
                      highlighted text differs from what was signed
                    </span>
                  </p>
                ) : null}
              </div>
            )}
          </div>

          <Button onClick={() => setSigned(null)}>Sign a new message</Button>
        </div>
      )}
    </div>
  )
}

/** Identity chip: a colour derived from the public key, the name, and a short fingerprint. */
function Identity({ pubkey, name }: { pubkey: string; name: string }) {
  return (
    <span className='inline-flex items-center gap-1.5'>
      <HashChip hash={pubkey} size={18} />
      <span className='font-medium text-fg'>{name}</span>
      <span className='font-mono text-xs text-muted'>·{pubkey.slice(0, 4)}</span>
    </span>
  )
}

/**
 * Single-region diff of `received` against `signed`: shared prefix and suffix are peeled off, leaving the changed
 * middle — `added` (what's now in received) and `removed` (what was in signed there). Handles the common case of one
 * edit/insert/delete cleanly without a full LCS.
 */
function diffParts(signed: string, received: string) {
  let start = 0
  const min = Math.min(signed.length, received.length)
  while (start < min && signed[start] === received[start]) start++
  let endS = signed.length
  let endR = received.length
  while (endS > start && endR > start && signed[endS - 1] === received[endR - 1]) {
    endS--
    endR--
  }
  return {
    before: received.slice(0, start),
    added: received.slice(start, endR),
    removed: signed.slice(start, endS),
    after: received.slice(endR),
  }
}

/** Down chevron for the custom-styled <select> (native arrow suppressed via appearance-none). */
function DownChevron() {
  return (
    <svg
      viewBox='0 0 16 16'
      fill='none'
      stroke='currentColor'
      strokeWidth='1.5'
      strokeLinecap='round'
      strokeLinejoin='round'
      className='size-3'
      aria-hidden
    >
      <path d='M4 6 L8 10 L12 6' />
    </svg>
  )
}

function Button({
  children,
  onClick,
  disabled,
}: {
  children: React.ReactNode
  onClick: () => void
  disabled?: boolean
}) {
  return (
    <button
      type='button'
      onClick={onClick}
      disabled={disabled}
      className='inline-flex h-10 shrink-0 items-center justify-center rounded-lg border border-hairline bg-transparent px-3 text-sm font-medium transition-all duration-200 hover:border-blue-500/50 active:translate-y-px disabled:pointer-events-none disabled:opacity-50 sm:h-9'
    >
      {children}
    </button>
  )
}
