'use client'

import * as Collapsible from '@radix-ui/react-collapsible'
import { type ReactNode, useMemo, useState } from 'react'
import { Field, FieldList, INPUT_CLASSES_XS } from './result-panel'
import { DEMO_SEED, TEXT_ENCODER, useMkit } from './use-mkit'

type Algo = 'ed25519' | 'secp256k1' | 'p256'

const ALGOS: ReadonlyArray<{ value: Algo; label: string; note: string }> = [
  { value: 'ed25519', label: 'Ed25519', note: 'Fast, the mkit default.' },
  { value: 'secp256k1', label: 'Secp256k1', note: 'What crypto wallets use.' },
  { value: 'p256', label: 'P-256', note: 'What hardware keys, passkeys, and Secure Enclave use.' },
]

const PREDICATE_TYPE = 'https://mkit.sh/attestation/Review/v1'
// alice's key per family — DEMO_SEED is out of range for the ECDSA curves, so we
// swap in a curve-safe seed when the algorithm isn't Ed25519.
const ALICE_ECDSA_SEED = '4a7c6b5a493827160908070605040302d1c0bfb8a79683726150403a2b1c0d0e'
// A second identity. A low value is in range for every curve (and fine for Ed25519).
const MALLORY_SEED = '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20'

// The two commits the attestation can point at.
const COMMIT_A = 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789'
const COMMIT_B = '1111111122222222333333334444444455555555666666667777777788888888'

// What alice actually signed. Editing the claim or repointing the subject in the
// UI diverges from this, so the signature no longer matches.
const ORIGINAL_CLAIM = '{"reviewed":true}'

const short = (h: string) => `${h.slice(0, 8)}…`

type Safe<T> = { ok: true; value: T } | { ok: false; error: string }
function safe<T>(fn: () => T): Safe<T> {
  try {
    return { ok: true, value: fn() }
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) }
  }
}

export function AttestDemo() {
  const api = useMkit()
  const [algo, setAlgo] = useState<Algo>('ed25519')
  const [claim, setClaim] = useState(ORIGINAL_CLAIM)
  const [subject, setSubject] = useState(COMMIT_A)
  const [verifyAs, setVerifyAs] = useState<'alice' | 'mallory'>('alice')

  const aliceSeed = algo === 'ed25519' ? DEMO_SEED : ALICE_ECDSA_SEED
  const alice = useMemo(() => safe(() => api.attest_keypair(aliceSeed, algo)), [api, aliceSeed, algo])
  const mallory = useMemo(() => safe(() => api.attest_keypair(MALLORY_SEED, algo)), [api, algo])

  // What alice signed: reviewed:true about COMMIT_A. Rebuilt only when the key /
  // algorithm changes — NOT when the user edits the claim or subject, which are
  // the verifier's view used to demonstrate tampering.
  const signed = useMemo(
    () => safe(() => api.attest_build(COMMIT_A, PREDICATE_TYPE, TEXT_ENCODER.encode(ORIGINAL_CLAIM), aliceSeed, algo)),
    [api, aliceSeed, algo],
  )

  const claimTampered = claim.trim() !== ORIGINAL_CLAIM
  const subjectTampered = subject !== COMMIT_A
  const wrongSigner = verifyAs === 'mallory'

  const verdict = useMemo(() => {
    if (!signed.ok) return false
    const kp = verifyAs === 'alice' ? alice : mallory
    if (!kp.ok) return false
    const envelope =
      claimTampered || subjectTampered
        ? tamperEnvelope(signed.value.envelope_json, subject, claim)
        : signed.value.envelope_json
    try {
      return api.attest_verify(envelope, kp.value.pubkey_hex, algo)
    } catch {
      return false
    }
  }, [api, signed, alice, mallory, verifyAs, claimTampered, subjectTampered, subject, claim, algo])

  const reason = claimTampered
    ? 'The claim was changed after signing.'
    : subjectTampered
      ? `This attestation is for commit ${short(COMMIT_A)}, not ${short(subject)}.`
      : wrongSigner
        ? 'Signed by alice, not mallory.'
        : null

  const fieldCls =
    'w-full rounded-md border border-hairline bg-bg py-1 text-sm outline-none transition-colors focus:border-blue-500'

  return (
    <div className='space-y-6'>
      {/* An attestation is a signed statement about a commit. This one is alice's
          review; verify it, then break each binding and watch it fail. */}
      <div className='space-y-4 rounded-md border border-hairline p-4'>
        <div className='flex flex-wrap items-center justify-between gap-2'>
          <span className='text-sm'>
            <span className='font-medium text-fg'>alice</span> <span className='text-muted'>attests</span>
          </span>
          <Badge ok={verdict}>{verdict ? 'Verified ✓' : 'Not verified ✗'}</Badge>
        </div>

        <dl className='space-y-3 text-sm'>
          <Row label='Claim'>
            <input
              className={`${fieldCls} px-2 font-mono`}
              value={claim}
              onChange={(e) => setClaim(e.target.value)}
              aria-label='Claim'
            />
          </Row>
          <Row label='About commit'>
            <select className={`${fieldCls} pl-2 pr-7`} value={subject} onChange={(e) => setSubject(e.target.value)}>
              <option value={COMMIT_A}>{short(COMMIT_A)}</option>
              <option value={COMMIT_B}>{short(COMMIT_B)} — a different commit</option>
            </select>
          </Row>
          <Row label='Verify with'>
            <select
              className={`${fieldCls} pl-2 pr-7`}
              value={verifyAs}
              onChange={(e) => setVerifyAs(e.target.value as 'alice' | 'mallory')}
            >
              <option value='alice'>alice’s key</option>
              <option value='mallory'>mallory’s key</option>
            </select>
          </Row>
        </dl>

        <p className={`text-sm ${reason ? 'text-red-600 dark:text-red-400' : 'text-muted'}`}>
          {reason ??
            'The signature covers this exact claim, this commit, and alice’s key. Change any one and it fails.'}
        </p>
      </div>

      {/* What it's for: a verified review unblocks a deploy. */}
      <div className='flex items-center justify-between gap-3 rounded-md border border-hairline px-4 py-3'>
        <span className='text-sm'>
          Deploy gate <span className='text-muted'>· needs a verified review</span>
        </span>
        <Badge ok={verdict}>{verdict ? 'Ready ✓' : 'Blocked'}</Badge>
      </div>

      <Collapsible.Root className='group'>
        <Collapsible.Trigger className='flex items-center gap-1 text-sm text-muted transition-colors select-none hover:text-fg'>
          <span className='inline-block transition-transform group-data-[state=open]:rotate-90'>›</span> Advanced
        </Collapsible.Trigger>
        <Collapsible.Content className='mt-3 space-y-4'>
          <div>
            <span className='mb-2 block text-sm text-muted'>Signature algorithm</span>
            <div className='grid gap-2'>
              {ALGOS.map((a) => (
                <label
                  key={a.value}
                  className='flex cursor-pointer items-start gap-3 rounded-md border border-hairline p-3 transition-colors hover:border-blue-500/50'
                >
                  {/* Custom radio: unselected fill is the page bg (not the border colour). */}
                  <input
                    type='radio'
                    name='attest-algo'
                    value={a.value}
                    checked={algo === a.value}
                    onChange={() => setAlgo(a.value)}
                    className='mt-0.5 size-4 shrink-0 appearance-none rounded-full border border-hairline bg-bg transition-colors checked:border-fg checked:bg-[radial-gradient(circle,var(--color-fg)_0_3.5px,transparent_4px)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500/40'
                  />
                  <span className='flex-1 space-y-0.5 text-sm'>
                    <span className='block font-medium'>{a.label}</span>
                    <span className='block text-xs text-muted'>{a.note}</span>
                  </span>
                </label>
              ))}
            </div>
          </div>

          {signed.ok && alice.ok ? (
            <FieldList>
              <Field label='alice’s public key'>
                <code className='font-mono text-xs break-all'>{alice.value.pubkey_hex}</code>
              </Field>
              <Field label='Signed attestation (DSSE + in-toto)'>
                <code className='block font-mono text-xs break-all whitespace-pre-wrap'>
                  {pretty(signed.value.envelope_json)}
                </code>
              </Field>
            </FieldList>
          ) : (
            <p className='text-sm text-red-600 dark:text-red-400'>{(!signed.ok && signed.error) || 'Key error.'}</p>
          )}

          <label className='block'>
            <span className='mb-2 block text-sm text-muted'>alice’s private key (32 bytes, 64 hex)</span>
            <input className={INPUT_CLASSES_XS} value={aliceSeed} readOnly />
          </label>
        </Collapsible.Content>
      </Collapsible.Root>
    </div>
  )
}

/** A label / value row inside the attestation card. */
function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className='grid grid-cols-[6.5rem_1fr] items-center gap-3'>
      <dt className='text-muted'>{label}</dt>
      <dd className='min-w-0'>{children}</dd>
    </div>
  )
}

/** Verified / blocked pill — green when ok, red otherwise. */
function Badge({ ok, children }: { ok: boolean; children: ReactNode }) {
  return (
    <span
      className={`shrink-0 rounded-full border px-2 py-0.5 text-xs font-medium ${
        ok
          ? 'border-green-600/40 bg-green-500/10 text-green-700 dark:text-green-400'
          : 'border-red-500/40 bg-red-500/10 text-red-600 dark:text-red-400'
      }`}
    >
      {children}
    </span>
  )
}

/**
 * Build a tampered copy of a signed DSSE envelope: swap the subject digest and/or predicate inside the base64 in-toto
 * payload, keeping the original signature. Used only when the user has edited the claim or repointed the commit — so
 * the signature can no longer match, and `attest_verify` returns false. Returns `{}` (which fails verification) on any
 * parse error.
 */
function tamperEnvelope(envelopeJson: string, subjectHex: string, claimJson: string): string {
  try {
    const env = JSON.parse(envelopeJson)
    const b64 = String(env.payload).replace(/-/g, '+').replace(/_/g, '/')
    const stmt = JSON.parse(atob(b64))
    const first = Array.isArray(stmt.subject) ? stmt.subject[0] : undefined
    if (first?.digest) {
      const k = Object.keys(first.digest)[0]
      if (k) first.digest[k] = subjectHex
    }
    try {
      stmt.predicate = JSON.parse(claimJson)
    } catch {
      stmt.predicate = claimJson
    }
    env.payload = btoa(JSON.stringify(stmt))
    return JSON.stringify(env)
  } catch {
    return '{}'
  }
}

function pretty(json: string): string {
  return json.replace(/,"payloadType":/, ',\n"payloadType":').replace(/,"signatures":/, ',\n"signatures":')
}
