'use client'

import { useMemo, useState } from 'react'
import { Field, FieldList, INPUT_CLASSES, INPUT_CLASSES_XS } from './result-panel'
import { DEMO_SEED, TEXT_ENCODER, useMkit } from './use-mkit'

type Algo = 'ed25519' | 'secp256k1' | 'p256'

const ALGOS: ReadonlyArray<{ value: Algo; label: string; note: string }> = [
  { value: 'ed25519', label: 'Ed25519', note: 'Fast, the mkit default.' },
  { value: 'secp256k1', label: 'Secp256k1', note: 'What crypto wallets use.' },
  { value: 'p256', label: 'P-256', note: 'What hardware keys, passkeys, and Secure Enclave use.' },
]

// Same seed works for Ed25519 but is out-of-range for secp256k1 / p256, so we keep one default per family and swap
// when the user flips algorithms. Implementation detail — never surfaced in the UI.
const ECDSA_SEED = '4a7c6b5a493827160908070605040302d1c0bfb8a79683726150403a2b1c0d0e'
const SAMPLE_COMMIT = 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789'

export function AttestDemo() {
  const api = useMkit()
  const [claim, setClaim] = useState('{"approved":true,"reviewer":"alice"}')
  const [algo, setAlgo] = useState<Algo>('ed25519')
  const [commitHash, setCommitHash] = useState(SAMPLE_COMMIT)
  const [seed, setSeed] = useState(DEMO_SEED)

  const keypair = useMemo(() => {
    try {
      return { ok: true as const, kp: api.attest_keypair(seed.trim(), algo) }
    } catch (e) {
      return { ok: false as const, error: e instanceof Error ? e.message : String(e) }
    }
  }, [api, seed, algo])

  const built = useMemo(() => {
    if (!keypair.ok) return { ok: false as const, error: keypair.error }
    try {
      const att = api.attest_build(
        commitHash.trim(),
        'https://example.com/Review/v1',
        TEXT_ENCODER.encode(claim.trim()),
        seed.trim(),
        algo,
      )
      return { ok: true as const, att }
    } catch (e) {
      return { ok: false as const, error: e instanceof Error ? e.message : String(e) }
    }
  }, [api, commitHash, claim, seed, algo, keypair])

  const verdict = useMemo(() => {
    if (!built.ok || !keypair.ok) return null
    return api.attest_verify(built.att.envelope_json, keypair.kp.pubkey_hex, algo)
  }, [api, built, keypair, algo])

  const onAlgoChange = (next: Algo) => {
    setAlgo(next)
    if (next === 'ed25519' && seed === ECDSA_SEED) setSeed(DEMO_SEED)
    else if (next !== 'ed25519' && seed === DEMO_SEED) setSeed(ECDSA_SEED)
  }

  return (
    <div className='space-y-6'>
      <label className='block'>
        <span className='mb-2 block text-sm text-[--color-muted]'>What you're claiming</span>
        <textarea className={INPUT_CLASSES} rows={2} value={claim} onChange={(e) => setClaim(e.target.value)} />
      </label>

      <div className='block'>
        <span className='mb-2 block text-sm text-[--color-muted]'>Signed with</span>
        <div className='grid gap-2'>
          {ALGOS.map((a) => (
            <label
              key={a.value}
              className='flex cursor-pointer items-start gap-3 border border-[--color-hairline] bg-[--color-paper] p-3 transition-colors hover:border-[--color-fg]'
            >
              <input
                type='radio'
                name='attest-algo'
                value={a.value}
                checked={algo === a.value}
                onChange={() => onAlgoChange(a.value)}
                className='mt-0.5 accent-[--color-fg]'
              />
              <span className='flex-1 space-y-0.5 text-sm'>
                <span className='block font-medium'>{a.label}</span>
                <span className='block text-xs text-[--color-muted]'>{a.note}</span>
              </span>
            </label>
          ))}
        </div>
      </div>

      <details className='group'>
        <summary className='cursor-pointer text-sm text-[--color-muted] select-none hover:text-[--color-fg]'>
          <span className='inline-block transition-transform group-open:rotate-90'>›</span> Advanced
        </summary>
        <div className='mt-3 space-y-4'>
          <label className='block'>
            <span className='mb-2 block text-sm text-[--color-muted]'>Commit being attested (64 hex)</span>
            <input className={INPUT_CLASSES_XS} value={commitHash} onChange={(e) => setCommitHash(e.target.value)} />
          </label>
          <label className='block'>
            <span className='mb-2 block text-sm text-[--color-muted]'>Private key (32 bytes, 64 hex)</span>
            <input className={INPUT_CLASSES_XS} value={seed} onChange={(e) => setSeed(e.target.value)} />
          </label>
        </div>
      </details>

      {built.ok && keypair.ok ? (
        <FieldList>
          <Field label='Public key'>
            <code className='font-mono text-sm break-all'>{keypair.kp.pubkey_hex}</code>
          </Field>
          <Field label='Signed attestation'>
            <code className='block font-mono text-xs break-all whitespace-pre-wrap'>
              {pretty(built.att.envelope_json)}
            </code>
          </Field>
          <Field label='Verifies'>
            {verdict === null ? null : (
              // Keyed on the verdict so flipping it re-mounts the
              // element and replays the stamp-in thunk.
              <span
                key={String(verdict)}
                className={`stamp ${verdict ? 'text-[--color-verified]' : 'text-[--color-accent]'}`}
              >
                {verdict ? 'Verified' : 'Rejected'}
              </span>
            )}
          </Field>
        </FieldList>
      ) : (
        <p className='text-[--color-accent]'>{built.error}</p>
      )}
    </div>
  )
}

function pretty(json: string): string {
  return json.replace(/,"payloadType":/, ',\n"payloadType":').replace(/,"signatures":/, ',\n"signatures":')
}
