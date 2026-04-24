'use client'

import { useMemo, useState } from 'react'
import { Field, FieldList, INPUT_CLASSES_XS } from './result-panel'
import { DEMO_SEED, TEXT_ENCODER, useMkit } from './use-mkit'

type Algo = 'ed25519' | 'secp256k1' | 'p256'

const ALGOS: ReadonlyArray<{ value: Algo; label: string; cose: string; note: string }> = [
  { value: 'ed25519', label: 'Ed25519', cose: 'COSE -19', note: 'default mkit signer; 32-byte pubkey' },
  {
    value: 'secp256k1',
    label: 'Secp256k1 (ES256K)',
    cose: 'COSE -47',
    note: 'wallet / Ethereum lineage; 33-byte compressed SEC1',
  },
  {
    value: 'p256',
    label: 'P-256 (ES256)',
    cose: 'COSE -7',
    note: 'iOS Secure Enclave / WebAuthn; 33-byte compressed SEC1',
  },
]

// A high-entropy default seed that happens to be a valid scalar for all three algorithms. The DEMO_SEED constant
// (0x0101…01) works for Ed25519 but is not a valid ECDSA private key for secp256k1 / p256, so we swap it in when the
// user selects one of the ECDSA algorithms.
const ECDSA_SEED = '4a7c6b5a493827160908070605040302d1c0bfb8a79683726150403a2b1c0d0e'

export function AttestDemo() {
  const api = useMkit()
  const [commitHash, setCommitHash] = useState('abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789')
  const [predicateType, setPredicateType] = useState('https://example.com/Review/v1')
  const [predicateJcs, setPredicateJcs] = useState('{"approved":true}')
  const [algo, setAlgo] = useState<Algo>('ed25519')
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
        predicateType.trim(),
        TEXT_ENCODER.encode(predicateJcs.trim()),
        seed.trim(),
        algo,
      )
      return { ok: true as const, att }
    } catch (e) {
      return { ok: false as const, error: e instanceof Error ? e.message : String(e) }
    }
  }, [api, commitHash, predicateType, predicateJcs, seed, algo, keypair])

  const verdict = useMemo(() => {
    if (!built.ok || !keypair.ok) return null
    return api.attest_verify(built.att.envelope_json, keypair.kp.pubkey_hex, algo)
  }, [api, built, keypair, algo])

  const onAlgoChange = (next: Algo) => {
    setAlgo(next)
    // If the current seed is the ed25519 default, swap to the ECDSA-safe default on pivot (and vice versa) so the
    // demo never lands in "invalid scalar" state when the user first flips the selector.
    if (next === 'ed25519' && seed === ECDSA_SEED) setSeed(DEMO_SEED)
    else if (next !== 'ed25519' && seed === DEMO_SEED) setSeed(ECDSA_SEED)
  }

  return (
    <div className='space-y-6'>
      <label className='block'>
        <span className='mb-2 block text-sm text-[--color-muted]'>Signing algorithm</span>
        <div className='grid gap-2'>
          {ALGOS.map((a) => (
            <label
              key={a.value}
              className='flex cursor-pointer items-start gap-3 rounded-md border border-[--color-hairline] p-3 transition-colors hover:border-[--color-fg]'
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
                <span className='block font-medium'>
                  {a.label} <span className='text-[--color-muted]'>· {a.cose}</span>
                </span>
                <span className='block text-xs text-[--color-muted]'>{a.note}</span>
              </span>
            </label>
          ))}
        </div>
      </label>

      <label className='block'>
        <span className='mb-2 block text-sm text-[--color-muted]'>Subject commit hash (64 hex)</span>
        <input className={INPUT_CLASSES_XS} value={commitHash} onChange={(e) => setCommitHash(e.target.value)} />
      </label>
      <label className='block'>
        <span className='mb-2 block text-sm text-[--color-muted]'>predicateType URI</span>
        <input className={INPUT_CLASSES_XS} value={predicateType} onChange={(e) => setPredicateType(e.target.value)} />
      </label>
      <label className='block'>
        <span className='mb-2 block text-sm text-[--color-muted]'>
          Predicate body (must be JCS-canonical JSON object)
        </span>
        <textarea
          className={INPUT_CLASSES_XS}
          rows={3}
          value={predicateJcs}
          onChange={(e) => setPredicateJcs(e.target.value)}
        />
      </label>
      <label className='block'>
        <span className='mb-2 block text-sm text-[--color-muted]'>Signer seed (32 bytes, 64 hex)</span>
        <input className={INPUT_CLASSES_XS} value={seed} onChange={(e) => setSeed(e.target.value)} />
      </label>

      {built.ok && keypair.ok ? (
        <FieldList>
          <Field label='Derived public key'>
            <code className='font-mono text-sm break-all'>{keypair.kp.pubkey_hex}</code>
          </Field>
          <Field label='keyid'>
            <code className='font-mono text-sm break-all'>{built.att.keyid}</code>
          </Field>
          <Field label='attestation_id (BLAKE3 of envelope bytes)'>
            <code className='font-mono text-sm break-all'>{built.att.attestation_id_hex}</code>
          </Field>
          <Field label='DSSE envelope (JCS-canonical)'>
            <code className='block font-mono text-xs break-all whitespace-pre-wrap'>
              {pretty(built.att.envelope_json)}
            </code>
          </Field>
          <Field label='verify_envelope verdict'>
            {verdict === null ? null : (
              <span className={verdict ? 'text-green-700' : 'text-red-600'}>
                {verdict ? 'signature valid ✓' : 'signature rejected ✗'}
              </span>
            )}
          </Field>
        </FieldList>
      ) : (
        <p className='text-red-600'>{built.error}</p>
      )}
    </div>
  )
}

function pretty(json: string): string {
  return json.replace(/,"payloadType":/, ',\n"payloadType":').replace(/,"signatures":/, ',\n"signatures":')
}
