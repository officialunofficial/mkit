'use client'

import { useMemo, useState } from 'react'
import { Field, FieldList, INPUT_CLASSES_XS } from './result-panel'
import { DEMO_SEED, TEXT_ENCODER, useMkit } from './use-mkit'

export function AttestDemo() {
  const api = useMkit()
  const [commitHash, setCommitHash] = useState('abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789')
  const [predicateType, setPredicateType] = useState('https://example.com/Review/v1')
  const [predicateJcs, setPredicateJcs] = useState('{"approved":true}')
  const [seed, setSeed] = useState(DEMO_SEED)

  const built = useMemo(() => {
    try {
      const att = api.attest_build(
        commitHash.trim(),
        predicateType.trim(),
        TEXT_ENCODER.encode(predicateJcs.trim()),
        seed.trim(),
      )
      return { ok: true as const, att }
    } catch (e) {
      return {
        ok: false as const,
        error: e instanceof Error ? e.message : String(e),
      }
    }
  }, [api, commitHash, predicateType, predicateJcs, seed])

  const verdict = useMemo(() => {
    if (!built.ok) return null
    const kp = api.keypair_from_seed(seed.trim())
    return api.attest_verify(built.att.envelope_json, kp.pubkey_hex)
  }, [api, built, seed])

  return (
    <div className='space-y-6'>
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
        <span className='mb-2 block text-sm text-[--color-muted]'>Signer seed</span>
        <input className={INPUT_CLASSES_XS} value={seed} onChange={(e) => setSeed(e.target.value)} />
      </label>

      {built.ok ? (
        <FieldList>
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
