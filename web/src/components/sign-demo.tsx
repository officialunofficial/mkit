'use client'

import { useMemo, useState } from 'react'
import { Field, FieldList, INPUT_CLASSES, INPUT_CLASSES_XS } from './result-panel'
import { DEMO_SEED, TEXT_ENCODER, useMkit } from './use-mkit'

export function SignDemo() {
  const api = useMkit()
  const [seed, setSeed] = useState(DEMO_SEED)
  const [message, setMessage] = useState('attest this commit')
  const [sig, setSig] = useState<string | null>(null)
  const [tamper, setTamper] = useState(false)

  const keypair = useMemo(() => {
    try {
      return api.keypair_from_seed(seed)
    } catch (e) {
      return { error: e instanceof Error ? e.message : String(e) }
    }
  }, [api, seed])

  const verdict = useMemo(() => {
    if ('error' in keypair || !sig) return null
    const probed = TEXT_ENCODER.encode(
      tamper ? message.replace(/.$/, (c) => String.fromCharCode(c.charCodeAt(0) ^ 1)) : message,
    )
    return api.verify_bytes_commit_domain(keypair.pubkey_hex, probed, sig)
  }, [api, keypair, sig, message, tamper])

  const fresh = () => {
    const kp = api.keypair_generate()
    setSeed(kp.seed_hex)
    setSig(null)
    setTamper(false)
  }

  const doSign = () => {
    setSig(api.sign_bytes_commit_domain(seed, TEXT_ENCODER.encode(message)))
    setTamper(false)
  }

  return (
    <div className='space-y-6'>
      <label className='block'>
        <span className='mb-2 block text-sm text-[--color-muted]'>Private key</span>
        <input className={INPUT_CLASSES_XS} value={seed} onChange={(e) => setSeed(e.target.value.trim())} />
      </label>
      <Button onClick={fresh}>Generate a new key</Button>

      <FieldList>
        <Field label='Public key'>
          {'error' in keypair ? (
            <span className='text-red-600'>{keypair.error}</span>
          ) : (
            <code className='font-mono text-sm'>{keypair.pubkey_hex}</code>
          )}
        </Field>
      </FieldList>

      <label className='block'>
        <span className='mb-2 block text-sm text-[--color-muted]'>Message</span>
        <input
          className={INPUT_CLASSES}
          value={message}
          onChange={(e) => {
            setMessage(e.target.value)
            setSig(null)
          }}
        />
      </label>
      <Button onClick={doSign} disabled={'error' in keypair}>
        Sign
      </Button>

      {sig ? (
        <>
          <FieldList>
            <Field label='Signature'>
              <code className='font-mono text-xs break-all'>{sig}</code>
            </Field>
          </FieldList>
          <label className='flex cursor-pointer items-center gap-2 py-2 text-sm'>
            <input
              type='checkbox'
              className='accent-[--color-fg]'
              checked={tamper}
              onChange={(e) => setTamper(e.target.checked)}
            />
            Tamper with the message before verifying
          </label>
          <FieldList>
            <Field label='Verifies'>
              {verdict === null ? null : (
                <span className={verdict ? 'text-green-700' : 'text-red-600'}>{verdict ? 'yes ✓' : 'no ✗'}</span>
              )}
            </Field>
          </FieldList>
        </>
      ) : null}
    </div>
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
      className='inline-flex h-9 shrink-0 items-center justify-center rounded-lg border border-[--color-hairline] bg-transparent px-3 text-sm font-medium transition-all duration-200 hover:border-[--color-fg] active:translate-y-px disabled:pointer-events-none disabled:opacity-50'
    >
      {children}
    </button>
  )
}
