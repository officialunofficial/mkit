import { Link } from 'waku'
import { AttestDemo } from '../components/attest-demo'
import { DemoBoundary } from '../components/demo-boundary'

export default function AttestPage() {
  return (
    <div className='space-y-8'>
      <title>mkit — attest</title>
      <header className='space-y-3'>
        <h1 className='text-4xl font-semibold tracking-tight'>Attestations</h1>
        <p className='max-w-prose text-base text-[--color-fg]'>
          A signed claim about a commit. The claim names the commit as its subject; the envelope wraps it with one or
          more signatures so anyone holding the public key can verify it later. Pick a signing algorithm —{' '}
          <code className='font-mono text-sm'>Ed25519</code> by default,{' '}
          <code className='font-mono text-sm'>Secp256k1</code> for wallet clients, or{' '}
          <code className='font-mono text-sm'>P-256</code> for Secure Enclave / WebAuthn.
        </p>
      </header>
      <DemoBoundary>
        <AttestDemo />
      </DemoBoundary>
      <Link
        to='/'
        className='-mx-2 inline-block px-2 py-2 text-sm underline underline-offset-4 transition-opacity duration-300 hover:opacity-70'
      >
        ← back
      </Link>
    </div>
  )
}

export const getConfig = async () => {
  return {
    render: 'static',
  } as const
}
