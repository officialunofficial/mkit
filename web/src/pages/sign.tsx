import { Link } from 'waku'
import { DemoBoundary } from '../components/demo-boundary'
import { SignDemo } from '../components/sign-demo'

export default function SignPage() {
  return (
    <div className='space-y-8'>
      <title>mkit — sign</title>
      <header className='space-y-3'>
        <h1 className='text-4xl font-semibold tracking-tight'>Ed25519 signing</h1>
        <p className='max-w-prose text-base text-[--color-fg]'>
          Strict ZIP-215 / RFC 8032 over <code className='font-mono text-sm'>BLAKE3(domain || signing_bytes)</code>. The{' '}
          <code className='font-mono text-sm'>mkit.commit\0</code> domain prefix keeps commit signatures from replaying
          as remix signatures.
        </p>
      </header>
      <DemoBoundary>
        <SignDemo />
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
