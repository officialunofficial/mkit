import { Link } from 'waku'
import { DemoBoundary } from '../components/demo-boundary'
import { SignDemo } from '../components/sign-demo'

export default function SignPage() {
  return (
    <div className='space-y-8'>
      <title>mkit — sign</title>
      <header className='space-y-3'>
        <h1 className='text-4xl font-semibold tracking-tight'>Sign a message, verify it back</h1>
        <p className='max-w-prose text-base text-[--color-fg]'>
          A private key signs a message; the matching public key verifies it. Anyone can confirm the message hasn't been
          changed and that you signed it. Flip a single character below and the verifier rejects it.
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
