import { Link } from 'waku'
import { AttestDemo } from '../components/attest-demo'
import { DemoBoundary } from '../components/demo-boundary'

export default function AttestPage() {
  return (
    <div className='space-y-8'>
      <title>mkit — attest</title>
      <header className='space-y-3'>
        <h1 className='text-4xl font-semibold tracking-tight'>Sign a claim about a commit</h1>
        <p className='max-w-prose text-base text-[--color-fg]'>
          Attach a signed statement — &ldquo;reviewed&rdquo;, &ldquo;deployed&rdquo;, &ldquo;tested&rdquo; — to any
          commit. Anyone holding your public key can verify it later, on any tool that reads the same envelope.
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
