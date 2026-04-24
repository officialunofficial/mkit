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
          An{' '}
          <a
            href='https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md'
            className='underline underline-offset-4 transition-opacity duration-300 hover:opacity-70'
          >
            in-toto v1 Statement
          </a>{' '}
          names the commit as its subject, wrapped in a{' '}
          <a
            href='https://github.com/secure-systems-lab/dsse/blob/master/envelope.md'
            className='underline underline-offset-4 transition-opacity duration-300 hover:opacity-70'
          >
            DSSE envelope
          </a>
          . The JCS encoder is hand-rolled per RFC 8785 — serde won't satisfy its sort and number rules.
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
