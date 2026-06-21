import { Link } from 'waku'
import { AttestDemo } from '../components/attest-demo'
import { DemoBoundary } from '../components/demo-boundary'
import { Seo } from '../components/seo'

export default function AttestPage() {
  return (
    <div className='space-y-8'>
      <Seo
        title='mkit — attest'
        description='Any claim about a commit — reviewed, tested, deployed — travels as an in-toto Statement in a signed DSSE envelope that anyone can verify.'
        path='/attest'
        card='Statements, signed'
      />
      <header className='space-y-3'>
        <h1 className='text-4xl font-semibold tracking-tight'>Statements, signed</h1>
        <p className='max-w-prose text-base text-fg'>
          An attestation is a signed statement about a commit — &ldquo;reviewed&rdquo;, &ldquo;deployed&rdquo;,
          &ldquo;tested&rdquo; — stored in the repo as a first-class object, not a side-channel. mkit uses the standard
          formats (an in-toto Statement inside a DSSE signing envelope), so anyone holding your public key can verify it
          later — with mkit, cosign, or any compliant verifier. Type a claim, pick a signing algorithm, and watch the
          envelope rebuild and verify.
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
