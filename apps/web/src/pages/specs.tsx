import { Link } from 'waku'
import { Seo } from '../components/seo'
import { SpecIndex } from '../components/spec-index'
import { WithToc } from '../components/with-toc'

export default function SpecsPage() {
  return (
    <WithToc>
      <div className='space-y-8'>
        <Seo
          title='mkit — specs'
          description='The specifications behind mkit: on-disk object formats, packfile and transport wire protocols, and signing and attestation contracts, each carrying its own maturity and bindingness status.'
          path='/specs'
          card='Specified down to the byte'
        />
        <header className='space-y-3'>
          <h1 className='text-4xl font-semibold tracking-tight'>Specified down to the byte</h1>
          <p className='max-w-prose text-base text-fg'>
            Every format mkit writes to disk or the wire has a specification, and this page indexes all of them. The
            documents are the contract: you can build a compatible implementation from them alone, without reading the
            Rust source. Each entry links to the full text under <code className='font-mono text-sm'>docs/specs/</code>{' '}
            in the repository.
          </p>
        </header>
        <SpecIndex />
        <Link
          to='/'
          className='-mx-2 inline-block px-2 py-2 text-sm underline underline-offset-4 transition-opacity duration-300 hover:opacity-70'
        >
          ← back
        </Link>
      </div>
    </WithToc>
  )
}

export const getConfig = async () => {
  return {
    render: 'static',
  } as const
}
