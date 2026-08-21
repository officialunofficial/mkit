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
        <header>
          <h1 className='ds-h1'>Specified Down to the Byte</h1>
          <p className='ds-note mt-1'>Every format mkit writes to disk or the wire has a specification.</p>
          <p className='mt-2 max-w-prose'>
            This page indexes all of them. The documents are the contract: you can build a compatible implementation
            from them alone, without reading the Rust source. Each entry links to the full text under{' '}
            <code>docs/specs/</code> in the repository.
          </p>
        </header>
        <SpecIndex />
      </div>
    </WithToc>
  )
}

export const getConfig = async () => {
  return {
    render: 'static',
  } as const
}
