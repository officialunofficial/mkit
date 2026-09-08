import { Seo } from '../components/seo'
import { SpecIndex } from '../components/spec-index'
import { WithToc } from '../components/with-toc'

export default function SpecsPage() {
  return (
    <WithToc>
      <div className='space-y-8'>
        <Seo
          title='mkit — specs'
          description='Specifications for mkit object formats, packfiles, transport protocols, signatures, and attestations. Each document states its status.'
          path='/specs'
          card='Format and protocol specifications'
        />
        <header>
          <h1 className='ds-h1'>Format and protocol specifications</h1>
          <p className='ds-note mt-1'>Object formats, repository state, and communication protocols.</p>
          <p className='mt-2 max-w-prose'>
            Use these documents to understand format and protocol requirements. Check each document’s status and
            implementation notes before relying on it. Each entry links to the full text under <code>docs/specs/</code>{' '}
            in the repository.
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
