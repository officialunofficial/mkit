import { ParityMatrix } from '../components/parity-matrix'
import { Seo } from '../components/seo'
import { WithToc } from '../components/with-toc'

export default function ParityPage() {
  return (
    <WithToc>
      <div className='space-y-8'>
        <Seo
          title='mkit — parity'
          description='mkit aims for CLI parity with git — same commands and flags, plus BLAKE3 addressing and a signature on every commit — but it is parity of behavior, not wire interop with .git.'
          path='/parity'
          card='How much of git is here?'
        />
        <header>
          <h1 className='ds-h1'>How Much of Git Is Here?</h1>
          <p className='ds-note mt-1'>Parity of behavior, not wire interop — mkit never shares bytes with .git.</p>
          <p className='mt-2 max-w-prose'>
            mkit matches the git commands and flags you already know. It also adds BLAKE3 addressing, a signature on
            every commit, and guards against silent data loss. It never shares bytes with a <code>.git</code> repo, so
            this is parity of behavior, not wire interop.
          </p>
        </header>
        <ParityMatrix />
      </div>
    </WithToc>
  )
}

export const getConfig = async () => {
  return {
    render: 'static',
  } as const
}
