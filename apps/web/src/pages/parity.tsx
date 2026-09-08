import { ParityLegend, ParityMatrix } from '../components/parity-matrix'
import { Seo } from '../components/seo'
import { WithToc } from '../components/with-toc'

export default function ParityPage() {
  return (
    <WithToc>
      <div className='space-y-8'>
        <Seo
          title='mkit — parity'
          description='Compare mkit and Git commands, flags, and behavior. mkit uses its own object format and transport protocol.'
          path='/parity'
          card='Git command compatibility'
        />
        <header>
          <h1 className='ds-h1'>Git command compatibility</h1>
          <p className='ds-note mt-1'>Supported commands, differences, and unsupported features.</p>
          {/* §2.7: the intro takes 4 of the root layout's 6 columns, the
              status legend the other 2, stacked vertically beside it. */}
          <div className='mt-2 grid grid-cols-1 gap-3 sm:grid-cols-6'>
            <p className='sm:col-span-4'>
              mkit supports many Git commands and flags, with the differences listed below. It uses BLAKE3 object IDs
              and signs every commit. Its storage format and transport protocol are incompatible with <code>.git</code>{' '}
              repositories.
            </p>
            <div className='sm:col-span-2'>
              <ParityLegend />
            </div>
          </div>
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
