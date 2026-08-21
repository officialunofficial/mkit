import { PerfSection } from '../components/perf-section'
import { Seo } from '../components/seo'
import { WithToc } from '../components/with-toc'

export default function PerformancePage() {
  return (
    <WithToc>
      <div className='space-y-8'>
        <Seo
          title='mkit — performance'
          description='mkit names every object by a BLAKE3 hash and splits large files into content-defined chunks, benchmarked head to head against git.'
          path='/performance'
          card='Measured against git'
        />
        <header>
          <h1 className='ds-h1'>Measured Against Git</h1>
          <p className='ds-note mt-1'>
            Real <code>hyperfine</code> runs of both CLIs on one machine — git&rsquo;s wins shown as plainly as
            mkit&rsquo;s.
          </p>
        </header>
        <PerfSection />
      </div>
    </WithToc>
  )
}

export const getConfig = async () => {
  return {
    render: 'static',
  } as const
}
