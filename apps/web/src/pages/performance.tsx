import { PerfSection } from '../components/perf-section'
import { Seo } from '../components/seo'
import { WithToc } from '../components/with-toc'

export default function PerformancePage() {
  return (
    <WithToc>
      <div className='space-y-8'>
        <Seo
          title='mkit — performance'
          description='mkit names every object by a BLAKE3 hash and splits large files into content-defined chunks, with benchmarks comparing mkit and Git.'
          path='/performance'
          card='Performance compared with Git'
        />
        <header>
          <h1 className='ds-h1'>Performance compared with Git</h1>
          <p className='ds-note mt-1'>
            Command timings, storage use, and transfer sizes measured on one machine with <code>hyperfine</code> and the
            repository benchmark scripts.
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
