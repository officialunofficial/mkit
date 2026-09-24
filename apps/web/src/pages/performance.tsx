import { PerfSection } from '../components/perf-section'
import { Seo } from '../components/seo'
import { WithToc } from '../components/with-toc'

export default function PerformancePage() {
  return (
    <WithToc>
      <div className='space-y-8'>
        <Seo
          title='mkit — performance'
          description='Benchmarks comparing mkit and Git: command duration, storage size, and push transfer size for large files and everyday operations.'
          path='/performance'
          card='Performance compared with Git'
        />
        <header>
          <h1 className='ds-h1'>Performance compared with Git</h1>
          <p className='ds-note mt-1'>
            Command durations, storage sizes, and transfer sizes measured on one machine with <code>hyperfine</code> and
            the repository benchmark scripts.
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
