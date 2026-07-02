import { Link } from 'waku'
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
        <header className='space-y-3'>
          <h1 className='text-4xl font-semibold tracking-tight'>Measured against git</h1>
          <p className='max-w-prose text-base text-fg'>
            The numbers below are real <code className='font-mono text-sm'>hyperfine</code> runs of both CLIs on one
            machine.
          </p>
        </header>
        <PerfSection />
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
