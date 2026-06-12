import { Link } from 'waku'
import { PerfSection } from '../components/perf-section'

export default function PerformancePage() {
  return (
    <div className='space-y-8'>
      <title>mkit — performance</title>
      <header className='space-y-3 pt-4'>
        <p className='microlabel text-[--color-accent]'>Demo Nº 05 — performance</p>
        <h1 className='text-5xl font-light'>Measured against git</h1>
        <p className='max-w-prose text-base text-[--color-fg]'>
          mkit names every object by a BLAKE3 hash and splits large files into content-defined chunks, so changing one
          megabyte of a video means storing one megabyte — git hashes with SHA-1 and stores each version of a file whole
          until a repack. That trade cuts both ways, and the numbers below show both edges: real{' '}
          <code className='font-mono text-sm'>hyperfine</code> runs of the two CLIs on one machine, git wins included.
        </p>
      </header>
      <PerfSection />
      <Link
        to='/'
        className='microlabel -mx-2 inline-block px-2 py-2 text-[--color-muted] transition-colors duration-200 hover:text-[--color-fg]'
      >
        ← Index
      </Link>
    </div>
  )
}

export const getConfig = async () => {
  return {
    render: 'static',
  } as const
}
