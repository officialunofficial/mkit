import { Link } from 'waku'
import { PerfSection } from '../components/perf-section'

export default function PerformancePage() {
  return (
    <div className='space-y-8'>
      <title>mkit — performance</title>
      <header className='space-y-3'>
        <h1 className='text-4xl font-semibold tracking-tight'>Measured against git</h1>
        <p className='max-w-prose text-base text-fg'>
          mkit names every object by a BLAKE3 hash and splits large files into content-defined chunks, so changing one
          megabyte of a video means storing one megabyte — git hashes with SHA-1 and stores each version of a file whole
          until a repack. That trade cuts both ways, and the numbers below show both edges: real{' '}
          <code className='font-mono text-sm'>hyperfine</code> runs of the two CLIs on one machine, git wins included.
          The same chunking pays off again over the network — a small edit to a large file now{' '}
          <em>pushes</em> as a chunk delta, not a whole chunk (see “Bytes on the wire”).
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
  )
}

export const getConfig = async () => {
  return {
    render: 'static',
  } as const
}
