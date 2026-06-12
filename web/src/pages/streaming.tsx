import { Link } from 'waku'
import { DemoBoundary } from '../components/demo-boundary'
import { StreamingDemo } from '../components/streaming-demo'

export default function StreamingPage() {
  return (
    <div className='space-y-8'>
      <title>mkit — streaming</title>
      <header className='space-y-3 pt-4'>
        <p className='microlabel text-accent'>Demo Nº 04 — streaming</p>
        <h1 className='text-5xl font-light'>Verifiable at gigabyte scale</h1>
        <p className='max-w-prose text-base text-fg'>
          Content addressing only works on big files if you can chunk, diff, and stream-verify them — git stores a fresh
          copy of a large binary on every edit. mkit cuts files at content-defined boundaries (FastCDC), records the
          chunk list in a ChunkedBlob, ships only the changed chunks as a delta, and verifies each chunk against the
          root hash as it arrives (Bao). Drop a file — or let the auto-editor run — and watch all four below.
        </p>
      </header>
      <DemoBoundary>
        <StreamingDemo />
      </DemoBoundary>
      <Link
        to='/'
        className='microlabel -mx-2 inline-block px-2 py-2 text-muted transition-colors duration-200 hover:text-fg'
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
