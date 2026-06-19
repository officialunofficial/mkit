import { Link } from 'waku'
import { DemoBoundary } from '../components/demo-boundary'
import { StreamingDemo } from '../components/streaming-demo'
import { Seo } from '../components/seo'

export default function StreamingPage() {
  return (
    <div className='space-y-8'>
      <Seo
        title='mkit — streaming'
        description='mkit cuts files at content-defined boundaries (FastCDC) and ships only the changed chunks, each verifiable against the root as it lands — at gigabyte scale.'
        path='/streaming'
        card='Verifiable at gigabyte scale'
      />
      <header className='space-y-3'>
        <h1 className='text-4xl font-semibold tracking-tight'>Verifiable at gigabyte scale</h1>
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
