import { Link } from 'waku'
import { DemoBoundary } from '../components/demo-boundary'
import { StreamingDemo } from '../components/streaming-demo'

export default function StreamingPage() {
  return (
    <div className='space-y-8'>
      <title>mkit — streaming</title>
      <header className='space-y-3'>
        <h1 className='text-4xl font-semibold tracking-tight'>Verifiable at gigabyte scale</h1>
        <p className='max-w-prose text-base text-[--color-fg]'>
          Content-addressed storage only works on big files if you can chunk, diff, and stream-verify them. Drop a file
          (or use the default) and watch four streaming primitives: FastCDC chunking, ChunkedBlob, the delta wire
          format, and Bao verified slices.
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
