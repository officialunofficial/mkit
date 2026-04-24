import { Link } from 'waku'
import { HashDemo } from '../components/hash-demo'
import { DemoBoundary } from '../components/demo-boundary'

export default function HashPage() {
  return (
    <div className='space-y-8'>
      <title>mkit — hash</title>
      <header className='space-y-3'>
        <h1 className='text-4xl font-semibold tracking-tight'>Content-addressed objects</h1>
        <p className='max-w-prose text-base text-[--color-fg]'>
          Every object opens with <code className='font-mono text-sm'>type || "MKT1" || 0x01</code>. Its id is the
          BLAKE3 of its bytes. A tree composes heterogenous blobs — text, image, anything — into a single address. Edit
          either side below; the tree and commit rewrite with them.
        </p>
      </header>
      <DemoBoundary>
        <HashDemo />
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
