import { Link } from 'waku'
import { HashDemo } from '../components/hash-demo'
import { DemoBoundary } from '../components/demo-boundary'

export default function HashPage() {
  return (
    <div className='space-y-8'>
      <title>mkit — hash</title>
      <header className='space-y-3'>
        <h1 className='text-4xl font-semibold tracking-tight'>What&rsquo;s in a hash?</h1>
        <p className='max-w-prose text-base text-[--color-fg]'>
          Every file, every folder, every commit is named by a BLAKE3 hash of its bytes — change a single character and
          the hash changes too. This page builds a tiny commit out of two files and shows every hash along the way.
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
