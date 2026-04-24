import { Link } from 'waku'
import { DemoBoundary } from '../components/demo-boundary'
import { TreeDemo } from '../components/tree-demo'

export default function TreePage() {
  return (
    <div className='space-y-8'>
      <title>mkit — tree</title>
      <header className='space-y-3'>
        <h1 className='text-4xl font-semibold tracking-tight'>Nested trees</h1>
        <p className='max-w-prose text-base text-[--color-fg]'>
          A tree is a lex-sorted list of <code className='font-mono text-sm'>(name, mode, hash)</code> entries — each
          hash pointing to a blob or another tree. Because entries address their children by BLAKE3 id, nesting composes
          naturally: a tree containing a tree is just another row whose <code className='font-mono text-sm'>mode</code>{' '}
          is <code className='font-mono text-sm'>tree</code>.
        </p>
      </header>
      <DemoBoundary>
        <TreeDemo />
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
