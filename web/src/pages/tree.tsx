import { Link } from 'waku'
import { DemoBoundary } from '../components/demo-boundary'
import { TreeDemo } from '../components/tree-demo'

export default function TreePage() {
  return (
    <div className='space-y-8'>
      <title>mkit — tree</title>
      <header className='space-y-3'>
        <h1 className='text-4xl font-semibold tracking-tight'>Folders, all the way down</h1>
        <p className='max-w-prose text-base text-[--color-fg]'>
          A folder is a list of files and other folders, each named by a BLAKE3 hash. A parent's hash is computed from
          its children's hashes, so the structure is a Merkle tree: edit any file and every hash above it rewrites —
          file → folder → parent folder → commit. The root hash is a fingerprint of everything below.
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
