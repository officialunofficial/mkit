import { Link } from 'waku'
import { DemoBoundary } from '../components/demo-boundary'
import { TreeDemo } from '../components/tree-demo'
import { Seo } from '../components/seo'

export default function TreePage() {
  return (
    <div className='space-y-8'>
      <Seo
        title='mkit — tree'
        description="A folder is a list of BLAKE3-named entries; a parent's hash is computed from its children's. The repo is a Merkle tree — edit a file and the hashes ripple to the root."
        path='/tree'
        card='Folders, all the way down'
      />
      <header className='space-y-3'>
        <h1 className='text-4xl font-semibold tracking-tight'>Folders, all the way down</h1>
        <p className='max-w-prose text-base text-fg'>
          A folder lists its entries by their BLAKE3 hashes, and each parent's hash is built from its children's — so the
          whole repo is one Merkle tree, fingerprinted by a single root hash. Edit any file and watch the change ripple
          up: file → folder → commit.
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
