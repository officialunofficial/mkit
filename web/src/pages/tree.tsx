import { Link } from 'waku'
import { DemoBoundary } from '../components/demo-boundary'
import { TreeDemo } from '../components/tree-demo'

export default function TreePage() {
  return (
    <div className='space-y-8'>
      <title>mkit — tree</title>
      <header className='space-y-3 pt-4'>
        <p className='microlabel text-accent'>Demo Nº 03 — tree</p>
        <h1 className='text-5xl font-light'>Folders, all the way down</h1>
        <p className='max-w-prose text-base text-fg'>
          A folder is a list of files and other folders, each entry named by a BLAKE3 hash; a parent's hash is computed
          from its children's. That makes the repo a Merkle tree — a structure where one root hash fingerprints
          everything below it. git is built the same way; mkit just makes it visible: edit any file and watch every hash
          above it rewrite — file → folder → parent folder → commit.
        </p>
      </header>
      <DemoBoundary>
        <TreeDemo />
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
