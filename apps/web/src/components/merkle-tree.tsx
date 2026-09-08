import { hashColor } from '../lib/hash-color'
import { sectionAnchor } from './result-panel'

export type MerkleNode = {
  hash: string
  label: string
  children?: MerkleNode[]
}

/** Each node shows its hash and label. Select a node to view its details. */
export function MerkleTree({ root }: { root: MerkleNode }) {
  return (
    <div className='overflow-x-auto py-4'>
      <ul className='merkle' aria-label='Merkle tree'>
        <Item node={root} />
      </ul>
    </div>
  )
}

function Item({ node }: { node: MerkleNode }) {
  const handleClick = () => {
    const el = document.getElementById(sectionAnchor(node.hash))
    if (!el) return
    const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches
    el.scrollIntoView({ behavior: reducedMotion ? 'instant' : 'smooth', block: 'start' })
  }
  return (
    <li>
      <button
        type='button'
        onClick={handleClick}
        title={`Jump to ${node.label} · ${node.hash.slice(0, 12)}…`}
        aria-label={`Jump to ${node.label}`}
        className='merkle__node group bg-transparent p-0'
      >
        <span className='inline-flex flex-col items-center gap-1'>
          <span
            aria-hidden
            className='inline-block'
            style={{
              width: 'var(--size-frame-header)',
              height: 'var(--size-frame-header)',
              background: hashColor(node.hash),
            }}
          />
          <code className='font-mono text-xs text-muted'>{node.hash.slice(0, 6)}</code>
          <span className='max-w-[8rem] truncate text-xs text-fg'>{node.label}</span>
        </span>
      </button>
      {node.children?.length ? (
        <ul>
          {node.children.map((c) => (
            <Item key={`${c.label}-${c.hash}`} node={c} />
          ))}
        </ul>
      ) : null}
    </li>
  )
}
