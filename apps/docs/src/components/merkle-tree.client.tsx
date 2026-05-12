'use client'

import { hashColor } from '../lib/hash-color'
import { sectionAnchor } from './result-panel.client'

export type MerkleNode = {
  hash: string
  label: string
  children?: MerkleNode[]
}

/**
 * Top-down Merkle visualisation: each node is a hash-coloured square plus the first 6 hex chars of its BLAKE3, with its
 * label below. Edges use the classic CSS ::before/::after elbow pattern from `.merkle` (see `styles.css`). The coloured
 * squares are the dominant signal — edit a leaf and the colours roll up the spine. Click any node to scroll to the
 * matching section below.
 */
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
    el.scrollIntoView({ behavior: 'smooth', block: 'start' })
    // Quick flash so the user sees where they landed; runs on the section's
    // background only, no permanent style change.
    el.animate([{ backgroundColor: 'rgba(0,0,0,0.06)' }, { backgroundColor: 'transparent' }], {
      duration: 900,
      easing: 'ease-out',
    })
  }
  return (
    <li>
      <button
        type='button'
        onClick={handleClick}
        title={`Jump to ${node.label} · ${node.hash.slice(0, 12)}…`}
        aria-label={`Jump to ${node.label}`}
        className='merkle__node group bg-transparent p-0 outline-none focus-visible:ring-1 focus-visible:ring-[--color-fg] focus-visible:ring-offset-2 focus-visible:ring-offset-[--color-bg]'
      >
        {/* Inner wrapper carries the hover/active scale so the button's
            ::before connector line (positioned against the LI) stays at
            its drawn size and doesn't get stretched by the transform. */}
        <span className='inline-flex flex-col items-center gap-1 transition-transform duration-150 group-hover:scale-[1.08] group-active:scale-[0.96]'>
          <span
            aria-hidden
            className='inline-block'
            style={{ width: 22, height: 22, background: hashColor(node.hash) }}
          />
          <code className='font-mono text-[10px] leading-none text-[--color-muted]'>{node.hash.slice(0, 6)}</code>
          <span className='max-w-[8rem] truncate text-[11px] leading-none text-[--color-fg]'>{node.label}</span>
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
