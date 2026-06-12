'use client'

import { useEffect, useMemo, useRef, useState } from 'react'
import { MerkleTree, type MerkleNode } from './merkle-tree'
import { HashChip, INPUT_CLASSES, ObjectRow, Section } from './result-panel'
import { DEMO_SEED, previewBytes, sanitizeTreeName, TEXT_ENCODER, useMkit } from './use-mkit'

type BlobNode = { kind: 'blob'; name: string; content: string }
type TreeNode = { kind: 'tree'; name: string; children: TreeNode2[] }
type TreeNode2 = BlobNode | TreeNode

// Default mirrors the shape of a small Rust project someone would
// expect to see after `mkit init && mkit add .`: a manifest at the
// root, source under `src/`, a README, a licence, a changelog, tests,
// and docs. Every blob has plausible content so the hash demo doesn't
// feel synthetic. Names are ASCII-safe; the order doesn't matter since
// `tree_encode` lex-sorts on the wasm side.
const DEFAULT_TREE: TreeNode = {
  kind: 'tree',
  name: '',
  children: [
    {
      kind: 'blob',
      name: 'README.md',
      content:
        '# mkit-demo\n\nA tiny Rust project under mkit version control.\n\n## Build\n\n```\ncargo build --release\n```\n',
    },
    {
      kind: 'blob',
      name: 'CHANGELOG.md',
      content: '# Changelog\n\n## 0.1.0 — initial commit\n\n- add `greet` helper\n- wire up CLI entrypoint\n',
    },
    {
      kind: 'blob',
      name: 'LICENSE',
      content: 'MIT License\n\nCopyright (c) 2026 mkit contributors\n',
    },
    {
      kind: 'blob',
      name: 'Cargo.toml',
      content: '[package]\nname = "mkit-demo"\nversion = "0.1.0"\nedition = "2024"\n\n[dependencies]\nanyhow = "1"\n',
    },
    {
      kind: 'blob',
      name: '.gitignore',
      content: '/target\n/Cargo.lock\n.DS_Store\n',
    },
    {
      kind: 'tree',
      name: 'src',
      children: [
        {
          kind: 'blob',
          name: 'main.rs',
          content: 'use mkit_demo::greet;\n\nfn main() {\n    println!("{}", greet("world"));\n}\n',
        },
        {
          kind: 'blob',
          name: 'lib.rs',
          content: 'pub fn greet(name: &str) -> String {\n    format!("hello, {name}")\n}\n',
        },
      ],
    },
    {
      kind: 'tree',
      name: 'tests',
      children: [
        {
          kind: 'blob',
          name: 'basic.rs',
          content:
            'use mkit_demo::greet;\n\n#[test]\nfn greets_world() {\n    assert_eq!(greet("world"), "hello, world");\n}\n',
        },
      ],
    },
    {
      kind: 'tree',
      name: 'docs',
      children: [
        {
          kind: 'blob',
          name: 'overview.md',
          content:
            '# Overview\n\nThis project demonstrates a committed mkit tree. The root is signed with an Ed25519 key; every object below is addressed by its BLAKE3.\n',
        },
      ],
    },
  ],
}

type EncodedBlob = { kind: 'blob'; path: string; hash: string; preview: string; byteCount: number }
type EncodedTree = { kind: 'tree'; path: string; hash: string; preview: string }

type Encoded = {
  root: EncodedTree
  subtrees: EncodedTree[]
  blobs: EncodedBlob[]
}

export function TreeDemo() {
  const api = useMkit()
  const [tree, setTree] = useState<TreeNode>(DEFAULT_TREE)
  const [commitMessage, setCommitMessage] = useState('first commit')
  const [selectedPath, setSelectedPath] = useState('README.md')
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set(['', 'src', 'tests', 'docs']))
  // Roving tabindex: exactly one treeitem carries `tabIndex=0`. Arrow-key nav updates it; click also updates so
  // keyboard focus follows pointer.
  const [focusedPath, setFocusedPath] = useState<string>('README.md')
  const treeRef = useRef<HTMLUListElement>(null)

  // Split: blob/tree encoding only depends on the tree shape. Commit signing hangs off the root hash + message.
  // Typing in the commit-message input now skips re-encoding every blob.
  const encoded = useMemo<Encoded | { error: string }>(() => {
    try {
      const blobs: EncodedBlob[] = []
      const subtrees: EncodedTree[] = []
      const walk = (node: TreeNode2, path: string): EncodedBlob | EncodedTree => {
        if (node.kind === 'blob') {
          const bytes = TEXT_ENCODER.encode(node.content)
          const enc = api.blob_encode(bytes)
          const out: EncodedBlob = {
            kind: 'blob',
            path,
            hash: enc.hash_hex,
            preview: previewBytes(enc.bytes),
            byteCount: bytes.byteLength,
          }
          blobs.push(out)
          return out
        }
        const childEntries = node.children
          .map((child) => {
            const childPath = path === '' ? child.name : `${path}/${child.name}`
            const childEnc = walk(child, childPath)
            return [sanitizeTreeName(child.name), childEnc.kind, childEnc.hash] as const
          })
          .toSorted((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
        const enc = api.tree_encode(JSON.stringify(childEntries))
        const out: EncodedTree = { kind: 'tree', path, hash: enc.hash_hex, preview: previewBytes(enc.bytes) }
        if (path !== '') subtrees.push(out)
        return out
      }
      const rootEncoded = walk(tree, '')
      if (rootEncoded.kind !== 'tree') throw new Error('root must be a tree')
      return {
        root: rootEncoded,
        subtrees: subtrees.toSorted((a, b) => (a.path < b.path ? -1 : 1)),
        blobs: blobs.toSorted((a, b) => (a.path < b.path ? -1 : 1)),
      }
    } catch (e) {
      return { error: e instanceof Error ? e.message : String(e) }
    }
  }, [api, tree])

  const commit = useMemo(() => {
    if ('error' in encoded) return null
    const c = api.commit_encode_and_sign(encoded.root.hash, '', commitMessage, 0n, DEMO_SEED)
    return { hash: c.hash_hex, verified: api.commit_verify(c.bytes) }
  }, [api, encoded, commitMessage])

  const rows = useMemo(() => flattenForNav(tree, expanded), [tree, expanded])

  // path → hash lookup for the nav chips. Root folder lives at '' so empty
  // paths stay coherent if anything ever needs it.
  const hashByPath = useMemo(() => {
    const m = new Map<string, string>()
    if ('error' in encoded) return m
    m.set(encoded.root.path, encoded.root.hash)
    for (const t of encoded.subtrees) m.set(t.path, t.hash)
    for (const b of encoded.blobs) m.set(b.path, b.hash)
    return m
  }, [encoded])

  // commit → root → … : a literal Merkle tree where every node carries
  // the hash of the bytes below it. We mirror the user's folder shape so
  // the visualisation matches the navigator on the left.
  const merkle = useMemo<MerkleNode | null>(() => {
    if ('error' in encoded || !commit) return null
    const build = (node: TreeNode2, path: string): MerkleNode => {
      const hash = hashByPath.get(path) ?? ''
      const label = node.kind === 'tree' ? (path === '' ? '/' : `${node.name}/`) : node.name
      if (node.kind !== 'tree') return { hash, label }
      const children = node.children
        .toSorted((a, b) => (a.name < b.name ? -1 : 1))
        .map((c) => build(c, path === '' ? c.name : `${path}/${c.name}`))
      return { hash, label, children }
    }
    return {
      hash: commit.hash,
      label: 'commit',
      children: [build(tree, '')],
    }
  }, [encoded, commit, hashByPath, tree])

  // Imperatively focus the DOM node for `focusedPath` whenever it
  // changes — the roving tabindex is driven by state. MUST stay above
  // any early return so the hook order is stable across loading →
  // ready → error transitions (Rules of Hooks).
  useEffect(() => {
    const el = treeRef.current?.querySelector<HTMLElement>(`[data-path="${CSS.escape(focusedPath)}"]`)
    if (el && document.activeElement?.closest('[role="tree"]') === treeRef.current) el.focus()
  }, [focusedPath])

  const selectedBlob = findBlob(tree, selectedPath)

  const toggleExpand = (path: string) => {
    setExpanded((prev) => {
      const next = new Set(prev)
      if (next.has(path)) next.delete(path)
      else next.add(path)
      return next
    })
  }

  const onContentChange = (value: string) => {
    if (!selectedBlob) return
    setTree((prev) => updateBlobAt(prev, selectedPath, value))
  }

  const focusedIndex = Math.max(
    0,
    rows.findIndex((r) => r.path === focusedPath),
  )

  const onTreeKeyDown = (e: React.KeyboardEvent<HTMLUListElement>) => {
    if (rows.length === 0) return
    const row = rows[focusedIndex]
    if (!row) return
    const move = (next: number) => {
      e.preventDefault()
      const clamped = Math.max(0, Math.min(rows.length - 1, next))
      setFocusedPath(rows[clamped]?.path ?? focusedPath)
    }
    switch (e.key) {
      case 'ArrowDown':
        return move(focusedIndex + 1)
      case 'ArrowUp':
        return move(focusedIndex - 1)
      case 'Home':
        return move(0)
      case 'End':
        return move(rows.length - 1)
      case 'ArrowRight': {
        e.preventDefault()
        if (row.node.kind !== 'tree') return
        if (!expanded.has(row.path)) {
          setExpanded((prev) => new Set(prev).add(row.path))
        } else {
          // Already open: focus first child.
          const next = rows[focusedIndex + 1]
          if (next && next.depth > row.depth) setFocusedPath(next.path)
        }
        return
      }
      case 'ArrowLeft': {
        e.preventDefault()
        if (row.node.kind === 'tree' && expanded.has(row.path)) {
          setExpanded((prev) => {
            const s = new Set(prev)
            s.delete(row.path)
            return s
          })
        } else {
          // Closed or leaf: focus parent.
          const parent = row.path.includes('/') ? row.path.slice(0, row.path.lastIndexOf('/')) : ''
          if (parent === '') return // at top level, nowhere to go
          const parentIdx = rows.findIndex((r) => r.path === parent)
          if (parentIdx >= 0) setFocusedPath(parent)
        }
        return
      }
      case 'Enter':
      case ' ': {
        e.preventDefault()
        if (row.node.kind === 'tree') toggleExpand(row.path)
        else setSelectedPath(row.path)
        return
      }
    }
  }

  return (
    // Mobile-first ordering: outputs above controls. See `hash-demo.tsx` for the same flex-col-reverse → lg:grid
    // pattern.
    <div className='flex flex-col-reverse gap-10 lg:grid lg:grid-cols-[minmax(0,20rem)_1fr] lg:gap-12'>
      <div className='space-y-6 lg:sticky lg:top-24 lg:self-start'>
        <label className='block'>
          <span className='mb-2 block text-sm text-muted'>Commit message</span>
          <input className={INPUT_CLASSES} value={commitMessage} onChange={(e) => setCommitMessage(e.target.value)} />
        </label>

        <div className='block'>
          <span className='mb-2 block text-sm text-muted'>Files</span>
          {/* role=tree + roving tabindex + full APG keyboard map. Each
              row is a treeitem with aria-expanded for folders, aria-
              selected for the current blob, aria-level for depth. */}
          <ul
            ref={treeRef}
            role='tree'
            aria-label='File tree'
            className='select-none border-y border-dashed border-hairline py-2 outline-none'
            onKeyDown={onTreeKeyDown}
          >
            {rows.map((row) => {
              const isSelected = row.node.kind === 'blob' && row.path === selectedPath
              const isFocused = row.path === focusedPath
              const isExpanded = row.node.kind === 'tree' && expanded.has(row.path)
              return (
                <li
                  key={row.path || '/'}
                  role='treeitem'
                  aria-level={row.depth + 1}
                  aria-selected={isSelected || undefined}
                  aria-expanded={row.node.kind === 'tree' ? isExpanded : undefined}
                  tabIndex={isFocused ? 0 : -1}
                  data-path={row.path}
                  onClick={() => {
                    setFocusedPath(row.path)
                    if (row.node.kind === 'tree') toggleExpand(row.path)
                    else setSelectedPath(row.path)
                  }}
                  className={`group flex h-7 cursor-pointer items-center text-sm outline-none transition-colors hover:bg-hairline/60 focus-visible:ring-1 focus-visible:ring-fg ${
                    isSelected ? 'bg-hairline font-medium text-fg' : 'text-muted hover:text-fg'
                  }`}
                >
                  {/* One vertical guide per ancestor depth. Each 16px
                      spacer hosts a 1px line at its centre (x=8) — that
                      centre aligns with the parent row's chevron/icon
                      column one level up, so the line visibly runs
                      underneath the folder it came from. Uniform row
                      heights stack the segments into one continuous
                      rule. */}
                  {Array.from({ length: row.depth }).map((_, i) => (
                    <span key={i} aria-hidden className='relative h-full w-4 shrink-0'>
                      <span className='absolute top-0 bottom-0 left-2 w-px bg-hairline' />
                    </span>
                  ))}
                  {/* Disclosure chevron — always present so folder/file
                      rows line up; invisible on leaves. Rotates 90° on
                      expand per the VS Code pattern. */}
                  <span aria-hidden className='flex size-4 shrink-0 items-center justify-center text-subtle'>
                    {row.node.kind === 'tree' ? (
                      <ChevronIcon className={`transition-transform duration-150 ${isExpanded ? 'rotate-90' : ''}`} />
                    ) : null}
                  </span>
                  <span aria-hidden className='mx-1.5 flex size-4 shrink-0 items-center text-subtle'>
                    {row.node.kind !== 'tree' ? <FileIcon /> : isExpanded ? <FolderOpenIcon /> : <FolderIcon />}
                  </span>
                  {hashByPath.has(row.path) ? (
                    <span className='mr-1.5 flex shrink-0 items-center'>
                      <HashChip hash={hashByPath.get(row.path)!} size={10} />
                    </span>
                  ) : null}
                  <span className='truncate'>{row.node.name}</span>
                </li>
              )
            })}
          </ul>
        </div>

        {selectedBlob ? (
          <label className='block'>
            <span className='mb-2 block text-sm text-muted'>Editing {selectedPath}</span>
            <textarea
              className={INPUT_CLASSES}
              rows={6}
              value={selectedBlob.content}
              onChange={(e) => onContentChange(e.target.value)}
            />
          </label>
        ) : null}
      </div>

      <div>
        {'error' in encoded ? (
          <p className='mb-4 text-red-600'>wasm encode failed: {encoded.error}</p>
        ) : (
          <div className='divide-y-2 divide-hairline border-y-2 border-hairline'>
            {merkle ? (
              <Section title='Merkle tree' description='Each square is the BLAKE3 of everything beneath it.'>
                <MerkleTree root={merkle} />
              </Section>
            ) : null}
            <Section title='Objects' description='Every commit, folder, and file under this commit.'>
              <div className='divide-y divide-hairline'>
                {commit ? (
                  <ObjectRow
                    hash={commit.hash}
                    label='commit'
                    meta='signed'
                    trailing={
                      <span className={`text-xs ${commit.verified ? 'text-green-700' : 'text-red-600'}`}>
                        {commit.verified ? 'verified ✓' : 'invalid ✗'}
                      </span>
                    }
                  />
                ) : null}
                <ObjectRow hash={encoded.root.hash} label='/' meta='root folder' />
                {encoded.subtrees.map((t) => (
                  <ObjectRow key={t.path} hash={t.hash} label={`${t.path}/`} meta='folder' />
                ))}
                {encoded.blobs.map((b) => (
                  <ObjectRow key={b.path} hash={b.hash} label={b.path} meta={`${b.byteCount} B`} />
                ))}
              </div>
            </Section>
          </div>
        )}
      </div>
    </div>
  )
}

function findBlob(tree: TreeNode, path: string): BlobNode | null {
  if (path === '') return null
  const segments = path.split('/')
  let current: TreeNode2 = tree
  for (const seg of segments) {
    if (current.kind !== 'tree') return null
    const next: TreeNode2 | undefined = current.children.find((c) => c.name === seg)
    if (!next) return null
    current = next
  }
  return current.kind === 'blob' ? current : null
}

type NavRow = { path: string; depth: number; node: TreeNode2 }

function flattenForNav(tree: TreeNode, expanded: Set<string>): NavRow[] {
  const rows: NavRow[] = []
  const walk = (node: TreeNode2, path: string, depth: number) => {
    if (depth > 0) rows.push({ path, depth: depth - 1, node })
    if (node.kind === 'tree') {
      const childrenVisible = depth === 0 || expanded.has(path)
      if (!childrenVisible) return
      for (const child of node.children.toSorted((a, b) => (a.name < b.name ? -1 : 1))) {
        walk(child, path === '' ? child.name : `${path}/${child.name}`, depth + 1)
      }
    }
  }
  walk(tree, '', 0)
  return rows
}

// React state is immutable, so editing a single leaf means rebuilding every ancestor on the way down. We copy the
// spine (the nodes along `path`) and share the untouched siblings by reference — cheap and keeps `useMemo` deps
// honest, since unchanged subtrees keep their identity.
function updateBlobAt(tree: TreeNode, path: string, newContent: string): TreeNode {
  const segments = path.split('/')
  const walk = (node: TreeNode2, depth: number): TreeNode2 => {
    if (depth === segments.length) {
      if (node.kind !== 'blob') return node
      return { ...node, content: newContent }
    }
    if (node.kind !== 'tree') return node
    const targetName = segments[depth]
    return {
      ...node,
      children: node.children.map((c) => (c.name === targetName ? walk(c, depth + 1) : c)),
    }
  }
  const result = walk(tree, 0)
  return result.kind === 'tree' ? result : tree
}

/**
 * Right-pointing chevron; rotated 90deg via Tailwind className when a folder is open. Kept separate from the folder
 * glyph (VS Code pattern) so disclosure state and node type read as two independent affordances.
 */
function ChevronIcon({ className = '' }: { className?: string }) {
  return (
    <svg
      viewBox='0 0 16 16'
      fill='none'
      stroke='currentColor'
      strokeWidth='1.5'
      strokeLinecap='round'
      strokeLinejoin='round'
      className={`size-3 ${className}`}
    >
      <path d='M6 4 L10 8 L6 12' />
    </svg>
  )
}

// Thin-stroke folder + file glyphs. Rendered at 16px, inherit currentColor via `stroke='currentColor'` so parent
// muted/fg classes control the shade without per-icon styling.
function FolderIcon() {
  return (
    <svg
      viewBox='0 0 16 16'
      fill='none'
      stroke='currentColor'
      strokeWidth='1'
      strokeLinejoin='round'
      className='size-4'
    >
      <path d='M1.5 4 H6 L7.25 5.25 H14.5 V13 H1.5 Z' />
    </svg>
  )
}

function FolderOpenIcon() {
  return (
    <svg
      viewBox='0 0 16 16'
      fill='none'
      stroke='currentColor'
      strokeWidth='1'
      strokeLinejoin='round'
      className='size-4'
    >
      <path d='M1.5 4 H6 L7.25 5.25 H14.5 V6.5 H1.5 Z' />
      <path d='M1.5 6.5 H14.5 L13 13 H3 Z' />
    </svg>
  )
}

function FileIcon() {
  return (
    <svg
      viewBox='0 0 16 16'
      fill='none'
      stroke='currentColor'
      strokeWidth='1'
      strokeLinejoin='round'
      className='size-4'
    >
      <path d='M4 2 H10 L12.5 4.5 V14 H4 Z' />
      <path d='M10 2 V4.5 H12.5' />
    </svg>
  )
}
