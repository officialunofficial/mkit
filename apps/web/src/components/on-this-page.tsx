'use client'

import { useEffect, useState } from 'react'

// "On this page" table of contents. Scans the rendered <main> for its
// section headers (<h2>), gives each a stable anchor id, and tracks which
// one is in view so the matching entry highlights as you scroll. It's
// progressive enhancement: the static HTML ships without it and it
// populates after hydration. Renders nothing on pages with fewer than two
// sections (the demos), so it never shows an empty rail.

type Item = { id: string; text: string }

/** Slug from heading text: lowercase, drop punctuation, dash the spaces. */
function slugify(text: string): string {
  return text
    .toLowerCase()
    .trim()
    .replace(/[^\w\s-]/g, '')
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-')
}

export function OnThisPage() {
  const [items, setItems] = useState<Item[]>([])
  const [activeId, setActiveId] = useState('')

  useEffect(() => {
    const main = document.querySelector('main')
    if (!main) return

    let io: IntersectionObserver | null = null

    const scan = () => {
      const headings = Array.from(main.querySelectorAll('h2')) as HTMLHeadingElement[]
      const found: Item[] = []
      for (const h of headings) {
        const text = (h.textContent ?? '').trim()
        if (!text) continue
        // Anchor target for the TOC links. The scroll offset that keeps the
        // sticky header from covering it is a CSS rule on headings, not an
        // inline style mutated here (see styles.css h1,h2,h3).
        if (!h.id) h.id = slugify(text)
        found.push({ id: h.id, text })
      }
      setItems(found)
      setActiveId('')

      io?.disconnect()
      io = null
      if (found.length < 2) return

      // Highlight the section nearest the top of the viewport. The bottom
      // margin biases "active" toward whatever just crossed the top edge.
      io = new IntersectionObserver(
        (entries) => {
          for (const entry of entries) {
            if (entry.isIntersecting) setActiveId((entry.target as HTMLElement).id)
          }
        },
        { rootMargin: '-80px 0px -65% 0px' },
      )
      for (const h of headings) {
        if (h.id) io.observe(h)
      }
    }

    scan()

    // Client-side navigation swaps <main>'s content without remounting this
    // component, so the headings change underneath us. Re-scan when they do;
    // rAF coalesces the burst of mutations a route change produces into one
    // scan. (Doc pages are static, so this only fires on navigation.)
    let raf = 0
    const mo = new MutationObserver(() => {
      cancelAnimationFrame(raf)
      raf = requestAnimationFrame(scan)
    })
    mo.observe(main, { childList: true, subtree: true })

    return () => {
      mo.disconnect()
      io?.disconnect()
      cancelAnimationFrame(raf)
    }
  }, [])

  if (items.length < 2) return null

  return (
    <nav aria-label='On this page' className='text-xs leading-4'>
      <p className='mb-2 font-medium text-primary'>On This Page</p>
      <ul className='border-l' style={{ borderColor: 'var(--border-color-subtle)' }}>
        {items.map((item) => {
          const active = activeId === item.id
          return (
            <li key={item.id}>
              <a
                href={`#${item.id}`}
                aria-current={active ? 'location' : undefined}
                className={`-ml-px block border-l py-1.5 pl-3 transition-colors duration-(--duration-fast) ease-standard ${
                  active
                    ? 'border-(--border-color-selected) font-medium text-primary'
                    : 'border-transparent text-secondary hover:text-primary'
                }`}
              >
                {item.text}
              </a>
            </li>
          )
        })}
      </ul>
    </nav>
  )
}
