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

    const headings = Array.from(main.querySelectorAll('h2')) as HTMLHeadingElement[]
    const found: Item[] = []
    for (const h of headings) {
      const text = (h.textContent ?? '').trim()
      if (!text) continue
      if (!h.id) h.id = slugify(text)
      // Keep the sticky header from covering the target on jump.
      h.style.scrollMarginTop = '5rem'
      found.push({ id: h.id, text })
    }
    setItems(found)
    if (found.length < 2) return

    // Highlight the section nearest the top of the viewport. The bottom
    // margin biases "active" toward whatever just crossed the top edge.
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) setActiveId((entry.target as HTMLElement).id)
        }
      },
      { rootMargin: '-80px 0px -65% 0px' },
    )
    for (const h of headings) {
      if (h.id) observer.observe(h)
    }
    return () => observer.disconnect()
  }, [])

  if (items.length < 2) return null

  return (
    <nav aria-label='On this page' className='text-sm'>
      <p className='mb-3 font-medium text-fg'>On this page</p>
      <ul className='border-l border-hairline'>
        {items.map((item) => {
          const active = activeId === item.id
          return (
            <li key={item.id}>
              <a
                href={`#${item.id}`}
                aria-current={active ? 'true' : undefined}
                className={`-ml-px block border-l py-1.5 pl-3 leading-snug transition-colors ${
                  active ? 'border-fg text-fg' : 'border-transparent text-muted hover:border-hairline hover:text-fg'
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
