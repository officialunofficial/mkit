'use client'

import { useEffect, useState } from 'react'
import { mulberry32, renderGridSvg } from '../lib/grid-svg'

const toDataUrl = (svg: string) => `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`

// Seeded fallback so the server-rendered HTML and the client's first render agree (no hydration
// mismatch); swapped for a fresh random grid on mount.
const fallbackSrc = toDataUrl(renderGridSvg(mulberry32(0x6d6b6974), 8, 12))

/**
 * Navbar logo: mints one random grid SVG per full page load and uses it both as the brand mark and as the site favicon,
 * so the tab icon always matches the logo in the header. Replaces the old standalone FaviconSwapper.
 */
export function GridLogo({ className }: { className?: string }) {
  const [src, setSrc] = useState(fallbackSrc)

  useEffect(() => {
    // Visual variation only; not security-sensitive, Math.random is fine.
    const href = toDataUrl(renderGridSvg(Math.random, 8, 12))
    setSrc(href)
    const link = document.querySelector<HTMLLinkElement>('link[rel~="icon"]') ?? makeLink()
    link.type = 'image/svg+xml'
    link.href = href
  }, [])

  return <img src={src} alt='mkit' className={className} draggable={false} />
}

function makeLink(): HTMLLinkElement {
  const el = document.createElement('link')
  el.rel = 'icon'
  document.head.appendChild(el)
  return el
}
