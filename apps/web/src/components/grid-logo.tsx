'use client'

import { useEffect, useState } from 'react'
import { renderGridSvg } from '../lib/grid-svg'

const toDataUrl = (svg: string) => `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`

// Static seeded fallback so server HTML and the client's first render agree (no hydration mismatch),
// without inlining ~8 KB of data URL into every page. Regenerate with:
//   bun -e "import {renderGridSvg, mulberry32} from './src/lib/grid-svg'; await Bun.write('public/images/grid-fallback.svg', renderGridSvg(mulberry32(0x6d6b6974), 8, 12))"
const FALLBACK_SRC = '/images/grid-fallback.svg'

/**
 * Navbar logo: mints one random grid SVG per full page load and uses it both as the brand mark and as the site favicon,
 * so the tab icon always matches the logo in the header. Replaces the old standalone FaviconSwapper.
 */
export function GridLogo({ className }: { className?: string }) {
  const [src, setSrc] = useState(FALLBACK_SRC)

  useEffect(() => {
    // Visual variation only; not security-sensitive, Math.random is fine.
    const href = toDataUrl(renderGridSvg(Math.random, 8, 12))
    setSrc(href)
    // The layout always ships a <link rel='icon'> in <head>, so the query can't miss on any
    // statically-prerendered page; skip quietly if a future layout drops it.
    const link = document.querySelector<HTMLLinkElement>('link[rel~="icon"]')
    if (link) {
      link.type = 'image/svg+xml'
      link.href = href
    }
  }, [])

  return <img src={src} alt='mkit' className={className} draggable={false} />
}
