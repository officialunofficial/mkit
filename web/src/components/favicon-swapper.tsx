'use client'

import { useEffect } from 'react'
import { renderGridSvg } from '../lib/grid-svg'

/**
 * Mints a fresh random grid SVG on every full page load and injects it as the site favicon. Runs in `useEffect` so the
 * server-rendered HTML still ships a stable fallback `<link rel=icon>`; the browser fetches that once, then we swap the
 * link's href to a data URL before the tab icon is typically resolved.
 */
export function FaviconSwapper() {
  useEffect(() => {
    const svg = renderGridSvg(Math.random, 8, 12)
    const href = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`
    const link = document.querySelector<HTMLLinkElement>('link[rel~="icon"]') ?? makeLink()
    link.type = 'image/svg+xml'
    link.href = href
  }, [])
  return null
}

function makeLink(): HTMLLinkElement {
  const el = document.createElement('link')
  el.rel = 'icon'
  document.head.appendChild(el)
  return el
}
