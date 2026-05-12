// NOTE: replaced by Vocs topNav — kept for reuse on the landing page hero only
'use client'

// TODO(vocs): `Link` from `waku` is not available in Vocs. The landing agent decides
// whether to swap in Vocs's own Link primitive or fall back to plain <a href>.
// Until then we use plain anchors, which work identically for the landing-page hero.

export const Header = () => {
  return (
    // Sticky header with a translucent white ground + backdrop blur.
    // At rest it reads as solid; when content scrolls under it the
    // blur softens whatever's behind without obscuring it, so the
    // transition between page body and chrome stays visible. The
    // explicit `var(--color-bg)` call is required — Tailwind v4 won't
    // auto-wrap a bare custom prop reference in every position, and an
    // unset background was why the header was invisible.
    <header
      className='sticky top-0 z-50 backdrop-blur-md backdrop-saturate-150'
      style={{ backgroundColor: 'color-mix(in srgb, var(--color-bg) 80%, transparent)' }}
    >
      <div className='mx-auto w-full max-w-5xl px-6'>
        <div className='flex items-center gap-6 py-4'>
          <a href='/' className='text-base tracking-tight'>
            mkit <span className='text-[--color-muted]'>demo</span>
          </a>
          <nav className='flex items-center gap-4 text-sm'>
            <a
              href='/demos/hash'
              className='-mx-1 px-1 py-2 underline-offset-4 transition-opacity duration-300 hover:underline'
            >
              hash
            </a>
            <a
              href='/demos/sign'
              className='-mx-1 px-1 py-2 underline-offset-4 transition-opacity duration-300 hover:underline'
            >
              sign
            </a>
            <a
              href='/demos/attest'
              className='-mx-1 px-1 py-2 underline-offset-4 transition-opacity duration-300 hover:underline'
            >
              attest
            </a>
            <a
              href='/demos/tree'
              className='-mx-1 px-1 py-2 underline-offset-4 transition-opacity duration-300 hover:underline'
            >
              tree
            </a>
            <a
              href='/demos/streaming'
              className='-mx-1 px-1 py-2 underline-offset-4 transition-opacity duration-300 hover:underline'
            >
              streaming
            </a>
          </nav>
        </div>
        {/* Top separator: 2px band carrying the brand gradient, wider
            than the element so it can slide. `background-position-x`
            reads `--mouse-x` (0..1, written by <PointerTracker/>), so
            moving the cursor horizontally drags the colour stops
            across the rule. The gradient is oversized (300%) so only
            a slice of the palette is visible at any moment — mouse
            movement reveals the rest. */}
        <div
          className='h-0.5 w-full'
          style={{
            backgroundImage: 'var(--gradient-h)',
            backgroundSize: '300% 100%',
            backgroundPositionX: 'calc(var(--mouse-x, 0.5) * 100%)',
            transition: 'background-position-x 200ms cubic-bezier(0.2, 0, 0, 1)',
          }}
          aria-hidden
        />
      </div>
      {/* Fade strip directly below the 2px rule: content scrolling
          upward softens into the opaque nav area instead of cutting
          at a hard edge. `pointer-events-none` keeps it from stealing
          clicks from anything that happens to land under it. */}
      <div
        className='pointer-events-none absolute inset-x-0 top-full h-6'
        style={{
          backgroundImage: 'linear-gradient(to bottom, var(--color-bg), transparent)',
        }}
        aria-hidden
      />
    </header>
  )
}
