import { Link } from 'waku'
import { GridLogo } from './grid-logo'
import { ThemeToggle } from './theme-toggle'

// Top-nav order: the three primary pages (tree, performance, parity)
// first, then the smaller single-primitive demos. Reordering the site nav
// is editing this list — nothing else.
const NAV_LINKS = [
  { to: '/tree', label: 'tree' },
  { to: '/performance', label: 'performance' },
  { to: '/parity', label: 'parity' },
  { to: '/push', label: 'push' },
  { to: '/demos', label: 'demos' },
] as const

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
          {/* Negative margin + padding grows the tap target to 44px (WCAG 2.5.8 / platform guidance)
              without shifting the 20px logo's visual position. */}
          <Link to='/' className='-m-3 flex items-center p-3' aria-label='mkit home'>
            <GridLogo className='size-5 rounded-[3px]' />
          </Link>
          {/* min-w-0 + flex-1 lets the nav shrink and scroll horizontally on
              narrow screens instead of overflowing the row; scrollbar hidden
              since the row is short and the links wrap off-edge cleanly. */}
          <nav className='flex min-w-0 flex-1 items-center gap-4 overflow-x-auto text-sm [scrollbar-width:none] [&::-webkit-scrollbar]:hidden'>
            {NAV_LINKS.map(({ to, label }) => (
              <Link
                key={to}
                to={to}
                className='-mx-1 shrink-0 px-1 py-2 underline-offset-4 transition-opacity duration-300 hover:underline'
              >
                {label}
              </Link>
            ))}
          </nav>
          <div className='ml-auto'>
            <ThemeToggle />
          </div>
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
