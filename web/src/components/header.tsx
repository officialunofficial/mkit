import { Link } from 'waku'
import { GridLogo } from './grid-logo'

const ENTRIES = ['hash', 'sign', 'tree', 'streaming', 'performance', 'attest'] as const

export const Header = () => {
  return (
    // Letterhead: seal + wordmark on the left, the document index on
    // the right, closed by a certificate double rule. Sticky with a
    // translucent paper ground + blur so content scrolling beneath
    // softens instead of cutting.
    <header
      className='sticky top-0 z-50 backdrop-blur-md backdrop-saturate-150'
      style={{ backgroundColor: 'color-mix(in srgb, var(--color-bg) 85%, transparent)' }}
    >
      <div className='mx-auto w-full max-w-5xl px-6'>
        <div className='flex flex-wrap items-center justify-between gap-x-6 gap-y-2 py-4'>
          <Link to='/' className='group flex items-center gap-3' aria-label='mkit home'>
            {/* The seal: random grid mark on a paper backing, set at a
                stamp's slight tilt; rights itself on hover. */}
            <span className='inline-block border border-fg bg-paper p-[3px] [transform:rotate(-4deg)] transition-transform duration-300 ease-[cubic-bezier(0.2,0,0,1)] group-hover:[transform:rotate(0deg)]'>
              <GridLogo className='block size-5' />
            </span>
            <span className='text-xl font-semibold tracking-tight'>mkit</span>
          </Link>
          <nav className='flex flex-wrap items-center gap-x-5 gap-y-1'>
            {ENTRIES.map((entry, i) => (
              <Link
                key={entry}
                to={`/${entry}`}
                className='microlabel group/item py-2 text-muted transition-colors duration-200 hover:text-fg'
              >
                <span
                  aria-hidden
                  className='mr-1 hidden text-subtle transition-colors duration-200 group-hover/item:text-accent sm:inline'
                >
                  {String(i + 1).padStart(2, '0')}
                </span>
                {entry}
              </Link>
            ))}
          </nav>
        </div>
        {/* Certificate rule with a ruler caret: the small vermillion
            tick tracks `--mouse-x` (written by <PointerTracker/>), so
            the letterhead quietly measures the reader's position —
            the one playful instrument on an otherwise formal sheet. */}
        <div className='relative'>
          <div className='rule-double' aria-hidden />
          <div
            aria-hidden
            className='absolute top-[6px] h-[5px] w-[9px] -translate-x-1/2 bg-accent'
            style={{
              left: 'calc(var(--mouse-x, 0.5) * 100%)',
              clipPath: 'polygon(50% 0, 100% 100%, 0 100%)',
              transition: 'left 200ms cubic-bezier(0.2, 0, 0, 1)',
            }}
          />
        </div>
      </div>
      {/* Fade strip below the rule: content scrolling upward softens
          into the opaque letterhead instead of cutting at a hard edge. */}
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
