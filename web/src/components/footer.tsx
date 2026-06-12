export const Footer = () => {
  return (
    // Colophon: double rule echoing the letterhead, then one line of
    // mono microtext — sources on the left, typesetting note on the
    // right, the way a printed certificate signs off.
    <footer>
      <div className='mx-auto w-full max-w-5xl px-6'>
        <div className='rule-double' aria-hidden />
        <div className='microlabel flex flex-col justify-between gap-2 py-8 text-muted sm:flex-row sm:items-baseline'>
          <div className='flex flex-wrap gap-x-5 gap-y-1'>
            <a
              href='https://github.com/officialunofficial/mkit'
              target='_blank'
              rel='noreferrer'
              className='underline underline-offset-4 transition-colors duration-200 hover:text-fg'
            >
              officialunofficial/mkit
            </a>
            <a
              href='https://crates.io/crates/mkit-cli'
              target='_blank'
              rel='noreferrer'
              className='underline underline-offset-4 transition-colors duration-200 hover:text-fg'
            >
              mkit-cli on crates.io
            </a>
          </div>
          <span className='text-subtle'>Set in Fraunces &amp; Plex Mono · hashed with BLAKE3</span>
        </div>
      </div>
    </footer>
  )
}
