export const Footer = () => {
  return (
    <footer>
      <div className='mx-auto w-full max-w-5xl px-6'>
        {/* Bottom separator: 1px dashed hairline. Dashed reads quieter
            than solid and keeps the bottom of the page deferential to
            the 2px gradient top — the two edges rhyme without
            matching. */}
        <div className='border-t border-dashed border-[--color-hairline]' aria-hidden />
        <div className='py-6 text-xs text-[--color-muted]'>
          <a
            href='https://github.com/officialunofficial/mkit'
            target='_blank'
            rel='noreferrer'
            className='underline underline-offset-4 transition-opacity duration-300 hover:opacity-70'
          >
            officialunofficial/mkit
          </a>
          <span aria-hidden> · </span>
          <a
            href='https://crates.io/crates/mkit-cli'
            target='_blank'
            rel='noreferrer'
            className='underline underline-offset-4 transition-opacity duration-300 hover:opacity-70'
          >
            mkit-cli on crates.io
          </a>
        </div>
      </div>
    </footer>
  )
}
