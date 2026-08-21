import { ArrowUpRightIcon } from '@phosphor-icons/react/ssr'
import type { ReactNode } from 'react'

/**
 * Footer link: dotted underline (§2.1D rule 1) plus the external mark and assistive-tech announcement §4.3 rule 4
 * requires.
 */
function FooterLink({ href, children }: { href: string; children: ReactNode }) {
  return (
    <a href={href} target='_blank' rel='noreferrer' className='ds-link inline-flex items-center gap-1'>
      {children}
      <ArrowUpRightIcon size={12} aria-hidden />
      <span className='sr-only'>(opens in a new tab)</span>
    </a>
  )
}

export const Footer = () => {
  return (
    <footer>
      <div className='mx-auto w-full max-w-(--page-column) px-6'>
        {/* §4.25 rule 1: a separator between peer sections is solid light in
            border-color-default. */}
        <div className='border-t' style={{ borderColor: 'var(--border-color-default)' }} aria-hidden />
        <div className='flex flex-wrap items-center gap-x-4 gap-y-1 py-6 text-xs text-secondary'>
          <FooterLink href='https://github.com/officialunofficial/mkit'>officialunofficial/mkit</FooterLink>
          <FooterLink href='https://crates.io/crates/mkit-cli'>mkit-cli on crates.io</FooterLink>
        </div>
      </div>
    </footer>
  )
}
