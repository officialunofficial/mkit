import type { ReactNode } from 'react'
import dmSansWoff2 from '@fontsource-variable/dm-sans/files/dm-sans-latin-wght-normal.woff2?url'
import dmMonoWoff2 from '@fontsource/dm-mono/files/dm-mono-latin-400-normal.woff2?url'

type RootProps = { children: ReactNode }

// Runs synchronously in <head> before the body paints, so the resolved theme
// is on <html data-theme> before first paint — no flash of the wrong theme.
// Preference ('system' | 'light' | 'dark') lives in localStorage; the resolved
// theme ('light' | 'dark') is mirrored onto the data-theme attribute. A
// matchMedia listener keeps `system` live when the OS flips.
const NO_FLASH = `(function(){try{
var p=localStorage.getItem('theme')||'system';
var m=window.matchMedia('(prefers-color-scheme: dark)');
var apply=function(){var d=p==='dark'||(p==='system'&&m.matches);document.documentElement.dataset.theme=d?'dark':'light';};
apply();
m.addEventListener('change',function(){if((localStorage.getItem('theme')||'system')==='system')apply();});
}catch(e){}})();`

/**
 * Custom Waku root element (replaces the framework default of `<html><head/><body>{children}</body></html>`). Adds
 * `lang`, the no-flash theme script, and `suppressHydrationWarning` so the script-set data-theme attribute doesn't trip
 * a server/client mismatch warning.
 */
export default function RootElement({ children }: RootProps) {
  return (
    <html lang='en' suppressHydrationWarning>
      <head>
        {/* Preload the two Latin-subset font files actually used to render page text (styles.css imports
            @fontsource-variable/dm-sans and @fontsource/dm-mono, both font-display: swap) — without this the
            browser only discovers them once it's parsed the CSS that declares the @font-face rules, serializing
            the fetch behind the stylesheet and lengthening the fallback-to-webfont swap. `crossOrigin` is required
            even though these are same-origin: @font-face fetches always run in CORS mode, and a preload without a
            matching crossorigin attribute is treated as a separate cache entry and fetched twice. */}
        <link rel='preload' href={dmSansWoff2} as='font' type='font/woff2' crossOrigin='anonymous' />
        <link rel='preload' href={dmMonoWoff2} as='font' type='font/woff2' crossOrigin='anonymous' />
        <script dangerouslySetInnerHTML={{ __html: NO_FLASH }} />
      </head>
      <body>{children}</body>
    </html>
  )
}

export const getConfig = async () => {
  return {
    render: 'static',
  } as const
}
