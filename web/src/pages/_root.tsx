import type { ReactNode } from 'react'

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
