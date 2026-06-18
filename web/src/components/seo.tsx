// Per-page document head: the <title>, meta description, and the Open Graph +
// Twitter card tags that drive link unfurls. React 19 hoists <title>/<meta> to
// <head> from anywhere in the tree, so pages render <Seo> inline at the top.
//
// og:image points at og.mkit.sh (the OG image worker in ../../og), which renders
// a 1200×630 social card on the fly from the title/description query params —
// `card` overrides the big headline drawn on the image when it should differ
// from the unfurl title.

const SITE_URL = 'https://mkit.sh'
const OG_URL = 'https://og.mkit.sh'

type SeoProps = {
  /** Browser tab title + og:title + twitter:title, e.g. `mkit — hash`. */
  title: string
  /** Meta description + og/twitter description. Keep it card- and SERP-sized (~1–2 sentences). */
  description: string
  /** Route path for canonical + og:url, e.g. `/` or `/hash`. */
  path: string
  /** Headline drawn on the OG image; defaults to `title`. */
  card?: string
}

export function Seo({ title, description, path, card }: SeoProps) {
  const url = `${SITE_URL}${path}`
  // The OG worker's `variant` selects the per-route mesh gradient; its keys are
  // the route names (`/` → `home`), so derive it straight from the path.
  const variant = path === '/' ? 'home' : path.replace(/^\//, '')
  const params = new URLSearchParams({ variant, title: card ?? title, description })
  const image = `${OG_URL}/?${params.toString()}`

  return (
    <>
      <title>{title}</title>
      <meta name='description' content={description} />
      <link rel='canonical' href={url} />

      <meta property='og:type' content='website' />
      <meta property='og:site_name' content='mkit' />
      <meta property='og:url' content={url} />
      <meta property='og:title' content={title} />
      <meta property='og:description' content={description} />
      <meta property='og:image' content={image} />
      <meta property='og:image:width' content='1200' />
      <meta property='og:image:height' content='630' />
      <meta property='og:image:alt' content={title} />

      <meta name='twitter:card' content='summary_large_image' />
      <meta name='twitter:title' content={title} />
      <meta name='twitter:description' content={description} />
      <meta name='twitter:image' content={image} />
    </>
  )
}
