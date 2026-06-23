# mkit-og

Open Graph image service for [mkit.sh](https://mkit.sh), served from
`og.mkit.sh`. A Cloudflare Worker that renders 1200×630 social-card PNG
images on the fly with [`workers-og`](https://github.com/kvnang/workers-og) (Satori + resvg),
matching the dark mkit theme: the colourful BLAKE3-grid mark, the `mkit`
wordmark, and a title/description in Geist.

## Usage

```
https://og.mkit.sh/
https://og.mkit.sh/?title=hash&description=Every%20object%20named%20by%20its%20BLAKE3%20hash.
```

| Query param   | Default                                                  |
| ------------- | -------------------------------------------------------- |
| `title`       | `mkit`                                                   |
| `description` | `A content-addressed version control toolkit written in Rust.` |

Responses are `image/png` with a one-year immutable cache header.

## Develop

```sh
cd og
npm install
npm run dev        # wrangler dev — open http://localhost:8787/
npm run typecheck  # wrangler types && tsc --noEmit
npm run deploy     # wrangler deploy (provisions og.mkit.sh on first run)
```

The brand mark is generated deterministically (`src/grid.ts`, seeded `"mkit"`),
a self-contained copy of the renderer in `apps/web/src/lib/grid-svg.ts` — mkit isn't a
single npm workspace, so the OG worker can't import across the `apps/web/` boundary.
