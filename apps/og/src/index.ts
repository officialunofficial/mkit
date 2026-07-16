import { Hono } from "hono";
import { Box, HStack, Img, svgToDataUri, Text, VStack } from "@officialunofficial/og";
import { loadGoogleFonts, renderOgImage } from "@officialunofficial/og/render";
import { MKIT_SEED, mulberry32, renderGridSvg } from "./grid";
import { sanitizeTitle } from "./title";

const app = new Hono();

// Title-first card in the same family as polychrome's social image (white
// card, black/greyscale type, brand-gradient rule at the foot). The
// description still travels in the page's og:description meta tag and is NOT
// drawn unless a caller explicitly passes ?description= — mkit.sh's <Seo>
// sends title only, so its cards stay title-only like before.
const DEFAULT_TITLE = "mkit";

// Tagline drawn under the brand-only default card (og.mkit.sh hit with no
// ?title= — no mkit.sh page produces that, every page passes its own title).
// Kept under the {@link MAX_DESCRIPTION_WORDS} cap.
const DEFAULT_DESCRIPTION = "Version control that signs every commit — Ed25519 signatures, BLAKE3 hashes, attestations built in.";

/** Hard cap on the words drawn in the description line — one small sentence, never a paragraph. */
const MAX_DESCRIPTION_WORDS = 15;

/** First {@link MAX_DESCRIPTION_WORDS} words of `text` (whitespace-split), unchanged when already within the cap. */
function capWords(text: string): string {
  const words = text.split(/\s+/);
  return words.length <= MAX_DESCRIPTION_WORDS ? text : words.slice(0, MAX_DESCRIPTION_WORDS).join(" ");
}

/**
 * Sunset accent: the pink→yellow leg of the brand gradient, using the exact
 * hex stops from mkit.sh's `--gradient-h` (apps/web/src/styles.css — keep in
 * sync with that variable). Drawn as the card's footer rule, standing in for
 * polychrome's red→magenta accent line.
 */
const ACCENT_GRADIENT = "linear-gradient(90deg, #fa7cfa 0%, #f5ca23 100%)";

// The colourful BLAKE3-grid mark — mkit's brand mark, the single pop of colour
// next to the mono wordmark.
const LOGO_SVG = svgToDataUri(renderGridSvg(mulberry32(MKIT_SEED), 8, 12));

// Render at 2x for Retina-quality output.
const SCALE = 2;

// The card is a pure function of `title` (same title in -> same PNG out), so it's
// safe to cache aggressively at the edge — a year, immutable. Set explicitly
// rather than relying on `renderOgImage`'s default, so this endpoint's caching
// contract stays intentional even if that default ever changes upstream.
const CACHE_CONTROL = "public, max-age=31536000, immutable";

app.get("/", async (c) => {
  const rawTitle = c.req.query("title");
  const title = sanitizeTitle(rawTitle, DEFAULT_TITLE);
  // Subtitle line: an explicit ?description= wins; the brand-only default card
  // (no title given) gets the built-in tagline; a titled card with no
  // description stays title-only. Empty means the Text node is skipped.
  const isBrandCard = sanitizeTitle(rawTitle, "") === "";
  const description = capWords(sanitizeTitle(c.req.query("description"), isBrandCard ? DEFAULT_DESCRIPTION : ""));

  const s = SCALE;
  // White, minimal layout in polychrome's social-card family: grid mark +
  // "mkit" wordmark top-left, one large left-aligned near-black title (plus an
  // optional grey subtitle) in the upper area, the brand-gradient rule at the
  // foot, lots of negative space between.
  const html = VStack(
    {
      width: 1200 * s,
      height: 630 * s,
      backgroundColor: "#ffffff",
      padding: 64 * s,
      fontFamily: "'Geist', sans-serif",
    },
    HStack(
      { alignItems: "center" },
      Img(LOGO_SVG, 44 * s, 44 * s, { borderRadius: 8 * s }),
      Text(
        {
          marginLeft: 16 * s,
          fontSize: 32 * s,
          fontWeight: 700,
          color: "#111111",
          letterSpacing: -1 * s,
        },
        "mkit",
      ),
    ),
    Text(
      {
        marginTop: 44 * s,
        fontSize: 76 * s,
        fontWeight: 600,
        color: "#111111",
        letterSpacing: -2.5 * s,
        lineHeight: 1.05,
      },
      title,
    ),
    ...(description
      ? [
          // 60% of the title size, regular weight, 50%-black — one quiet
          // informative sentence, never competing with the title.
          Text(
            {
              marginTop: 26 * s,
              maxWidth: (1200 - 128) * s,
              fontSize: 46 * s,
              fontWeight: 400,
              color: "rgba(0, 0, 0, 0.5)",
              letterSpacing: -0.5 * s,
              lineHeight: 1.3,
            },
            description,
          ),
        ]
      : []),
    Box({ flex: 1 }),
    Box({ height: 8 * s, width: "100%", backgroundImage: ACCENT_GRADIENT }),
  );

  const fonts = await loadGoogleFonts([
    { family: "Geist", weight: 400 },
    { family: "Geist", weight: 600 },
    { family: "Geist", weight: 700 },
  ]);

  return renderOgImage(html, { fonts, width: 1200, height: 630, scale: s, cacheControl: CACHE_CONTROL });
});

export default app;
