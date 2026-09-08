import { Hono } from "hono";
import { Box, HStack, Img, svgToDataUri, Text, VStack } from "@officialunofficial/og";
import { loadGoogleFonts, renderOgImage } from "@officialunofficial/og/render";
import { MKIT_SEED, mulberry32, renderGridSvg } from "./grid";
import { sanitizeTitle } from "./title";

const app = new Hono();

// Static social cards use Pigment’s light palette and DM Sans typography.
const DEFAULT_TITLE = "mkit";

// Tagline drawn under the brand-only default card (og.mkit.sh hit with no
// ?title= — no mkit.sh page produces that, every page passes its own title).
// Kept under the {@link MAX_DESCRIPTION_WORDS} cap.
const DEFAULT_DESCRIPTION = "Version control with Ed25519 signatures, BLAKE3 object IDs, and signed attestations.";

/** Hard cap on the words drawn in the description line — one small sentence, never a paragraph. */
const MAX_DESCRIPTION_WORDS = 15;

/** First {@link MAX_DESCRIPTION_WORDS} words of `text` (whitespace-split), unchanged when already within the cap. */
function capWords(text: string): string {
  const words = text.split(/\s+/);
  return words.length <= MAX_DESCRIPTION_WORDS ? text : words.slice(0, MAX_DESCRIPTION_WORDS).join(" ");
}

// Pigment light-theme roles. Raster cards have a fixed light background.
const COLORS = {
  page: "#ffffff",
  text: "#0a0a0a",
  secondary: "#8a8a8a",
  border: "#d4d4d4",
};

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
  // Social-image sizes scale for a 1200 × 630 export; colors and typeface match the site.
  const html = VStack(
    {
      width: 1200 * s,
      height: 630 * s,
      backgroundColor: COLORS.page,
      padding: 64 * s,
      fontFamily: "'DM Sans', sans-serif",
    },
    HStack(
      { alignItems: "center" },
      Img(LOGO_SVG, 44 * s, 44 * s, { borderRadius: 8 * s }),
      Text(
        {
          marginLeft: 16 * s,
          fontSize: 32 * s,
          fontWeight: 600,
          color: COLORS.text,
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
        color: COLORS.text,
        letterSpacing: -2.5 * s,
        lineHeight: 1.05,
      },
      title,
    ),
    ...(description
      ? [
          // Optional description in the secondary text role.
          Text(
            {
              marginTop: 26 * s,
              maxWidth: (1200 - 128) * s,
              fontSize: 46 * s,
              fontWeight: 400,
              color: COLORS.secondary,
              letterSpacing: -0.5 * s,
              lineHeight: 1.3,
            },
            description,
          ),
        ]
      : []),
    Box({ flex: 1 }),
    Box({ height: 1 * s, width: "100%", backgroundColor: COLORS.border }),
  );

  const fonts = await loadGoogleFonts([
    { family: "DM Sans", weight: 400 },
    { family: "DM Sans", weight: 600 },
  ]);

  return renderOgImage(html, { fonts, width: 1200, height: 630, scale: s, cacheControl: CACHE_CONTROL });
});

export default app;
