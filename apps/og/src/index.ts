import { Hono } from "hono";
import { Box, HStack, Img, svgToDataUri, Text, VStack } from "@officialunofficial/og";
import { loadGoogleFonts, renderOgImage } from "@officialunofficial/og/render";
import { MKIT_SEED, mulberry32, renderGridSvg } from "./grid";

const app = new Hono();

// Title-only card (matching the Modal docs social image): the brand by default.
// The description still travels in the page's og:description meta tag; it is not
// drawn on the image.
const DEFAULT_TITLE = "mkit";

// The colourful BLAKE3-grid mark — mkit's brand mark, the single pop of colour
// next to the mono wordmark.
const LOGO_SVG = svgToDataUri(renderGridSvg(mulberry32(MKIT_SEED), 8, 12));

// Render at 2x for Retina-quality output.
const SCALE = 2;

app.get("/", async (c) => {
  const title = c.req.query("title") || DEFAULT_TITLE;

  const s = SCALE;
  // Flat-black, minimal layout (modal.com/docs social image): grid mark + "mkit"
  // wordmark top-left, one large left-aligned title in the upper area, a hairline
  // rule at the foot, lots of negative space between.
  const html = VStack(
    {
      width: 1200 * s,
      height: 630 * s,
      backgroundColor: "#000000",
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
          color: "#ffffff",
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
        color: "#ffffff",
        letterSpacing: -2.5 * s,
        lineHeight: 1.05,
      },
      title,
    ),
    Box({ flex: 1 }),
    Box({ height: 1 * s, width: "100%", backgroundColor: "#333333" }),
  );

  const fonts = await loadGoogleFonts([
    { family: "Geist", weight: 600 },
    { family: "Geist", weight: 700 },
  ]);

  return renderOgImage(html, { fonts, width: 1200, height: 630, scale: s });
});

export default app;
