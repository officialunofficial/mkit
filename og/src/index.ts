import { Hono } from "hono";
import { ImageResponse, loadGoogleFont } from "workers-og";
import { MKIT_SEED, mulberry32, renderGridSvg } from "./grid";

const app = new Hono();

// Title-only card (matching the Modal docs social image): the brand by default.
// The description still travels in the page's og:description meta tag; it is not
// drawn on the image.
const DEFAULT_TITLE = "mkit";

function escapeHtml(str: string): string {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function svgToDataUri(svg: string): string {
  return `data:image/svg+xml,${encodeURIComponent(svg.trim())}`;
}

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
  const html = `<div style="display:flex;flex-direction:column;width:${1200 * s}px;height:${630 * s}px;background-color:#000000;padding:${64 * s}px;font-family:'Geist',sans-serif;"><div style="display:flex;align-items:center;"><img src="${LOGO_SVG}" width="${44 * s}" height="${44 * s}" style="border-radius:${8 * s}px;" /><div style="display:flex;margin-left:${16 * s}px;font-size:${32 * s}px;font-weight:700;color:#ffffff;letter-spacing:${-1 * s}px;">mkit</div></div><div style="display:flex;margin-top:${44 * s}px;font-size:${76 * s}px;font-weight:600;color:#ffffff;letter-spacing:${-2.5 * s}px;line-height:1.05;">${escapeHtml(title)}</div><div style="display:flex;flex:1;"></div><div style="display:flex;height:${1 * s}px;width:100%;background-color:#333333;"></div></div>`;

  const [geist600, geist700] = await Promise.all([
    loadGoogleFont({ family: "Geist", weight: 600 }),
    loadGoogleFont({ family: "Geist", weight: 700 }),
  ]);

  const response = new ImageResponse(html, {
    width: 1200 * s,
    height: 630 * s,
    fonts: [
      { name: "Geist", data: geist600, weight: 600, style: "normal" },
      { name: "Geist", data: geist700, weight: 700, style: "normal" },
    ],
  });

  const body = await response.arrayBuffer();
  return c.body(body, 200, {
    "Content-Type": "image/png",
    "Cache-Control": "public, max-age=31536000, immutable",
  });
});

export default app;
