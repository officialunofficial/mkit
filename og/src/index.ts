import { Hono } from "hono";
import { ImageResponse, loadGoogleFont } from "workers-og";
import { MKIT_SEED, mulberry32, renderGridSvg } from "./grid";

const app = new Hono();

// Defaults mirror the site: title from the brand, description from the README
// tagline (web/src/pages/_layout.tsx carries a demo-specific variant).
const DEFAULT_TITLE = "mkit";
const DEFAULT_DESCRIPTION = "A content-addressed version control toolkit written in Rust.";

function escapeHtml(str: string): string {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function svgToDataUri(svg: string): string {
  return `data:image/svg+xml,${encodeURIComponent(svg.trim())}`;
}

// The colourful BLAKE3-grid mark is the single pop of colour on an otherwise
// monochrome card — the same deterministic mark the web app shows. The "mkit"
// wordmark stays mono.
const LOGO_SVG = svgToDataUri(renderGridSvg(mulberry32(MKIT_SEED), 8, 12));

// Render at 2x for Retina-quality output.
const SCALE = 2;

app.get("/", async (c) => {
  const title = c.req.query("title") || DEFAULT_TITLE;
  const description = c.req.query("description") || DEFAULT_DESCRIPTION;

  const s = SCALE;
  // Palette tracks the dark theme in web/src/styles.css (OKLCH tokens resolved to
  // hex): near-black bg, hairline rule, near-white ink, muted description, Geist.
  const html = `<div style="display:flex;flex-direction:column;width:${1200 * s}px;height:${630 * s}px;background-color:#161616;border:${s}px solid #454545;padding:${60 * s}px;font-family:'Geist',sans-serif;"><div style="display:flex;align-items:center;"><img src="${LOGO_SVG}" width="${96 * s}" height="${96 * s}" style="border-radius:${6 * s}px;" /></div><div style="display:flex;flex-direction:column;flex:1;justify-content:center;"><div style="display:flex;font-size:${64 * s}px;font-weight:700;color:#f2f2f2;letter-spacing:${-2 * s}px;line-height:1.1;">${escapeHtml(title)}</div><div style="display:flex;font-size:${28 * s}px;color:#8f8f8f;line-height:1.4;margin-top:${20 * s}px;">${escapeHtml(description)}</div></div><div style="display:flex;align-items:center;font-size:${28 * s}px;font-weight:600;color:#f2f2f2;letter-spacing:${-1 * s}px;">mkit</div></div>`;

  const [geist400, geist700] = await Promise.all([
    loadGoogleFont({ family: "Geist", weight: 400 }),
    loadGoogleFont({ family: "Geist", weight: 700 }),
  ]);

  const response = new ImageResponse(html, {
    width: 1200 * s,
    height: 630 * s,
    fonts: [
      { name: "Geist", data: geist400, weight: 400, style: "normal" },
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
