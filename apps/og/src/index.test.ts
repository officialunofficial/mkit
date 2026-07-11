import { beforeEach, describe, expect, it, vi } from "vitest";
import { MAX_TITLE_LENGTH } from "./title";

// `renderOgImage`/`loadGoogleFonts` do real font fetches (network) and Satori/resvg
// rendering — slow and non-hermetic for a unit test, and this handler test only
// needs to assert what the *handler* does with its input (title sanitization,
// response headers), not that the renderer produces a correct PNG. Mock the
// renderer boundary and inspect what the handler hands it.
const renderOgImage = vi.fn(async (html: string, options: { cacheControl?: string }) => {
  return new Response("fake-png-bytes", {
    status: 200,
    headers: {
      "Content-Type": "image/png",
      "Cache-Control": options.cacheControl ?? "public, max-age=31536000, immutable",
    },
  });
});
const loadGoogleFonts = vi.fn(async () => []);

vi.mock("@officialunofficial/og/render", () => ({
  loadGoogleFonts: (...args: unknown[]) => loadGoogleFonts(...(args as [])),
  renderOgImage: (...args: [string, { cacheControl?: string }]) => renderOgImage(...args),
}));

describe("GET / (og handler)", () => {
  beforeEach(() => {
    renderOgImage.mockClear();
    loadGoogleFonts.mockClear();
  });

  it("responds 200 with an image/png Content-Type", async () => {
    const { default: app } = await import("./index");
    const res = await app.request("/");
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("image/png");
  });

  it("sets a long-lived, immutable Cache-Control header", async () => {
    const { default: app } = await import("./index");
    const res = await app.request("/");
    const cacheControl = res.headers.get("Cache-Control");
    expect(cacheControl).toBeTruthy();
    expect(cacheControl).toContain("public");
    expect(cacheControl).toContain("immutable");
    expect(cacheControl).toContain("max-age=31536000");
  });

  it("defaults the title to the brand name when no query param is given", async () => {
    const { default: app } = await import("./index");
    await app.request("/");
    const [html] = renderOgImage.mock.calls.at(-1) ?? [];
    expect(html).toContain(">mkit<");
  });

  it("renders a provided title into the card markup", async () => {
    const { default: app } = await import("./index");
    await app.request("/?title=hash%20every%20object");
    const [html] = renderOgImage.mock.calls.at(-1) ?? [];
    expect(html).toContain("hash every object");
  });

  it("caps an oversized title before it reaches the renderer", async () => {
    const { default: app } = await import("./index");
    const huge = "a".repeat(MAX_TITLE_LENGTH * 20);
    await app.request(`/?title=${huge}`);
    const [html] = renderOgImage.mock.calls.at(-1) ?? [];
    expect(html).not.toContain(huge);
    // The capped run of `a`s (length MAX_TITLE_LENGTH) should appear, but not one
    // char longer.
    expect(html).toContain("a".repeat(MAX_TITLE_LENGTH));
    expect(html).not.toContain("a".repeat(MAX_TITLE_LENGTH + 1));
  });

  it("falls back to the brand title for a whitespace-only title param", async () => {
    const { default: app } = await import("./index");
    await app.request("/?title=%20%20%20");
    const [html] = renderOgImage.mock.calls.at(-1) ?? [];
    expect(html).toContain(">mkit<");
  });
});
