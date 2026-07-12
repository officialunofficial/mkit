import { describe, expect, it } from "vitest";
import { MKIT_SEED, mulberry32, renderGridSvg } from "./grid";

describe("mulberry32", () => {
  it("is deterministic for a given seed", () => {
    const a = mulberry32(42);
    const b = mulberry32(42);
    const seqA = Array.from({ length: 5 }, () => a());
    const seqB = Array.from({ length: 5 }, () => b());
    expect(seqA).toEqual(seqB);
  });

  it("produces values in [0, 1)", () => {
    const rand = mulberry32(MKIT_SEED);
    for (let i = 0; i < 50; i++) {
      const v = rand();
      expect(v).toBeGreaterThanOrEqual(0);
      expect(v).toBeLessThan(1);
    }
  });

  it("differs across different seeds", () => {
    const a = mulberry32(1)();
    const b = mulberry32(2)();
    expect(a).not.toBe(b);
  });
});

describe("renderGridSvg", () => {
  it("renders an n x n grid of coloured squares at the given cell size", () => {
    const svg = renderGridSvg(mulberry32(MKIT_SEED), 8, 12);
    expect(svg).toContain('width="96"');
    expect(svg).toContain('height="96"');
    expect(svg).toContain("<svg");
    // 8x8 = 64 rects.
    expect(svg.match(/<rect/g)?.length).toBe(64);
  });

  it("is deterministic for the same seed", () => {
    const a = renderGridSvg(mulberry32(MKIT_SEED), 8, 12);
    const b = renderGridSvg(mulberry32(MKIT_SEED), 8, 12);
    expect(a).toBe(b);
  });

  it("defaults to an 8x8 grid with 12px cells", () => {
    const svg = renderGridSvg(mulberry32(MKIT_SEED));
    expect(svg.match(/<rect/g)?.length).toBe(64);
    expect(svg).toContain('width="96"');
  });

  it("respects a smaller grid size", () => {
    const svg = renderGridSvg(mulberry32(MKIT_SEED), 2, 10);
    expect(svg.match(/<rect/g)?.length).toBe(4);
    expect(svg).toContain('width="20"');
  });
});

describe("MKIT_SEED", () => {
  it('encodes the ASCII bytes of "mkit"', () => {
    expect(MKIT_SEED).toBe(0x6d6b6974);
  });
});
