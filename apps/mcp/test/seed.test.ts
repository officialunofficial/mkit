import { describe, expect, it } from "vitest";
import { chunkContentByBytes, fileStatements, findOversized, sqlStr } from "../scripts/seed.mjs";

const enc = new TextEncoder();
const bytes = (s: string) => enc.encode(s).length;

describe("sqlStr", () => {
  it("quotes and doubles interior single-quotes", () => {
    expect(sqlStr("a'b")).toBe("'a''b'");
  });
});

describe("chunkContentByBytes", () => {
  it("reassembles to the original exactly (ASCII)", () => {
    const s = "x".repeat(1000);
    expect(chunkContentByBytes(s, 100).join("")).toBe(s);
  });

  it("keeps each chunk's ESCAPED byte length within budget", () => {
    const s = "a'b'c'".repeat(500); // quote-heavy: each ' escapes to ''
    const chunks = chunkContentByBytes(s, 50);
    for (const c of chunks) expect(bytes(c.replace(/'/g, "''"))).toBeLessThanOrEqual(50);
    expect(chunks.join("")).toBe(s);
  });

  it("is byte-aware for multi-byte UTF-8 (CJK) — chunks stay within budget", () => {
    const s = "中".repeat(300); // 3 bytes each = 900 bytes
    const chunks = chunkContentByBytes(s, 99);
    for (const c of chunks) expect(bytes(c)).toBeLessThanOrEqual(99);
    expect(chunks.join("")).toBe(s);
    expect(chunks.length).toBeGreaterThan(1);
  });

  it("never splits a surrogate pair on a boundary", () => {
    // 😀 (U+1F600) is a surrogate pair, 4 UTF-8 bytes. Budget forces a cut mid-string.
    const s = "😀😀😀😀😀";
    const chunks = chunkContentByBytes(s, 4); // one emoji per chunk at most
    const dec = new TextDecoder();
    for (const c of chunks) {
      // Each chunk is valid (no lone surrogate): re-encoding round-trips
      // (a lone surrogate would become U+FFFD and fail this).
      expect(dec.decode(enc.encode(c))).toBe(c);
    }
    expect(chunks.join("")).toBe(s);
  });

  it("always makes progress (no infinite loop) even when one code point exceeds budget", () => {
    const chunks = chunkContentByBytes("😀😀", 1); // budget smaller than a single code point
    expect(chunks.join("")).toBe("😀😀");
    expect(chunks.length).toBe(2);
  });
});

describe("fileStatements", () => {
  it("emits a single INSERT when the file fits", () => {
    const stmts = fileStatements("v0.2.0", "a/b.rs", "small", 99_000);
    expect(stmts.length).toBe(1);
    expect(stmts[0]).toMatch(/^INSERT INTO files/);
  });

  it("splits a large file into INSERT + UPDATE appends, all within cap, reassembling exactly", () => {
    const path = "rust/crates/x/src/big.rs";
    const content = "line of source code\n".repeat(20_000); // ~400 KB, no quotes
    const cap = 99_000;
    const stmts = fileStatements("v0.2.0", path, content, cap);
    expect(stmts.length).toBeGreaterThan(1);
    expect(stmts[0]).toMatch(/^INSERT INTO files/);
    for (let i = 1; i < stmts.length; i++) expect(stmts[i]).toMatch(/^UPDATE files SET content = content \|\|/);
    expect(findOversized(stmts, cap)).toHaveLength(0);
    // Reassemble via the known delimiters (content has no quotes so this is exact).
    const insertChunk = stmts[0].slice(stmts[0].indexOf(`${path}', '`) + `${path}', '`.length, -3);
    const updateChunks = stmts
      .slice(1)
      .map((s) => s.slice(s.indexOf("content || '") + "content || '".length, s.indexOf("' WHERE")));
    expect(insertChunk + updateChunks.join("")).toBe(content);
  });
});

describe("findOversized", () => {
  it("flags statements over the cap, largest first", () => {
    const small = "INSERT INTO files VALUES ('ok');";
    const big = `INSERT INTO files VALUES ('${"x".repeat(100_000)}');`;
    const over = findOversized([small, big], 99_000);
    expect(over).toHaveLength(1);
    expect(over[0][1]).toBe(big);
    expect(over[0][0]).toBeGreaterThan(99_000);
  });
});
