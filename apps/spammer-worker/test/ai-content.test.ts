// test/ai-content.test.ts
//
// Pure logic only — `parseAndValidate` never touches the network, so this
// runs in the "unit" vitest project (plain Node, see vitest.config.ts). The
// whole point of this suite is to prove EVERY malformed-model-output shape
// falls back to `null` rather than throwing or smuggling bad data (wrong
// type, empty, over-length) into `ContentPools`.

import { describe, expect, it } from "vitest";
import { FALLBACK_POOLS, parseAndValidate } from "../src/ai-content";

function wellFormedJson(overrides: Partial<{ chat: unknown; commit: unknown; remix: unknown }> = {}): string {
  const body = {
    chat: ["gm signed lobby", "loving the live feed"],
    commit: ["gm demo commit", "another signed push"],
    remix: ["remixing this one", "forking for fun"],
    ...overrides,
  };
  return JSON.stringify(body);
}

describe("ai-content.ts — parseAndValidate", () => {
  it("accepts a well-formed bare-JSON response", () => {
    const result = parseAndValidate(wellFormedJson());
    expect(result).toEqual({
      chat: ["gm signed lobby", "loving the live feed"],
      commit: ["gm demo commit", "another signed push"],
      remix: ["remixing this one", "forking for fun"],
    });
  });

  it("accepts JSON wrapped in prose/markdown fences by extracting the {...} slice", () => {
    const wrapped = `Sure, here you go:\n\`\`\`json\n${wellFormedJson()}\n\`\`\`\nHope that helps!`;
    expect(parseAndValidate(wrapped)).not.toBeNull();
  });

  it("trims whitespace from each phrase", () => {
    const result = parseAndValidate(wellFormedJson({ chat: ["  padded  ", "clean"] }));
    expect(result?.chat).toEqual(["padded", "clean"]);
  });

  it("rejects non-JSON text entirely", () => {
    expect(parseAndValidate("I cannot help with that request.")).toBeNull();
  });

  it("rejects JSON missing a required key", () => {
    const body = JSON.stringify({ chat: ["only chat"], commit: ["only commit"] });
    expect(parseAndValidate(body)).toBeNull();
  });

  it("rejects a category that isn't an array", () => {
    expect(parseAndValidate(wellFormedJson({ chat: "not an array" }))).toBeNull();
  });

  it("rejects an empty array for any category", () => {
    expect(parseAndValidate(wellFormedJson({ remix: [] }))).toBeNull();
  });

  it("rejects a non-string entry in any category", () => {
    expect(parseAndValidate(wellFormedJson({ commit: ["fine", 42] }))).toBeNull();
  });

  it("rejects a blank/whitespace-only entry", () => {
    expect(parseAndValidate(wellFormedJson({ chat: ["fine", "   "] }))).toBeNull();
  });

  it("rejects an entry over its category's length cap", () => {
    const tooLong = "x".repeat(61); // over commit's 60-char cap
    expect(parseAndValidate(wellFormedJson({ commit: ["fine", tooLong] }))).toBeNull();
  });

  it("accepts an entry exactly at its category's length cap", () => {
    const exact = "x".repeat(60); // commit's cap is exactly 60
    expect(parseAndValidate(wellFormedJson({ commit: ["fine", exact] }))).not.toBeNull();
  });

  it("rejects malformed JSON (trailing comma)", () => {
    const malformed = '{"chat": ["a",], "commit": ["b"], "remix": ["c"]}';
    expect(parseAndValidate(malformed)).toBeNull();
  });

  it("rejects a JSON array at the top level (not an object)", () => {
    expect(parseAndValidate('["chat", "commit", "remix"]')).toBeNull();
  });
});

describe("ai-content.ts — FALLBACK_POOLS", () => {
  it("mirrors content.ts's static pools exactly, non-empty in every category", () => {
    expect(FALLBACK_POOLS.chat.length).toBeGreaterThan(0);
    expect(FALLBACK_POOLS.commit.length).toBeGreaterThan(0);
    expect(FALLBACK_POOLS.remix.length).toBeGreaterThan(0);
  });
});
