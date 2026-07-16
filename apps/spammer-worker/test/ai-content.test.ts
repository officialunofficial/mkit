// test/ai-content.test.ts
//
// Pure logic only — `parseAndValidate` never touches the network, so this
// runs in the "unit" vitest project (plain Node, see vitest.config.ts). The
// whole point of this suite is to prove EVERY malformed-model-output shape
// falls back to `null` rather than throwing or smuggling bad data (wrong
// type, empty, over-length) into `ContentPools`.

import { describe, expect, it } from "vitest";
import {
  fillReplyTemplate,
  FALLBACK_POOLS,
  generatePersonalizedReply,
  parseAndValidate,
  REPLY_SHORT_HEX_LEN,
  validatePersonalizedReplyText,
  type ContentPools,
} from "../src/ai-content";
import { REPLY_TEMPLATES } from "../src/content";

function wellFormedJson(overrides: Partial<{ chat: unknown; commit: unknown; remix: unknown; reply: unknown }> = {}): string {
  const body = {
    chat: ["gm signed lobby", "loving the live feed"],
    commit: ["gm demo commit", "another signed push"],
    remix: ["remixing this one", "forking for fun"],
    reply: ["gm {author}, {hash} just landed", "nice push to {branch}, {author}"],
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
      reply: ["gm {author}, {hash} just landed", "nice push to {branch}, {author}"],
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

  it("rejects JSON missing only the reply key (all-or-nothing, same as any other category)", () => {
    const body = JSON.stringify({
      chat: ["fine"],
      commit: ["fine"],
      remix: ["fine"],
    });
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

describe("ai-content.ts — parseAndValidate — reply category", () => {
  it("rejects a reply category that isn't an array", () => {
    expect(parseAndValidate(wellFormedJson({ reply: "not an array" }))).toBeNull();
  });

  it("rejects an empty reply array", () => {
    expect(parseAndValidate(wellFormedJson({ reply: [] }))).toBeNull();
  });

  it("rejects a non-string reply entry", () => {
    expect(parseAndValidate(wellFormedJson({ reply: ["fine", 42] }))).toBeNull();
  });

  it("rejects a blank/whitespace-only reply entry", () => {
    expect(parseAndValidate(wellFormedJson({ reply: ["fine {hash}", "   "] }))).toBeNull();
  });

  it("rejects a reply entry over the 100-char cap", () => {
    const tooLong = "x".repeat(101);
    expect(parseAndValidate(wellFormedJson({ reply: ["fine {hash}", tooLong] }))).toBeNull();
  });

  it("accepts a reply entry exactly at the 100-char cap", () => {
    const exact = "x".repeat(100);
    expect(parseAndValidate(wellFormedJson({ reply: ["fine {hash}", exact] }))).not.toBeNull();
  });

  it("rejects a reply template referencing an unknown slot", () => {
    expect(parseAndValidate(wellFormedJson({ reply: ["fine {hash}", "nice {feature} shipped"] }))).toBeNull();
  });

  it("rejects a reply template referencing an unknown slot even alongside allowed ones", () => {
    expect(parseAndValidate(wellFormedJson({ reply: ["gm {author}, {hash} on {commitMessage}"] }))).toBeNull();
  });

  it("accepts reply templates using every allowed slot combination", () => {
    const result = parseAndValidate(
      wellFormedJson({
        reply: ["gm {author}", "{hash} landed", "on {branch} now", "{author} pushed {hash} to {branch}", "no slots at all"],
      }),
    );
    expect(result).not.toBeNull();
  });
});

describe("ai-content.ts — ContentPools backward compatibility", () => {
  it("an old-shape stored pool (no reply key) is a valid ContentPools value", () => {
    // Simulates a value already sitting in DO storage from before the reply
    // category existed — TypeScript must accept this without a cast, and a
    // consumer must be able to read it back without throwing.
    const oldShapePool: ContentPools = {
      chat: ["hi"],
      commit: ["hi"],
      remix: ["hi"],
    };
    expect(oldShapePool.reply).toBeUndefined();
    // The documented consumer idiom: pools?.reply ?? <static fallback>.
    expect(oldShapePool.reply ?? REPLY_TEMPLATES).toBe(REPLY_TEMPLATES);
  });
});

describe("ai-content.ts — fillReplyTemplate", () => {
  const slots = { hash: "abcdef1234567890", author: "0123456789abcdef" };

  it("fills {hash} and {author} with their short-hex forms", () => {
    const result = fillReplyTemplate("gm {author}, {hash} just landed", slots);
    expect(result).toBe(`gm ${slots.author.slice(0, REPLY_SHORT_HEX_LEN)}, ${slots.hash.slice(0, REPLY_SHORT_HEX_LEN)} just landed`);
  });

  it("fills {branch} verbatim (not shortened) when provided", () => {
    const result = fillReplyTemplate("{author} pushed to {branch}", { ...slots, branch: "feature/cool-thing" });
    expect(result).toBe(`${slots.author.slice(0, REPLY_SHORT_HEX_LEN)} pushed to feature/cool-thing`);
  });

  it("handles a template with no slots at all", () => {
    expect(fillReplyTemplate("just saying hi", slots)).toBe("just saying hi");
  });

  it("returns null when the template references {branch} but slots.branch is undefined (a main push)", () => {
    expect(fillReplyTemplate("{author} pushed to {branch}", slots)).toBeNull();
  });

  it("returns null when the template references an unknown slot", () => {
    expect(fillReplyTemplate("nice {feature} shipped", slots)).toBeNull();
  });

  it("is deterministic — same inputs always yield the same output", () => {
    const a = fillReplyTemplate("{hash} by {author}", slots);
    const b = fillReplyTemplate("{hash} by {author}", slots);
    expect(a).toBe(b);
  });

  it("fills every REPLY_TEMPLATES entry without {branch} when slots.branch is undefined, or returns null for entries that require it", () => {
    for (const template of REPLY_TEMPLATES) {
      const result = fillReplyTemplate(template, slots);
      if (template.includes("{branch}")) {
        expect(result).toBeNull();
      } else {
        expect(result).not.toBeNull();
      }
    }
  });

  it("fills every REPLY_TEMPLATES entry when slots.branch is provided", () => {
    for (const template of REPLY_TEMPLATES) {
      const result = fillReplyTemplate(template, { ...slots, branch: "feature/x" });
      expect(result).not.toBeNull();
      expect(result).not.toMatch(/\{[a-zA-Z]+\}/);
    }
  });
});

describe("ai-content.ts — validatePersonalizedReplyText", () => {
  it("accepts a short, well-formed line", () => {
    expect(validatePersonalizedReplyText("gm 1a2b3c4d, abcdef12 just landed")).toBe(
      "gm 1a2b3c4d, abcdef12 just landed",
    );
  });

  it("trims surrounding whitespace", () => {
    expect(validatePersonalizedReplyText("  gm  ")).toBe("gm");
  });

  it("rejects an empty/whitespace-only line", () => {
    expect(validatePersonalizedReplyText("   ")).toBeNull();
  });

  it("rejects a line over the 100-char cap", () => {
    expect(validatePersonalizedReplyText("x".repeat(101))).toBeNull();
  });

  it("accepts a line exactly at the 100-char cap", () => {
    expect(validatePersonalizedReplyText("x".repeat(100))).not.toBeNull();
  });

  it("rejects a multi-line response", () => {
    expect(validatePersonalizedReplyText("line one\nline two")).toBeNull();
  });
});

describe("ai-content.ts — generatePersonalizedReply", () => {
  const event = { shortHash: "abcdef12", shortAuthor: "01234567" };

  it("returns a validated line on a well-formed Ai response", async () => {
    const fakeAi = { run: async () => ({ response: "gm abcdef12, signed and landed" }) } as unknown as Ai;
    const result = await generatePersonalizedReply(fakeAi, event);
    expect(result).toBe("gm abcdef12, signed and landed");
  });

  it("returns null on garbage/malformed Ai output", async () => {
    const fakeAi = { run: async () => ({ response: "line one\nline two" }) } as unknown as Ai;
    expect(await generatePersonalizedReply(fakeAi, event)).toBeNull();
  });

  it("returns null on an unexpected response shape", async () => {
    const fakeAi = { run: async () => ({ notResponse: "oops" }) } as unknown as Ai;
    expect(await generatePersonalizedReply(fakeAi, event)).toBeNull();
  });

  it("returns null (never throws) when the Ai call itself throws", async () => {
    const fakeAi = {
      run: async () => {
        throw new Error("Workers AI quota exceeded");
      },
    } as unknown as Ai;
    await expect(generatePersonalizedReply(fakeAi, event)).resolves.toBeNull();
  });

  it("returns null on an over-length response", async () => {
    const fakeAi = { run: async () => ({ response: "x".repeat(101) }) } as unknown as Ai;
    expect(await generatePersonalizedReply(fakeAi, event)).toBeNull();
  });
});

describe("ai-content.ts — FALLBACK_POOLS", () => {
  it("mirrors content.ts's static pools exactly, non-empty in every category", () => {
    expect(FALLBACK_POOLS.chat.length).toBeGreaterThan(0);
    expect(FALLBACK_POOLS.commit.length).toBeGreaterThan(0);
    expect(FALLBACK_POOLS.remix.length).toBeGreaterThan(0);
    expect(FALLBACK_POOLS.reply?.length).toBeGreaterThan(0);
  });

  it("REPLY_TEMPLATES has a mix of entries with and without {branch}", () => {
    const withBranch = REPLY_TEMPLATES.filter((t) => t.includes("{branch}"));
    const withoutBranch = REPLY_TEMPLATES.filter((t) => !t.includes("{branch}"));
    expect(withBranch.length).toBeGreaterThan(0);
    expect(withoutBranch.length).toBeGreaterThan(0);
  });

  it("every REPLY_TEMPLATES entry is within the 100-char cap and uses only allowed slots", () => {
    const slotRe = /\{([a-zA-Z]+)\}/g;
    for (const template of REPLY_TEMPLATES) {
      expect(template.length).toBeLessThanOrEqual(100);
      for (const match of template.matchAll(slotRe)) {
        expect(["hash", "author", "branch"]).toContain(match[1]);
      }
    }
  });
});
