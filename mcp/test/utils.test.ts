import { describe, expect, it } from "vitest";
import {
  buildFTSQuery,
  buildFileTree,
  buildSnippets,
  escapeLike,
  formatSnippet,
  formatWithLineNumbers,
  getLanguage,
  isValidPath,
  selectTopSnippets,
  sortVersionsDesc,
  stripCratePrefix,
} from "../src/utils.ts";

describe("sortVersionsDesc", () => {
  it("sorts semver tags newest-first", () => {
    const v = ["v0.1.0", "v0.2.0", "v0.1.9"];
    sortVersionsDesc(v);
    expect(v).toEqual(["v0.2.0", "v0.1.9", "v0.1.0"]);
  });
  it("handles pre-release/build suffixes without NaN instability", () => {
    const v = ["v0.2.0", "v0.3.0-rc1", "v0.10.0+build.5", "v0.1.0"];
    sortVersionsDesc(v);
    // 0.10.0 > 0.3.0(-rc1) > 0.2.0 > 0.1.0 on the numeric core.
    expect(v).toEqual(["v0.10.0+build.5", "v0.3.0-rc1", "v0.2.0", "v0.1.0"]);
  });
});

describe("getLanguage / stripCratePrefix / isValidPath", () => {
  it("maps extensions", () => {
    expect(getLanguage("a.rs")).toBe("rust");
    expect(getLanguage("a.toml")).toBe("toml");
    expect(getLanguage("a.md")).toBe("markdown");
    expect(getLanguage("man/mkit.1")).toBe("");
  });
  it("strips the mkit- prefix", () => {
    expect(stripCratePrefix("mkit-core")).toBe("core");
    expect(stripCratePrefix("core")).toBe("core");
  });
  it("rejects traversal and absolute paths", () => {
    expect(isValidPath("docs/SPEC-OBJECTS.md")).toBe(true);
    expect(isValidPath("../etc/passwd")).toBe(false);
    expect(isValidPath("/etc/passwd")).toBe(false);
  });
});

describe("formatWithLineNumbers / formatSnippet", () => {
  it("numbers lines 0-indexed and honors a range", () => {
    const content = "a\nb\nc\nd";
    expect(formatWithLineNumbers(content)).toBe("0: a\n1: b\n2: c\n3: d");
    expect(formatWithLineNumbers(content, 1, 2)).toBe("1: b\n2: c");
    expect(formatWithLineNumbers(content, 5, 9)).toBe("");
  });
  it("formats a snippet span", () => {
    expect(formatSnippet(["a", "b", "c"], 0, 2)).toBe("0: a\n1: b");
  });
});

describe("buildFileTree", () => {
  it("groups files under their directory relative to prefix", () => {
    const tree = buildFileTree(["rust/crates/mkit-core/src/lib.rs", "rust/crates/mkit-core/Cargo.toml"], "rust/crates/mkit-core/");
    expect(tree).toContain("Cargo.toml");
    expect(tree).toContain("src/");
    expect(tree).toContain("  lib.rs");
  });
});

describe("buildFTSQuery", () => {
  it("rejects substring queries under 3 chars", () => {
    expect(buildFTSQuery("ab", "substring").ftsQuery).toBeNull();
  });
  it("quotes substring queries and counts occurrences", () => {
    const { ftsQuery, snippetMatcher } = buildFTSQuery("envelope", "substring");
    expect(ftsQuery).toBe('"envelope"');
    expect(snippetMatcher("the envelope envelope")).toBe(2);
  });
  it("builds prefix word queries", () => {
    const { ftsQuery } = buildFTSQuery("dsse sign", "word");
    expect(ftsQuery).toBe("dsse* sign*");
  });
  it("splits punctuation into separate bareword tokens (no FTS5 syntax errors)", () => {
    // 'envelope.sign' and 'trust-roots.toml' must not reach FTS5 with a literal
    // '.' / '-' (which throws). Each becomes whitespace-separated prefix tokens.
    expect(buildFTSQuery("envelope.sign", "word").ftsQuery).toBe("envelope* sign*");
    expect(buildFTSQuery("trust-roots.toml", "word").ftsQuery).toBe("trust* roots* toml*");
    expect(buildFTSQuery("docs/CLI.md", "word").ftsQuery).toBe("docs* CLI* md*");
  });
});

describe("selectTopSnippets", () => {
  it("drops zero-score and majority-overlapping windows", () => {
    const scores = [0, 0, 3, 0, 0, 0, 0, 0, 2, 0];
    const selected = selectTopSnippets(buildSnippets(scores), 5);
    expect(selected.length).toBeGreaterThan(0);
    expect(selected.length).toBeLessThanOrEqual(2);
  });
});

describe("escapeLike", () => {
  it("escapes LIKE wildcards", () => {
    expect(escapeLike("a_b%c")).toBe("a\\_b\\%c");
  });
});
