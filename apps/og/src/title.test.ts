import { describe, expect, it } from "vitest";
import { MAX_TITLE_LENGTH, sanitizeTitle } from "./title";

describe("sanitizeTitle", () => {
  it("returns the fallback for null/undefined/empty input", () => {
    expect(sanitizeTitle(null, "mkit")).toBe("mkit");
    expect(sanitizeTitle(undefined, "mkit")).toBe("mkit");
    expect(sanitizeTitle("", "mkit")).toBe("mkit");
  });

  it("returns the fallback for a whitespace-only title", () => {
    expect(sanitizeTitle("   \t\n  ", "mkit")).toBe("mkit");
  });

  it("trims surrounding whitespace on an otherwise short title", () => {
    expect(sanitizeTitle("  hash  ", "mkit")).toBe("hash");
  });

  it("passes a normal-length title through unchanged", () => {
    expect(sanitizeTitle("Content-addressed version control", "mkit")).toBe(
      "Content-addressed version control",
    );
  });

  it("caps a title longer than MAX_TITLE_LENGTH", () => {
    const huge = "x".repeat(MAX_TITLE_LENGTH * 10);
    const result = sanitizeTitle(huge, "mkit");
    expect(result.length).toBe(MAX_TITLE_LENGTH);
    expect(result).toBe("x".repeat(MAX_TITLE_LENGTH));
  });

  it("caps a title exactly one char over the limit", () => {
    const overByOne = "y".repeat(MAX_TITLE_LENGTH + 1);
    expect(sanitizeTitle(overByOne, "mkit").length).toBe(MAX_TITLE_LENGTH);
  });

  it("leaves a title exactly at the limit untouched", () => {
    const exact = "z".repeat(MAX_TITLE_LENGTH);
    expect(sanitizeTitle(exact, "mkit")).toBe(exact);
  });
});
