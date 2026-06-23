import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { EmptyCorpusError, err, guardTool, LOG_PREFIX, ok } from "../src/utils.ts";

describe("err / ok result shape", () => {
  it("err flags isError and wraps text", () => {
    expect(err("boom")).toEqual({ content: [{ type: "text", text: "boom" }], isError: true });
  });
  it("ok wraps text without isError", () => {
    expect(ok("hi")).toEqual({ content: [{ type: "text", text: "hi" }] });
  });
});

describe("guardTool", () => {
  let errorSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
  });
  afterEach(() => {
    errorSpy.mockRestore();
  });

  it("passes through a successful result unchanged", async () => {
    const wrapped = guardTool("get_overview", async () => ok("content"));
    const res = await wrapped({});
    expect(res).toEqual({ content: [{ type: "text", text: "content" }] });
    expect(errorSpy).not.toHaveBeenCalled();
  });

  it("turns a thrown D1 error into a graceful error result (no throw) and logs it", async () => {
    // Simulate the D1 layer failing (outage). The handler must not throw.
    const wrapped = guardTool("search_code", async () => {
      throw new Error("D1_ERROR: network is unreachable");
    });
    const res = await wrapped({});
    expect(res.isError).toBe(true);
    expect(res.content[0].text).toMatch(/temporarily unavailable/i);
    // Logged with the stable prefix + tool name, but NOT the (absent) args.
    expect(errorSpy).toHaveBeenCalledOnce();
    const logged = errorSpy.mock.calls[0].join(" ");
    expect(logged).toContain(LOG_PREFIX);
    expect(logged).toContain("tool=search_code");
  });

  it("turns an EmptyCorpusError into a clear empty-index message", async () => {
    // Simulate latestVersion() throwing when no versions are indexed.
    const wrapped = guardTool("list_crates", async () => {
      throw new EmptyCorpusError();
    });
    const res = await wrapped({});
    expect(res.isError).toBe(true);
    expect(res.content[0].text).toMatch(/empty or unavailable/i);
    const logged = errorSpy.mock.calls[0].join(" ");
    expect(logged).toContain("tool=list_crates");
    expect(logged).toContain("empty-corpus");
  });

  it("handles a synchronous throw too", async () => {
    const wrapped = guardTool("get_file", () => {
      throw new Error("sync boom");
    });
    const res = await wrapped({});
    expect(res.isError).toBe(true);
  });

  it("does not log the caller's arguments (no payload leakage)", async () => {
    const secret = "SECRET_QUERY_PAYLOAD_xyz";
    const wrapped = guardTool("search_docs", async (_args: { query: string }) => {
      throw new Error("D1 down");
    });
    await wrapped({ query: secret });
    const logged = errorSpy.mock.calls.map((c: unknown[]) => c.join(" ")).join(" ");
    expect(logged).not.toContain(secret);
  });
});
