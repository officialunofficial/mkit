/**
 * Proves `createMcpHandler`'s MODERN (2026-07-28) serving path, not just its
 * 2025-era stateless fallback that `tools.test.ts`/`resilience.test.ts`
 * exercise via the legacy `@modelcontextprotocol/sdk` client (see
 * `harness.ts`). Uses the new `@modelcontextprotocol/client` package, which
 * speaks the per-request envelope by default — so a passing round-trip here
 * is the actual evidence that the stateless-revision migration serves real
 * traffic, not just that the legacy fallback still works.
 */
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { workerUrl, stopWorker, startWorker, resetCorpus, seedCorpus } from "./harness.ts";

describe("MCP tools (modern 2026-07-28 protocol)", () => {
  let client: Client;

  beforeAll(async () => {
    await startWorker();
  });
  afterAll(stopWorker);
  beforeEach(async () => {
    await resetCorpus();
    await seedCorpus();
    const transport = new StreamableHTTPClientTransport(workerUrl());
    client = new Client({ name: "mkit-mcp-modern-tests", version: "0" });
    await client.connect(transport);
  });
  afterEach(async () => {
    await client.close();
  });

  it("list_versions returns the seeded versions, newest first", async () => {
    const result = await client.callTool({ name: "list_versions", arguments: {} });
    const text = (result.content as Array<{ type: string; text?: string }>)
      .map((c) => c.text ?? "")
      .join("\n");

    expect(result.isError).toBeFalsy();
    expect(text).toContain("v0.3.0");
    expect(text).toContain("v0.2.0");
    expect(text.indexOf("v0.3.0")).toBeLessThan(text.indexOf("v0.2.0"));
  });

  it("get_file rejects a path-traversal attempt", async () => {
    const result = await client.callTool({
      name: "get_file",
      arguments: { path: "../../../etc/passwd" },
    });

    expect(result.isError).toBe(true);
  });
});
