import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { applyMigrations, McpTestClient, resetCorpus, toolText } from "./harness.ts";

// Integration-level proof of the guardTool/EmptyCorpusError resilience fix:
// with a migrated-but-empty corpus (no versions indexed), every version-
// defaulting tool calls latestVersion() which throws EmptyCorpusError. Without
// the guard that surfaced as an unhandled exception to the client; it must now
// come back as a graceful tool error result.
describe("MCP resilience: empty corpus", () => {
  beforeAll(async () => {
    await applyMigrations();
  });
  beforeEach(async () => {
    await resetCorpus();
  });

  it("a version-defaulting tool returns a graceful error instead of crashing", async () => {
    const client = new McpTestClient();
    await client.initialize();

    const result = await client.callTool("get_file", { path: "README.md" });

    expect(result.isError).toBe(true);
    expect(toolText(result).toLowerCase()).toMatch(/empty|unavailable|index/);
  });

  it("list_versions reports an empty index without throwing", async () => {
    const client = new McpTestClient();
    await client.initialize();

    const result = await client.callTool("list_versions");

    expect(result.isError).toBe(true);
    expect(toolText(result).toLowerCase()).toContain("no versions");
  });
});
