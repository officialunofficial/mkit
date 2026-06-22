import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { applyMigrations, McpTestClient, resetCorpus, seedCorpus, toolText } from "./harness.ts";

describe("MCP tools (integration)", () => {
  beforeAll(async () => {
    await applyMigrations();
  });
  beforeEach(async () => {
    await resetCorpus();
    await seedCorpus();
  });

  // Tracer bullet: proves the whole path — miniflare D1 seed, the Durable
  // Object MCP session, the streamable-HTTP initialize handshake, and a
  // tools/call round-trip — all work end-to-end.
  it("list_versions returns the seeded versions, newest first", async () => {
    const client = new McpTestClient();
    await client.initialize();

    const result = await client.callTool("list_versions");
    const text = toolText(result);

    expect(result.isError).toBeFalsy();
    expect(text).toContain("v0.3.0");
    expect(text).toContain("v0.2.0");
    expect(text.indexOf("v0.3.0")).toBeLessThan(text.indexOf("v0.2.0"));
  });

  it("get_file returns content for an indexed path, defaulting to the latest version", async () => {
    const client = new McpTestClient();
    await client.initialize();

    const result = await client.callTool("get_file", { path: "README.md" });
    const text = toolText(result);

    expect(result.isError).toBeFalsy();
    // Latest is v0.3.0 — its README, not the older v0.2.0 one.
    expect(text).toContain("README.md (v0.3.0)");
    expect(text).toContain("content-addressed");
    expect(text).not.toContain("older");
  });

  it("get_file returns a graceful error (not a crash) for a missing path", async () => {
    const client = new McpTestClient();
    await client.initialize();

    const result = await client.callTool("get_file", { path: "does/not/exist.rs" });

    expect(result.isError).toBe(true);
    expect(toolText(result)).toContain("file not found");
  });

  it("get_file rejects a path-traversal attempt", async () => {
    const client = new McpTestClient();
    await client.initialize();

    const result = await client.callTool("get_file", { path: "../../../etc/passwd" });

    expect(result.isError).toBe(true);
    expect(toolText(result).toLowerCase()).toContain("invalid path");
  });

  it("search_code finds a Rust source match with a ranked snippet", async () => {
    const client = new McpTestClient();
    await client.initialize();

    const result = await client.callTool("search_code", { query: "blake3_object_id" });
    const text = toolText(result);

    expect(result.isError).toBeFalsy();
    expect(text).toContain("rust/crates/mkit-core/src/lib.rs");
    expect(text).toContain("blake3_object_id");
  });

  it("search_code returns a clean no-matches message when nothing matches", async () => {
    const client = new McpTestClient();
    await client.initialize();

    const result = await client.callTool("search_code", { query: "zzz_no_such_symbol_zzz" });

    expect(result.isError).toBeFalsy();
    expect(toolText(result)).toContain("No matches");
  });

  it("list_crates lists workspace crates with descriptions", async () => {
    const client = new McpTestClient();
    await client.initialize();

    const result = await client.callTool("list_crates");
    const text = toolText(result);

    expect(result.isError).toBeFalsy();
    expect(text).toContain("mkit-core");
    expect(text).toContain("Core object model");
  });

  it("get_crate_readme resolves an unprefixed crate name (core -> mkit-core)", async () => {
    const client = new McpTestClient();
    await client.initialize();

    const result = await client.callTool("get_crate_readme", { crate: "core" });
    const text = toolText(result);

    expect(result.isError).toBeFalsy();
    expect(text).toContain("mkit-core");
    expect(text).toContain("core object model and hashing");
  });

  it("get_spec resolves a bare spec name and its docs/SPEC- path form identically", async () => {
    const client = new McpTestClient();
    await client.initialize();

    const bare = toolText(await client.callTool("get_spec", { name: "OBJECTS" }));
    const full = toolText(await client.callTool("get_spec", { name: "docs/SPEC-OBJECTS.md" }));

    expect(bare).toContain("# Objects");
    expect(bare).toContain("on-disk object formats");
    expect(full).toBe(bare);
  });

  it("get_command returns a single subcommand's reference", async () => {
    const client = new McpTestClient();
    await client.initialize();

    const result = await client.callTool("get_command", { name: "commit" });
    const text = toolText(result);

    expect(result.isError).toBeFalsy();
    expect(text).toContain("mkit commit (v0.3.0)");
    expect(text).toContain("Records staged changes");
  });
});
