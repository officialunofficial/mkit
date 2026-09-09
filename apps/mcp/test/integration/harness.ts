/**
 * Integration test harness for the mkit MCP Worker.
 *
 * Drives the *real* public interface — the stateless MCP endpoint served by
 * `createMcpHandler` straight off the Worker's `fetch`, backed by a
 * miniflare D1 — so tests verify observable tool behavior, not private
 * helpers. This harness uses the legacy (v1) `@modelcontextprotocol/sdk`
 * client with its streamable-HTTP transport, pointing it at the test Worker
 * over the local HTTP server started by Wrangler — which
 * exercises `createMcpHandler`'s 2025-era stateless fallback leg. See
 * `test/integration/modern.test.ts` for a client on the 2026-07-28 modern
 * path. Either way this keeps the harness to the part that is actually
 * specific to mkit — seeding a corpus — and leaves protocol concerns (the
 * initialize handshake, session-id tracking, SSE framing) to the SDK.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { type CallToolResult, CallToolResultSchema } from "@modelcontextprotocol/sdk/types.js";
import { createTestHarness } from "wrangler";

// Vitest isolates test files; each owns its Worker and ephemeral D1 storage.
const server = createTestHarness({ workers: [{ configPath: "./wrangler.jsonc" }] });
const worker = server.getWorker<{ SEARCH_DB: D1Database }>();
let endpoint: URL;

export async function startWorker(): Promise<void> {
  const { url } = await server.listen();
  endpoint = new URL(url);
  await worker.applyD1Migrations("SEARCH_DB");
}

export async function stopWorker(): Promise<void> {
  await server.close();
}

export function workerUrl(): URL {
  return endpoint;
}

/** Truncate every corpus table so a test starts from a known state. */
export async function resetCorpus(): Promise<void> {
  const { SEARCH_DB: db } = await worker.getEnv();
  await db.batch([
    db.prepare("DELETE FROM files"),
    db.prepare("DELETE FROM crates"),
    db.prepare("DELETE FROM commands"),
    db.prepare("DELETE FROM versions"),
  ]);
}

/**
 * Seed a tiny but representative corpus: two versions (latest = v0.3.0), a few
 * files (incl. a Rust source file with a searchable token, a crate README, a
 * SPEC doc, and SKILL.md), one crate, and one command. FTS indexes populate
 * automatically via the schema's AFTER INSERT triggers.
 */
export async function seedCorpus(): Promise<void> {
  const { SEARCH_DB: db } = await worker.getEnv();
  const v = "v0.3.0";
  const libRs = [
    "/// Core object hashing.",
    "pub fn blake3_object_id(bytes: &[u8]) -> ObjectId {",
    "    blake3::hash(bytes).into()",
    "}",
  ].join("\n");

  await db.batch([
    db.prepare("INSERT INTO versions (version) VALUES (?), (?)").bind("v0.2.0", v),
    db
      .prepare("INSERT INTO files (version, path, content) VALUES (?, ?, ?)")
      .bind(
        v,
        "README.md",
        "# mkit\n\nA content-addressed, signed version-control toolkit.\n",
      ),
    db
      .prepare("INSERT INTO files (version, path, content) VALUES (?, ?, ?)")
      .bind(v, "rust/crates/mkit-core/src/lib.rs", libRs),
    db
      .prepare("INSERT INTO files (version, path, content) VALUES (?, ?, ?)")
      .bind(
        v,
        "rust/crates/mkit-core/README.md",
        "# mkit-core\n\nThe core object model and hashing.\n",
      ),
    db
      .prepare("INSERT INTO files (version, path, content) VALUES (?, ?, ?)")
      .bind(
        v,
        "docs/specs/SPEC-OBJECTS.md",
        "# Objects\n\nWire and on-disk object formats.\n",
      ),
    db
      .prepare("INSERT INTO files (version, path, content) VALUES (?, ?, ?)")
      .bind(v, "SKILL.md", "# mkit CLI guide\n\nDriving the mkit CLI.\n"),
    // A file that only exists in the older version, to prove version scoping.
    db
      .prepare("INSERT INTO files (version, path, content) VALUES (?, ?, ?)")
      .bind("v0.2.0", "README.md", "# mkit (older)\n"),
    db
      .prepare("INSERT INTO crates (version, name, path, description) VALUES (?, ?, ?, ?)")
      .bind(
        v,
        "mkit-core",
        "rust/crates/mkit-core",
        "Core object model, hashing, and store.",
      ),
    db
      .prepare("INSERT INTO commands (version, name, summary, body) VALUES (?, ?, ?, ?)")
      .bind(
        v,
        "commit",
        "Record a new commit.",
        "# commit\n\nRecords staged changes as a signed commit.\n",
      ),
  ]);
}

/**
 * Connect an MCP client to the test Worker over streamable-HTTP. The transport's
 * connects to Wrangler's local HTTP server backed by the bundled Worker and D1.
 * The returned client has already completed the initialize handshake.
 */
export async function connectMcpClient(): Promise<Client> {
  const transport = new StreamableHTTPClientTransport(workerUrl());
  const client = new Client({ name: "mkit-mcp-tests", version: "0" });
  await client.connect(transport);
  return client;
}

/**
 * Call a tool and return its result. Pins the strict `CallToolResultSchema` (so
 * `content`/`isError` are well-typed, not the legacy `toolResult` union) and
 * always sends an `arguments` object — every tool here expects one, even the
 * no-arg ones.
 */
export function callTool(
  client: Client,
  name: string,
  args: Record<string, unknown> = {},
): Promise<CallToolResult> {
  // `callTool`'s return type unions in a legacy `{ toolResult }` shape that has
  // no `content`; pinning CallToolResultSchema guarantees the server's standard
  // result at runtime, so narrow the static type to match.
  return client.callTool(
    { name, arguments: args },
    CallToolResultSchema,
  ) as Promise<CallToolResult>;
}

/** Join a tool result's text content for easy assertions. */
export function toolText(result: CallToolResult): string {
  return result.content.map((c) => (c.type === "text" ? c.text : "")).join("\n");
}
