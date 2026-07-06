/**
 * Integration test harness for the mkit MCP Worker.
 *
 * Drives the *real* public interface — the streamable-HTTP MCP endpoint served
 * by `MkitMCP.serve("/")` over a Durable Object, backed by a miniflare D1 — so
 * tests verify observable tool behavior, not private helpers. We use the
 * canonical `@modelcontextprotocol/sdk` client, pointing its streamable-HTTP
 * transport at the test Worker via the `fetch` injection (routes to `SELF`
 * instead of the global). That keeps the harness to the part that is actually
 * specific to mkit — seeding a corpus — and leaves protocol concerns (the
 * initialize handshake, session-id tracking, SSE framing) to the SDK.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { type CallToolResult, CallToolResultSchema } from "@modelcontextprotocol/sdk/types.js";
import { applyD1Migrations, env, SELF } from "cloudflare:test";

interface TestEnv {
  SEARCH_DB: D1Database;
  TEST_MIGRATIONS: Array<{ name: string; queries: string[] }>;
}
const testEnv = env as unknown as TestEnv;

/** Apply the D1 schema migrations (idempotent). */
export async function applyMigrations(): Promise<void> {
  await applyD1Migrations(testEnv.SEARCH_DB, testEnv.TEST_MIGRATIONS);
}

/** Truncate every corpus table so a test starts from a known state. */
export async function resetCorpus(): Promise<void> {
  const db = testEnv.SEARCH_DB;
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
  const db = testEnv.SEARCH_DB;
  const v = "v0.3.0";
  const libRs = [
    "/// Core object hashing.",
    "pub fn blake3_object_id(bytes: &[u8]) -> ObjectId {",
    "    blake3::hash(bytes).into()",
    "}",
  ].join("\n");

  await db.batch([
    db.prepare("INSERT INTO versions (version) VALUES (?), (?)").bind("v0.2.0", v),
    db.prepare("INSERT INTO files (version, path, content) VALUES (?, ?, ?)").bind(
      v,
      "README.md",
      "# mkit\n\nA content-addressed, signed version-control toolkit.\n",
    ),
    db.prepare("INSERT INTO files (version, path, content) VALUES (?, ?, ?)").bind(
      v,
      "rust/crates/mkit-core/src/lib.rs",
      libRs,
    ),
    db.prepare("INSERT INTO files (version, path, content) VALUES (?, ?, ?)").bind(
      v,
      "rust/crates/mkit-core/README.md",
      "# mkit-core\n\nThe core object model and hashing.\n",
    ),
    db.prepare("INSERT INTO files (version, path, content) VALUES (?, ?, ?)").bind(
      v,
      "docs/specs/SPEC-OBJECTS.md",
      "# Objects\n\nWire and on-disk object formats.\n",
    ),
    db.prepare("INSERT INTO files (version, path, content) VALUES (?, ?, ?)").bind(
      v,
      "SKILL.md",
      "# mkit CLI guide\n\nDriving the mkit CLI.\n",
    ),
    // A file that only exists in the older version, to prove version scoping.
    db.prepare("INSERT INTO files (version, path, content) VALUES (?, ?, ?)").bind(
      "v0.2.0",
      "README.md",
      "# mkit (older)\n",
    ),
    db.prepare("INSERT INTO crates (version, name, path, description) VALUES (?, ?, ?, ?)").bind(
      v,
      "mkit-core",
      "rust/crates/mkit-core",
      "Core object model, hashing, and store.",
    ),
    db.prepare("INSERT INTO commands (version, name, summary, body) VALUES (?, ?, ?, ?)").bind(
      v,
      "commit",
      "Record a new commit.",
      "# commit\n\nRecords staged changes as a signed commit.\n",
    ),
  ]);
}

/**
 * Connect an MCP client to the test Worker over streamable-HTTP. The transport's
 * `fetch` is routed to `SELF` (the pool's service binding to the Worker under
 * test) so requests hit the real Durable Object + D1 rather than the network.
 * The returned client has already completed the initialize handshake.
 */
export async function connectMcpClient(): Promise<Client> {
  const transport = new StreamableHTTPClientTransport(new URL("https://mcp.test/"), {
    fetch: (input: string | URL, init?: RequestInit) =>
      SELF.fetch(
        input as Parameters<typeof SELF.fetch>[0],
        init as Parameters<typeof SELF.fetch>[1],
      ),
  });
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
  return client.callTool({ name, arguments: args }, CallToolResultSchema) as Promise<CallToolResult>;
}

/** Join a tool result's text content for easy assertions. */
export function toolText(result: CallToolResult): string {
  return result.content.map((c) => (c.type === "text" ? c.text : "")).join("\n");
}
