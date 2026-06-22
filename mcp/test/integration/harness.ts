/**
 * Integration test harness for the mkit MCP Worker.
 *
 * Drives the *real* public interface — the streamable-HTTP MCP endpoint served
 * by `MkitMCP.serve("/")` over a Durable Object, backed by a miniflare D1 — so
 * tests verify observable tool behavior, not private helpers. The endpoint
 * speaks the MCP streamable-HTTP transport: an `initialize` POST (no session)
 * returns an `mcp-session-id` header and an SSE-framed result, after which
 * `tools/call` POSTs carry that session id and stream their result as SSE.
 */
import { applyD1Migrations, env, SELF } from "cloudflare:test";

interface TestEnv {
  SEARCH_DB: D1Database;
  TEST_MIGRATIONS: Array<{ name: string; queries: string[] }>;
}
const testEnv = env as unknown as TestEnv;

const ACCEPT = "application/json, text/event-stream";

export interface ToolResult {
  content: Array<{ type: string; text: string }>;
  isError?: boolean;
}

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
      "docs/SPEC-OBJECTS.md",
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

interface JsonRpcMessage {
  jsonrpc: "2.0";
  id?: number;
  method?: string;
  params?: unknown;
  result?: unknown;
  error?: { code: number; message: string };
}

async function postRpc(body: object, sessionId?: string): Promise<Response> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Accept: ACCEPT,
  };
  if (sessionId) headers["mcp-session-id"] = sessionId;
  return SELF.fetch("https://mcp.test/", {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
}

/**
 * Read an SSE-framed streamable-HTTP response and return the first JSON-RPC
 * message whose id matches. Resolves as soon as that frame arrives (the
 * transport may keep the stream open with keepalive comments), so it never
 * blocks on a stream that does not close promptly.
 */
async function readSseResult(res: Response, id: number): Promise<JsonRpcMessage> {
  if (!res.body) throw new Error(`no response body (status ${res.status})`);
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (value) buf += decoder.decode(value, { stream: true });
      let sep: number;
      while ((sep = buf.indexOf("\n\n")) !== -1) {
        const frame = buf.slice(0, sep);
        buf = buf.slice(sep + 2);
        for (const line of frame.split("\n")) {
          if (!line.startsWith("data:")) continue;
          const data = line.slice(5).trim();
          if (!data) continue;
          let msg: JsonRpcMessage;
          try {
            msg = JSON.parse(data) as JsonRpcMessage;
          } catch {
            continue; // keepalive / non-JSON line
          }
          if (msg.id === id) return msg;
        }
      }
      if (done) break;
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  throw new Error(`no JSON-RPC frame for id ${id} (status ${res.status}); leftover: ${buf.slice(0, 200)}`);
}

/** A minimal MCP client speaking streamable-HTTP against the test Worker. */
export class McpTestClient {
  private sessionId = "";
  private nextId = 1;

  async initialize(): Promise<void> {
    const id = this.nextId++;
    const res = await postRpc({
      jsonrpc: "2.0",
      id,
      method: "initialize",
      params: {
        protocolVersion: "2025-06-18",
        capabilities: {},
        clientInfo: { name: "mkit-mcp-tests", version: "0" },
      },
    });
    if (res.status !== 200) {
      throw new Error(`initialize failed: HTTP ${res.status} — ${await res.text()}`);
    }
    const sid = res.headers.get("mcp-session-id");
    if (!sid) throw new Error("initialize response missing mcp-session-id header");
    this.sessionId = sid;
    const msg = await readSseResult(res, id);
    if (msg.error) throw new Error(`initialize error: ${JSON.stringify(msg.error)}`);

    // Required follow-up: the `notifications/initialized` notification (no id) → 202.
    const note = await postRpc({ jsonrpc: "2.0", method: "notifications/initialized" }, this.sessionId);
    await note.body?.cancel().catch(() => {});
  }

  async callTool(name: string, args: Record<string, unknown> = {}): Promise<ToolResult> {
    if (!this.sessionId) throw new Error("callTool before initialize()");
    const id = this.nextId++;
    const res = await postRpc(
      { jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } },
      this.sessionId,
    );
    if (res.status !== 200) {
      throw new Error(`tools/call ${name} failed: HTTP ${res.status} — ${await res.text()}`);
    }
    const msg = await readSseResult(res, id);
    if (msg.error) throw new Error(`tools/call ${name} JSON-RPC error: ${JSON.stringify(msg.error)}`);
    return msg.result as ToolResult;
  }
}

/** Join a tool result's text content for easy assertions. */
export function toolText(result: ToolResult): string {
  return result.content.map((c) => c.text).join("\n");
}
