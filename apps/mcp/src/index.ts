/**
 * mkit MCP
 *
 * A Model Context Protocol server that exposes the mkit toolkit — workspace
 * crate source, the docs/SPEC-* corpus, and the CLI reference — to AI
 * assistants. The corpus is baked into D1 at deploy time by
 * scripts/build-index.mjs, so this Worker serves everything from D1 with
 * no runtime credentials.
 *
 * Tools (7 mirror the Commonware MCP, 5 are mkit-specific):
 *   get_overview, list_crates, get_crate_readme, list_files, get_file,
 *   search_code, list_versions,
 *   list_specs, get_spec, get_command, get_cli_reference, search_docs
 */

import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { Env } from "./env.d.ts";
import {
  buildFileTree,
  buildFTSQuery,
  buildSnippets,
  EmptyCorpusError,
  err,
  escapeLike,
  formatSnippet,
  formatWithLineNumbers,
  getLanguage,
  guardTool,
  isValidPath,
  ok,
  selectTopSnippets,
  sortVersionsDesc,
  stripCratePrefix,
  type ToolResult,
} from "./utils.ts";
import pkg from "../package.json";

interface CrateRow {
  name: string;
  path: string;
  description: string;
}

const MAX_SEARCH_RESULTS = 50;

// Surfaced to the agent at connection time (the MCP `initialize` result's
// `instructions`). This is the seamless onboarding path: it tells an agent what
// mkit is and which tool to reach for first, without it having to guess.
const INSTRUCTIONS = `mkit is a content-addressed, cryptographically-signed version-control toolkit — a Rust workspace plus the \`mkit\` CLI (Git-like commits/refs/transports over BLAKE3 object IDs, with native in-toto/DSSE attestation). This server indexes mkit's source, SPEC docs, and CLI reference at a pinned release.

Start here:
- get_overview — what mkit is, its architecture, and the object model. Read this first for a general understanding.
- get_cli_reference — the agent-oriented guide to driving the \`mkit\` CLI (setup, signing, attestation, transports, and exactly how it differs from git).

Then, by need:
- Driving the CLI: get_command "<name>" for one subcommand's flags/behavior; get_command with no name lists all subcommands.
- Wire/on-disk formats & design: list_specs, then get_spec "<NAME>" (e.g. OBJECTS, SIGNING, ATTESTATIONS, TRANSPORT, PACKFILE).
- Implementation: list_crates → list_files "<crate>" → get_file "<path>" (line ranges supported). Search with search_code (Rust source) or search_docs (prose); use mode "word" for natural-language terms, "substring" for exact strings.

All content is version-pinned — omit \`version\` for the latest (list_versions shows what's indexed).

To OPERATE a local mkit repository (status/add/commit/attest/verify), use the local MCP server that ships inside the CLI instead: \`mkit mcp --repository <path>\` (register via \`claude mcp add mkit-repo -- mkit mcp --repository <path>\`; reference: get_command "mcp" on releases that include it, or \`mkit help\`). This server is documentation/source only.`;

export class MkitMCP extends McpAgent<Env, {}, {}> {
  server = new McpServer({ name: "mkit", version: pkg.version }, { instructions: INSTRUCTIONS });

  async init() {
    // Thin wrapper preserving zod-schema -> handler-arg typing while casting
    // around the agents/SDK McpServer overload skew (same approach as the
    // makechain MCP). Every callback is wrapped in `guardTool` so a D1 outage,
    // an empty corpus, or any other throw becomes a graceful MCP error result
    // (logged for observability) instead of an unhandled exception to the client.
    const tool = <TShape extends Record<string, z.ZodTypeAny>>(
      name: string,
      description: string,
      params: TShape,
      cb: (args: { [K in keyof TShape]: z.infer<TShape[K]> }) => Promise<ToolResult> | ToolResult,
    ) =>
      (this.server.tool as (...args: unknown[]) => unknown)(
        name,
        description,
        params,
        guardTool(name, cb),
      );

    // --- get_file ----------------------------------------------------------
    tool(
      "get_file",
      "Retrieve a file from the mkit repository by its path (relative to the repo " +
        "root, e.g. 'rust/crates/mkit-attest/src/envelope.rs' or 'docs/SPEC-ATTESTATIONS.md'). " +
        "Optionally pass a version (e.g. 'v0.2.0', defaults to latest) and a " +
        "start_line/end_line range (0-indexed, inclusive) matching search_code output.",
      {
        path: z.string().describe("File path relative to the repo root"),
        version: z.string().optional().describe("Version tag (e.g. 'v0.2.0'). Defaults to latest."),
        start_line: z.number().int().min(0).optional().describe("Start line (0-indexed, inclusive)."),
        end_line: z.number().int().min(0).optional().describe("End line (0-indexed, inclusive)."),
      },
      async ({ path, version, start_line, end_line }) => {
        if (!isValidPath(path)) return err(`Error: invalid path '${path}'`);
        const ver = version || (await this.latestVersion());
        const content = await this.fetchFile(ver, path);
        if (content === null) return err(`Error: file not found at ${path} (version ${ver})`);
        const formatted = formatWithLineNumbers(content, start_line, end_line);
        const total = content.split("\n").length;
        const range =
          start_line !== undefined || end_line !== undefined
            ? ` [lines ${start_line ?? 0}-${end_line ?? total - 1}]`
            : "";
        return ok(`# ${path} (${ver})${range}\n\n\`\`\`${getLanguage(path)}\n${formatted}\n\`\`\``);
      },
    );

    // --- search_code -------------------------------------------------------
    tool(
      "search_code",
      "Search source files in the mkit workspace for a pattern. Returns matching " +
        "files with ranked, context-bearing snippets. Good for finding definitions, " +
        "call sites, or how a feature is implemented.",
      {
        query: z.string().describe("Search query"),
        mode: z
          .enum(["substring", "word"])
          .optional()
          .default("substring")
          .describe("'substring' = literal match (min 3 chars); 'word' = word/prefix match"),
        crate: z.string().optional().describe("Limit to a crate (e.g. 'mkit-attest')"),
        file_type: z
          .enum(["rs", "toml", "md", "all"])
          .optional()
          .default("rs")
          .describe("File type filter"),
        version: z.string().optional().describe("Version tag. Defaults to latest."),
        limit: z.number().int().min(1).max(MAX_SEARCH_RESULTS).optional().default(10),
      },
      async ({ query, mode, crate, file_type, version, limit }) => {
        const ver = version || (await this.latestVersion());
        const results = await this.search(ver, query, mode, crate, file_type, limit);
        if (results.length === 0) return ok(`No matches for "${query}" (version ${ver}).`);
        const body = results
          .map((r) => `## ${r.file}\n\n${r.matches.map((m) => "```\n" + m + "\n```").join("\n\n")}`)
          .join("\n\n");
        return ok(`# search_code "${query}" (${ver}) — ${results.length} file(s)\n\n${body}`);
      },
    );

    // --- search_docs -------------------------------------------------------
    tool(
      "search_docs",
      "Search the mkit prose docs (docs/SPEC-*.md, CLI.md, PARITY.md, READMEs, " +
        "SKILL.md) for a pattern. Use this for wire-format / on-disk / design questions; " +
        "use search_code for Rust source.",
      {
        query: z.string().describe("Search query"),
        mode: z.enum(["substring", "word"]).optional().default("word"),
        version: z.string().optional(),
        limit: z.number().int().min(1).max(MAX_SEARCH_RESULTS).optional().default(10),
      },
      async ({ query, mode, version, limit }) => {
        const ver = version || (await this.latestVersion());
        const results = await this.search(ver, query, mode, undefined, "md", limit);
        if (results.length === 0) return ok(`No doc matches for "${query}" (version ${ver}).`);
        const body = results
          .map((r) => `## ${r.file}\n\n${r.matches.map((m) => "```\n" + m + "\n```").join("\n\n")}`)
          .join("\n\n");
        return ok(`# search_docs "${query}" (${ver}) — ${results.length} doc(s)\n\n${body}`);
      },
    );

    // --- list_crates -------------------------------------------------------
    tool(
      "list_crates",
      "List the mkit workspace crates with their descriptions and paths.",
      { version: z.string().optional() },
      async ({ version }) => {
        const ver = version || (await this.latestVersion());
        const crates = await this.crates(ver);
        if (crates.length === 0) return err(`Error: no crates indexed for ${ver}`);
        const body = crates.map((c) => `- **${c.name}** (\`${c.path}\`) — ${c.description}`).join("\n");
        return ok(`# mkit crates (${ver})\n\n${body}`);
      },
    );

    // --- get_crate_readme --------------------------------------------------
    tool(
      "get_crate_readme",
      "Get the README for a workspace crate (e.g. 'mkit-keystore'). Falls back to " +
        "the crate's Cargo.toml description if it has no README.",
      { crate: z.string().describe("Crate name, e.g. 'mkit-core'"), version: z.string().optional() },
      async ({ crate, version }) => {
        const ver = version || (await this.latestVersion());
        const row = await this.resolveCrate(ver, crate);
        if (!row) return err(`Error: unknown crate '${crate}'. Use list_crates.`);
        const readme = await this.fetchFile(ver, `${row.path}/README.md`);
        if (readme !== null) return ok(readme);
        return ok(`# ${row.name} (${ver})\n\n_No README._\n\n${row.description}`);
      },
    );

    // --- get_overview ------------------------------------------------------
    tool(
      "get_overview",
      "Get the mkit repository overview (top-level README): what mkit is, its design, " +
        "and how the pieces fit together.",
      { version: z.string().optional() },
      async ({ version }) => {
        const ver = version || (await this.latestVersion());
        const content = await this.fetchFile(ver, "README.md");
        return content === null ? err("Error fetching overview") : ok(content);
      },
    );

    // --- list_files --------------------------------------------------------
    tool(
      "list_files",
      "List indexed files in a crate or directory (omit `crate` to list top-level dirs). " +
        "Use to discover structure before get_file.",
      {
        crate: z.string().optional().describe("Crate name or directory path"),
        version: z.string().optional(),
      },
      async ({ crate, version }) => {
        const ver = version || (await this.latestVersion());
        const all = await this.fileList(ver);
        if (all.length === 0) return err(`Error: no files indexed for ${ver}`);
        if (!crate) {
          const dirs = [...new Set(all.map((f) => f.split("/")[0]))].sort();
          return ok(`# Top-level (${ver})\n\n${dirs.map((d) => `- ${d}/`).join("\n")}`);
        }
        const row = await this.resolveCrate(ver, crate);
        const prefix = row ? `${row.path}/` : `${crate.replace(/\/$/, "")}/`;
        const filtered = all.filter((f) => f.startsWith(prefix));
        if (filtered.length === 0) return err(`Error: no files under '${crate}' (${ver})`);
        return ok(`# Files in ${crate} (${ver})\n\n\`\`\`\n${buildFileTree(filtered, prefix)}\n\`\`\``);
      },
    );

    // --- list_versions -----------------------------------------------------
    tool(
      "list_versions",
      "List the mkit versions available in this index (newest first).",
      {},
      async () => {
        const versions = await this.versions();
        if (versions.length === 0) return err("Error: no versions indexed");
        return ok(`# Indexed versions\n\n${versions.map((v) => `- ${v}`).join("\n")}`);
      },
    );

    // --- list_specs --------------------------------------------------------
    tool(
      "list_specs",
      "List the mkit SPEC documents (docs/SPEC-*.md) — the authoritative wire-format, " +
        "on-disk, and subsystem specifications.",
      { version: z.string().optional() },
      async ({ version }) => {
        const ver = version || (await this.latestVersion());
        const specs = (await this.fileList(ver))
          .filter((p) => /^docs\/SPEC-.*\.md$/.test(p))
          .sort();
        if (specs.length === 0) return err(`Error: no SPEC docs indexed for ${ver}`);
        const names = specs.map((p) => p.replace(/^docs\/SPEC-/, "").replace(/\.md$/, ""));
        return ok(
          `# mkit SPEC documents (${ver})\n\n` +
            specs.map((p, i) => `- **${names[i]}** — \`${p}\``).join("\n") +
            `\n\nFetch one with get_spec (e.g. get_spec "ATTESTATIONS").`,
        );
      },
    );

    // --- get_spec ----------------------------------------------------------
    tool(
      "get_spec",
      "Get a mkit SPEC document by name (e.g. 'ATTESTATIONS', 'SPEC-OBJECTS', or " +
        "'docs/SPEC-SIGNING.md' all work). Use list_specs to discover names.",
      { name: z.string().describe("Spec name, e.g. 'OBJECTS'"), version: z.string().optional() },
      async ({ name, version }) => {
        const ver = version || (await this.latestVersion());
        const bare = name
          .replace(/^docs\//, "")
          .replace(/^SPEC-/i, "")
          .replace(/\.md$/i, "")
          .toUpperCase();
        const path = `docs/SPEC-${bare}.md`;
        if (!isValidPath(path)) return err(`Error: invalid spec name '${name}'`);
        const content = await this.fetchFile(ver, path);
        if (content === null) return err(`Error: spec '${bare}' not found (${ver}). Use list_specs.`);
        return ok(content);
      },
    );

    // --- get_command -------------------------------------------------------
    tool(
      "get_command",
      "Get the reference for a single mkit CLI subcommand (e.g. 'attest', 'verify-attest', " +
        "'keygen', 'commit') — flags, behavior, and mkit-specific notes. Omit `name` to list " +
        "all subcommands.",
      { name: z.string().optional().describe("Subcommand, e.g. 'attest'"), version: z.string().optional() },
      async ({ name, version }) => {
        const ver = version || (await this.latestVersion());
        if (!name) {
          const rows = await this.allCommands(ver);
          if (rows.length === 0) return err(`Error: no commands indexed for ${ver}`);
          return ok(
            `# mkit subcommands (${ver})\n\n` +
              rows.map((r) => `- **${r.name}** — ${r.summary}`).join("\n"),
          );
        }
        const row = await this.command(ver, name.replace(/^mkit\s+/, "").trim());
        if (!row) return err(`Error: unknown command '${name}'. Use get_command (no name) to list.`);
        return ok(`# mkit ${row.name} (${ver})\n\n${row.body}`);
      },
    );

    // --- get_cli_reference -------------------------------------------------
    tool(
      "get_cli_reference",
      "Get the agent-oriented mkit CLI guide (the project's SKILL.md): setup, the " +
        "git-parity model, and the differentiator commands (attestation, signing, " +
        "transports). For exhaustive per-command detail use get_command or " +
        "get_file 'docs/CLI.md'.",
      { version: z.string().optional() },
      async ({ version }) => {
        const ver = version || (await this.latestVersion());
        const skill = await this.fetchFile(ver, "SKILL.md");
        if (skill !== null) return ok(skill);
        const cli = await this.fetchFile(ver, "docs/CLI.md");
        return cli === null ? err("Error: no CLI reference indexed") : ok(cli);
      },
    );
  }

  // --- D1 helpers ----------------------------------------------------------

  private async latestVersion(): Promise<string> {
    const versions = await this.versions();
    if (versions.length === 0) throw new EmptyCorpusError();
    return versions[0];
  }

  private async versions(): Promise<string[]> {
    const res = await this.env.SEARCH_DB.prepare("SELECT version FROM versions").all<{
      version: string;
    }>();
    const versions = res.results.map((r) => r.version);
    sortVersionsDesc(versions);
    return versions;
  }

  private async fetchFile(version: string, path: string): Promise<string | null> {
    const row = await this.env.SEARCH_DB.prepare(
      "SELECT content FROM files WHERE version = ? AND path = ?",
    )
      .bind(version, path)
      .first<{ content: string }>();
    return row ? row.content : null;
  }

  private async fileList(version: string): Promise<string[]> {
    const res = await this.env.SEARCH_DB.prepare("SELECT path FROM files WHERE version = ?")
      .bind(version)
      .all<{ path: string }>();
    return res.results.map((r) => r.path);
  }

  private async crates(version: string): Promise<CrateRow[]> {
    const res = await this.env.SEARCH_DB.prepare(
      "SELECT name, path, description FROM crates WHERE version = ? ORDER BY name",
    )
      .bind(version)
      .all<CrateRow>();
    return res.results;
  }

  private async resolveCrate(version: string, crate: string): Promise<CrateRow | null> {
    const byName = await this.env.SEARCH_DB.prepare(
      "SELECT name, path, description FROM crates WHERE version = ? AND name = ?",
    )
      .bind(version, crate)
      .first<CrateRow>();
    if (byName) return byName;
    // Tolerate an unprefixed name (e.g. 'core' -> 'mkit-core').
    return this.env.SEARCH_DB.prepare(
      "SELECT name, path, description FROM crates WHERE version = ? AND name = ?",
    )
      .bind(version, `mkit-${stripCratePrefix(crate)}`)
      .first<CrateRow>();
  }

  private async allCommands(version: string): Promise<Array<{ name: string; summary: string }>> {
    const res = await this.env.SEARCH_DB.prepare(
      "SELECT name, summary FROM commands WHERE version = ? ORDER BY name",
    )
      .bind(version)
      .all<{ name: string; summary: string }>();
    return res.results;
  }

  private async command(
    version: string,
    name: string,
  ): Promise<{ name: string; body: string } | null> {
    return this.env.SEARCH_DB.prepare(
      "SELECT name, body FROM commands WHERE version = ? AND name = ?",
    )
      .bind(version, name)
      .first<{ name: string; body: string }>();
  }

  private async search(
    version: string,
    query: string,
    mode: "substring" | "word",
    crate: string | undefined,
    fileType: string,
    limit: number,
  ): Promise<Array<{ file: string; matches: string[] }>> {
    const { ftsQuery, snippetMatcher } = buildFTSQuery(query, mode);
    if (ftsQuery === null) return [];
    const ftsTable = mode === "substring" ? "files_fts_substring" : "files_fts_word";

    let sql = `SELECT f.path, f.content FROM ${ftsTable}
               JOIN files f ON ${ftsTable}.rowid = f.id
               WHERE ${ftsTable} MATCH ? AND f.version = ?`;
    const params: (string | number)[] = [ftsQuery, version];

    if (crate) {
      const row = await this.resolveCrate(version, crate);
      const folder = row ? row.path : crate;
      sql += " AND f.path LIKE ? ESCAPE '\\'";
      params.push(`${escapeLike(folder)}/%`);
    }
    if (fileType !== "all") {
      sql += " AND f.path LIKE ? ESCAPE '\\'";
      params.push(`%.${escapeLike(fileType)}`);
    }
    sql += ` ORDER BY bm25(${ftsTable}) LIMIT ?`;
    params.push(limit);

    const res = await this.env.SEARCH_DB.prepare(sql)
      .bind(...params)
      .all<{ path: string; content: string }>();

    return res.results.map((row) => {
      const lines = row.content.split("\n");
      const lineScores = lines.map((line) => snippetMatcher(line.toLowerCase()));
      const selected = selectTopSnippets(buildSnippets(lineScores), 5);
      return { file: row.path, matches: selected.map(({ start, end }) => formatSnippet(lines, start, end)) };
    });
  }
}

const mcpHandler = MkitMCP.serve("/", { binding: "MCP" });

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    return mcpHandler.fetch(request, env, ctx);
  },
};
