/**
 * Runtime helpers for the mkit MCP server.
 *
 * Snippet ranking / formatting / file-tree logic is adapted from the
 * Commonware MCP (the closest analog — a version-pinned Rust-workspace docs
 * MCP). The corpus-parsing helpers it used at index time live in
 * scripts/build-index.mjs instead, since mkit bakes its corpus at deploy.
 */

/** An MCP tool result: a content array, optionally flagged as an error. */
export interface ToolResult {
  content: Array<{ type: "text"; text: string }>;
  isError?: boolean;
}

export const err = (text: string): ToolResult => ({
  content: [{ type: "text" as const, text }],
  isError: true,
});
export const ok = (text: string): ToolResult => ({ content: [{ type: "text" as const, text }] });

/**
 * Raised by the D1 layer when the corpus has no indexed versions (empty or
 * un-seeded database). Distinguished from a genuine D1 outage so tool handlers
 * can return a clear "index is empty/unavailable" message instead of a generic
 * failure. See `guardTool`.
 */
export class EmptyCorpusError extends Error {
  constructor(message = "No versions indexed") {
    super(message);
    this.name = "EmptyCorpusError";
  }
}

/** Stable prefix for all structured error logs (greppable in Cloudflare logs). */
export const LOG_PREFIX = "[mkit-mcp]";

const EMPTY_CORPUS_MESSAGE =
  "The mkit documentation index is empty or unavailable right now — no versions are indexed. " +
  "Please try again later.";
const D1_FAILURE_MESSAGE =
  "The mkit documentation index is temporarily unavailable (backend error). Please try again later.";

/**
 * Wrap a tool callback so a thrown D1 error (or any exception) becomes a
 * graceful MCP error result rather than an unhandled exception surfaced to the
 * client. Logs the failure with a stable prefix + tool name for Cloudflare
 * observability. Empty-corpus throws get a distinct, clearer message.
 *
 * `console.error` deliberately logs the error only (tool name + message/stack),
 * never the caller's arguments, to avoid leaking query/content payloads.
 */
export function guardTool<TArgs>(
  name: string,
  cb: (args: TArgs) => Promise<ToolResult> | ToolResult,
): (args: TArgs) => Promise<ToolResult> {
  return async (args: TArgs) => {
    try {
      return await cb(args);
    } catch (e) {
      if (e instanceof EmptyCorpusError) {
        console.error(`${LOG_PREFIX} tool=${name} empty-corpus:`, e.message);
        return err(EMPTY_CORPUS_MESSAGE);
      }
      console.error(`${LOG_PREFIX} tool=${name} d1-error:`, e instanceof Error ? e.stack ?? e.message : e);
      return err(D1_FAILURE_MESSAGE);
    }
  };
}

/** Sort semver-ish version tags (e.g. v0.2.0) in descending order, in place. */
export function sortVersionsDesc(versions: string[]): void {
  // Parse only the numeric X.Y.Z core; drop any -prerelease/+build suffix so a
  // tag like v0.3.0-rc1 doesn't yield NaN (which makes the sort unstable and
  // "latest" nondeterministic). NaN-guard each component to 0. Known limitation:
  // a pre-release ties with its release (v0.3.0-rc1 == v0.3.0) — fine here, where
  // indexed versions are always plain X.Y.Z workspace versions.
  const core = (v: string) =>
    v
      .replace(/^v/, "")
      .split(/[-+]/)[0]
      .split(".")
      .map((n) => Number(n) || 0);
  versions.sort((a, b) => {
    const partsA = core(a);
    const partsB = core(b);
    for (let i = 0; i < 3; i++) {
      if ((partsA[i] ?? 0) !== (partsB[i] ?? 0)) {
        return (partsB[i] ?? 0) - (partsA[i] ?? 0);
      }
    }
    return 0;
  });
}

/** Language hint for fenced code blocks, by file extension. */
export function getLanguage(path: string): string {
  if (path.endsWith(".rs")) return "rust";
  if (path.endsWith(".toml")) return "toml";
  if (path.endsWith(".md")) return "markdown";
  return "";
}

/** Crate names are `mkit-*`; folder paths under rust/crates/ keep the prefix. */
export function stripCratePrefix(name: string): string {
  return name.replace(/^mkit-/, "");
}

/** Reject path traversal / absolute paths. */
export function isValidPath(path: string): boolean {
  if (path.includes("..")) return false;
  if (path.startsWith("/")) return false;
  return true;
}

/** A span of consecutive lines with a cumulative match score. */
export interface Snippet {
  start: number; // first line index (0-based)
  end: number; // one past last line index (exclusive)
  score: number;
}

/** Build candidate snippet windows centered on each matching line. */
export function buildSnippets(lineScores: number[], windowSize = 7): Snippet[] {
  const snippets: Snippet[] = [];
  const halfWindow = Math.floor(windowSize / 2);
  const totalLines = lineScores.length;

  for (let lineNum = 0; lineNum < totalLines; lineNum++) {
    if (lineScores[lineNum] <= 0) continue;
    const start = Math.max(0, lineNum - halfWindow);
    const end = Math.min(totalLines, lineNum + halfWindow + 1);
    let totalScore = 0;
    for (let i = start; i < end; i++) totalScore += lineScores[i];
    snippets.push({ start, end, score: totalScore });
  }
  return snippets;
}

/** True if more than half of the candidate's lines overlap the selected span. */
export function hasMajorityOverlap(
  candidateStart: number,
  candidateEnd: number,
  selectedStart: number,
  selectedEnd: number,
): boolean {
  const overlapStart = Math.max(candidateStart, selectedStart);
  const overlapEnd = Math.min(candidateEnd, selectedEnd);
  const overlapCount = Math.max(0, overlapEnd - overlapStart);
  const candidateSize = candidateEnd - candidateStart;
  return overlapCount > candidateSize / 2;
}

/** Pick the top non-overlapping snippets by score. */
export function selectTopSnippets(
  snippets: Snippet[],
  maxSnippets: number,
): Array<{ start: number; end: number }> {
  const sorted = [...snippets].filter((s) => s.score > 0).sort((a, b) => b.score - a.score);
  const selected: Array<{ start: number; end: number }> = [];
  for (const snippet of sorted) {
    if (selected.length >= maxSnippets) break;
    const { start, end } = snippet;
    let hasOverlap = false;
    for (const sel of selected) {
      if (hasMajorityOverlap(start, end, sel.start, sel.end)) {
        hasOverlap = true;
        break;
      }
    }
    if (!hasOverlap) selected.push({ start, end });
  }
  return selected;
}

/** Render a snippet with 0-indexed line numbers (matches formatWithLineNumbers). */
export function formatSnippet(lines: string[], start: number, end: number): string {
  return lines
    .slice(start, end)
    .map((l, idx) => `${start + idx}: ${l}`)
    .join("\n");
}

/** Render file content with 0-indexed line numbers, optionally a range. */
export function formatWithLineNumbers(
  content: string,
  startLine?: number,
  endLine?: number,
): string {
  const lines = content.split("\n");
  const start = startLine !== undefined ? Math.max(0, startLine) : 0;
  const end = endLine !== undefined ? Math.min(lines.length - 1, endLine) : lines.length - 1;
  if (start > end || start >= lines.length) return "";
  return lines
    .slice(start, end + 1)
    .map((line, idx) => `${start + idx}: ${line}`)
    .join("\n");
}

/** Render a list of file paths as an indented tree, relative to `prefix`. */
export function buildFileTree(files: string[], prefix: string): string {
  const tree: Map<string, string[]> = new Map();
  for (const file of files) {
    const relative = file.slice(prefix.length);
    const parts = relative.split("/");
    const dir = parts.length > 1 ? parts.slice(0, -1).join("/") : ".";
    const filename = parts[parts.length - 1];
    if (!tree.has(dir)) tree.set(dir, []);
    tree.get(dir)!.push(filename);
  }
  const lines: string[] = [];
  const sortedDirs = [...tree.keys()].sort();
  for (const dir of sortedDirs) {
    if (dir !== ".") lines.push(`${dir}/`);
    const filesInDir = tree.get(dir)!.sort();
    for (const file of filesInDir) {
      lines.push(dir === "." ? file : `  ${file}`);
    }
  }
  return lines.join("\n");
}

/** Build an FTS5 query + a per-line scorer for snippet selection. */
export function buildFTSQuery(
  query: string,
  mode: "substring" | "word",
): { ftsQuery: string | null; snippetMatcher: (line: string) => number } {
  const trimmed = query.trim();
  if (mode === "substring") {
    if (trimmed.length < 3) return { ftsQuery: null, snippetMatcher: () => 0 };
    const escaped = trimmed.replace(/"/g, '""');
    const queryLower = trimmed.toLowerCase();
    return {
      ftsQuery: `"${escaped}"`,
      snippetMatcher: (line) => {
        let count = 0;
        let idx = 0;
        while ((idx = line.indexOf(queryLower, idx)) !== -1) {
          count++;
          idx += queryLower.length;
        }
        return count;
      },
    };
  }
  // Whitelist FTS5-safe bareword characters: anything else (".", "/", "'", ",",
  // "=", "-", quotes, parens, …) becomes a separator. Blacklisting misses
  // punctuation that makes FTS5 throw "syntax error" — e.g. 'envelope.sign' or
  // 'trust-roots.toml', which are realistic queries and this is search_docs's
  // default mode.
  const escaped = trimmed.replace(/[^\p{L}\p{N}_]+/gu, " ").trim();
  const words = escaped.split(/\s+/).filter((w) => w.length > 0);
  if (words.length === 0) return { ftsQuery: null, snippetMatcher: () => 0 };
  const ftsQuery = words.map((w) => `${w}*`).join(" ");
  const wordsLower = words.map((w) => w.toLowerCase());
  return {
    ftsQuery,
    snippetMatcher: (line) => {
      let count = 0;
      for (const word of wordsLower) {
        let idx = 0;
        while ((idx = line.indexOf(word, idx)) !== -1) {
          count++;
          idx += word.length;
        }
      }
      return count;
    },
  };
}

/** Escape SQL LIKE wildcards for use with `ESCAPE '\'`. */
export function escapeLike(s: string): string {
  return s.replace(/[%_\\]/g, "\\$&");
}
