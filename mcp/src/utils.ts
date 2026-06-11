/**
 * Runtime helpers for the mkit MCP server.
 *
 * Snippet ranking / formatting / file-tree logic is adapted from the
 * Commonware MCP (the closest analog — a version-pinned Rust-workspace docs
 * MCP). The corpus-parsing helpers it used at index time live in
 * scripts/build-index.mjs instead, since mkit bakes its corpus at deploy.
 */

/** Sort semver-ish version tags (e.g. v0.2.0) in descending order, in place. */
export function sortVersionsDesc(versions: string[]): void {
  versions.sort((a, b) => {
    const partsA = a.replace(/^v/, "").split(".").map(Number);
    const partsB = b.replace(/^v/, "").split(".").map(Number);
    for (let i = 0; i < 3; i++) {
      if (partsA[i] !== partsB[i]) {
        return partsB[i] - partsA[i];
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
  const escaped = trimmed.replace(/["()*:^-]/g, " ").trim();
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
