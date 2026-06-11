#!/usr/bin/env node
// Deploy-time corpus indexer for the mkit MCP.
//
// Walks the (private) mkit working tree and emits dist/seed.sql — a single
// transactional SQL file applied to D1 via `wrangler d1 execute --file`. This
// is the inversion of Commonware's cron-fetch-from-public-GitHub model: because
// the mkit repo is private, the corpus is baked at deploy from the source tree
// (CI has access) and served publicly from D1 with no runtime credentials.
//
// Pure Node, no dependencies — safe to run in CI before `wrangler deploy`.

import { readFileSync, writeFileSync, mkdirSync, readdirSync, statSync, existsSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseCrateInfo, parseCommands, parseWorkspaceVersion } from "./parse.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..", ".."); // mcp/scripts -> mcp -> repo root
const distDir = resolve(here, "..", "dist");

// --- helpers ---------------------------------------------------------------

const sqlStr = (s) => `'${String(s).replace(/'/g, "''")}'`;
const rel = (abs) => relative(repoRoot, abs).split("\\").join("/");

function read(abs) {
  return readFileSync(abs, "utf8");
}

// Cloudflare D1 rejects any single SQL statement over 100 KB (applies to
// `wrangler d1 execute --file`). Keep each emitted statement well under that.
const MAX_STMT_BYTES = 99_000;
// Raw chars per chunk: 45k chars escape to <=90k bytes even if every char is a
// quote (doubled), leaving ample room for the statement scaffolding.
const CHUNK_RAW_CHARS = 45_000;

/** Split a string into <=maxChars pieces without ever splitting a surrogate pair. */
function chunkString(s, maxChars) {
  const chunks = [];
  for (let i = 0; i < s.length; ) {
    let j = Math.min(s.length, i + maxChars);
    // Don't cut between a high and low surrogate.
    if (j < s.length) {
      const code = s.charCodeAt(j);
      if (code >= 0xdc00 && code <= 0xdfff) j -= 1;
    }
    chunks.push(s.slice(i, j));
    i = j;
  }
  return chunks;
}

/**
 * Emit the SQL to store one file's content. Small files are a single INSERT;
 * large ones are an INSERT plus `UPDATE ... content = content || '<chunk>'`
 * appends, so no single statement exceeds D1's per-statement cap. The FTS
 * AFTER-UPDATE trigger re-syncs the index to the full content after each append.
 */
function emitFile(out, ver, path, content) {
  const single = `INSERT INTO files (version, path, content) VALUES (${sqlStr(ver)}, ${sqlStr(path)}, ${sqlStr(content)});`;
  if (Buffer.byteLength(single, "utf8") <= MAX_STMT_BYTES) {
    out.push(single);
    return;
  }
  const [first, ...rest] = chunkString(content, CHUNK_RAW_CHARS);
  out.push(
    `INSERT INTO files (version, path, content) VALUES (${sqlStr(ver)}, ${sqlStr(path)}, ${sqlStr(first)});`,
  );
  for (const chunk of rest) {
    out.push(
      `UPDATE files SET content = content || ${sqlStr(chunk)} WHERE version = ${sqlStr(ver)} AND path = ${sqlStr(path)};`,
    );
  }
}

/** Recursively collect files under `dir` matching `test(path)`, skipping noise. */
function walk(dir, test, out = []) {
  if (!existsSync(dir)) return out;
  for (const entry of readdirSync(dir)) {
    if (entry === "target" || entry === "node_modules" || entry === ".git") continue;
    const abs = join(dir, entry);
    const st = statSync(abs);
    if (st.isDirectory()) walk(abs, test, out);
    else if (test(abs)) out.push(abs);
  }
  return out;
}

// --- collect corpus --------------------------------------------------------

const version = parseWorkspaceVersion(read(join(repoRoot, "rust", "Cargo.toml")));
const cratesRoot = join(repoRoot, "rust", "crates");

const files = new Map(); // repo-relative path -> content
const addFile = (abs) => {
  if (existsSync(abs) && statSync(abs).isFile()) files.set(rel(abs), read(abs));
};

// Crate sources (src/**/*.rs), Cargo.toml, and per-crate README.
const crates = [];
for (const dir of existsSync(cratesRoot) ? readdirSync(cratesRoot) : []) {
  const crateDir = join(cratesRoot, dir);
  if (!statSync(crateDir).isDirectory()) continue;
  const cargo = join(crateDir, "Cargo.toml");
  if (!existsSync(cargo)) continue;
  addFile(cargo);
  addFile(join(crateDir, "README.md"));
  for (const rs of walk(join(crateDir, "src"), (p) => p.endsWith(".rs"))) addFile(rs);
  const { name, description } = parseCrateInfo(read(cargo), `rust/crates/${dir}`);
  crates.push({ name, path: `rust/crates/${dir}`, description });
}
crates.sort((a, b) => a.name.localeCompare(b.name));

// docs/**/*.md (SPEC-*.md, CLI.md, PARITY.md, …) and top-level docs.
for (const md of walk(join(repoRoot, "docs"), (p) => p.endsWith(".md"))) addFile(md);
for (const f of ["README.md", "CHANGELOG.md", "GOVERNANCE.md", "SKILL.md", "man/mkit.1"]) {
  addFile(join(repoRoot, f));
}

// CLI subcommand corpus, parsed from docs/CLI.md.
const cliMdPath = join(repoRoot, "docs", "CLI.md");
const commands = existsSync(cliMdPath) ? parseCommands(read(cliMdPath)) : [];

// --- emit seed.sql ---------------------------------------------------------

const out = [];
out.push("BEGIN TRANSACTION;");
out.push(`DELETE FROM commands WHERE version = ${sqlStr(version)};`);
out.push(`DELETE FROM crates   WHERE version = ${sqlStr(version)};`);
out.push(`DELETE FROM files    WHERE version = ${sqlStr(version)};`);
out.push(`DELETE FROM versions WHERE version = ${sqlStr(version)};`);
for (const [path, content] of files) {
  emitFile(out, version, path, content);
}
for (const c of crates) {
  out.push(
    `INSERT INTO crates (version, name, path, description) VALUES (${sqlStr(version)}, ${sqlStr(c.name)}, ${sqlStr(c.path)}, ${sqlStr(c.description)});`,
  );
}
for (const c of commands) {
  out.push(
    `INSERT INTO commands (version, name, summary, body) VALUES (${sqlStr(version)}, ${sqlStr(c.name)}, ${sqlStr(c.summary)}, ${sqlStr(c.body)});`,
  );
}
out.push(`INSERT INTO versions (version) VALUES (${sqlStr(version)});`);
out.push("COMMIT;");

// Guard: D1 rejects any statement over 100 KB. Fail loudly here rather than at
// deploy time so an oversized file can never silently break `db:seed`.
const offenders = out
  .map((stmt) => [Buffer.byteLength(stmt, "utf8"), stmt])
  .filter(([bytes]) => bytes > MAX_STMT_BYTES);
if (offenders.length > 0) {
  const worst = offenders.sort((a, b) => b[0] - a[0])[0];
  throw new Error(
    `build-index: ${offenders.length} SQL statement(s) exceed ${MAX_STMT_BYTES} bytes ` +
      `(D1's per-statement cap). Largest is ${worst[0]} bytes: ${worst[1].slice(0, 120)}…`,
  );
}

mkdirSync(distDir, { recursive: true });
writeFileSync(join(distDir, "seed.sql"), out.join("\n") + "\n");
const manifest = {
  version,
  files: files.size,
  crates: crates.length,
  commands: commands.length,
  crateNames: crates.map((c) => c.name),
  commandNames: commands.map((c) => c.name),
};
writeFileSync(join(distDir, "manifest.json"), JSON.stringify(manifest, null, 2) + "\n");

console.log(
  `build-index: ${version} — ${files.size} files, ${crates.length} crates, ${commands.length} commands -> dist/seed.sql`,
);
