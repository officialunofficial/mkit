#!/usr/bin/env node
// Deploy-time corpus indexer for the mkit MCP.
//
// Walks the mkit working tree and emits dist/seed.sql — a single
// transactional SQL file applied to D1 via `wrangler d1 execute --file`. The
// corpus is baked at deploy time from the source tree (rather than cron-fetched
// at runtime) and served publicly from D1 with no runtime credentials.
//
// Pure Node, no dependencies — safe to run in CI before `wrangler deploy`.

import { readFileSync, writeFileSync, mkdirSync, readdirSync, statSync, existsSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseCrateInfo, parseCommands, parseWorkspaceVersion } from "./parse.mjs";
import { sqlStr, fileStatements, findOversized } from "./seed.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..", ".."); // mcp/scripts -> mcp -> repo root
const distDir = resolve(here, "..", "dist");

// Cloudflare D1 rejects any single SQL statement over 100 KB (applies to
// `wrangler d1 execute --file`). fileStatements keeps each statement under this.
const MAX_STMT_BYTES = 99_000;

// --- helpers ---------------------------------------------------------------

const rel = (abs) => relative(repoRoot, abs).split("\\").join("/");

function read(abs) {
  return readFileSync(abs, "utf8");
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

// No `BEGIN TRANSACTION;`/`COMMIT;` wrapper: `wrangler d1 execute --file` runs
// its own transaction and naively strips the first BEGIN/COMMIT it finds, then
// throws if "BEGIN TRANSACTION" appears again. Since the seed embeds whole repo
// files as string literals, our own wrapper would (a) always trip that path and
// (b) let a doc that merely contains "COMMIT;" get silently mangled. Omitting it
// makes the trimmer a no-op; re-seeding stays idempotent via delete-by-version.
const out = [];
out.push(`DELETE FROM commands WHERE version = ${sqlStr(version)};`);
out.push(`DELETE FROM crates   WHERE version = ${sqlStr(version)};`);
out.push(`DELETE FROM files    WHERE version = ${sqlStr(version)};`);
out.push(`DELETE FROM versions WHERE version = ${sqlStr(version)};`);
for (const [path, content] of files) {
  out.push(...fileStatements(version, path, content, MAX_STMT_BYTES));
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

// Guard 1: D1 rejects any statement over 100 KB. Fail loudly here, not at deploy.
const offenders = findOversized(out, MAX_STMT_BYTES);
if (offenders.length > 0) {
  const [worstBytes, worstStmt] = offenders[0];
  throw new Error(
    `build-index: ${offenders.length} SQL statement(s) exceed ${MAX_STMT_BYTES} bytes ` +
      `(D1's per-statement cap). Largest is ${worstBytes} bytes: ${worstStmt.slice(0, 120)}…`,
  );
}

// Guard 2: a corpus file literally containing "BEGIN TRANSACTION" would make
// wrangler's trimmer mangle/reject the seed. Catch it at index time with a clear
// message rather than a baffling deploy failure.
const seedText = out.join("\n") + "\n";
if (seedText.includes("BEGIN TRANSACTION")) {
  throw new Error(
    'build-index: a corpus file contains the literal "BEGIN TRANSACTION", which ' +
      "breaks `wrangler d1 execute --file` (its transaction trimmer). Rename/escape " +
      "the offending occurrence or exclude that file from the index.",
  );
}

mkdirSync(distDir, { recursive: true });
writeFileSync(join(distDir, "seed.sql"), seedText);
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
