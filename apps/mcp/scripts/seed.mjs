// Pure, dependency-free SQL-emit helpers for the deploy-time indexer. Kept
// side-effect-free so the risky size/chunking logic is unit-testable.

/** SQLite string literal: single-quote and double interior quotes. */
export const sqlStr = (s) => `'${String(s).replace(/'/g, "''")}'`;

/** UTF-8 byte length of a string. */
const bytes = (s) => Buffer.byteLength(s, "utf8");

/**
 * Split `content` into pieces whose *escaped* (`'`→`''`) UTF-8 byte length each
 * fits within `maxEscapedBytes`. Iterates by code point so a surrogate pair is
 * never split, and always makes progress (≥1 code point per chunk) so it can't
 * loop. Concatenating the pieces reproduces `content` exactly.
 *
 * This is byte-aware, not char-aware: 45k chars of multi-byte text (CJK,
 * box-drawing) encode to ~135k bytes, which a char-count split would overflow.
 */
export function chunkContentByBytes(content, maxEscapedBytes) {
  const chunks = [];
  let start = 0;
  let acc = 0;
  let i = 0;
  while (i < content.length) {
    const code = content.charCodeAt(i);
    const isPair = code >= 0xd800 && code <= 0xdbff && i + 1 < content.length;
    const cp = isPair ? content.slice(i, i + 2) : content[i];
    const step = isPair ? 2 : 1;
    const cost = cp === "'" ? 2 : bytes(cp);
    if (acc + cost > maxEscapedBytes && i > start) {
      chunks.push(content.slice(start, i));
      start = i;
      acc = 0;
    }
    acc += cost;
    i += step;
  }
  if (start < content.length || chunks.length === 0) chunks.push(content.slice(start));
  return chunks;
}

/**
 * SQL statements that store one file's content. Small files are a single
 * INSERT; large ones are an INSERT plus `UPDATE … content = content || '<chunk>'`
 * appends, so no statement exceeds D1's per-statement cap. The FTS AFTER-UPDATE
 * trigger re-syncs the index to the full content after each append.
 */
export function fileStatements(ver, path, content, maxStmtBytes) {
  const single = `INSERT INTO files (version, path, content) VALUES (${sqlStr(ver)}, ${sqlStr(path)}, ${sqlStr(content)});`;
  if (bytes(single) <= maxStmtBytes) return [single];

  // Budget for the escaped content = cap minus the largest scaffold (the empty
  // '' already accounts for the quotes the content sits between).
  const insertScaffold = `INSERT INTO files (version, path, content) VALUES (${sqlStr(ver)}, ${sqlStr(path)}, '');`;
  const updateScaffold = `UPDATE files SET content = content || '' WHERE version = ${sqlStr(ver)} AND path = ${sqlStr(path)};`;
  const budget = maxStmtBytes - Math.max(bytes(insertScaffold), bytes(updateScaffold));
  const chunks = chunkContentByBytes(content, budget);

  const stmts = [
    `INSERT INTO files (version, path, content) VALUES (${sqlStr(ver)}, ${sqlStr(path)}, ${sqlStr(chunks[0])});`,
  ];
  for (let k = 1; k < chunks.length; k++) {
    stmts.push(
      `UPDATE files SET content = content || ${sqlStr(chunks[k])} WHERE version = ${sqlStr(ver)} AND path = ${sqlStr(path)};`,
    );
  }
  return stmts;
}

/** Return [byteLength, statement] for every statement over `maxBytes`. */
export function findOversized(statements, maxBytes) {
  return statements
    .map((s) => [bytes(s), s])
    .filter(([b]) => b > maxBytes)
    .sort((a, b) => b[0] - a[0]);
}
