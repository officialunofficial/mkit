// Type declarations for the dependency-free SQL-emit helpers in seed.mjs.
export function sqlStr(s: unknown): string;
export function chunkContentByBytes(content: string, maxEscapedBytes: number): string[];
export function fileStatements(
  ver: string,
  path: string,
  content: string,
  maxStmtBytes: number,
): string[];
export function findOversized(
  statements: string[],
  maxBytes: number,
): Array<[number, string]>;
