-- mkit MCP search/corpus schema.
--
-- All content is baked at deploy time from the mkit working tree by
-- scripts/build-index.mjs and applied via `wrangler d1 execute --file`. Content
-- is stored here (not fetched at runtime), so the public Worker never needs
-- repo credentials. Rows are keyed by version so multiple releases coexist;
-- the published-version dimension is forward-compatible with future deploys.

-- Every indexed file: crate source, docs/SPEC-*.md, READMEs, CLI reference, SKILL.md.
CREATE TABLE IF NOT EXISTS files (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  version TEXT NOT NULL,
  path TEXT NOT NULL,
  content TEXT NOT NULL,
  UNIQUE(version, path)
);
CREATE INDEX IF NOT EXISTS idx_files_version ON files(version);

-- FTS5 over files: trigram for literal substring search, unicode61 for word search.
CREATE VIRTUAL TABLE IF NOT EXISTS files_fts_substring USING fts5(
  path, content, content='files', content_rowid='id', tokenize='trigram'
);
CREATE VIRTUAL TABLE IF NOT EXISTS files_fts_word USING fts5(
  path, content, content='files', content_rowid='id', tokenize='unicode61'
);

CREATE TRIGGER IF NOT EXISTS files_ai AFTER INSERT ON files BEGIN
  INSERT INTO files_fts_substring(rowid, path, content) VALUES (new.id, new.path, new.content);
  INSERT INTO files_fts_word(rowid, path, content) VALUES (new.id, new.path, new.content);
END;
CREATE TRIGGER IF NOT EXISTS files_ad AFTER DELETE ON files BEGIN
  INSERT INTO files_fts_substring(files_fts_substring, rowid, path, content) VALUES ('delete', old.id, old.path, old.content);
  INSERT INTO files_fts_word(files_fts_word, rowid, path, content) VALUES ('delete', old.id, old.path, old.content);
END;
CREATE TRIGGER IF NOT EXISTS files_au AFTER UPDATE ON files BEGIN
  INSERT INTO files_fts_substring(files_fts_substring, rowid, path, content) VALUES ('delete', old.id, old.path, old.content);
  INSERT INTO files_fts_substring(rowid, path, content) VALUES (new.id, new.path, new.content);
  INSERT INTO files_fts_word(files_fts_word, rowid, path, content) VALUES ('delete', old.id, old.path, old.content);
  INSERT INTO files_fts_word(rowid, path, content) VALUES (new.id, new.path, new.content);
END;

-- Workspace crates (name + folder path + description from each Cargo.toml).
CREATE TABLE IF NOT EXISTS crates (
  version TEXT NOT NULL,
  name TEXT NOT NULL,
  path TEXT NOT NULL,
  description TEXT NOT NULL,
  UNIQUE(version, name)
);
CREATE INDEX IF NOT EXISTS idx_crates_version ON crates(version);

-- CLI subcommands parsed from docs/CLI.md (name + one-line summary + full prose).
CREATE TABLE IF NOT EXISTS commands (
  version TEXT NOT NULL,
  name TEXT NOT NULL,
  summary TEXT NOT NULL,
  body TEXT NOT NULL,
  UNIQUE(version, name)
);
CREATE INDEX IF NOT EXISTS idx_commands_version ON commands(version);

-- Available indexed versions (newest wins as "latest").
CREATE TABLE IF NOT EXISTS versions (
  version TEXT PRIMARY KEY,
  indexed_at TEXT NOT NULL DEFAULT (datetime('now'))
);
