# mkit-server-native

The native (tokio) adapter of the mkit server. This crate currently holds the
`SQLite` metadata backend:

- `RusqliteConn`: `mkit-server`'s synchronous `SqlConn` over a local `SQLite`
  file (rusqlite, `SQLite` bundled; `sqlite` feature, on by default)
- `Blocking<S>`: runs a store whose bodies are synchronous on tokio's
  blocking pool, keeping `apply` cancellation-safe
- `SqliteKvStore`: `Blocking<SqlKvStore<RusqliteConn>>`, the `NamespaceStore`
  a native server uses

The store logic is `mkit-server`'s `SqlKvStore`, shared with the Durable
Object backend: both run the same statements and the same schema migrations.
The HTTP router, the filesystem blob store and the `mkit-server` binary come
later.

## Operations

### File layout

One database file holds every partition: the `kv` table is keyed by
`(part, key)`, where `part` is the partition's portable encoding. The
`mkit_schema` table records the physical schema version. With WAL, `SQLite`
keeps two companion files next to the database, `<file>-wal` and
`<file>-shm`; they are part of the database while it is open.

The connection runs with `journal_mode = WAL`, `synchronous = FULL` (a
committed batch is on disk before `apply` returns) and a 5 s busy timeout.
Several processes may open one file, but `SQLite` has a single writer:
batches from every partition commit one at a time.

### Migrations

Opening a store (`SqlKvStore::open`) applies any missing physical migrations,
each in its own transaction. They are forward-only and idempotent. A database
whose recorded schema is newer than the binary's is refused with
`StoreError::Unsupported` and left untouched: there is no downgrade, so take
a backup before upgrading. New key layouts need no physical migration; the
per-partition layout version (the `v` row) covers them.

### Physical backup

Take a consistent copy of the whole database, online, with
`StoreMaintenance::backup_to(dest)`, which runs `VACUUM INTO '<dest>'`
(`RusqliteConn`'s backup hook; the shared SQL store has no engine-specific
backup of its own, and a Durable Object uses the portable export). `dest`
must not exist. The copy is compacted and self-contained (no WAL files). The
`sqlite3` shell's `.backup` command, or `VACUUM INTO` from any `SQLite`
client, works too. Do not copy the database file alone while the server runs:
recent commits may still sit in `<file>-wal`.

To restore, stop the server, move the database and its `-wal` and `-shm`
files aside, put the backup in the database's place, and start the server.
Migrations run on open, so a backup from an older binary is brought forward.

### Portable logical backup

`mkit_server::store::export_partition` streams one partition's rows in the
backend-neutral export format, and `import_stream` restores them into any
backend: another `SQLite` file, a Durable Object, the in-memory store. Use it
to move between backends or to back up single partitions. It is not a
snapshot: export a quiesced partition. `ImportMode::Fresh` restores into
empty partitions; an interrupted import can be rerun with
`ImportMode::Merge`.

### Capacity

Open the store with `SqlKvStore::open_with_capacity(conn, Capacity::new(cap))`.
`cap` is the hard limit, which the connection enforces as `max_page_count`.
Once the database uses `cap - reserve` bytes (pages holding data; free pages
don't count), batches that add data fail with `StoreError::Full`. Reads and
delete-only batches keep working, so pruning can still run.

The reserve exists because deleting from the b-tree can itself need new
pages. The default is the larger of about 20 MiB (two maximal batches'
worst-case growth at 4 KiB pages) and `cap / 64`; `Capacity::with_reserve`
overrides it. See `mkit_server::sql::Capacity` for the derivation.

`SQLITE_FULL` means `Full` only at the page limit. A full host disk reports the
same code, but surfaces as `StoreError::Unavailable`, because deleting rows
does not free disk space (the file never shrinks without `VACUUM`). Watch the
host's free space separately.
