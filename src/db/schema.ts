// schema_version tracks applied migrations.
// Run SCHEMA first (creates the version table if missing), then runMigrations().
export const SCHEMA = `
  CREATE TABLE IF NOT EXISTS schema_version (
    version  INTEGER PRIMARY KEY,
    applied_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
  );

  CREATE TABLE IF NOT EXISTS peers (
    url             TEXT    PRIMARY KEY,
    last_sync_at    INTEGER NOT NULL DEFAULT 0,
    healthy         INTEGER NOT NULL DEFAULT 1,
    node_version    TEXT,
    signer_address  TEXT
  );
`

// Ordered migrations — each runs exactly once, gated by schema_version.
// v1: composite PK (input_hash, namespace) replaces single-column input_hash PK,
//     allowing WYRIWE attestation records to coexist with basic records
//     for the same calldata in a different namespace.
export const MIGRATIONS: { version: number; sql: string }[] = [
  {
    version: 1,
    sql: `
      DROP TABLE IF EXISTS records;
      CREATE TABLE records (
        input_hash  TEXT    NOT NULL,
        namespace   TEXT    NOT NULL,
        key         TEXT    NOT NULL,
        value       TEXT    NOT NULL,
        timestamp   INTEGER NOT NULL,
        signature   TEXT    NOT NULL,
        source_peer TEXT,
        PRIMARY KEY (input_hash, namespace)
      );
      CREATE INDEX IF NOT EXISTS idx_records_ns_ts
        ON records (namespace, timestamp);
    `,
  },
]
