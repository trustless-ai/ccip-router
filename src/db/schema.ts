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
  {
    version: 2,
    sql: `
      CREATE TABLE IF NOT EXISTS ens_records (
        name        TEXT    NOT NULL,
        type        TEXT    NOT NULL,
        coin_type   INTEGER NOT NULL DEFAULT -1,
        text_key    TEXT    NOT NULL DEFAULT '',
        value       TEXT    NOT NULL,
        modified_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
        PRIMARY KEY (name, type, coin_type, text_key)
      );
    `,
  },
  {
    version: 3,
    sql: `
      CREATE TABLE IF NOT EXISTS messages (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        from_url    TEXT    NOT NULL,
        from_signer TEXT    NOT NULL,
        type        TEXT    NOT NULL,
        body        TEXT    NOT NULL,
        version     TEXT    NOT NULL DEFAULT '',
        signature   TEXT    NOT NULL,
        timestamp   INTEGER NOT NULL,
        received_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
        read        INTEGER NOT NULL DEFAULT 0,
        official    INTEGER NOT NULL DEFAULT 0
      );
      CREATE INDEX IF NOT EXISTS idx_messages_read ON messages (read);
    `,
  },
  {
    version: 4,
    sql: `
      CREATE TABLE IF NOT EXISTS join_requests (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        url            TEXT    NOT NULL,
        signature      TEXT    NOT NULL,
        signer_address TEXT    NOT NULL,
        status         TEXT    NOT NULL DEFAULT 'pending',
        health_ok      INTEGER NOT NULL DEFAULT 0,
        health_data    TEXT,
        created_at     INTEGER NOT NULL DEFAULT (strftime('%s','now')),
        UNIQUE(signer_address)
      );
    `,
  },
]
