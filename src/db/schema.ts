export const SCHEMA = `
  CREATE TABLE IF NOT EXISTS records (
    input_hash  TEXT    PRIMARY KEY,
    namespace   TEXT    NOT NULL,
    key         TEXT    NOT NULL,
    value       TEXT    NOT NULL,
    timestamp   INTEGER NOT NULL,
    signature   TEXT    NOT NULL,
    source_peer TEXT
  );

  CREATE INDEX IF NOT EXISTS idx_records_ns_ts
    ON records (namespace, timestamp);

  CREATE TABLE IF NOT EXISTS peers (
    url             TEXT    PRIMARY KEY,
    last_sync_at    INTEGER NOT NULL DEFAULT 0,
    healthy         INTEGER NOT NULL DEFAULT 1,
    node_version    TEXT,
    signer_address  TEXT
  );
`
