import Database from 'better-sqlite3'
import { SCHEMA } from './schema.js'
import type { DB, MeshRecord, PeerState } from './types.js'

type RecordRow = {
  input_hash: string
  namespace: string
  key: string
  value: string
  timestamp: number
  signature: string
  source_peer: string | null
}

type PeerRow = {
  url: string
  last_sync_at: number
  healthy: number
  node_version: string | null
  signer_address: string | null
}

export class SQLiteDB implements DB {
  private db: Database.Database

  private stmts: {
    insert: Database.Statement
    getSince: Database.Statement
    getSinceAfterCursor: Database.Statement
    getOne: Database.Statement
    upsertPeer: Database.Statement
    getPeers: Database.Statement
    count: Database.Statement
    recent: Database.Statement
    removePeer: Database.Statement
    doubleSigns: Database.Statement
  }

  constructor(path: string) {
    this.db = new Database(path)
    this.db.pragma('journal_mode = WAL')
    this.db.pragma('foreign_keys = ON')
    this.db.exec(SCHEMA)

    this.stmts = {
      insert: this.db.prepare(`
        INSERT OR IGNORE INTO records
          (input_hash, namespace, key, value, timestamp, signature, source_peer)
        VALUES
          (@inputHash, @namespace, @key, @value, @timestamp, @signature, @sourcePeer)
      `),

      // cursor is composite: timestamp|input_hash — avoids skipping records
      // when multiple records share the same timestamp
      getSince: this.db.prepare(`
        SELECT * FROM records
        WHERE namespace = @namespace AND timestamp > @since
        ORDER BY timestamp ASC, input_hash ASC
        LIMIT @limit
      `),

      getSinceAfterCursor: this.db.prepare(`
        SELECT * FROM records
        WHERE namespace = @namespace
          AND (
            timestamp > @cursorTs
            OR (timestamp = @cursorTs AND input_hash > @cursorHash)
          )
        ORDER BY timestamp ASC, input_hash ASC
        LIMIT @limit
      `),

      getOne: this.db.prepare(`
        SELECT * FROM records WHERE input_hash = ?
      `),

      upsertPeer: this.db.prepare(`
        INSERT INTO peers (url, last_sync_at, healthy, node_version, signer_address)
        VALUES (@url, @lastSyncAt, @healthy, @nodeVersion, @signerAddress)
        ON CONFLICT(url) DO UPDATE SET
          last_sync_at   = excluded.last_sync_at,
          healthy        = excluded.healthy,
          node_version   = excluded.node_version,
          signer_address = excluded.signer_address
      `),

      getPeers: this.db.prepare(`SELECT * FROM peers`),

      count: this.db.prepare(`
        SELECT COUNT(*) as n FROM records WHERE namespace = ?
      `),

      recent: this.db.prepare(`
        SELECT * FROM records
        WHERE namespace = ?
        ORDER BY timestamp DESC
        LIMIT ?
      `),

      removePeer: this.db.prepare(`
        DELETE FROM peers WHERE url = ?
      `),

      // detect two records with same input_hash but different signatures — slashable
      // keep these last — doubleSigns must be after recent + removePeer
    doubleSigns: this.db.prepare(`
        SELECT input_hash FROM records
        WHERE input_hash = @inputHash AND signature != @signature
      `),
    }
  }

  async insertRecord(record: MeshRecord): Promise<void> {
    const existing = this.stmts.doubleSigns.get({
      inputHash: record.inputHash,
      signature: record.signature,
    })
    if (existing) {
      console.warn(`[double-sign] input_hash=${record.inputHash} — flagged for future slashing`)
    }

    this.stmts.insert.run({
      inputHash:  record.inputHash,
      namespace:  record.namespace,
      key:        record.key,
      value:      record.value,
      timestamp:  record.timestamp,
      signature:  record.signature,
      sourcePeer: record.sourcePeer,
    })
  }

  async getRecordsSince(
    namespace: string,
    since: number,
    limit: number,
    cursor?: string,
  ): Promise<MeshRecord[]> {
    let rows: RecordRow[]

    if (cursor) {
      const [cursorTs, cursorHash] = cursor.split('|')
      rows = this.stmts.getSinceAfterCursor.all({
        namespace,
        cursorTs:   Number(cursorTs),
        cursorHash,
        limit,
      }) as RecordRow[]
    } else {
      rows = this.stmts.getSince.all({ namespace, since, limit }) as RecordRow[]
    }

    return rows.map(toMeshRecord)
  }

  async getRecord(inputHash: string): Promise<MeshRecord | null> {
    const row = this.stmts.getOne.get(inputHash) as RecordRow | undefined
    return row ? toMeshRecord(row) : null
  }

  async upsertPeer(peer: PeerState): Promise<void> {
    this.stmts.upsertPeer.run({
      url:           peer.url,
      lastSyncAt:    peer.lastSyncAt,
      healthy:       peer.healthy ? 1 : 0,
      nodeVersion:   peer.nodeVersion,
      signerAddress: peer.signerAddress,
    })
  }

  async getPeers(): Promise<PeerState[]> {
    const rows = this.stmts.getPeers.all() as PeerRow[]
    return rows.map(toPeerState)
  }

  async recordCount(namespace: string): Promise<number> {
    const row = this.stmts.count.get(namespace) as { n: number }
    return row.n
  }

  async getRecentRecords(namespace: string, limit: number): Promise<MeshRecord[]> {
    const rows = this.stmts.recent.all(namespace, limit) as RecordRow[]
    return rows.map(toMeshRecord)
  }

  async removePeer(url: string): Promise<void> {
    this.stmts.removePeer.run(url)
  }

  close(): void {
    this.db.close()
  }
}

function toMeshRecord(row: RecordRow): MeshRecord {
  return {
    inputHash:  row.input_hash,
    namespace:  row.namespace,
    key:        row.key,
    value:      row.value,
    timestamp:  row.timestamp,
    signature:  row.signature,
    sourcePeer: row.source_peer,
  }
}

function toPeerState(row: PeerRow): PeerState {
  return {
    url:           row.url,
    lastSyncAt:    row.last_sync_at,
    healthy:       row.healthy === 1,
    nodeVersion:   row.node_version,
    signerAddress: row.signer_address,
  }
}
