import Database from 'better-sqlite3'
import { SCHEMA, MIGRATIONS } from './schema.js'
import type { DB, MeshRecord, PeerState, Contribution, NameRecord, Message, MessageType } from './types.js'

type EnsRow = {
  name:        string
  type:        string
  coin_type:   number
  text_key:    string
  value:       string
  modified_at: number
}

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
    getOneNs: Database.Statement
    getAllByHash: Database.Statement
    upsertPeer: Database.Statement
    getPeers: Database.Statement
    count: Database.Statement
    recent: Database.Statement
    removePeer: Database.Statement
    contributions: Database.Statement
    doubleSigns: Database.Statement
    ensUpsert: Database.Statement
    ensDelete: Database.Statement
    ensGet: Database.Statement
    ensList: Database.Statement
    ensListAll: Database.Statement
    msgInsert:      Database.Statement
    msgList:        Database.Statement
    msgMarkRead:    Database.Statement
    msgMarkAllRead: Database.Statement
    msgUnreadCount: Database.Statement
  }

  constructor(path: string) {
    this.db = new Database(path)
    this.db.pragma('journal_mode = WAL')
    this.db.pragma('foreign_keys = ON')
    this.db.exec(SCHEMA)
    this.runMigrations()

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

      // first match across all namespaces (basic tier lookup)
      getOne: this.db.prepare(`
        SELECT * FROM records WHERE input_hash = ? LIMIT 1
      `),

      // exact match on composite PK
      getOneNs: this.db.prepare(`
        SELECT * FROM records WHERE input_hash = ? AND namespace = ?
      `),

      // all records for an inputHash across every namespace (used by /verify)
      getAllByHash: this.db.prepare(`
        SELECT * FROM records WHERE input_hash = ? ORDER BY namespace ASC
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

      ensNameCount: this.db.prepare(`
        SELECT COUNT(DISTINCT name) as n FROM ens_records
      `),

      recent: this.db.prepare(`
        SELECT * FROM records
        WHERE namespace = ?
        ORDER BY timestamp DESC
        LIMIT ?
      `),

      removePeer: this.db.prepare(`DELETE FROM peers WHERE url = ?`),

      contributions: this.db.prepare(`
        SELECT source_peer, COUNT(*) as count
        FROM records WHERE namespace = ?
        GROUP BY source_peer ORDER BY count DESC
      `),

      // double-sign: same (input_hash, namespace), different signature — slashable
      doubleSigns: this.db.prepare(`
        SELECT input_hash FROM records
        WHERE input_hash = @inputHash
          AND namespace  = @namespace
          AND signature != @signature
      `),

      ensUpsert: this.db.prepare(`
        INSERT INTO ens_records (name, type, coin_type, text_key, value, modified_at)
        VALUES (@name, @type, @coinType, @textKey, @value, @modifiedAt)
        ON CONFLICT (name, type, coin_type, text_key) DO UPDATE SET
          value       = excluded.value,
          modified_at = excluded.modified_at
      `),

      ensDelete: this.db.prepare(`
        DELETE FROM ens_records
        WHERE name = @name AND type = @type AND coin_type = @coinType AND text_key = @textKey
      `),

      ensGet: this.db.prepare(`
        SELECT value FROM ens_records
        WHERE name = @name AND type = @type AND coin_type = @coinType AND text_key = @textKey
      `),

      ensList: this.db.prepare(`
        SELECT * FROM ens_records WHERE name = ? ORDER BY type ASC, coin_type ASC, text_key ASC
      `),

      ensListAll: this.db.prepare(`
        SELECT * FROM ens_records ORDER BY name ASC, type ASC, coin_type ASC, text_key ASC
      `),

      msgInsert: this.db.prepare(`
        INSERT INTO messages (from_url, from_signer, type, body, version, signature, timestamp, official)
        VALUES (@fromUrl, @fromSigner, @type, @body, @version, @signature, @timestamp, @official)
      `),

      msgList: this.db.prepare(`
        SELECT * FROM messages ORDER BY received_at DESC LIMIT ?
      `),

      msgMarkRead: this.db.prepare(`
        UPDATE messages SET read = 1 WHERE id = ?
      `),

      msgMarkAllRead: this.db.prepare(`
        UPDATE messages SET read = 1 WHERE read = 0
      `),

      msgUnreadCount: this.db.prepare(`
        SELECT COUNT(*) as count FROM messages WHERE read = 0
      `),
    }
  }

  // Run pending migrations in order, tracking applied versions in schema_version.
  private runMigrations() {
    const applied = this.db
      .prepare(`SELECT version FROM schema_version ORDER BY version ASC`)
      .all() as { version: number }[]
    const appliedVersions = new Set(applied.map((r) => r.version))

    for (const migration of MIGRATIONS) {
      if (appliedVersions.has(migration.version)) continue
      console.log(`[db] applying migration v${migration.version}`)
      this.db.exec(migration.sql)
      this.db
        .prepare(`INSERT INTO schema_version (version) VALUES (?)`)
        .run(migration.version)
    }
  }

  async insertRecord(record: MeshRecord): Promise<void> {
    const existing = this.stmts.doubleSigns.get({
      inputHash: record.inputHash,
      namespace: record.namespace,
      signature: record.signature,
    })
    if (existing) {
      console.warn(`[double-sign] input_hash=${record.inputHash} ns=${record.namespace} — flagged for future slashing`)
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

  async getRecord(inputHash: string, namespace?: string): Promise<MeshRecord | null> {
    const row = namespace
      ? this.stmts.getOneNs.get(inputHash, namespace) as RecordRow | undefined
      : this.stmts.getOne.get(inputHash) as RecordRow | undefined
    return row ? toMeshRecord(row) : null
  }

  async getRecordsByInputHash(inputHash: string): Promise<MeshRecord[]> {
    const rows = this.stmts.getAllByHash.all(inputHash) as RecordRow[]
    return rows.map(toMeshRecord)
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

  async ensNameCount(): Promise<number> {
    const row = this.stmts.ensNameCount.get() as { n: number }
    return row.n
  }

  async getRecentRecords(namespace: string, limit: number): Promise<MeshRecord[]> {
    const rows = this.stmts.recent.all(namespace, limit) as RecordRow[]
    return rows.map(toMeshRecord)
  }

  async getContributions(namespace: string): Promise<Contribution[]> {
    const rows = this.stmts.contributions.all(namespace) as { source_peer: string | null; count: number }[]
    return rows.map((r) => ({ sourcePeer: r.source_peer, count: r.count }))
  }

  async removePeer(url: string): Promise<void> {
    this.stmts.removePeer.run(url)
  }

  async upsertNameRecord(r: Omit<NameRecord, 'modifiedAt'>): Promise<void> {
    this.stmts.ensUpsert.run({
      name:       r.name,
      type:       r.type,
      coinType:   r.coinType,
      textKey:    r.textKey,
      value:      r.value,
      modifiedAt: Math.floor(Date.now() / 1000),
    })
  }

  async deleteNameRecord(name: string, type: string, coinType: number, textKey: string): Promise<void> {
    this.stmts.ensDelete.run({ name, type, coinType, textKey })
  }

  async getNameRecordValue(
    name:     string,
    type:     string,
    coinType: number  = -1,
    textKey:  string  = '',
  ): Promise<string | null> {
    const row = this.stmts.ensGet.get({ name, type, coinType, textKey }) as { value: string } | undefined
    return row?.value ?? null
  }

  async listNameRecords(name?: string): Promise<NameRecord[]> {
    const rows = (name
      ? this.stmts.ensList.all(name)
      : this.stmts.ensListAll.all()) as EnsRow[]
    return rows.map(toNameRecord)
  }

  async insertMessage(msg: Omit<Message, 'id' | 'receivedAt'>): Promise<number> {
    const result = this.stmts.msgInsert.run({
      fromUrl:    msg.fromUrl,
      fromSigner: msg.fromSigner,
      type:       msg.type,
      body:       msg.body,
      version:    msg.version,
      signature:  msg.signature,
      timestamp:  msg.timestamp,
      official:   msg.official ? 1 : 0,
    })
    return result.lastInsertRowid as number
  }

  async getMessages(limit = 50): Promise<Message[]> {
    const rows = this.stmts.msgList.all(limit) as MessageRow[]
    return rows.map(toMessage)
  }

  async markMessagesRead(ids?: number[]): Promise<void> {
    if (!ids || ids.length === 0) {
      this.stmts.msgMarkAllRead.run()
    } else {
      for (const id of ids) this.stmts.msgMarkRead.run(id)
    }
  }

  async unreadMessageCount(): Promise<number> {
    const row = this.stmts.msgUnreadCount.get() as { count: number }
    return row.count
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

type MessageRow = {
  id:          number
  from_url:    string
  from_signer: string
  type:        string
  body:        string
  version:     string
  signature:   string
  timestamp:   number
  received_at: number
  read:        number
  official:    number
}

function toMessage(row: MessageRow): Message {
  return {
    id:         row.id,
    fromUrl:    row.from_url,
    fromSigner: row.from_signer,
    type:       row.type as MessageType,
    body:       row.body,
    version:    row.version,
    signature:  row.signature,
    timestamp:  row.timestamp,
    receivedAt: row.received_at,
    read:       row.read === 1,
    official:   row.official === 1,
  }
}

function toNameRecord(row: EnsRow): NameRecord {
  return {
    name:       row.name,
    type:       row.type as NameRecord['type'],
    coinType:   row.coin_type,
    textKey:    row.text_key,
    value:      row.value,
    modifiedAt: row.modified_at,
  }
}
