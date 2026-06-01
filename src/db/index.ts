import { SQLiteDB } from './sqlite.js'
import type { DB } from './types.js'

export { SQLiteDB } from './sqlite.js'
export type { DB, MeshRecord, PeerState } from './types.js'

let _db: SQLiteDB | null = null

// Singleton — one DB instance per process.
// Path defaults to DATA_DIR env or local ./data.db
export function getDB(): DB {
  if (!_db) {
    const path = process.env.DB_PATH ?? './data.db'
    _db = new SQLiteDB(path)
  }
  return _db
}
