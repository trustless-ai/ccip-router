import { SQLiteDB } from './sqlite.js'
import type { DB } from './types.js'

export { SQLiteDB } from './sqlite.js'
export type { DB, MeshRecord, PeerState } from './types.js'

let _db: SQLiteDB | null = null

// Singleton — call with path once at boot (index.ts), then call without args everywhere else.
export function getDB(path?: string): DB {
  if (!_db) {
    if (!path) throw new Error('getDB() called before DB was initialised — pass path on first call')
    _db = new SQLiteDB(path)
  }
  return _db
}
