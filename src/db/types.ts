// DB interface — implementation (SQLite) lives in db/sqlite.ts
// CcipRouter depends on this interface, not the implementation.
// Swap the implementation without touching router logic.

export type MeshRecord = {
  inputHash: string    // primary key — keccak256 of input, hex
  namespace: string
  key: string
  value: string
  timestamp: number
  signature: string
  sourcePeer: string | null  // null = produced locally
}

export type PeerState = {
  url: string
  lastSyncAt: number
  healthy: boolean
  nodeVersion: string | null
  signerAddress: string | null  // recovered from signed records during sync
}

export interface DB {
  insertRecord(record: MeshRecord): Promise<void>
  getRecordsSince(namespace: string, since: number, limit: number, cursor?: string): Promise<MeshRecord[]>
  getRecord(inputHash: string, namespace?: string): Promise<MeshRecord | null>
  getRecordsByInputHash(inputHash: string): Promise<MeshRecord[]>
  getRecentRecords(namespace: string, limit: number): Promise<MeshRecord[]>
  upsertPeer(peer: PeerState): Promise<void>
  removePeer(url: string): Promise<void>
  getPeers(): Promise<PeerState[]>
  recordCount(namespace: string): Promise<number>
}
