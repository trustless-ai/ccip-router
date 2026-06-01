import type { MeshRecord } from '../db/types.js'

export type PeerSyncState = {
  url: string
  lastSyncAt: number
  healthy: boolean
}

// Pulls records from a single peer since the last successful sync cursor.
// Skips unreachable peers — retry on next tick.
export async function syncPeer(peer: PeerSyncState, namespace: string): Promise<MeshRecord[]> {
  try {
    const url = `${peer.url}/records?since=${peer.lastSyncAt}&namespace=${namespace}&limit=500`
    const res = await fetch(url, { signal: AbortSignal.timeout(10_000) })
    if (!res.ok) throw new Error(`peer ${peer.url} returned ${res.status}`)
    const body = await res.json() as { records: MeshRecord[] }
    peer.healthy = true
    peer.lastSyncAt = Math.floor(Date.now() / 1000)
    return body.records
  } catch {
    peer.healthy = false
    return []
  }
}

// TODO: persist peer sync state, insert validated records into local DB
