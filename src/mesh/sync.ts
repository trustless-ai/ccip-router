import type { DB, MeshRecord, PeerState } from '../db/types.js'
import type { Config } from '../config.js'
import { recoverRecordSigner } from '../crypto/index.js'

// Manual sync trigger — used by the admin dashboard "Sync now" button.
export async function syncAll(config: Config, db: DB): Promise<number> {
  const peers = await db.getPeers()
  const results = await Promise.allSettled(
    peers.map(async (peer) => {
      const update = await syncPeer(peer, config.syncNamespace, db)
      await db.upsertPeer({ ...peer, ...update })
    }),
  )
  return results.filter((r) => r.status === 'fulfilled').length
}

const SUPPORTED_PROTOCOL = 1

type RecordsResponse = {
  protocol:     number
  node_version: string
  namespace:    string
  records:      MeshRecord[]
  cursor:       string | null
}

type HealthResponse = {
  version:       string
  signerAddress: string | null
}

// Pull all new records from a single peer, paginating until cursor is null.
// After records are synced, fetches /health to populate nodeVersion.
export async function syncPeer(
  peer: PeerState,
  namespace: string,
  db: DB,
): Promise<Partial<PeerState>> {
  let cursor: string | undefined = undefined
  let inserted = 0
  let rejected = 0
  let discoveredSigner: string | null = null

  try {
    do {
      const url  = buildRecordsUrl(peer.url, namespace, peer.lastSyncAt, cursor)
      const body = await fetchRecords(url)

      if (body.protocol !== SUPPORTED_PROTOCOL) {
        console.warn(`[sync] ${peer.url} speaks protocol ${body.protocol} — skipping`)
        return { healthy: false, nodeVersion: body.node_version ?? peer.nodeVersion }
      }

      for (const record of body.records) {
        const result = await validateAndInsert(record, db, peer.signerAddress)
        if (result.inserted) {
          inserted++
          if (result.signer && !discoveredSigner) discoveredSigner = result.signer
        } else {
          rejected++
        }
      }

      cursor = body.cursor ?? undefined
    } while (cursor !== undefined)

    if (inserted > 0 || rejected > 0) {
      console.log(`[sync] ${peer.url} — +${inserted} inserted, ${rejected} rejected`)
    }

    // Fetch /health to get the peer's current nodeVersion (non-blocking best-effort)
    const health = await fetchPeerHealth(peer.url)

    return {
      healthy:       true,
      lastSyncAt:    Math.floor(Date.now() / 1000),
      nodeVersion:   health?.version        ?? peer.nodeVersion,
      signerAddress: discoveredSigner       ?? health?.signerAddress ?? peer.signerAddress,
    }
  } catch (err) {
    console.warn(`[sync] ${peer.url} unreachable — ${String(err)}`)
    return { healthy: false }
  }
}

// Validate a single record's signature then insert.
// Signer pinning: if the peer's signer address is already known, reject any
// record signed by a different key — prevents a compromised peer from injecting
// records on behalf of another node.
async function validateAndInsert(
  record: MeshRecord,
  db: DB,
  knownSigner: string | null,
): Promise<{ inserted: boolean; signer: string | null }> {
  if (record.signature === '0x') {
    console.warn(`[sync] unsigned record ${record.inputHash} — accepted (dry-run peer)`)
    await db.insertRecord(record)
    return { inserted: true, signer: null }
  }

  let signer: string
  try {
    signer = await recoverRecordSigner(record)
  } catch {
    console.warn(`[sync] malformed signature on ${record.inputHash} — rejected`)
    return { inserted: false, signer: null }
  }

  if (knownSigner && signer.toLowerCase() !== knownSigner.toLowerCase()) {
    console.warn(
      `[sync] signer mismatch on ${record.inputHash}: ` +
      `expected ${knownSigner.slice(0, 10)}… got ${signer.slice(0, 10)}… — rejected`,
    )
    return { inserted: false, signer: null }
  }

  await db.insertRecord(record)
  return { inserted: true, signer }
}

function buildRecordsUrl(
  baseUrl: string,
  namespace: string,
  since: number,
  cursor?: string,
): string {
  const url = new URL('/records', baseUrl)
  url.searchParams.set('namespace', namespace)
  url.searchParams.set('since', String(since))
  url.searchParams.set('limit', '500')
  if (cursor) url.searchParams.set('cursor', cursor)
  return url.toString()
}

async function fetchRecords(url: string): Promise<RecordsResponse> {
  const res = await fetch(url, { signal: AbortSignal.timeout(10_000) })
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.json() as Promise<RecordsResponse>
}

async function fetchPeerHealth(baseUrl: string): Promise<HealthResponse | null> {
  try {
    const res = await fetch(new URL('/health', baseUrl).toString(), {
      signal: AbortSignal.timeout(5_000),
    })
    if (!res.ok) return null
    return res.json() as Promise<HealthResponse>
  } catch {
    return null
  }
}
