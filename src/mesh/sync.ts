import type { DB, MeshRecord, PeerState } from '../db/types.js'
import { recoverRecordSigner } from '../crypto/index.js'

const SUPPORTED_PROTOCOL = 1

type RecordsResponse = {
  protocol: number
  node_version: string
  namespace: string
  records: MeshRecord[]
  cursor: string | null
}

// Pull all new records from a single peer, paginating until cursor is null.
// Returns the discovered signer address (consistent across the batch) or null.
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
      const url = buildUrl(peer.url, namespace, peer.lastSyncAt, cursor)
      const body = await fetchRecords(url)

      if (body.protocol !== SUPPORTED_PROTOCOL) {
        console.warn(`[sync] ${peer.url} speaks protocol ${body.protocol} — skipping`)
        return { healthy: false, nodeVersion: body.node_version ?? peer.nodeVersion }
      }

      for (const record of body.records) {
        const result = await validateAndInsert(record, db)
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

    return {
      healthy:       true,
      lastSyncAt:    Math.floor(Date.now() / 1000),
      nodeVersion:   null, // populated from /health separately
      signerAddress: discoveredSigner ?? peer.signerAddress,
    }
  } catch (err) {
    console.warn(`[sync] ${peer.url} unreachable — ${String(err)}`)
    return { healthy: false }
  }
}

// Validate a single record's signature, then insert if valid.
// Dry-run records (signature === '0x') are accepted but flagged.
async function validateAndInsert(
  record: MeshRecord,
  db: DB,
): Promise<{ inserted: boolean; signer: string | null }> {
  if (record.signature === '0x') {
    // unsigned — accept in dev/dry-run, log warning
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

  await db.insertRecord(record)
  return { inserted: true, signer }
}

function buildUrl(
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
