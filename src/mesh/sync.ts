import type { DB, MeshRecord, PeerState } from '../db/types.js'
import type { Config } from '../config.js'
import { recoverRecordSigner } from '../crypto/index.js'
import { fetchPeerVni, verifyVni } from './vni.js'
import { NODE_VERSION } from '../version.js'

// Manual sync trigger — used by the admin dashboard "Sync now" button.
export async function syncAll(config: Config, db: DB): Promise<number> {
  const peers = await db.getPeers()
  const results = await Promise.allSettled(
    peers.map(async (peer) => {
      const update = await syncPeer(peer, config.syncNamespace, db, config.autoDiscover, config.nodeUrl ?? undefined)
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
// Optionally runs peer gossip (auto-discovery) after syncing.
export async function syncPeer(
  peer: PeerState,
  namespace: string,
  db: DB,
  autoDiscover = true,
  nodeUrl?: string,
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

    // Fetch /vni — authoritative signed identity (preferred over health signerAddress)
    const vni    = await fetchPeerVni(peer.url)
    const vniSigner = vni ? await verifyVni(vni) : null

    // Fetch /health for nodeVersion fallback
    const health = await fetchPeerHealth(peer.url)

    // Auto-discovery: pull peer's known peers and add any new ones
    if (autoDiscover) await discoverPeers(peer, db, nodeUrl)

    const resolvedVersion = vni?.version ?? health?.version ?? peer.nodeVersion ?? null

    if (resolvedVersion && isOlderVersion(resolvedVersion, NODE_VERSION)) {
      console.warn(
        `[sync] ${peer.url} is running v${resolvedVersion} — we are v${NODE_VERSION}. ` +
        `Peer should upgrade.`,
      )
    }

    return {
      healthy:       true,
      lastSyncAt:    Math.floor(Date.now() / 1000),
      nodeVersion:   resolvedVersion,
      signerAddress: vniSigner ?? discoveredSigner ?? health?.signerAddress ?? peer.signerAddress,
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
  url.searchParams.set('protocol', String(SUPPORTED_PROTOCOL))
  if (cursor) url.searchParams.set('cursor', cursor)
  return url.toString()
}

// Returns true if `a` is an older semver than `b`. Non-semver strings return false.
function isOlderVersion(a: string, b: string): boolean {
  const parse = (v: string) => v.split('.').map(Number)
  const [aMaj, aMin, aPatch] = parse(a)
  const [bMaj, bMin, bPatch] = parse(b)
  if (isNaN(aMaj) || isNaN(bMaj)) return false
  if (aMaj !== bMaj) return aMaj < bMaj
  if (aMin !== bMin) return aMin < bMin
  return (aPatch ?? 0) < (bPatch ?? 0)
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

// Fetch the peer's /peers list and add any newly discovered nodes to our DB.
// Bounded to 10 new peers per sync cycle — prevents runaway growth.
async function discoverPeers(peer: PeerState, db: DB, nodeUrl?: string): Promise<void> {
  try {
    const res = await fetch(new URL('/peers', peer.url).toString(), {
      signal: AbortSignal.timeout(5_000),
    })
    if (!res.ok) return
    const data = await res.json() as { peers?: { url: string; signerAddress: string | null }[] }
    if (!data.peers?.length) return

    const existing = new Set((await db.getPeers()).map((p) => p.url))
    let added = 0
    const selfUrl = nodeUrl?.replace(/\/$/, '') ?? ''
    for (const discovered of data.peers) {
      if (added >= 10) break
      if (!discovered.url || existing.has(discovered.url)) continue
      try { new URL(discovered.url) } catch { continue }
      const url = discovered.url.replace(/\/$/, '')
      if (selfUrl && url === selfUrl) continue  // never add self as peer
      await db.upsertPeer({ url, lastSyncAt: 0, healthy: true, nodeVersion: null, signerAddress: discovered.signerAddress })
      added++
    }
    if (added > 0) console.log(`[sync] discovered ${added} new peer(s) from ${peer.url}`)
  } catch {
    // non-fatal — gossip is best-effort
  }
}
