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

// Pull all records for a single namespace from a peer, paginating until cursor is null.
// Returns insert/reject counts and the first signer seen (for peer identity discovery).
async function pullNamespace(
  peer: PeerState,
  namespace: string,
  db: DB,
  meshSigners: Set<string>,
): Promise<{ inserted: number; rejected: number; signer: string | null; unsupported: boolean }> {
  let cursor: string | undefined = undefined
  let inserted = 0
  let rejected = 0
  let signer: string | null = null

  do {
    const url  = buildRecordsUrl(peer.url, namespace, peer.lastSyncAt, cursor)
    const body = await fetchRecords(url)

    if (body.protocol !== SUPPORTED_PROTOCOL) {
      return { inserted, rejected, signer, unsupported: true }
    }

    for (const record of body.records) {
      const result = await validateAndInsert(record, db, peer.signerAddress, meshSigners)
      if (result.inserted) {
        inserted++
        if (result.signer && !signer) signer = result.signer
      } else {
        rejected++
      }
    }

    cursor = body.cursor ?? undefined
  } while (cursor !== undefined)

  return { inserted, rejected, signer, unsupported: false }
}

// Pull all new records from a single peer — base namespace + wyriwe sub-namespace.
// Runs peer gossip (auto-discovery) and fetches VNI/health once after both namespaces sync.
export async function syncPeer(
  peer: PeerState,
  namespace: string,
  db: DB,
  autoDiscover = true,
  nodeUrl?: string,
): Promise<Partial<PeerState>> {
  let discoveredSigner: string | null = null

  // Build the set of all known mesh signers once per sync cycle.
  // Records relayed through a peer may carry any registered node's signature —
  // accepting only peerSigner would reject legitimate relayed records.
  const allPeers = await db.getPeers()
  const meshSigners = new Set(
    allPeers.flatMap((p) => (p.signerAddress ? [p.signerAddress.toLowerCase()] : []))
  )

  try {
    // Sync base namespace
    const base = await pullNamespace(peer, namespace, db, meshSigners)
    if (base.unsupported) {
      console.warn(`[sync] ${peer.url} speaks unsupported protocol — skipping`)
      return { healthy: false }
    }
    if (base.signer) discoveredSigner = base.signer

    // Sync wyriwe sub-namespace — best-effort, never fails the peer
    const wyriwe = await pullNamespace(peer, namespace + ':wyriwe', db, meshSigners).catch(() => ({ inserted: 0, rejected: 0, signer: null, unsupported: false }))
    if (wyriwe.signer && !discoveredSigner) discoveredSigner = wyriwe.signer

    const inserted = base.inserted + wyriwe.inserted
    const rejected = base.rejected + wyriwe.rejected
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
// Signer pinning: if the peer's own signer is known, records from that signer are
// unconditionally accepted. Records signed by a different key are accepted if the
// signer belongs to any known mesh peer — this handles relayed records that a router
// pulls from its DB and re-serves with the original signer intact. Records from an
// unknown signer are rejected.
async function validateAndInsert(
  record: MeshRecord,
  db: DB,
  peerSigner: string | null,
  meshSigners: Set<string>,
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

  if (peerSigner && signer.toLowerCase() !== peerSigner.toLowerCase()) {
    // Not from this peer directly — accept if it's from any known mesh member (relayed record)
    if (!meshSigners.has(signer.toLowerCase())) {
      console.warn(
        `[sync] signer mismatch on ${record.inputHash}: ` +
        `expected ${peerSigner.slice(0, 10)}… got ${signer.slice(0, 10)}… — rejected (unknown signer)`,
      )
      return { inserted: false, signer: null }
    }
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

// Normalise a URL to a lowercase origin+path for self-URL comparison.
// Strips trailing slash and lowercases everything — tolerates http vs https drift.
function normalizeUrlForCompare(url: string): string {
  try {
    const u = new URL(url)
    return (u.protocol + '//' + u.hostname + (u.port ? ':' + u.port : '') + u.pathname).toLowerCase().replace(/\/$/, '')
  } catch {
    return url.toLowerCase().replace(/\/$/, '')
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

    const existing = new Set((await db.getPeers()).map((p) => normalizeUrlForCompare(p.url)))
    let added = 0
    const selfNorm = nodeUrl ? normalizeUrlForCompare(nodeUrl) : ''
    for (const discovered of data.peers) {
      if (added >= 10) break
      if (!discovered.url) continue
      try { new URL(discovered.url) } catch { continue }
      const norm = normalizeUrlForCompare(discovered.url)
      if (selfNorm && norm === selfNorm) continue  // never add self as peer
      if (existing.has(norm)) continue
      const url = discovered.url.replace(/\/$/, '')
      await db.upsertPeer({ url, lastSyncAt: 0, healthy: true, nodeVersion: null, signerAddress: discovered.signerAddress })
      existing.add(norm)  // prevent double-add within same cycle
      added++
    }
    if (added > 0) console.log(`[sync] discovered ${added} new peer(s) from ${peer.url}`)
  } catch {
    // non-fatal — gossip is best-effort
  }
}
