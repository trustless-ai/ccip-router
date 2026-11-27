import type { DB, MeshRecord, PeerState } from '../db/types.js'
import type { Config } from '../config.js'
import { recoverRecordSigner } from '../crypto/index.js'
import { resolvePeerVni, type VniResolution } from './vni.js'
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

// ERC-8309: a peer compares `since` with ITS OWN ingest clock, so pull from a little before our last
// successful pull to cover clock skew between the two nodes. Re-delivered records dedupe to no-ops.
export const SINCE_SKEW_MARGIN_S = 60
export function sinceFor(lastSyncAt: number): number {
  return lastSyncAt > 0 ? Math.max(0, lastSyncAt - SINCE_SKEW_MARGIN_S) : 0
}

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

// A peer's signer is only ever taken from its verified /vni (never gossip, /health or the first
// record it serves).
export type PeerIdentity = { signerAddress: string | null; identityKey: string | null; validFrom: number | null }

// Max seconds a delegation's validFrom may sit in the future (ERC-8309 validFrom monotonicity).
export const VALID_FROM_SKEW_S = 300
const eqi = (a: string | null | undefined, b: string | null | undefined) =>
  !!a && !!b && a.toLowerCase() === b.toLowerCase()

// ERC-8309 pinning. Peers pin the identity key (nodeId), not the signer.
//  - first verified /vni pins its identity (if a signer was stored before identities existed, the
//    new identity must be that key, or delegate to it: the existing key becomes the identity key);
//  - later, a different identity is refused (re-pinning is an operator action: remove and re-add);
//  - same identity: validFrom must increase strictly to change signer (rotation); equal validFrom
//    is accepted only for the same signer, or when the signer was cleared; lower is a rollback;
//  - a validFrom more than VALID_FROM_SKEW_S in the future is refused.
// A refused document leaves the previous identity and signer in place.
export function applyVniResolution(
  prev: PeerIdentity,
  res: VniResolution,
  now: number,
): PeerIdentity & { refused?: 'future_valid_from' | 'identity_mismatch' | 'identity_changed' | 'stale_valid_from' } {
  if (res.status === 'unreachable') return prev
  if (res.status === 'unverified') return { ...prev, signerAddress: null }

  const next: PeerIdentity = { signerAddress: res.signer, identityKey: res.identityKey, validFrom: res.validFrom }
  if (res.validFrom > now + VALID_FROM_SKEW_S) return { ...prev, refused: 'future_valid_from' }

  if (!prev.identityKey) {
    if (prev.signerAddress && !eqi(prev.signerAddress, res.identityKey) && !eqi(prev.signerAddress, res.signer)) {
      return { ...prev, refused: 'identity_mismatch' }
    }
    return next
  }
  if (!eqi(prev.identityKey, res.identityKey)) return { ...prev, refused: 'identity_changed' }

  const pv = prev.validFrom ?? 0
  if (res.validFrom > pv) return next
  if (res.validFrom === pv && (prev.signerAddress === null || eqi(prev.signerAddress, res.signer))) return next
  return { ...prev, refused: 'stale_valid_from' }
}

// Bounded deferral (ERC-8309 rotation propagation): when records were rejected only because
// their signer is not (yet) known, do not advance lastSyncAt, so the next cycle pulls them again
// after the delegation may have propagated, for at most MAX_DEFER_CYCLES cycles. Then advance and
// let them go. State is per peer and in memory; a restart simply re-pulls once.
export const MAX_DEFER_CYCLES = 5
const deferCycles = new Map<string, number>()

export function nextLastSyncAt(
  peerUrl: string,
  previous: number,
  startedAt: number,
  unknownSignerRejections: number,
  state: Map<string, number> = deferCycles,
): number {
  if (unknownSignerRejections === 0) { state.delete(peerUrl); return startedAt }
  const n = (state.get(peerUrl) ?? 0) + 1
  if (n > MAX_DEFER_CYCLES) {
    console.warn(`[sync] ${peerUrl}: ${unknownSignerRejections} record(s) from unknown signers dropped after ${MAX_DEFER_CYCLES} deferred cycles`)
    state.delete(peerUrl)
    return startedAt
  }
  state.set(peerUrl, n)
  return previous
}

type PullResult = { inserted: number; rejected: number; unknownSigner: number; unsupported: boolean }

// Pull all records for a single namespace from a peer, paginating until cursor is null.
async function pullNamespace(
  peer: PeerState,
  peerSigner: string | null,
  namespace: string,
  db: DB,
  meshSigners: Set<string>,
): Promise<PullResult> {
  let cursor: string | undefined = undefined
  let inserted = 0
  let rejected = 0
  let unknownSigner = 0

  do {
    const url  = buildRecordsUrl(peer.url, namespace, sinceFor(peer.lastSyncAt), cursor)
    const body = await fetchRecords(url)

    if (body.protocol !== SUPPORTED_PROTOCOL) {
      return { inserted, rejected, unknownSigner, unsupported: true }
    }

    for (const record of body.records) {
      const result = await validateAndInsert(record, db, peerSigner, peer.url, meshSigners)
      if (result.inserted) inserted++
      else {
        rejected++
        if (result.reason === 'unknown_signer') unknownSigner++
      }
    }

    cursor = body.cursor ?? undefined
  } while (cursor !== undefined)

  return { inserted, rejected, unknownSigner, unsupported: false }
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
  // The next pull resumes from when THIS pull started, not when it finished: records the peer
  // ingests while we are paginating must not fall behind our next `since`.
  const startedAt = Math.floor(Date.now() / 1000)

  try {
    // Resolve the peer's identity from its verified /vni BEFORE accepting any of its records.
    // Never from gossip, /health or the signer of the first record it serves (ERC-8309).
    const vniRes   = await resolvePeerVni(peer.url)
    const identity = applyVniResolution(
      { signerAddress: peer.signerAddress, identityKey: peer.identityKey ?? null, validFrom: peer.validFrom ?? null },
      vniRes, startedAt,
    )
    const peerSigner = identity.signerAddress
    if (vniRes.status === 'unverified') {
      console.warn(`[sync] ${peer.url} serves no verifiable /vni — only records from already-verified mesh signers are accepted`)
    }
    if (identity.refused) {
      console.warn(`[sync] ${peer.url} /vni refused (${identity.refused}) — keeping pinned identity ${identity.identityKey?.slice(0, 10) ?? 'none'}…`)
    }
    const vni = vniRes.status === 'verified' ? vniRes.vni : null
    const pin = { signerAddress: peerSigner, identityKey: identity.identityKey, validFrom: identity.validFrom }

    // Signers this node has verified through /vni: the peer's own plus every stored peer's.
    // Stored signers are written only from a verified /vni (gossip stores none).
    const allPeers = await db.getPeers()
    const meshSigners = new Set(
      allPeers.flatMap((p) => (p.url !== peer.url && p.signerAddress ? [p.signerAddress.toLowerCase()] : []))
    )
    if (peerSigner) meshSigners.add(peerSigner.toLowerCase())

    // Sync base namespace
    const base = await pullNamespace(peer, peerSigner, namespace, db, meshSigners)
    if (base.unsupported) {
      console.warn(`[sync] ${peer.url} speaks unsupported protocol — skipping`)
      return { healthy: false, ...pin }
    }

    // Sync wyriwe sub-namespace — best-effort, never fails the peer
    const empty: PullResult = { inserted: 0, rejected: 0, unknownSigner: 0, unsupported: false }
    const wyriwe = await pullNamespace(peer, peerSigner, namespace + ':wyriwe', db, meshSigners).catch(() => empty)

    const inserted = base.inserted + wyriwe.inserted
    const rejected = base.rejected + wyriwe.rejected
    if (inserted > 0 || rejected > 0) {
      console.log(`[sync] ${peer.url} — +${inserted} inserted, ${rejected} rejected`)
    }
    const lastSyncAt = nextLastSyncAt(peer.url, peer.lastSyncAt, startedAt, base.unknownSigner + wyriwe.unknownSigner)

    // Fetch /health for nodeVersion fallback
    const health = await fetchPeerHealth(peer.url)

    // Auto-discovery: pull peer's known peers and add any new ones
    if (autoDiscover) await discoverPeers(peer, db, nodeUrl)

    // The legacy /vni carried the implementation version as a string; the ERC-8309 one carries the
    // protocol version as a number, so the implementation version comes from /health there.
    const vniImplVersion = typeof vni?.version === 'string' ? vni.version : undefined
    const resolvedVersion = vniImplVersion ?? health?.version ?? peer.nodeVersion ?? null

    if (resolvedVersion && isOlderVersion(resolvedVersion, NODE_VERSION)) {
      console.warn(
        `[sync] ${peer.url} is running v${resolvedVersion} — we are v${NODE_VERSION}. ` +
        `Peer should upgrade.`,
      )
    }

    return {
      healthy:       true,
      lastSyncAt,
      nodeVersion:   resolvedVersion,
      ...pin,
    }
  } catch (err) {
    console.warn(`[sync] ${peer.url} unreachable — ${String(err)}`)
    return { healthy: false }
  }
}

// ERC-8309: a record without a signature MUST be rejected. Unsigned "0x" records exist only on
// dry-run nodes (no gateway key); a dev mesh of dry-run nodes can opt back in explicitly.
export function acceptUnsignedRecords(env: NodeJS.ProcessEnv = process.env): boolean {
  return env.MESH_ACCEPT_UNSIGNED?.toLowerCase() === 'true'
}

// Validate a single record's signature then insert.
// Signer pinning: if the peer's own signer is known, records from that signer are
// unconditionally accepted. Records signed by a different key are accepted if the
// signer belongs to any known mesh peer — this handles relayed records that a router
// pulls from its DB and re-serves with the original signer intact. Records from an
// unknown signer are rejected. Unsigned records are rejected unless MESH_ACCEPT_UNSIGNED=true.
export async function validateAndInsert(
  record: MeshRecord,
  db: DB,
  peerSigner: string | null,
  peerUrl: string,
  meshSigners: Set<string>,
  acceptUnsigned: boolean = acceptUnsignedRecords(),
): Promise<{ inserted: boolean; signer: string | null; reason?: 'unsigned' | 'malformed_signature' | 'unknown_signer' }> {
  if (record.signature === '0x') {
    if (!acceptUnsigned) {
      console.warn(`[sync] unsigned record ${record.inputHash} from ${peerUrl} — rejected (ERC-8309: records must be signed; set MESH_ACCEPT_UNSIGNED=true only on a dev mesh)`)
      return { inserted: false, signer: null, reason: 'unsigned' }
    }
    console.warn(`[sync] unsigned record ${record.inputHash} — accepted (MESH_ACCEPT_UNSIGNED=true, dev mesh)`)
    await db.insertRecord({ ...record, sourcePeer: record.sourcePeer ?? peerUrl })
    return { inserted: true, signer: null }
  }

  let signer: string
  try {
    signer = await recoverRecordSigner(record)
  } catch {
    console.warn(`[sync] malformed signature on ${record.inputHash} — rejected`)
    return { inserted: false, signer: null, reason: 'malformed_signature' }
  }

  // Accept the peer's own verified signer, or any signer this node has verified through /vni
  // (a relayed record keeps its originating signer). With no verified peer signer, ONLY the
  // second case applies: an unknown peer can relay known nodes' records but cannot introduce a
  // signer by serving records signed with it.
  const s = signer.toLowerCase()
  const fromPeer = peerSigner !== null && s === peerSigner.toLowerCase()
  if (!fromPeer && !meshSigners.has(s)) {
    console.warn(
      `[sync] unknown signer on ${record.inputHash}: ${signer.slice(0, 10)}… via ${peerUrl}` +
      (peerSigner ? ` (peer signer ${peerSigner.slice(0, 10)}…)` : ' (peer has no verified signer)') + ' — rejected',
    )
    return { inserted: false, signer: null, reason: 'unknown_signer' }
  }

  await db.insertRecord({ ...record, sourcePeer: record.sourcePeer ?? peerUrl })
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
      if (await db.isBlockedPeer(url)) continue    // respect manual removals
      // The gossiped signerAddress is self-reported and NOT stored: the peer's signer is set only
      // after its own /vni verifies on first sync (ERC-8309 Peer Discovery).
      await db.upsertPeer({ url, lastSyncAt: 0, healthy: true, nodeVersion: null, signerAddress: null })
      existing.add(norm)  // prevent double-add within same cycle
      added++
    }
    if (added > 0) console.log(`[sync] discovered ${added} new peer(s) from ${peer.url}`)
  } catch {
    // non-fatal — gossip is best-effort
  }
}
