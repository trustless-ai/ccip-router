import { test, describe, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { SQLiteDB } from '../db/sqlite.js'
import type { MeshRecord } from '../db/types.js'

function makeDB() {
  return new SQLiteDB(':memory:')
}

function makeRecord(overrides: Partial<MeshRecord> = {}): MeshRecord {
  return {
    inputHash:  '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    namespace:  'test-ns',
    key:        '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    value:      '0xdeadbeef',
    timestamp:  1_700_000_000,
    signature:  '0x' + 'cc'.repeat(65),
    sourcePeer: null,
    ...overrides,
  }
}

describe('insertRecord + getRecord', () => {
  test('inserts and retrieves a record by inputHash', async () => {
    const db = makeDB()
    const rec = makeRecord()
    await db.insertRecord(rec)
    const found = await db.getRecord(rec.inputHash)
    assert.ok(found)
    assert.equal(found.inputHash, rec.inputHash)
    assert.equal(found.namespace, rec.namespace)
    db.close()
  })

  test('getRecord with namespace does exact-match lookup', async () => {
    const db = makeDB()
    await db.insertRecord(makeRecord({ namespace: 'ns-a' }))
    await db.insertRecord(makeRecord({ namespace: 'ns-b' }))

    const hash = makeRecord().inputHash
    const a = await db.getRecord(hash, 'ns-a')
    const b = await db.getRecord(hash, 'ns-b')
    assert.equal(a?.namespace, 'ns-a')
    assert.equal(b?.namespace, 'ns-b')
    db.close()
  })

  test('getRecord returns null for unknown hash', async () => {
    const db = makeDB()
    const result = await db.getRecord('0x' + '00'.repeat(32))
    assert.equal(result, null)
    db.close()
  })
})

describe('deduplication (INSERT OR IGNORE)', () => {
  test('same (inputHash, namespace) is inserted once', async () => {
    const db = makeDB()
    const rec = makeRecord()
    await db.insertRecord(rec)
    await db.insertRecord(rec)
    const count = await db.recordCount(rec.namespace)
    assert.equal(count, 1)
    db.close()
  })

  test('same inputHash with different namespace creates two records', async () => {
    const db = makeDB()
    await db.insertRecord(makeRecord({ namespace: 'ns-a' }))
    await db.insertRecord(makeRecord({ namespace: 'ns-b' }))
    const a = await db.recordCount('ns-a')
    const b = await db.recordCount('ns-b')
    assert.equal(a, 1)
    assert.equal(b, 1)
    db.close()
  })
})

describe('ERC-8309 divergence preservation', () => {
  // R-DUP: two OBSERVATION-IDENTICAL records (same (inputHash, namespace, value))
  // from different signers collapse to one — dedup is a correct no-op here.
  // Identity excludes signature/timestamp/peer. (Quorum profiles that count
  // per-value corroboration need the discarded multiplicity — a declared
  // extension, not mandated by this base; see the §Deduplication amendment note.)
  test('R-DUP: observation-identical records (same value) from different signers collapse to one', async () => {
    const db = makeDB()
    const rec = makeRecord({ value: '0xSAME', sourcePeer: 'nodeA' })
    await db.insertRecord(rec)
    await db.insertRecord({ ...rec, signature: '0x' + 'dd'.repeat(65), sourcePeer: 'nodeB' })
    const recs = await db.getRecordsByInputHash(rec.inputHash)
    assert.equal(recs.length, 1)
    assert.equal(recs[0].value, '0xSAME')
    db.close()
  })

  // R-DIV: two VALID observations with DIFFERENT value for the same key are BOTH
  // retained — the second is not silently dropped. This is the amendment; it was
  // RED before the PK widen (first-valid-wins) and is GREEN after.
  test('R-DIV: genuine divergence retains both observations, not one', async () => {
    const db = makeDB()
    const base = makeRecord({ value: '0xOUTPUT_A', sourcePeer: 'gatewayA' })
    await db.insertRecord(base)
    await db.insertRecord({ ...base, value: '0xOUTPUT_B', signature: '0x' + 'bb'.repeat(65), sourcePeer: 'gatewayB' })
    const recs = await db.getRecordsByInputHash(base.inputHash)
    assert.equal(recs.length, 2)
    assert.deepEqual(new Set(recs.map(r => r.value)), new Set(['0xOUTPUT_A', '0xOUTPUT_B']))
    db.close()
  })

  // Divergence is surfaced as a first-class state, never folded into agreement
  // and never a silently-chosen winner.
  test('getRecordState reports absent | single | divergent', async () => {
    const db = makeDB()
    const base = makeRecord({ value: '0xA' })
    const absent = await db.getRecordState(base.inputHash, base.namespace)
    assert.equal(absent.state, 'absent')

    await db.insertRecord(base)
    const single = await db.getRecordState(base.inputHash, base.namespace)
    assert.equal(single.state, 'single')

    await db.insertRecord({ ...base, value: '0xB', signature: '0x' + 'bb'.repeat(65), sourcePeer: 'nodeB' })
    const divergent = await db.getRecordState(base.inputHash, base.namespace)
    assert.equal(divergent.state, 'divergent')
    if (divergent.state === 'divergent') assert.equal(divergent.records.length, 2)
    db.close()
  })

  // Observation-identical collapse keeps the FIRST attestation (INSERT OR IGNORE),
  // not the last — locks the tie-break so it can't silently flip to keep-last.
  test('dedup keeps the first observation (first-valid-wins), not the last', async () => {
    const db = makeDB()
    const first = makeRecord({ value: '0xSAME', sourcePeer: 'nodeA' })
    await db.insertRecord(first)
    await db.insertRecord({ ...first, signature: '0x' + 'dd'.repeat(65), sourcePeer: 'nodeB' })
    const recs = await db.getRecordsByInputHash(first.inputHash)
    assert.equal(recs.length, 1)
    assert.equal(recs[0].sourcePeer, 'nodeA')  // REPLACE would surface nodeB
    db.close()
  })
})

// Equivocation (one signer, two signatures) is a distinct event from honest
// multi-vantage divergence (two signers). The detector must fire on the first
// and stay silent on the second — the base separates the two.
// The base extension: records keeps ONE observation per value (first-valid-wins), which discards
// per-value corroboration. A signature-keyed attestation table retains every distinct signed message
// without touching observation identity — quorum-class policies count these vantages.
describe('ERC-8309 attestation retention (signature-keyed)', () => {
  test('exact replay (same signature) is an idempotent no-op', async () => {
    const db = makeDB()
    const r = makeRecord({ value: '0xV', sourcePeer: 'nodeA', signature: '0x' + 'aa'.repeat(65) })
    await db.insertRecord(r)
    await db.insertRecord(r)   // byte-identical replay
    const atts = await db.getAttestations(r.inputHash, r.namespace, '0xV')
    assert.equal(atts.length, 1)
    db.close()
  })

  test('retains BOTH attestations of one value from different signers (corroboration records drops)', async () => {
    const db = makeDB()
    const base = makeRecord({ value: '0xV', sourcePeer: 'nodeA', signature: '0x' + 'aa'.repeat(65) })
    await db.insertRecord(base)
    await db.insertRecord({ ...base, sourcePeer: 'nodeB', signature: '0x' + 'bb'.repeat(65) })
    const recs = await db.getRecordsByInputHash(base.inputHash)
    assert.equal(recs.length, 1)                       // records collapses to one observation
    const atts = await db.getAttestations(base.inputHash, base.namespace, '0xV')
    assert.equal(atts.length, 2)                       // attestations keeps both signed messages
    assert.deepEqual(new Set(atts.map(a => a.sourcePeer)), new Set(['nodeA', 'nodeB']))
    db.close()
  })

  test('observation identity unchanged: same value, two signers is still single, not divergent', async () => {
    const db = makeDB()
    const base = makeRecord({ value: '0xV', signature: '0x' + 'aa'.repeat(65) })
    await db.insertRecord(base)
    await db.insertRecord({ ...base, sourcePeer: 'nodeB', signature: '0x' + 'bb'.repeat(65) })
    const st = await db.getRecordState(base.inputHash, base.namespace)
    assert.equal(st.state, 'single')                   // divergence is by distinct value, not attestation count
    db.close()
  })

  test('getAttestations is empty for an unattested value', async () => {
    const db = makeDB()
    await db.insertRecord(makeRecord({ value: '0xV' }))
    const atts = await db.getAttestations(makeRecord().inputHash, makeRecord().namespace, '0xOTHER')
    assert.equal(atts.length, 0)
    db.close()
  })

  // ECDSA malleability: (r, s, v) and (r, n-s, v') are the SAME signed message. Without low-s
  // canonicalization of the dedup key, one attestation stores as two (storage-growth / corroboration
  // inflation). They must collapse to one.
  test('malleated signatures (low-s vs high-s) collapse to one attestation', async () => {
    const db = makeDB()
    const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n
    const r = 'ab'.repeat(32)
    const sLow = 0x1111111111111111111111111111111111111111111111111111111111111111n
    const hex = (x: bigint) => x.toString(16).padStart(64, '0')
    const sigLowS  = '0x' + r + hex(sLow)     + '1b'  // v=27, already low-s
    const sigHighS = '0x' + r + hex(N - sLow) + '1c'  // v=28, high-s malleation of the SAME signature
    const base = makeRecord({ value: '0xV', sourcePeer: 'nodeA', signature: sigHighS })
    await db.insertRecord(base)
    await db.insertRecord({ ...base, signature: sigLowS })
    const atts = await db.getAttestations(base.inputHash, base.namespace, '0xV')
    assert.equal(atts.length, 1)  // one signed message, not two
    db.close()
  })

  // Unsigned/dry-run records carry signature "0x". Keyed on the raw signature they would ALL collide
  // on "0x" and silently dedup away their own multiplicity. A content-digest fallback identity keeps
  // distinct unsigned records distinct.
  test('distinct unsigned records for one observation do NOT collapse on "0x"', async () => {
    const db = makeDB()
    const base = makeRecord({ value: '0xV', signature: '0x', sourcePeer: 'nodeA', timestamp: 100 })
    await db.insertRecord(base)
    await db.insertRecord({ ...base, timestamp: 200 })  // distinct observation content, same "0x"
    const atts = await db.getAttestations(base.inputHash, base.namespace, '0xV')
    assert.equal(atts.length, 2)
    db.close()
  })

  // Transport metadata (source_peer) is not part of identity — otherwise it could mint attestations.
  test('source_peer does not redefine unsigned identity (same observation, two peers = one)', async () => {
    const db = makeDB()
    const base = makeRecord({ value: '0xV', signature: '0x', sourcePeer: 'nodeA', timestamp: 100 })
    await db.insertRecord(base)
    await db.insertRecord({ ...base, sourcePeer: 'nodeB' })  // same content, different transport
    const atts = await db.getAttestations(base.inputHash, base.namespace, '0xV')
    assert.equal(atts.length, 1)
    db.close()
  })

  // Only signed attestations are eligible for V2 / quorum counting. "0x" stays observable, never counted.
  test('getSignedAttestations excludes unsigned "0x" records', async () => {
    const db = makeDB()
    const ih = '0x' + 'cd'.repeat(32)
    const signed = makeRecord({ inputHash: ih, value: '0xV', signature: '0x' + 'aa'.repeat(65), sourcePeer: 'nodeA' })
    await db.insertRecord(signed)
    await db.insertRecord({ ...signed, signature: '0x', sourcePeer: 'nodeB' })  // unsigned/dry-run
    const all = await db.getAttestations(ih, signed.namespace, '0xV')
    const eligible = await db.getSignedAttestations(ih, signed.namespace, '0xV')
    assert.equal(all.length, 2)       // both observable
    assert.equal(eligible.length, 1)  // only the signed one counts
    assert.notEqual(eligible[0].signature, '0x')
    db.close()
  })
})

describe('getRecordsByInputHash', () => {
  test('returns all records for a given inputHash across namespaces', async () => {
    const db = makeDB()
    await db.insertRecord(makeRecord({ namespace: 'ns-a' }))
    await db.insertRecord(makeRecord({ namespace: 'ns-b' }))
    await db.insertRecord(makeRecord({ namespace: 'ns-c' }))
    const recs = await db.getRecordsByInputHash(makeRecord().inputHash)
    assert.equal(recs.length, 3)
    db.close()
  })

  test('returns empty array for unknown hash', async () => {
    const db = makeDB()
    const recs = await db.getRecordsByInputHash('0x' + '00'.repeat(32))
    assert.deepEqual(recs, [])
    db.close()
  })
})

describe('getRecordsPage: ingest-time since + cursor pagination (ERC-8309)', () => {
  // A clock we can move: received_at is the serving node's ingest time, not the record timestamp.
  function clockDB(start = 5000) {
    let t = start
    const db = new SQLiteDB(':memory:', { now: () => t })
    return { db, set: (v: number) => { t = v } }
  }
  const H = (b: string) => '0x' + b.repeat(32)

  test('since filters on ingest time, strictly greater', async () => {
    const { db, set } = clockDB()
    set(1000); await db.insertRecord(makeRecord({ inputHash: H('aa'), timestamp: 1 }))
    set(2000); await db.insertRecord(makeRecord({ inputHash: H('bb'), timestamp: 2 }))
    const a = await db.getRecordsPage('test-ns', 1500, 100)
    assert.deepEqual(a.records.map((r) => r.inputHash), [H('bb')])
    const b = await db.getRecordsPage('test-ns', 1000, 100)        // since == first ingest time
    assert.deepEqual(b.records.map((r) => r.inputHash), [H('bb')])  // strict >
    assert.equal(b.cursor, null)
    db.close()
  })

  test('multi-hop: a relayed record with an OLD timestamp is still served to a peer that polled later', async () => {
    // Node B. Peer C last polled B at t=2000. A record signed at t=100 (on node A) reaches B at t=2500.
    const { db, set } = clockDB()
    set(1900); await db.insertRecord(makeRecord({ inputHash: H('aa'), timestamp: 1900 }))
    set(2500); await db.insertRecord(makeRecord({ inputHash: H('bb'), timestamp: 100, sourcePeer: 'https://a.example' }))
    const page = await db.getRecordsPage('test-ns', 2000, 100)    // C's next pull, since = its last poll
    assert.deepEqual(page.records.map((r) => r.inputHash), [H('bb')])
    assert.equal(page.records[0].timestamp, 100)                   // signed timestamp is untouched
    db.close()
  })

  test('re-delivery of a stored record does not move its ingest time', async () => {
    const { db, set } = clockDB()
    set(1000); await db.insertRecord(makeRecord({ inputHash: H('aa') }))
    set(9000); await db.insertRecord(makeRecord({ inputHash: H('aa') }))   // same observation again
    assert.equal((await db.getRecordsPage('test-ns', 1000, 100)).records.length, 0)
    db.close()
  })

  test('cursor walks every record exactly once, one per page', async () => {
    const { db, set } = clockDB()
    set(1000); await db.insertRecord(makeRecord({ inputHash: H('aa') }))
    set(1000); await db.insertRecord(makeRecord({ inputHash: H('bb') }))
    set(2000); await db.insertRecord(makeRecord({ inputHash: H('cc') }))
    const seen: string[] = []
    let cursor: string | undefined
    for (let i = 0; i < 10; i++) {
      const p = await db.getRecordsPage('test-ns', 0, 1, cursor)
      seen.push(...p.records.map((r) => r.inputHash))
      if (!p.cursor) break
      cursor = p.cursor
    }
    assert.deepEqual(seen, [H('aa'), H('bb'), H('cc')])
    db.close()
  })

  test('a divergence (same inputHash, same ingest second) is not skipped across page boundaries', async () => {
    const { db } = clockDB(1000)
    for (const v of ['0x01', '0x02', '0x03']) await db.insertRecord(makeRecord({ inputHash: H('aa'), value: v }))
    await db.insertRecord(makeRecord({ inputHash: H('bb'), value: '0x09' }))
    const seen: string[] = []
    let cursor: string | undefined
    for (let i = 0; i < 10; i++) {
      const p = await db.getRecordsPage('test-ns', 0, 1, cursor)
      seen.push(...p.records.map((r) => `${r.inputHash.slice(2, 4)}:${r.value}`))
      if (!p.cursor) break
      cursor = p.cursor
    }
    assert.deepEqual(seen, ['aa:0x01', 'aa:0x02', 'aa:0x03', 'bb:0x09'])
    db.close()
  })

  test('a two-part cursor from an older node resumes without throwing', async () => {
    const { db, set } = clockDB()
    set(1000); await db.insertRecord(makeRecord({ inputHash: H('aa') }))
    set(2000); await db.insertRecord(makeRecord({ inputHash: H('bb') }))
    const p = await db.getRecordsPage('test-ns', 0, 100, `1000|${H('aa')}`)
    assert.ok(p.records.some((r) => r.inputHash === H('bb')))
    db.close()
  })
})

describe('getContributions', () => {
  test('groups records by sourcePeer', async () => {
    const db = makeDB()
    await db.insertRecord(makeRecord({ inputHash: '0x' + 'a1'.repeat(32), sourcePeer: 'http://peer-a' }))
    await db.insertRecord(makeRecord({ inputHash: '0x' + 'a2'.repeat(32), sourcePeer: 'http://peer-a' }))
    await db.insertRecord(makeRecord({ inputHash: '0x' + 'b1'.repeat(32), sourcePeer: 'http://peer-b' }))
    await db.insertRecord(makeRecord({ inputHash: '0x' + 'local'.repeat(12) + '00'.repeat(8), sourcePeer: null }))

    const contributions = await db.getContributions('test-ns')
    const byPeer = Object.fromEntries(contributions.map((c) => [c.sourcePeer ?? 'local', c.count]))

    assert.equal(byPeer['http://peer-a'], 2)
    assert.equal(byPeer['http://peer-b'], 1)
    assert.equal(byPeer['local'], 1)
    db.close()
  })
})

describe('peer operations', () => {
  test('upsert inserts and updates a peer', async () => {
    const db = makeDB()
    await db.upsertPeer({ url: 'http://peer-1', lastSyncAt: 0, healthy: true, nodeVersion: null, signerAddress: null })
    let peers = await db.getPeers()
    assert.equal(peers.length, 1)
    assert.equal(peers[0].url, 'http://peer-1')

    await db.upsertPeer({ url: 'http://peer-1', lastSyncAt: 9999, healthy: false, nodeVersion: '0.1.0', signerAddress: '0xabc' })
    peers = await db.getPeers()
    assert.equal(peers.length, 1)
    assert.equal(peers[0].lastSyncAt, 9999)
    assert.equal(peers[0].healthy, false)
    assert.equal(peers[0].nodeVersion, '0.1.0')
    db.close()
  })

  test('removePeer deletes a peer', async () => {
    const db = makeDB()
    await db.upsertPeer({ url: 'http://peer-x', lastSyncAt: 0, healthy: true, nodeVersion: null, signerAddress: null })
    await db.removePeer('http://peer-x')
    const peers = await db.getPeers()
    assert.equal(peers.length, 0)
    db.close()
  })
})

describe('peer identity pin (ERC-8309 two-tier)', () => {
  test('an upsert without identityKey (startup seeding, admin re-add) keeps the pinned identity', async () => {
    const db = makeDB()
    const url = 'https://peer.example'
    await db.upsertPeer({ url, lastSyncAt: 5, healthy: true, nodeVersion: null, signerAddress: '0xS', identityKey: '0xI', validFrom: 7 })
    await db.upsertPeer({ url, lastSyncAt: 0, healthy: true, nodeVersion: null, signerAddress: null })
    const p = (await db.getPeers()).find((x) => x.url === url)!
    assert.equal(p.identityKey, '0xI')
    assert.equal(p.validFrom, 7)
    assert.equal(p.signerAddress, null)
    await db.upsertPeer({ ...p, identityKey: '0xJ', validFrom: 9 })   // an explicit identity does update
    assert.equal((await db.getPeers()).find((x) => x.url === url)!.identityKey, '0xJ')
    db.close()
  })
})
