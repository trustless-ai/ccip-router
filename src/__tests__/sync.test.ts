import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { privateKeyToAccount } from 'viem/accounts'
import { SQLiteDB } from '../db/sqlite.js'
import { signRecord } from '../crypto/sign.js'
import { validateAndInsert, acceptUnsignedRecords } from '../mesh/sync.js'
import type { MeshRecord } from '../db/types.js'

const KEY = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d' as const
const SIGNER = privateKeyToAccount(KEY).address
const INPUT = ('0x' + 'ab'.repeat(32)) as `0x${string}`
const PEER = 'https://peer.example'

async function signed(value: `0x${string}`, timestamp = 1000): Promise<MeshRecord> {
  const signature = await signRecord(INPUT, 'test-ns', value, timestamp, KEY)
  return { inputHash: INPUT, namespace: 'test-ns', key: INPUT, value, timestamp, signature, sourcePeer: null }
}

describe('ERC-8309 sync: unsigned records', () => {
  test('acceptUnsignedRecords is off unless MESH_ACCEPT_UNSIGNED=true', () => {
    assert.equal(acceptUnsignedRecords({}), false)
    assert.equal(acceptUnsignedRecords({ MESH_ACCEPT_UNSIGNED: 'false' }), false)
    assert.equal(acceptUnsignedRecords({ MESH_ACCEPT_UNSIGNED: '1' }), false)
    assert.equal(acceptUnsignedRecords({ MESH_ACCEPT_UNSIGNED: 'TRUE' }), true)
  })

  test('an unsigned "0x" record is rejected and not stored by default', async () => {
    const db = new SQLiteDB(':memory:')
    const rec: MeshRecord = { inputHash: INPUT, namespace: 'test-ns', key: INPUT, value: '0x01', timestamp: 1000, signature: '0x', sourcePeer: null }
    const r = await validateAndInsert(rec, db, null, PEER, new Set(), false)
    assert.deepEqual(r, { inserted: false, signer: null, reason: 'unsigned' })
    assert.equal(await db.getRecord(INPUT, 'test-ns'), null)
  })

  test('an unsigned record is accepted only with the explicit dev opt-in', async () => {
    const db = new SQLiteDB(':memory:')
    const rec: MeshRecord = { inputHash: INPUT, namespace: 'test-ns', key: INPUT, value: '0x01', timestamp: 1000, signature: '0x', sourcePeer: null }
    const r = await validateAndInsert(rec, db, null, PEER, new Set(), true)
    assert.equal(r.inserted, true)
    assert.notEqual(await db.getRecord(INPUT, 'test-ns'), null)
  })

  test('a validly signed record from the pinned peer signer is still accepted', async () => {
    const db = new SQLiteDB(':memory:')
    const r = await validateAndInsert(await signed('0x02'), db, SIGNER, PEER, new Set([SIGNER.toLowerCase()]), false)
    assert.equal(r.inserted, true)
    assert.equal(r.signer?.toLowerCase(), SIGNER.toLowerCase())
  })

  test('a signed record from an unknown signer is still rejected', async () => {
    const db = new SQLiteDB(':memory:')
    const other = '0x000000000000000000000000000000000000dEaD'
    const r = await validateAndInsert(await signed('0x03'), db, other, PEER, new Set([other.toLowerCase()]), false)
    assert.equal(r.inserted, false)
  })
})

describe('ERC-8309 sync: since margin', () => {
  test('first pull asks for everything', async () => {
    const { sinceFor } = await import('../mesh/sync.js')
    assert.equal(sinceFor(0), 0)
  })
  test('later pulls start SINCE_SKEW_MARGIN_S before the last pull, never below 0', async () => {
    const { sinceFor, SINCE_SKEW_MARGIN_S } = await import('../mesh/sync.js')
    assert.equal(sinceFor(10_000), 10_000 - SINCE_SKEW_MARGIN_S)
    assert.equal(sinceFor(30), 0)
  })
})

describe('ERC-8309 sync: signer trust comes only from a verified /vni', () => {
  test('resolvePeerSigner: verified replaces, unverified clears, unreachable keeps', async () => {
    const { resolvePeerSigner } = await import('../mesh/sync.js')
    const vni = { status: 'verified', signer: SIGNER, vni: {} } as any
    assert.equal(resolvePeerSigner('0xold', vni), SIGNER)
    assert.equal(resolvePeerSigner('0xold', { status: 'unverified' }), null)
    assert.equal(resolvePeerSigner('0xold', { status: 'unreachable' }), '0xold')
  })

  test('with no verified peer signer, a record signed by an unknown key is rejected', async () => {
    const db = new SQLiteDB(':memory:')
    const r = await validateAndInsert(await signed('0x04'), db, null, PEER, new Set(), false)
    assert.equal(r.inserted, false)
    assert.equal(r.reason, 'unknown_signer')
  })

  test('with no verified peer signer, a relayed record from an already-verified signer is accepted', async () => {
    const db = new SQLiteDB(':memory:')
    const r = await validateAndInsert(await signed('0x05'), db, null, PEER, new Set([SIGNER.toLowerCase()]), false)
    assert.equal(r.inserted, true)
  })

  test('nextLastSyncAt defers on unknown-signer rejections for at most MAX_DEFER_CYCLES, then advances', async () => {
    const { nextLastSyncAt, MAX_DEFER_CYCLES } = await import('../mesh/sync.js')
    const state = new Map<string, number>()
    for (let i = 0; i < MAX_DEFER_CYCLES; i++) assert.equal(nextLastSyncAt(PEER, 100, 500 + i, 1, state), 100)
    assert.equal(nextLastSyncAt(PEER, 100, 999, 1, state), 999)          // bound reached: advance
    assert.equal(state.has(PEER), false)
    assert.equal(nextLastSyncAt(PEER, 100, 1000, 0, state), 1000)        // no rejections: advance
  })
})

describe('ERC-8309 syncPeer end to end (stubbed network)', () => {
  const ATTACKER_KEY = '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a' as const
  const ATTACKER = privateKeyToAccount(ATTACKER_KEY).address

  async function withFetch(routes: Record<string, unknown>, fn: () => Promise<void>) {
    const real = globalThis.fetch
    globalThis.fetch = (async (input: any) => {
      const u = new URL(String(input))
      const body = routes[u.origin + u.pathname]
      if (body === undefined) return new Response('not found', { status: 404 })
      return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } })
    }) as typeof fetch
    try { await fn() } finally { globalThis.fetch = real }
  }
  const page = (records: MeshRecord[]) => ({ protocol: 1, node_version: 'x', namespace: 'test-ns', records, cursor: null })

  test('a peer with a verified /vni has its records accepted on first contact and its signer stored', async () => {
    const { makeVni } = await import('../mesh/vni.js')
    const { syncPeer } = await import('../mesh/sync.js')
    const db = new SQLiteDB(':memory:')
    const rec = await signed('0x10')
    await withFetch({
      [`${PEER}/vni`]: await makeVni(KEY, PEER),
      [`${PEER}/records`]: page([rec]),
    }, async () => {
      const update = await syncPeer({ url: PEER, lastSyncAt: 0, healthy: true, nodeVersion: null, signerAddress: null }, 'test-ns', db, false)
      assert.equal(update.signerAddress?.toLowerCase(), SIGNER.toLowerCase())
      assert.notEqual(await db.getRecord(INPUT, 'test-ns'), null)
    })
  })

  test('a peer with no verifiable /vni cannot introduce its own signer by serving records', async () => {
    const { syncPeer } = await import('../mesh/sync.js')
    const db = new SQLiteDB(':memory:')
    const sig = await signRecord(INPUT, 'test-ns', '0x11', 1000, ATTACKER_KEY)
    const rec: MeshRecord = { inputHash: INPUT, namespace: 'test-ns', key: INPUT, value: '0x11', timestamp: 1000, signature: sig, sourcePeer: null }
    await withFetch({ [`${PEER}/records`]: page([rec]) }, async () => {   // /vni -> 404
      const update = await syncPeer({ url: PEER, lastSyncAt: 0, healthy: true, nodeVersion: null, signerAddress: null }, 'test-ns', db, false)
      assert.equal(update.signerAddress, null)                 // not learned from the record's signer
      assert.equal(update.lastSyncAt, 0)                       // deferred, not advanced
      assert.equal(await db.getRecord(INPUT, 'test-ns'), null)
    })
  })

  test('a gossiped signerAddress is not stored, so it is never trusted', async () => {
    const { syncPeer } = await import('../mesh/sync.js')
    const { makeVni } = await import('../mesh/vni.js')
    const db = new SQLiteDB(':memory:')
    const VICTIM = 'https://victim.example'
    await withFetch({
      [`${PEER}/vni`]: await makeVni(KEY, PEER),
      [`${PEER}/records`]: page([]),
      [`${PEER}/peers`]: { peers: [{ url: VICTIM, signerAddress: ATTACKER }] },
    }, async () => {
      await syncPeer({ url: PEER, lastSyncAt: 0, healthy: true, nodeVersion: null, signerAddress: null }, 'test-ns', db, true)
    })
    const victim = (await db.getPeers()).find((p) => p.url === VICTIM)
    assert.ok(victim, 'peer is still discovered')
    assert.equal(victim!.signerAddress, null, 'but its self-reported signer is not stored')
  })
})
