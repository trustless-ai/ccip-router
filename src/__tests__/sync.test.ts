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
  test('applyVniResolution: unreachable keeps, unverified clears the signer but keeps the pin', async () => {
    const { applyVniResolution } = await import('../mesh/sync.js')
    const prev = { signerAddress: '0xS', identityKey: '0xI', validFrom: 5 }
    assert.deepEqual(applyVniResolution(prev, { status: 'unreachable' }, 1000), prev)
    assert.deepEqual(applyVniResolution(prev, { status: 'unverified' }, 1000), { ...prev, signerAddress: null })
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

describe('ERC-8309 identity pinning (applyVniResolution)', () => {
  const I = '0x1111111111111111111111111111111111111111'
  const S1 = '0x2222222222222222222222222222222222222222'
  const S2 = '0x3333333333333333333333333333333333333333'
  const X = '0x4444444444444444444444444444444444444444'
  const v = (signer: string, identityKey: string, validFrom: number) =>
    ({ status: 'verified', signer, identityKey, validFrom, format: 'erc8309', vni: {} }) as any
  const NOW = 1_800_000_000

  test('first verified /vni pins the identity', async () => {
    const { applyVniResolution } = await import('../mesh/sync.js')
    assert.deepEqual(applyVniResolution({ signerAddress: null, identityKey: null, validFrom: null }, v(S1, I, 10), NOW),
      { signerAddress: S1, identityKey: I, validFrom: 10 })
  })

  test('upgrade: a peer stored with a legacy signer may pin only that key as identity (or as signer)', async () => {
    const { applyVniResolution } = await import('../mesh/sync.js')
    assert.equal(applyVniResolution({ signerAddress: I, identityKey: null, validFrom: null }, v(S1, I, 10), NOW).identityKey, I)
    assert.equal(applyVniResolution({ signerAddress: X, identityKey: null, validFrom: null }, v(S1, I, 10), NOW).refused, 'identity_mismatch')
  })

  test('rotation: same identity, strictly higher validFrom changes the signer', async () => {
    const { applyVniResolution } = await import('../mesh/sync.js')
    const r = applyVniResolution({ signerAddress: S1, identityKey: I, validFrom: 10 }, v(S2, I, 11), NOW)
    assert.deepEqual(r, { signerAddress: S2, identityKey: I, validFrom: 11 })
  })

  test('rollback: a lower validFrom, or an equal one with a different signer, is refused', async () => {
    const { applyVniResolution } = await import('../mesh/sync.js')
    const prev = { signerAddress: S2, identityKey: I, validFrom: 11 }
    assert.equal(applyVniResolution(prev, v(S1, I, 10), NOW).refused, 'stale_valid_from')
    assert.equal(applyVniResolution(prev, v(S1, I, 11), NOW).refused, 'stale_valid_from')
    assert.equal(applyVniResolution(prev, v(S1, I, 10), NOW).signerAddress, S2)   // pinned signer kept
  })

  test('equal validFrom is accepted again after the signer was cleared (restart / outage)', async () => {
    const { applyVniResolution } = await import('../mesh/sync.js')
    assert.equal(applyVniResolution({ signerAddress: null, identityKey: I, validFrom: 11 }, v(S2, I, 11), NOW).signerAddress, S2)
  })

  test('a different identity for a pinned peer is refused', async () => {
    const { applyVniResolution } = await import('../mesh/sync.js')
    const r = applyVniResolution({ signerAddress: S1, identityKey: I, validFrom: 10 }, v(X, X, 0), NOW)
    assert.equal(r.refused, 'identity_changed')
    assert.equal(r.identityKey, I)
  })

  test('a validFrom beyond the skew allowance is refused', async () => {
    const { applyVniResolution, VALID_FROM_SKEW_S } = await import('../mesh/sync.js')
    const prev = { signerAddress: S1, identityKey: I, validFrom: 10 }
    assert.equal(applyVniResolution(prev, v(S2, I, NOW + VALID_FROM_SKEW_S + 1), NOW).refused, 'future_valid_from')
    assert.equal(applyVniResolution(prev, v(S2, I, NOW + VALID_FROM_SKEW_S), NOW).signerAddress, S2)
  })
})

describe('ERC-8309 two-tier rotation end to end (stubbed network)', () => {
  const IDENTITY_KEY = '0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6' as const
  const NEW_SIGNER_KEY = '0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a' as const

  test('after a rotation, records from the new signer are accepted and the identity stays pinned', async () => {
    const { makeErc8309Vni, makeDelegation } = await import('../mesh/vni.js')
    const { syncPeer } = await import('../mesh/sync.js')
    const db = new SQLiteDB(':memory:')
    const real = globalThis.fetch
    const routes: Record<string, unknown> = {}
    globalThis.fetch = (async (input: any) => {
      const u = new URL(String(input)); const body = routes[u.origin + u.pathname]
      return body === undefined ? new Response('nf', { status: 404 }) : new Response(JSON.stringify(body), { status: 200 })
    }) as typeof fetch
    try {
      const now = Math.floor(Date.now() / 1000)
      const d1 = await makeDelegation(IDENTITY_KEY, SIGNER, now - 100)
      routes[`${PEER}/vni`] = await makeErc8309Vni(KEY, PEER, d1)
      routes[`${PEER}/records`] = { protocol: 1, node_version: 'x', namespace: 'test-ns', records: [await signed('0x20')], cursor: null }
      let peer = { url: PEER, lastSyncAt: 0, healthy: true, nodeVersion: null, signerAddress: null as string | null, identityKey: null as string | null, validFrom: null as number | null }
      peer = { ...peer, ...(await syncPeer(peer, 'test-ns', db, false)) } as any
      assert.equal(peer.identityKey?.toLowerCase(), d1.identityKey.toLowerCase())
      assert.equal(peer.signerAddress?.toLowerCase(), SIGNER.toLowerCase())

      // rotate: identity delegates a new signer with a higher validFrom
      const newSigner = privateKeyToAccount(NEW_SIGNER_KEY).address
      const d2 = await makeDelegation(IDENTITY_KEY, newSigner, now - 50)
      routes[`${PEER}/vni`] = await makeErc8309Vni(NEW_SIGNER_KEY, PEER, d2)
      const INPUT2 = ('0x' + 'cd'.repeat(32)) as `0x${string}`
      const sig2 = await signRecord(INPUT2, 'test-ns', '0x21', 2000, NEW_SIGNER_KEY)
      routes[`${PEER}/records`] = { protocol: 1, node_version: 'x', namespace: 'test-ns', cursor: null,
        records: [{ inputHash: INPUT2, namespace: 'test-ns', key: INPUT2, value: '0x21', timestamp: 2000, signature: sig2, sourcePeer: null }] }
      peer = { ...peer, ...(await syncPeer(peer, 'test-ns', db, false)) } as any
      assert.equal(peer.signerAddress?.toLowerCase(), newSigner.toLowerCase())
      assert.equal(peer.validFrom, now - 50)
      assert.notEqual(await db.getRecord(INPUT2, 'test-ns'), null)

      // replaying the old delegation (rollback) does not bring the old signer back
      routes[`${PEER}/vni`] = await makeErc8309Vni(KEY, PEER, d1)
      peer = { ...peer, ...(await syncPeer(peer, 'test-ns', db, false)) } as any
      assert.equal(peer.signerAddress?.toLowerCase(), newSigner.toLowerCase())
    } finally { globalThis.fetch = real }
  })
})

describe('0.9.1: same-signer divergence = same signer, same input, same timestamp, different value', () => {
  function captureWarn() {
    const warns: string[] = []; const orig = console.log
    console.log = ((m?: unknown) => { warns.push(String(m)) }) as typeof console.log
    return { warns, restore: () => { console.log = orig } }
  }
  const eq = (w: string[]) => w.filter((x) => x.includes('[same-signer divergence]')).length

  test('flags two values signed by one key for the same input and timestamp', async () => {
    const db = new SQLiteDB(':memory:')
    const c = captureWarn()
    try {
      await validateAndInsert(await signed('0x30', 5000), db, SIGNER, PEER, new Set([SIGNER.toLowerCase()]), false)
      await validateAndInsert(await signed('0x31', 5000), db, SIGNER, PEER, new Set([SIGNER.toLowerCase()]), false)
    } finally { c.restore() }
    assert.equal(eq(c.warns), 1)
    assert.ok(c.warns.some((w) => w.includes(SIGNER)), 'names the recovered signer, not a URL')
  })

  test('does NOT flag successive re-attestations (different timestamps) — the live false positive', async () => {
    const db = new SQLiteDB(':memory:')
    const c = captureWarn()
    try {
      for (const [v, t] of [['0x40', 1000], ['0x41', 2000], ['0x42', 3000]] as const)
        await validateAndInsert(await signed(v, t), db, SIGNER, PEER, new Set([SIGNER.toLowerCase()]), false)
    } finally { c.restore() }
    assert.equal(eq(c.warns), 0)
  })

  test('does NOT warn again when a stored record is re-delivered', async () => {
    const db = new SQLiteDB(':memory:')
    const a = await signed('0x50', 6000), b = await signed('0x51', 6000)
    const c = captureWarn()
    try {
      for (const r of [a, b, a, b, a]) await validateAndInsert(r, db, SIGNER, PEER, new Set([SIGNER.toLowerCase()]), false)
    } finally { c.restore() }
    assert.equal(eq(c.warns), 1)
  })

  test('does NOT flag two different signers (that is an ERC-8309 divergence)', async () => {
    const db = new SQLiteDB(':memory:')
    const OTHER_KEY = '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a' as const
    const other = privateKeyToAccount(OTHER_KEY).address
    const sig = await signRecord(INPUT, 'test-ns', '0x61', 7000, OTHER_KEY)
    const known = new Set([SIGNER.toLowerCase(), other.toLowerCase()])
    const c = captureWarn()
    try {
      await validateAndInsert(await signed('0x60', 7000), db, SIGNER, PEER, known, false)
      await validateAndInsert({ inputHash: INPUT, namespace: 'test-ns', key: INPUT, value: '0x61', timestamp: 7000, signature: sig, sourcePeer: null }, db, SIGNER, PEER, known, false)
    } finally { c.restore() }
    assert.equal(eq(c.warns), 0)
  })
})

describe('0.9.1: own signer, non-ERC-8309 records, startup seeding', () => {
  test('a record signed by this node, relayed back by a peer, is not an unknown signer', async () => {
    const { syncPeer } = await import('../mesh/sync.js')
    const { makeVni } = await import('../mesh/vni.js')
    const SELF_KEY = '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a' as const
    const self = privateKeyToAccount(SELF_KEY).address
    const own = await signRecord(INPUT, 'test-ns', '0x70', 1000, SELF_KEY)
    const db = new SQLiteDB(':memory:')
    const real = globalThis.fetch
    const routes: Record<string, unknown> = {
      [`${PEER}/vni`]: await makeVni(KEY, PEER),
      [`${PEER}/records`]: { protocol: 1, node_version: 'x', namespace: 'test-ns', cursor: null,
        records: [{ inputHash: INPUT, namespace: 'test-ns', key: INPUT, value: '0x70', timestamp: 1000, signature: own, sourcePeer: null }] },
    }
    globalThis.fetch = (async (input: any) => { const u = new URL(String(input)); const b = routes[u.origin + u.pathname]
      return b === undefined ? new Response('nf', { status: 404 }) : new Response(JSON.stringify(b), { status: 200 }) }) as typeof fetch
    try {
      const peer = { url: PEER, lastSyncAt: 500, healthy: true, nodeVersion: null, signerAddress: null }
      const update = await syncPeer(peer, 'test-ns', db, false, undefined, self)
      assert.notEqual(update.lastSyncAt, 500, 'not deferred')
      const without = await syncPeer(peer, 'test-ns', new SQLiteDB(':memory:'), false, undefined, null)
      assert.equal(without.lastSyncAt, 500, 'control: without the self signer it is deferred')
    } finally { globalThis.fetch = real }
  })

  test('a WYRIWE EIP-712 record from a trusted key is rejected as non_erc8309_signature, not unknown_signer', async () => {
    const { buildDomain, WYRIWE_TYPES } = await import('../attestation/eip712.js')
    const account = privateKeyToAccount(KEY)
    const registry = '0x95a1e10D1508EF5CD11e3F4d296359c93f15e48D' as const
    const h = (b: string) => ('0x' + b.repeat(32)) as `0x${string}`
    const msg = { agentId: h('01'), registry, modelHash: h('02'), rawInputHash: h('03'), sanitizationPipelineHash: h('04'),
      inputHash: INPUT, outputHash: h('05'), commitmentHash: h('06'), timestamp: 1234n }
    const sig = await account.signTypedData({ domain: buildDomain(1, registry), types: WYRIWE_TYPES, primaryType: 'WyriweAttestation', message: msg })
    const value = JSON.stringify({ ...msg, timestamp: '1234', chainId: 1 })
    const rec: MeshRecord = { inputHash: INPUT, namespace: 'test-ns:wyriwe', key: INPUT, value, timestamp: 1234, signature: sig, sourcePeer: null }
    const db = new SQLiteDB(':memory:')
    const known = await validateAndInsert(rec, db, null, PEER, new Set([SIGNER.toLowerCase()]), false)
    assert.equal(known.reason, 'non_erc8309_signature')
    assert.equal(known.inserted, false)
    const unknown = await validateAndInsert(rec, db, null, PEER, new Set(), false)
    assert.equal(unknown.reason, 'unknown_signer', 'control: an untrusted EIP-712 signer stays unknown')
  })

  test('seedConfiguredPeers adds new peers and leaves stored ones (and their verified signers) alone', async () => {
    const { seedConfiguredPeers } = await import('../mesh/sync.js')
    const db = new SQLiteDB(':memory:')
    await db.upsertPeer({ url: PEER, lastSyncAt: 99, healthy: true, nodeVersion: null, signerAddress: SIGNER, identityKey: SIGNER, validFrom: 0 })
    await seedConfiguredPeers(db, [PEER, 'https://new.example'])
    const peers = await db.getPeers()
    const p = peers.find((x) => x.url === PEER)!
    assert.equal(p.signerAddress, SIGNER)
    assert.equal(p.lastSyncAt, 99)
    assert.ok(peers.some((x) => x.url === 'https://new.example' && x.signerAddress === null))
  })
})

describe('0.9.2: WYRIWE domain name (WyriweAttestation) and legacy recognition', () => {
  async function wyriweRecord(domainName: string, key: `0x${string}`) {
    const { buildDomain, WYRIWE_TYPES } = await import('../attestation/eip712.js')
    const registry = '0x95a1e10D1508EF5CD11e3F4d296359c93f15e48D' as const
    const h = (b: string) => ('0x' + b.repeat(32)) as `0x${string}`
    const msg = { agentId: h('01'), registry, modelHash: h('02'), rawInputHash: h('03'), sanitizationPipelineHash: h('04'),
      inputHash: INPUT, outputHash: h('05'), commitmentHash: h('06'), timestamp: 1234n }
    const sig = await privateKeyToAccount(key).signTypedData({ domain: buildDomain(1, registry, domainName), types: WYRIWE_TYPES, primaryType: 'WyriweAttestation', message: msg })
    return { inputHash: INPUT, namespace: 'test-ns:wyriwe', key: INPUT, value: JSON.stringify({ ...msg, timestamp: '1234', chainId: 1 }), timestamp: 1234, signature: sig, sourcePeer: null } as MeshRecord
  }

  test('buildDomain defaults to the WyriweAttestation name the on-chain verifier checks', async () => {
    const { buildDomain } = await import('../attestation/eip712.js')
    assert.equal(buildDomain(1, '0x0000000000000000000000000000000000000001').name, 'WyriweAttestation')
  })

  test('trustedWyriweSigner finds a trusted signer under the current and the legacy domain, and nothing for strangers', async () => {
    const { trustedWyriweSigner } = await import('../crypto/sign.js')
    const trusted = new Set([SIGNER.toLowerCase()])
    assert.equal((await trustedWyriweSigner(await wyriweRecord('WyriweAttestation', KEY), trusted))?.domain, 'current')
    assert.equal((await trustedWyriweSigner(await wyriweRecord('ERC8004AttestationGateway', KEY), trusted))?.domain, 'legacy')
    const STRANGER = '0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a' as const
    assert.equal(await trustedWyriweSigner(await wyriweRecord('WyriweAttestation', STRANGER), trusted), null)
  })
})
