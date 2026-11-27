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
    assert.deepEqual(r, { inserted: false, signer: null })
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
