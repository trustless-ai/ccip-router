import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { signRecord, recoverRecordSigner, verifyRecord } from '../crypto/sign.js'

// Hardhat dev key 0 — public, safe for tests only
const KEY   = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80' as `0x${string}`
const ADDR  = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266'
const KEY2  = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d' as `0x${string}`

const INPUT_HASH = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' as `0x${string}`
const NAMESPACE  = 'test-namespace'
const VALUE      = '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' as `0x${string}`
const TIMESTAMP  = 1_700_000_000

describe('signRecord + recoverRecordSigner', () => {
  test('round-trips — recovered signer matches key owner', async () => {
    const sig = await signRecord(INPUT_HASH, NAMESPACE, VALUE, TIMESTAMP, KEY)
    const record = { inputHash: INPUT_HASH, namespace: NAMESPACE, key: INPUT_HASH, value: VALUE, timestamp: TIMESTAMP, signature: sig, sourcePeer: null }
    const signer = await recoverRecordSigner(record)
    assert.equal(signer.toLowerCase(), ADDR.toLowerCase())
  })

  test('signature is 0x-prefixed hex', async () => {
    const sig = await signRecord(INPUT_HASH, NAMESPACE, VALUE, TIMESTAMP, KEY)
    assert.match(sig, /^0x[0-9a-f]+$/)
  })

  test('different timestamps produce different signatures', async () => {
    const sig1 = await signRecord(INPUT_HASH, NAMESPACE, VALUE, TIMESTAMP, KEY)
    const sig2 = await signRecord(INPUT_HASH, NAMESPACE, VALUE, TIMESTAMP + 1, KEY)
    assert.notEqual(sig1, sig2)
  })
})

describe('verifyRecord', () => {
  test('returns true for the correct expected signer', async () => {
    const sig = await signRecord(INPUT_HASH, NAMESPACE, VALUE, TIMESTAMP, KEY)
    const record = { inputHash: INPUT_HASH, namespace: NAMESPACE, key: INPUT_HASH, value: VALUE, timestamp: TIMESTAMP, signature: sig, sourcePeer: null }
    const ok = await verifyRecord(record, ADDR as `0x${string}`)
    assert.equal(ok, true)
  })

  test('returns false for a different expected signer', async () => {
    const sig = await signRecord(INPUT_HASH, NAMESPACE, VALUE, TIMESTAMP, KEY)
    const record = { inputHash: INPUT_HASH, namespace: NAMESPACE, key: INPUT_HASH, value: VALUE, timestamp: TIMESTAMP, signature: sig, sourcePeer: null }
    // KEY2's address — not the signer of this record
    const wrongAddr = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8' as `0x${string}`
    const ok = await verifyRecord(record, wrongAddr)
    assert.equal(ok, false)
  })

  test('returns false for a tampered value', async () => {
    const sig = await signRecord(INPUT_HASH, NAMESPACE, VALUE, TIMESTAMP, KEY)
    const tampered = { inputHash: INPUT_HASH, namespace: NAMESPACE, key: INPUT_HASH, value: '0xdeadbeef' as `0x${string}`, timestamp: TIMESTAMP, signature: sig, sourcePeer: null }
    const ok = await verifyRecord(tampered, ADDR as `0x${string}`)
    assert.equal(ok, false)
  })
})
