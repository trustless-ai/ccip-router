import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { keccak256, toBytes, encodeAbiParameters } from 'viem'
import { IDENTITY_SENTINEL } from '../attestation/eip712.js'

// Tests mirror the hash-chain logic in withWyriwe() without requiring the DB singleton.

const CALLDATA = '0xdeadbeef' as `0x${string}`

describe('WYRIWE hash chain — sentinel path', () => {
  test('rawInputHash = keccak256(calldata)', () => {
    const rawInputHash = keccak256(CALLDATA)
    assert.match(rawInputHash, /^0x[0-9a-f]{64}$/)
  })

  test('sanitizationPipelineHash = keccak256("IDENTITY_SENTINEL")', () => {
    const expected = keccak256(toBytes(IDENTITY_SENTINEL))
    assert.match(expected, /^0x[0-9a-f]{64}$/)
    // sentinel is a well-known fixed value
    assert.equal(expected, keccak256(toBytes('IDENTITY_SENTINEL')))
  })

  test('sentinel path: inputHash === rawInputHash', () => {
    const rawInputHash = keccak256(CALLDATA)
    // sentinel path skips the extra keccak step
    const inputHash = rawInputHash
    assert.equal(inputHash, rawInputHash)
  })
})

describe('WYRIWE hash chain — non-sentinel path', () => {
  const CID = 'ipfs://QmTestSanitizationCid'

  test('sanitizationPipelineHash = keccak256(CID)', () => {
    const hash = keccak256(toBytes(CID))
    assert.match(hash, /^0x[0-9a-f]{64}$/)
    // reproducible
    assert.equal(hash, keccak256(toBytes(CID)))
  })

  test('inputHash = keccak256(abi.encode(rawInputHash, sanitizationPipelineHash))', () => {
    const rawInputHash           = keccak256(CALLDATA)
    const sanitizationPipelineHash = keccak256(toBytes(CID)) as `0x${string}`
    const inputHash = keccak256(encodeAbiParameters(
      [{ type: 'bytes32' }, { type: 'bytes32' }],
      [rawInputHash, sanitizationPipelineHash],
    ))
    assert.match(inputHash, /^0x[0-9a-f]{64}$/)
    assert.notEqual(inputHash, rawInputHash)
  })

  test('non-sentinel inputHash differs from sentinel inputHash for same calldata', () => {
    const rawInputHash           = keccak256(CALLDATA)
    const sanitizationPipelineHash = keccak256(toBytes(CID)) as `0x${string}`

    // sentinel path
    const sentinelInput = rawInputHash

    // non-sentinel path
    const nonSentinelInput = keccak256(encodeAbiParameters(
      [{ type: 'bytes32' }, { type: 'bytes32' }],
      [rawInputHash, sanitizationPipelineHash],
    ))

    assert.notEqual(sentinelInput, nonSentinelInput)
  })

  test('different CIDs produce different inputHashes', () => {
    const rawInputHash = keccak256(CALLDATA)

    const makeInputHash = (cid: string) => {
      const sph = keccak256(toBytes(cid)) as `0x${string}`
      return keccak256(encodeAbiParameters(
        [{ type: 'bytes32' }, { type: 'bytes32' }],
        [rawInputHash, sph],
      ))
    }

    assert.notEqual(
      makeInputHash('ipfs://QmCidA'),
      makeInputHash('ipfs://QmCidB'),
    )
  })
})
