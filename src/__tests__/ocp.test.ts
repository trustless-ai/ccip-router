import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { buildCommitmentHash } from '../attestation/ocp.js'

const AGENT_ID    = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' as `0x${string}`
const MODEL_HASH  = '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' as `0x${string}`
const INPUT_HASH  = '0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc' as `0x${string}`
const OUTPUT_HASH = '0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd' as `0x${string}`
const TIMESTAMP   = 1_700_000_000n

describe('buildCommitmentHash', () => {
  test('is deterministic — same inputs produce same hash', () => {
    const obs = { agentId: AGENT_ID, modelHash: MODEL_HASH, inputHash: INPUT_HASH, outputHash: OUTPUT_HASH, timestamp: TIMESTAMP }
    assert.equal(buildCommitmentHash(obs), buildCommitmentHash(obs))
  })

  test('returns a 0x-prefixed 32-byte hex string', () => {
    const hash = buildCommitmentHash({
      agentId: AGENT_ID, modelHash: MODEL_HASH, inputHash: INPUT_HASH,
      outputHash: OUTPUT_HASH, timestamp: TIMESTAMP,
    })
    assert.match(hash, /^0x[0-9a-f]{64}$/)
  })

  test('changes when agentId changes', () => {
    const base = { agentId: AGENT_ID, modelHash: MODEL_HASH, inputHash: INPUT_HASH, outputHash: OUTPUT_HASH, timestamp: TIMESTAMP }
    const alt  = { ...base, agentId: '0x1111111111111111111111111111111111111111111111111111111111111111' as `0x${string}` }
    assert.notEqual(buildCommitmentHash(base), buildCommitmentHash(alt))
  })

  test('changes when outputHash changes', () => {
    const base = { agentId: AGENT_ID, modelHash: MODEL_HASH, inputHash: INPUT_HASH, outputHash: OUTPUT_HASH, timestamp: TIMESTAMP }
    const alt  = { ...base, outputHash: '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee' as `0x${string}` }
    assert.notEqual(buildCommitmentHash(base), buildCommitmentHash(alt))
  })

  test('changes when timestamp changes', () => {
    const base = { agentId: AGENT_ID, modelHash: MODEL_HASH, inputHash: INPUT_HASH, outputHash: OUTPUT_HASH, timestamp: TIMESTAMP }
    const alt  = { ...base, timestamp: TIMESTAMP + 1n }
    assert.notEqual(buildCommitmentHash(base), buildCommitmentHash(alt))
  })
})
