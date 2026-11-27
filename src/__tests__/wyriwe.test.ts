import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { keccak256, toBytes, toHex, concat } from 'viem'
import { IDENTITY_SENTINEL_CID } from '../attestation/eip712.js'
import { wyriweTripleHash, withWyriwe } from '../attestation/withWyriwe.js'

// ERC-8299 Test Case 1 (identity transform), values computed independently with `cast`
// (keccak256 over utf8("ipfs://QmccvoM6…") || rawInputHash).
const RAW = toHex(toBytes('transfer 1 ETH to 0xABCD...'))
const RAW_INPUT_HASH = '0x49a368dd77974bb589199333d0ee5e6796c1ae449b13b5336bdb5a3606ac4772'
const PIPELINE_HASH = '0xebb1960748d3e0606a21326e17d2489750ec408cd81df457630f3af6b670f57c'

describe('ERC-8299 triple-hash (wyriweTripleHash)', () => {
  test('identity path reproduces the independently computed Test Case 1 vector', () => {
    const t = wyriweTripleHash(RAW)
    assert.equal(t.rawInputHash, RAW_INPUT_HASH)
    assert.equal(t.sanitizationPipelineHash, PIPELINE_HASH)
    assert.equal(t.inputHash, RAW_INPUT_HASH, 'identity transform: inputHash == rawInputHash')
  })

  test('the pipeline hash binds the raw input: a different input gives a different pipeline hash', () => {
    assert.notEqual(wyriweTripleHash(RAW).sanitizationPipelineHash, wyriweTripleHash('0xdeadbeef').sanitizationPipelineHash)
  })

  test('the sentinel URI is the full ipfs:// URI', () => {
    assert.equal(IDENTITY_SENTINEL_CID, 'ipfs://QmccvoM6aRVgZ2dtFWvT6Wm3DmTvoAUHHotK7uQufnStVR')
  })

  test('sanitized path: inputHash = keccak256(sanitized bytes), pipeline = keccak256(utf8(uri) || rawInputHash)', () => {
    const uri = 'ipfs://QmStripHtmlSpec'
    const sanitize = (raw: `0x${string}`) => toHex(toBytes('transfer 1 ETH to 0xABCD...'))
    const raw = toHex(toBytes('transfer 1 ETH to 0xABCD... <script>alert(1)</script>'))
    const t = wyriweTripleHash(raw, { uri, sanitize })
    assert.equal(t.inputHash, keccak256(toBytes('transfer 1 ETH to 0xABCD...')))
    // independent: hex string concatenation of utf8(uri) and the raw input hash
    assert.equal(t.sanitizationPipelineHash, keccak256(('0x' + Buffer.from(uri, 'utf8').toString('hex') + keccak256(raw).slice(2)) as `0x${string}`))
    assert.notEqual(t.inputHash, t.rawInputHash)
  })

  test('withWyriwe refuses a sanitization URI without a sanitize function', () => {
    assert.throws(() => withWyriwe(async () => '0x', {
      gatewayKey: '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d',
      registryAddress: '0x95a1e10D1508EF5CD11e3F4d296359c93f15e48D',
      agentId: ('0x' + '00'.repeat(31) + '01') as `0x${string}`,
      modelHash: ('0x' + '11'.repeat(32)) as `0x${string}`,
      sanitizationCID: 'ipfs://QmStripHtmlSpec',
    }), /sanitize function/)
  })
})
