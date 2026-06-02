import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { makeVni, verifyVni } from '../mesh/vni.js'

// Hardhat dev key 0 — public, safe for tests only
const KEY  = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80' as `0x${string}`
const ADDR = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266'
const URL  = 'http://localhost:3001'

describe('makeVni', () => {
  test('returns a signed VNI with expected fields', async () => {
    const vni = await makeVni(KEY, URL)
    assert.equal(vni.signerAddress, ADDR)
    assert.equal(vni.url, URL)
    assert.ok(vni.version.match(/^\d+\.\d+\.\d+$/), 'version should be semver')
    assert.ok(typeof vni.timestamp === 'number')
    assert.match(vni.nodeId, /^0x[0-9a-f]{64}$/)
    assert.match(vni.signature, /^0x[0-9a-f]+$/)
  })

  test('nodeId is keccak256 of signer address — stable for same key', async () => {
    const a = await makeVni(KEY, URL)
    const b = await makeVni(KEY, URL)
    assert.equal(a.nodeId, b.nodeId)
  })
})

describe('verifyVni', () => {
  test('round-trips — verifyVni returns the signer address', async () => {
    const vni = await makeVni(KEY, URL)
    const recovered = await verifyVni(vni)
    assert.equal(recovered?.toLowerCase(), ADDR.toLowerCase())
  })

  test('returns null when url is tampered', async () => {
    const vni = await makeVni(KEY, URL)
    const tampered = { ...vni, url: 'http://evil.example.com' }
    const result = await verifyVni(tampered)
    assert.equal(result, null)
  })

  test('returns null when signerAddress is tampered', async () => {
    const vni = await makeVni(KEY, URL)
    const tampered = { ...vni, signerAddress: '0x0000000000000000000000000000000000000001' as `0x${string}` }
    const result = await verifyVni(tampered)
    assert.equal(result, null)
  })

  test('returns null when nodeId is tampered', async () => {
    const vni = await makeVni(KEY, URL)
    const tampered = { ...vni, nodeId: '0x' + 'ee'.repeat(32) as `0x${string}` }
    const result = await verifyVni(tampered)
    assert.equal(result, null)
  })
})
