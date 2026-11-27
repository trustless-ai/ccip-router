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

describe('verifyVni: interop with other implementations', () => {
  // Live /vni of the ENS Boiler gateway (an independent /records implementation), fetched 27 Nov 2026.
  // It signs the five base fields and adds an unsigned `nodeType`.
  const ENS_BOILER_VNI = {
    nodeId: '0xed30845605b17e8ab79319314a05b645f9002ddcd746f7cc2e28251ef521360c',
    signerAddress: '0x85Fa13511D170FBe173761b63D7f8DD4A6f6Bf1A',
    url: 'https://gateway.verticecriativo.pt',
    version: 'ens-boiler',
    timestamp: 1795771915,
    nodeType: 'Origin',
    signature: '0x856aaacad533415da886825671d45ff49bc50884768dd985f39cdb9779a71a8e33144924b4a88fb763650de289bdfc3da9af1fff7cf62fc71c274e28bb000d931c',
  } as any

  test('accepts a valid document that carries extra unsigned fields', async () => {
    assert.equal((await verifyVni(ENS_BOILER_VNI))?.toLowerCase(), ENS_BOILER_VNI.signerAddress.toLowerCase())
  })

  test('changing the unsigned extra field does not change the verdict (it is not trusted either way)', async () => {
    assert.ok(await verifyVni({ ...ENS_BOILER_VNI, nodeType: 'Router' }))
  })

  test('changing a signed field still fails', async () => {
    assert.equal(await verifyVni({ ...ENS_BOILER_VNI, timestamp: ENS_BOILER_VNI.timestamp + 1 }), null)
  })

  test('a nodeId that is not keccak256(signer) fails', async () => {
    const vni = await makeVni(KEY, URL)
    assert.equal(await verifyVni({ ...vni, nodeId: ('0x' + '11'.repeat(32)) as `0x${string}` }), null)
  })

  test('a non-object or unsigned document fails without throwing', async () => {
    assert.equal(await verifyVni(null as any), null)
    assert.equal(await verifyVni({} as any), null)
  })
})
