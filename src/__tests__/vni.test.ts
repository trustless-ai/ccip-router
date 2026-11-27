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

describe('ERC-8309 two-tier /vni', () => {
  const IDENTITY = '0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6' as `0x${string}`

  test('single-key document: identity == signer, delegation 0x, validFrom 0, verifies', async () => {
    const { makeErc8309Vni, verifyErc8309Vni, nodeIdOf } = await import('../mesh/vni.js')
    const vni = await makeErc8309Vni(KEY, URL)
    assert.equal(vni.identityKey, ADDR)
    assert.equal(vni.delegation, '0x')
    assert.equal(vni.validFrom, 0)
    assert.equal(vni.version, 1)
    assert.equal(vni.nodeId, nodeIdOf(ADDR))
    assert.deepEqual(await verifyErc8309Vni(vni), { signer: ADDR, identityKey: ADDR, validFrom: 0 })
  })

  test('single-key nodeId equals the legacy nodeId (no identity change on upgrade)', async () => {
    const { makeErc8309Vni } = await import('../mesh/vni.js')
    assert.equal((await makeErc8309Vni(KEY, URL)).nodeId, (await makeVni(KEY, URL)).nodeId)
  })

  test('two-tier document verifies; nodeId derives from the identity key', async () => {
    const { makeErc8309Vni, makeDelegation, verifyErc8309Vni, nodeIdOf } = await import('../mesh/vni.js')
    const d = await makeDelegation(IDENTITY, ADDR, 1_700_000_000)
    const vni = await makeErc8309Vni(KEY, URL, d)
    assert.equal(vni.nodeId, nodeIdOf(d.identityKey))
    assert.deepEqual(await verifyErc8309Vni(vni), { signer: ADDR, identityKey: d.identityKey, validFrom: 1_700_000_000 })
  })

  test('tampering fails: delegation for another signer, a changed validFrom, url, or a fake single-key delegation', async () => {
    const { makeErc8309Vni, makeDelegation, verifyErc8309Vni } = await import('../mesh/vni.js')
    const d = await makeDelegation(IDENTITY, ADDR, 1_700_000_000)
    const vni = await makeErc8309Vni(KEY, URL, d)
    const other = await makeDelegation(IDENTITY, '0x000000000000000000000000000000000000dEaD', 1_700_000_000)
    assert.equal(await verifyErc8309Vni({ ...vni, delegation: other.delegation }), null)
    assert.equal(await verifyErc8309Vni({ ...vni, validFrom: 1_700_000_001 }), null)
    assert.equal(await verifyErc8309Vni({ ...vni, url: 'http://evil.example' }), null)
    const single = await makeErc8309Vni(KEY, URL)
    assert.equal(await verifyErc8309Vni({ ...single, validFrom: 5 }), null)
    assert.equal(await verifyErc8309Vni({ ...single, delegation: d.delegation }), null)
  })

  test('verifyAnyVni accepts both the ERC-8309 and the legacy document', async () => {
    const { makeErc8309Vni, verifyAnyVni } = await import('../mesh/vni.js')
    assert.equal((await verifyAnyVni(await makeErc8309Vni(KEY, URL)))?.format, 'erc8309')
    const legacy = await verifyAnyVni(await makeVni(KEY, URL))
    assert.deepEqual(legacy, { signer: ADDR, identityKey: ADDR, validFrom: 0, format: 'legacy' })
  })

  test('checkDelegation rejects a delegation that does not authorise the signer', async () => {
    const { makeDelegation, checkDelegation } = await import('../mesh/vni.js')
    const d = await makeDelegation(IDENTITY, ADDR, 1_700_000_000)
    assert.equal(await checkDelegation(ADDR, d), true)
    assert.equal(await checkDelegation('0x000000000000000000000000000000000000dEaD', d), false)
  })
})
