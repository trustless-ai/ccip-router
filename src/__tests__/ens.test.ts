import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { encodeAbiParameters, decodeAbiParameters } from 'viem'
import { decodeDnsName, encodeDnsName } from '../ens/dns.js'
import { withEns } from '../ens/withEns.js'

// ── DNS helpers ────────────────────────────────────────────────────────────────

function makeDnsHex(name: string): `0x${string}` {
  const bytes = encodeDnsName(name)
  return ('0x' + Buffer.from(bytes).toString('hex')) as `0x${string}`
}

// Build a full resolve(bytes,bytes) calldata
function makeResolveCalldata(name: string, innerCalldata: `0x${string}`): `0x${string}` {
  const nameHex = makeDnsHex(name)
  const encoded = encodeAbiParameters(
    [{ type: 'bytes' }, { type: 'bytes' }],
    [nameHex, innerCalldata],
  )
  return `0x9061b923${encoded.slice(2)}` as `0x${string}`
}

const ZERO32 = '0x' + '00'.repeat(32) as `0x${string}`
const SENDER = '0x0000000000000000000000000000000000000001' as `0x${string}`

// ── DNS decode / encode ────────────────────────────────────────────────────────

describe('DNS wire-format', () => {
  test('encodeDnsName round-trips through decodeDnsName', () => {
    const name    = 'vitalik.eth'
    const encoded = encodeDnsName(name)
    assert.equal(decodeDnsName(encoded), name)
  })

  test('two-label name', () => {
    assert.equal(decodeDnsName(encodeDnsName('sub.name.eth')), 'sub.name.eth')
  })

  test('single label', () => {
    assert.equal(decodeDnsName(encodeDnsName('eth')), 'eth')
  })

  test('encoded bytes end with null terminator', () => {
    const encoded = encodeDnsName('vitalik.eth')
    assert.equal(encoded[encoded.length - 1], 0)
  })
})

// ── withEns dispatch ───────────────────────────────────────────────────────────

describe('withEns — addr(bytes32)', () => {
  const innerCalldata = `0x3b3b57de${ZERO32.slice(2)}` as `0x${string}`

  test('calls resolver with type=addr and returns ABI-encoded address', async () => {
    const ADDR = '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045' as `0x${string}`
    const resolver = withEns(async (name, record) => {
      assert.equal(name, 'vitalik.eth')
      assert.equal(record.type, 'addr')
      return ADDR
    })
    const result = await resolver(SENDER, makeResolveCalldata('vitalik.eth', innerCalldata), 'test')
    const [decoded] = decodeAbiParameters([{ type: 'address' }], result)
    assert.equal((decoded as string).toLowerCase(), ADDR.toLowerCase())
  })

  test('null → zero address', async () => {
    const resolver = withEns(async () => null)
    const result   = await resolver(SENDER, makeResolveCalldata('vitalik.eth', innerCalldata), 'test')
    const [decoded] = decodeAbiParameters([{ type: 'address' }], result)
    assert.equal(decoded, '0x0000000000000000000000000000000000000000')
  })
})

describe('withEns — text(bytes32,string)', () => {
  test('calls resolver with type=text + key and returns ABI-encoded string', async () => {
    const innerCalldata = encodeAbiParameters(
      [{ type: 'bytes32' }, { type: 'string' }],
      [ZERO32, 'avatar'],
    )
    const calldata = `0x59d1d43c${innerCalldata.slice(2)}` as `0x${string}`

    const resolver = withEns(async (name, record) => {
      assert.equal(name, 'vitalik.eth')
      assert.equal(record.type, 'text')
      assert.equal((record as any).key, 'avatar')
      return 'https://example.com/avatar.png'
    })
    const result   = await resolver(SENDER, makeResolveCalldata('vitalik.eth', calldata), 'test')
    const [decoded] = decodeAbiParameters([{ type: 'string' }], result)
    assert.equal(decoded, 'https://example.com/avatar.png')
  })

  test('null → empty string', async () => {
    const innerCalldata = encodeAbiParameters(
      [{ type: 'bytes32' }, { type: 'string' }],
      [ZERO32, 'url'],
    )
    const calldata = `0x59d1d43c${innerCalldata.slice(2)}` as `0x${string}`
    const resolver = withEns(async () => null)
    const result   = await resolver(SENDER, makeResolveCalldata('vitalik.eth', calldata), 'test')
    const [decoded] = decodeAbiParameters([{ type: 'string' }], result)
    assert.equal(decoded, '')
  })
})

describe('withEns — contenthash(bytes32)', () => {
  test('calls resolver with type=contenthash and returns ABI-encoded bytes', async () => {
    const CID_HEX  = '0xe3010170122029f2d17be6139079dc48696d1f582a8530eb9805b561eda517e22a892c7e3f10' as `0x${string}`
    const innerCalldata = `0xbc1c58d1${ZERO32.slice(2)}` as `0x${string}`

    const resolver = withEns(async (name, record) => {
      assert.equal(record.type, 'contenthash')
      return CID_HEX
    })
    const result   = await resolver(SENDER, makeResolveCalldata('vitalik.eth', innerCalldata), 'test')
    const [decoded] = decodeAbiParameters([{ type: 'bytes' }], result)
    assert.equal(decoded, CID_HEX)
  })

  test('null → empty bytes', async () => {
    const innerCalldata = `0xbc1c58d1${ZERO32.slice(2)}` as `0x${string}`
    const resolver = withEns(async () => null)
    const result   = await resolver(SENDER, makeResolveCalldata('vitalik.eth', innerCalldata), 'test')
    const [decoded] = decodeAbiParameters([{ type: 'bytes' }], result)
    assert.equal(decoded, '0x')
  })
})

describe('withEns — unknown selector', () => {
  test('returns 0x for unrecognised inner call', async () => {
    const innerCalldata = '0xdeadbeef' as `0x${string}`
    const resolver = withEns(async () => 'should not be called')
    const result   = await resolver(SENDER, makeResolveCalldata('vitalik.eth', innerCalldata), 'test')
    assert.equal(result, '0x')
  })
})

describe('withEns — wrong outer selector', () => {
  test('throws on non-resolve calldata', async () => {
    const resolver = withEns(async () => null)
    await assert.rejects(
      () => resolver(SENDER, '0xdeadbeef00' as `0x${string}`, 'test'),
      /unexpected selector/,
    )
  })
})
