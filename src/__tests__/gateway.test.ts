import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { decodeRequest, encodeResponse, CcipRequestError } from '../gateway/eip3668.js'

describe('decodeRequest', () => {
  test('parses checksummed sender + 0x-prefixed calldata', () => {
    const req = decodeRequest(
      '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
      '0xdeadbeef',
    )
    assert.equal(req.sender, '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266')
    assert.equal(req.calldata, '0xdeadbeef')
  })

  test('strips .json suffix from calldata', () => {
    const req = decodeRequest(
      '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
      '0xdeadbeef.json',
    )
    assert.equal(req.calldata, '0xdeadbeef')
  })

  test('prepends 0x to bare sender', () => {
    const req = decodeRequest(
      'f39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
      '0xabcd',
    )
    assert.equal(req.sender, '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266')
  })

  test('prepends 0x to bare calldata', () => {
    const req = decodeRequest(
      '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
      'deadbeef',
    )
    assert.equal(req.calldata, '0xdeadbeef')
  })

  test('throws CcipRequestError(400) for invalid sender', () => {
    assert.throws(
      () => decodeRequest('notanaddress', '0xdeadbeef'),
      (err: unknown) => {
        assert.ok(err instanceof CcipRequestError)
        assert.equal(err.status, 400)
        return true
      },
    )
  })

  test('throws CcipRequestError(400) for invalid calldata', () => {
    assert.throws(
      () => decodeRequest('0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266', 'not-hex!'),
      (err: unknown) => {
        assert.ok(err instanceof CcipRequestError)
        assert.equal(err.status, 400)
        return true
      },
    )
  })
})

describe('encodeResponse', () => {
  test('wraps result in EIP-3668 envelope', () => {
    const res = encodeResponse('0xabcdef')
    assert.deepEqual(res, { data: '0xabcdef' })
  })
})
