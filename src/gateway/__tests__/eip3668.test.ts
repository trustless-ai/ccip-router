import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { decodeRequest, CcipRequestError } from '../eip3668.js'

describe('decodeRequest', () => {
  const sender = '0xe61f5a6783ae09949b9a1b6821b68f89c0d7bb2d'
  const calldata = '0xabcdef'

  it('accepts 0x-prefixed sender and calldata', () => {
    const req = decodeRequest(sender, calldata)
    assert.equal(req.sender.toLowerCase(), sender)
    assert.equal(req.calldata, calldata)
  })

  it('accepts bare hex calldata without 0x prefix', () => {
    const req = decodeRequest(sender, 'abcdef')
    assert.equal(req.calldata, '0xabcdef')
  })

  it('strips .json suffix from calldata', () => {
    const req = decodeRequest(sender, `${calldata}.json`)
    assert.equal(req.calldata, calldata)
  })

  it('strips .json suffix from bare calldata', () => {
    const req = decodeRequest(sender, 'abcdef.json')
    assert.equal(req.calldata, '0xabcdef')
  })

  it('throws CcipRequestError(400) for invalid sender', () => {
    assert.throws(
      () => decodeRequest('notanaddress', calldata),
      (err: unknown) => err instanceof CcipRequestError && err.status === 400,
    )
  })

  it('throws CcipRequestError(400) for invalid calldata', () => {
    assert.throws(
      () => decodeRequest(sender, 'not-hex'),
      (err: unknown) => err instanceof CcipRequestError && err.status === 400,
    )
  })
})
