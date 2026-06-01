import { isAddress, isHex } from 'viem'

export type CcipRequest = {
  sender: `0x${string}`
  calldata: `0x${string}`
}

export type CcipResponse = {
  data: `0x${string}`
}

// Decode sender + calldata from EIP-3668 URL path segments.
// Handles: checksummed / lowercase addresses, 0x-prefixed / bare hex calldata, .json suffix.
export function decodeRequest(rawSender: string, rawData: string): CcipRequest {
  const sender = rawSender.startsWith('0x') ? rawSender : `0x${rawSender}`
  if (!isAddress(sender)) {
    throw new CcipRequestError(`invalid sender address: "${rawSender}"`, 400)
  }

  const stripped = rawData.replace(/\.json$/, '')
  const calldata = (stripped.startsWith('0x') ? stripped : `0x${stripped}`) as `0x${string}`
  if (!isHex(calldata)) {
    throw new CcipRequestError(`invalid calldata: "${rawData}"`, 400)
  }

  return { sender: sender as `0x${string}`, calldata }
}

// Wrap resolver output in the EIP-3668 JSON response envelope.
export function encodeResponse(result: `0x${string}`): CcipResponse {
  return { data: result }
}

export class CcipRequestError extends Error {
  constructor(message: string, public readonly status: 400 | 500) {
    super(message)
    this.name = 'CcipRequestError'
  }
}
