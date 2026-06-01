import { keccak256, encodePacked } from 'viem'

// Basic tier: input_hash = keccak256(calldata)
// Advanced tier (withWyriwe): full triple-hash chain lives in attestation/withWyriwe.ts
export function hashCalldata(calldata: `0x${string}`): `0x${string}` {
  return keccak256(calldata)
}

// Hash the fields that a record signature must cover.
// Any peer receiving a record recomputes this before verifying the signature.
export function hashRecordPayload(
  inputHash: `0x${string}`,
  namespace: string,
  value: `0x${string}`,
  timestamp: number,
): `0x${string}` {
  return keccak256(
    encodePacked(
      ['bytes32', 'string', 'bytes32', 'uint64'],
      [inputHash, namespace, keccak256(value), BigInt(timestamp)],
    ),
  )
}
