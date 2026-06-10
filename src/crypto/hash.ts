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

import { encodeAbiParameters } from 'viem'

export type SnapshotRow = {
  contributor: `0x${string}`
  score: bigint
  timestamp: bigint
}

export function computeSnapshotRoot(rows: SnapshotRow[]): `0x${string}` {
  if (rows.length === 0) return keccak256('0x')
  const encoded = encodeAbiParameters(
    [{ type: 'tuple[]', components: [
      { name: 'contributor', type: 'address' },
      { name: 'score',       type: 'uint256' },
      { name: 'timestamp',   type: 'uint256' },
    ] as const }],
    [rows],
  )
  return keccak256(encoded)
}

export function computeCommitmentHash(
  snapshotRoot: `0x${string}`,
  periodId: bigint,
  nodeAddress: `0x${string}`,
): `0x${string}` {
  const encoded = encodeAbiParameters(
    [{ type: 'bytes32' }, { type: 'uint256' }, { type: 'address' }],
    [snapshotRoot, periodId, nodeAddress],
  )
  return keccak256(encoded)
}
