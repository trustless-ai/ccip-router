import { encodeAbiParameters, keccak256 } from 'viem'

// OCP / ERC-8263 observation commitment
// Binds the five fields that fully describe a single agent observation:
// who (agentId), what model (modelHash), what input (inputHash),
// what output (outputHash), and when (timestamp).
//
// commitmentHash = keccak256(abi.encode(OcpObservation))
// This is the value that goes on-chain in Phase 2 (AttestationIndex).

export type OcpObservation = {
  agentId:    `0x${string}`  // bytes32
  modelHash:  `0x${string}`  // bytes32
  inputHash:  `0x${string}`  // bytes32 — sanitized input (not raw)
  outputHash: `0x${string}`  // bytes32
  timestamp:  bigint
}

export function buildCommitmentHash(obs: OcpObservation): `0x${string}` {
  return keccak256(
    encodeAbiParameters(
      [
        { name: 'agentId',    type: 'bytes32' },
        { name: 'modelHash',  type: 'bytes32' },
        { name: 'inputHash',  type: 'bytes32' },
        { name: 'outputHash', type: 'bytes32' },
        { name: 'timestamp',  type: 'uint256' },
      ],
      [obs.agentId, obs.modelHash, obs.inputHash, obs.outputHash, obs.timestamp],
    ),
  )
}
