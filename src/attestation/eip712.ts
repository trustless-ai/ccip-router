// Advanced tier — EIP-712 attestation production after execution
// Implements the WYRIWE attestation profile (ERC8004AttestationGateway domain)

export const ATTESTATION_TYPEHASH =
  'WyriweAttestation(bytes32 agentId,address registry,bytes32 modelHash,bytes32 rawInputHash,bytes32 sanitizationPipelineHash,bytes32 inputHash,bytes32 outputHash,uint256 timestamp)'

// IDENTITY_SENTINEL path: no sanitization pipeline was applied.
// sanitizationPipelineHash is set to keccak256("IDENTITY_SENTINEL") as a well-known sentinel value.
// inputHash == rawInputHash in this path.
export const IDENTITY_SENTINEL = 'IDENTITY_SENTINEL' as const

export type WyriweAttestation = {
  agentId: `0x${string}`                   // bytes32 — ERC-8004 agent identity
  registry: `0x${string}`                  // address — on-chain registry
  modelHash: `0x${string}`                 // bytes32 — AI model identifier
  rawInputHash: `0x${string}`              // bytes32 — keccak256(raw calldata)
  sanitizationPipelineHash: `0x${string}`  // bytes32 — sentinel or pipeline hash
  inputHash: `0x${string}`                 // bytes32 — keccak256(sanitized input)
  outputHash: `0x${string}`               // bytes32 — keccak256(output)
  timestamp: bigint
}

// EIP-712 type definition — passed to viem signTypedData
export const WYRIWE_TYPES = {
  WyriweAttestation: [
    { name: 'agentId',                   type: 'bytes32' },
    { name: 'registry',                  type: 'address' },
    { name: 'modelHash',                 type: 'bytes32' },
    { name: 'rawInputHash',              type: 'bytes32' },
    { name: 'sanitizationPipelineHash',  type: 'bytes32' },
    { name: 'inputHash',                 type: 'bytes32' },
    { name: 'outputHash',               type: 'bytes32' },
    { name: 'timestamp',                 type: 'uint256' },
  ],
} as const

// EIP-712 domain — chainId MUST match the chain the registry is deployed on
export function buildDomain(chainId: number, verifyingContract: `0x${string}`) {
  return {
    name:              'ERC8004AttestationGateway',
    version:           '1',
    chainId,
    verifyingContract,
  } as const
}
