// Advanced tier — EIP-712 attestation production after execution
// Implements the ERC-8299 WYRIWE attestation profile (domain name "WyriweAttestation")

export const ATTESTATION_TYPEHASH =
  'WyriweAttestation(bytes32 agentId,address registry,bytes32 modelHash,bytes32 rawInputHash,bytes32 sanitizationPipelineHash,bytes32 inputHash,bytes32 outputHash,bytes32 commitmentHash,uint256 timestamp)'

// ERC-8299 identity transform (no sanitization). The pipeline hash binds this spec URI to the raw
// input: sanitizationPipelineHash = keccak256(utf8(IDENTITY_SENTINEL_CID) || rawInputHash), and
// inputHash == rawInputHash. (Before 0.9.2 this code used keccak256("IDENTITY_SENTINEL"), which
// is not the ERC-8299 construction and bound nothing to the input.)
export const IDENTITY_SENTINEL_CID = 'ipfs://QmccvoM6aRVgZ2dtFWvT6Wm3DmTvoAUHHotK7uQufnStVR' as const
/** @deprecated pre-0.9.2 sentinel string; kept for reading old records only. */
export const IDENTITY_SENTINEL = 'IDENTITY_SENTINEL' as const

export type WyriweAttestation = {
  agentId:                  `0x${string}`  // bytes32 — ERC-8004 agent identity
  registry:                 `0x${string}`  // address — on-chain registry
  modelHash:                `0x${string}`  // bytes32 — AI model identifier
  rawInputHash:             `0x${string}`  // bytes32 — keccak256(raw calldata)
  sanitizationPipelineHash: `0x${string}`  // bytes32 — sentinel or pipeline hash
  inputHash:                `0x${string}`  // bytes32 — keccak256(sanitized input)
  outputHash:               `0x${string}`  // bytes32 — keccak256(output)
  commitmentHash:           `0x${string}`  // bytes32 — ERC-8281 (OCP) / ERC-8263 observation commitment
  timestamp:                bigint
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
    { name: 'outputHash',                type: 'bytes32' },
    { name: 'commitmentHash',            type: 'bytes32' },
    { name: 'timestamp',                 type: 'uint256' },
  ],
} as const

// EIP-712 domain for ERC-8299 WyriweAttestation: { name "WyriweAttestation", version "1", chainId,
// verifyingContract = ERC-8004 registry } — the domain WyriweProofVerifier checks on-chain.
// Records signed before 0.9.2 used the name "ERC8004AttestationGateway" (LEGACY), which no
// on-chain verifier accepted; recovery still tries it so those records stay attributable.
export const WYRIWE_DOMAIN_NAME = 'WyriweAttestation'
export const LEGACY_WYRIWE_DOMAIN_NAME = 'ERC8004AttestationGateway'

// chainId MUST match the chain the registry is deployed on
export function buildDomain(chainId: number, verifyingContract: `0x${string}`, name: string = WYRIWE_DOMAIN_NAME) {
  return {
    name,
    version:           '1',
    chainId,
    verifyingContract,
  } as const
}
