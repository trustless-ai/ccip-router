// Advanced tier — EIP-712 attestation production after execution
// Implements the WYRIWE attestation profile (ERC8004AttestationGateway domain)

export const ATTESTATION_TYPEHASH =
  'WyriweAttestation(bytes32 agentId,address registry,bytes32 modelHash,bytes32 rawInputHash,bytes32 sanitizationPipelineHash,bytes32 inputHash,bytes32 outputHash,uint256 timestamp)'

export type WyriweAttestation = {
  agentId: `0x${string}`       // bytes32
  registry: `0x${string}`      // address
  modelHash: `0x${string}`     // bytes32 — AI model identifier
  rawInputHash: `0x${string}`  // bytes32 — keccak256(raw_user_input)
  sanitizationPipelineHash: `0x${string}` // bytes32
  inputHash: `0x${string}`     // bytes32 — keccak256(sanitized_input)
  outputHash: `0x${string}`    // bytes32 — keccak256(output)
  timestamp: bigint
}

// EIP-712 domain — chainId MUST be block.chainid, never hardcoded
export function buildDomain(chainId: number, verifyingContract: `0x${string}`) {
  return {
    name: 'ERC8004AttestationGateway',
    version: '1',
    chainId,
    verifyingContract,
  }
}

// TODO: sign attestation with gateway hot key, write to local DB + mesh
