import { recoverMessageAddress, recoverTypedDataAddress } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { hashRecordPayload } from './hash.js'
import { buildDomain, WYRIWE_TYPES, LEGACY_WYRIWE_DOMAIN_NAME, WYRIWE_DOMAIN_NAME } from '../attestation/eip712.js'
import type { MeshRecord } from '../db/types.js'

// Sign a record payload with the gateway hot key.
// Returns EIP-191 personal_sign signature over the record hash.
export async function signRecord(
  inputHash: `0x${string}`,
  namespace: string,
  value: `0x${string}`,
  timestamp: number,
  gatewayKey: `0x${string}`,
): Promise<`0x${string}`> {
  const account = privateKeyToAccount(gatewayKey)
  const payloadHash = hashRecordPayload(inputHash, namespace, value, timestamp)
  return account.signMessage({ message: { raw: payloadHash } })
}

// Recover the signer address from a record signature.
// Returns the address that signed — caller decides if it's trusted.
export async function recoverRecordSigner(record: MeshRecord): Promise<`0x${string}`> {
  const payloadHash = hashRecordPayload(
    record.inputHash as `0x${string}`,
    record.namespace,
    record.value as `0x${string}`,
    record.timestamp,
  )
  return recoverMessageAddress({
    message:   { raw: payloadHash },
    signature: record.signature as `0x${string}`,
  })
}

// Verify a record signature against an expected signer address.
// Used by peer sync before every db.insertRecord().
export async function verifyRecord(
  record: MeshRecord,
  expectedSigner: `0x${string}`,
): Promise<boolean> {
  try {
    const signer = await recoverRecordSigner(record)
    return signer.toLowerCase() === expectedSigner.toLowerCase()
  } catch {
    return false
  }
}

// Recover the signer of a WYRIWE attestation record (EIP-712) under the given domain name.
// ecrecover always yields SOME address for a well-formed signature: a recovered address means
// nothing until it is compared with a signer the caller trusts.
// Returns null if the record is malformed or missing required fields.
export async function recoverWyriweAttestation(
  record: MeshRecord,
  domainName: string = WYRIWE_DOMAIN_NAME,
): Promise<`0x${string}` | null> {
  try {
    const att = JSON.parse(record.value) as {
      agentId:                  `0x${string}`
      registry:                 `0x${string}`
      modelHash:                `0x${string}`
      rawInputHash:             `0x${string}`
      sanitizationPipelineHash: `0x${string}`
      inputHash:                `0x${string}`
      outputHash:               `0x${string}`
      commitmentHash:           `0x${string}`
      timestamp:                string
      chainId:                  number
    }

    return await recoverTypedDataAddress({
      domain:      buildDomain(att.chainId, att.registry, domainName),
      types:       WYRIWE_TYPES,
      primaryType: 'WyriweAttestation',
      message: {
        agentId:                  att.agentId,
        registry:                 att.registry,
        modelHash:                att.modelHash,
        rawInputHash:             att.rawInputHash,
        sanitizationPipelineHash: att.sanitizationPipelineHash,
        inputHash:                att.inputHash,
        outputHash:               att.outputHash,
        commitmentHash:           att.commitmentHash,
        timestamp:                BigInt(att.timestamp),
      },
      signature: record.signature as `0x${string}`,
    })
  } catch {
    return null
  }
}

// The WYRIWE signer among `trusted` (lowercased addresses), trying the current domain name and the
// legacy one. Returns the matching signer and which domain it was signed under, or null.
export async function trustedWyriweSigner(
  record: MeshRecord,
  trusted: Set<string>,
): Promise<{ signer: `0x${string}`; domain: 'current' | 'legacy' } | null> {
  for (const [name, domain] of [[WYRIWE_DOMAIN_NAME, 'current'], [LEGACY_WYRIWE_DOMAIN_NAME, 'legacy']] as const) {
    const s = await recoverWyriweAttestation(record, name)
    if (s && trusted.has(s.toLowerCase())) return { signer: s, domain }
  }
  return null
}
