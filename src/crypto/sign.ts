import { recoverMessageAddress } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { hashRecordPayload } from './hash.js'
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
