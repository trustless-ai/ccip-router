import { keccak256, toBytes } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { getDB } from '../db/index.js'
import type { ResolverFn } from '../router/index.js'
import {
  buildDomain,
  WYRIWE_TYPES,
  IDENTITY_SENTINEL,
  type WyriweAttestation,
} from './eip712.js'
import { buildCommitmentHash } from './ocp.js'

export type WyriweOpts = {
  gatewayKey:      `0x${string}`  // hot signing key
  registryAddress: `0x${string}`  // ERC-8004 registry (verifyingContract in domain)
  agentId:         `0x${string}`  // bytes32 — ERC-8004 agent identity
  modelHash:       `0x${string}`  // bytes32 — AI model identifier
  chainId?:        number         // chain where registry is deployed (default: 1)
  // sanitizationCID?: string     // future: non-sentinel path
}

// Advanced tier — wraps any ResolverFn with full WYRIWE attestation production.
//
// After every resolver call this produces an EIP-712 WyriweAttestation:
//   1. rawInputHash             = keccak256(calldata)
//   2. sanitizationPipelineHash = keccak256("IDENTITY_SENTINEL")  [sentinel path]
//   3. inputHash                = rawInputHash                     [sentinel path]
//   4. call resolver → response
//   5. outputHash               = keccak256(response)
//   6. sign WyriweAttestation with gatewayKey via EIP-712
//   7. write attestation record to DB under "{namespace}:wyriwe"
//
// The resolver response is returned unchanged — transparent to CCIP-Read callers.
// CcipRouter writes the basic signed record; this writes the WYRIWE attestation on top.
export function withWyriwe(resolver: ResolverFn, opts: WyriweOpts): ResolverFn {
  const account       = privateKeyToAccount(opts.gatewayKey)
  const chainId       = opts.chainId ?? 1
  const sentinelHash  = keccak256(toBytes(IDENTITY_SENTINEL)) as `0x${string}`

  return async (sender, calldata, namespace) => {
    // ── Triple-hash chain ──────────────────────────────────────────────────
    const rawInputHash = keccak256(calldata)

    // IDENTITY_SENTINEL path — no sanitization pipeline applied
    const sanitizationPipelineHash = sentinelHash
    const inputHash                = rawInputHash

    // ── Resolver call ──────────────────────────────────────────────────────
    const response = await resolver(sender, calldata, namespace)

    // ── Output hash ────────────────────────────────────────────────────────
    const outputHash = keccak256(toBytes(response))

    // ── OCP commitment hash (ERC-8263) ────────────────────────────────────
    const timestamp = BigInt(Math.floor(Date.now() / 1000))

    const commitmentHash = buildCommitmentHash({
      agentId:    opts.agentId,
      modelHash:  opts.modelHash,
      inputHash,     // sanitized input (== rawInputHash on sentinel path)
      outputHash,
      timestamp,
    })

    // ── Build attestation struct ───────────────────────────────────────────
    const attestation: WyriweAttestation = {
      agentId:                  opts.agentId,
      registry:                 opts.registryAddress,
      modelHash:                opts.modelHash,
      rawInputHash,
      sanitizationPipelineHash,
      inputHash,
      outputHash,
      commitmentHash,
      timestamp,
    }

    // ── EIP-712 sign ───────────────────────────────────────────────────────
    const signature = await account.signTypedData({
      domain:      buildDomain(chainId, opts.registryAddress),
      types:       WYRIWE_TYPES,
      primaryType: 'WyriweAttestation',
      message:     attestation,
    })

    // ── Persist to "{namespace}:wyriwe" ────────────────────────────────────
    // Separate namespace avoids colliding with basic records.
    // Mesh peers sync these alongside regular records.
    // JSON-serialise bigint timestamp as string for DB compatibility.
    try {
      await getDB().insertRecord({
        inputHash:  rawInputHash,
        namespace:  namespace + ':wyriwe',
        key:        rawInputHash,
        // chainId stored alongside attestation so /verify can reconstruct the EIP-712 domain
        value:      JSON.stringify({ ...attestation, timestamp: timestamp.toString(), chainId }),
        timestamp:  Number(timestamp),
        signature,
        sourcePeer: null,
      })
    } catch (err) {
      console.error('[wyriwe] failed to persist attestation:', err)
    }

    return response
  }
}
