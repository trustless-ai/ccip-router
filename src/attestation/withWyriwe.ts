import { keccak256, toBytes, encodeAbiParameters } from 'viem'
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
  gatewayKey:       `0x${string}`  // hot signing key
  registryAddress:  `0x${string}`  // ERC-8004 registry (verifyingContract in domain)
  agentId:          `0x${string}`  // bytes32 — ERC-8004 agent identity
  modelHash:        `0x${string}`  // bytes32 — AI model identifier
  chainId?:         number         // chain where registry is deployed (default: 1)
  sanitizationCID?: string         // IPFS CID / URI of sanitization pipeline; omit for sentinel (identity) path
}

// Advanced tier — wraps any ResolverFn with full WYRIWE attestation production.
//
// Triple-hash chain (two paths):
//
//   Sentinel path (no sanitizationCID):
//     sanitizationPipelineHash = keccak256("IDENTITY_SENTINEL")
//     inputHash                = rawInputHash
//
//   Non-sentinel path (sanitizationCID provided):
//     sanitizationPipelineHash = keccak256(sanitizationCID)
//     inputHash                = keccak256(abi.encode(rawInputHash, sanitizationPipelineHash))
export function withWyriwe(resolver: ResolverFn, opts: WyriweOpts): ResolverFn {
  const account      = privateKeyToAccount(opts.gatewayKey)
  const chainId      = opts.chainId ?? 1
  const sentinelHash = keccak256(toBytes(IDENTITY_SENTINEL)) as `0x${string}`

  return async (sender, calldata, namespace) => {
    // ── Triple-hash chain ──────────────────────────────────────────────────
    const rawInputHash = keccak256(calldata)

    let sanitizationPipelineHash: `0x${string}`
    let inputHash: `0x${string}`

    if (opts.sanitizationCID) {
      sanitizationPipelineHash = keccak256(toBytes(opts.sanitizationCID)) as `0x${string}`
      inputHash = keccak256(encodeAbiParameters(
        [{ type: 'bytes32' }, { type: 'bytes32' }],
        [rawInputHash, sanitizationPipelineHash],
      )) as `0x${string}`
    } else {
      sanitizationPipelineHash = sentinelHash
      inputHash                = rawInputHash
    }

    // ── Resolver call ──────────────────────────────────────────────────────
    const response = await resolver(sender, calldata, namespace)

    // ── Output hash ────────────────────────────────────────────────────────
    const outputHash = keccak256(toBytes(response))

    // ── ERC-8281 (OCP) commitment hash (ERC-8263) ─────────────────────────
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
        // chainId stored so /verify can reconstruct the EIP-712 domain
        // sanitizationCID stored so /verify can reflect the pipeline used (null = sentinel)
        value:      JSON.stringify({
          ...attestation, timestamp: timestamp.toString(), chainId,
          sanitizationCID: opts.sanitizationCID ?? null,
        }),
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
