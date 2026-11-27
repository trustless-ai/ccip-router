import { keccak256, toHex, toBytes, concat } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { getDB } from '../db/index.js'
import type { ResolverFn } from '../router/index.js'
import {
  buildDomain,
  WYRIWE_TYPES,
  IDENTITY_SENTINEL_CID,
  type WyriweAttestation,
} from './eip712.js'
import { buildCommitmentHash } from './ocp.js'

export type WyriweOpts = {
  gatewayKey:       `0x${string}`  // hot signing key
  registryAddress:  `0x${string}`  // ERC-8004 registry (verifyingContract in domain)
  agentId:          `0x${string}`  // bytes32 — ERC-8004 agent identity
  modelHash:        `0x${string}`  // bytes32 — AI model identifier
  chainId?:         number         // chain where registry is deployed (default: 1)
  sanitizationCID?: string         // full spec URI, e.g. "ipfs://Qm…"; omit for the identity (sentinel) path
  sanitize?: (raw: `0x${string}`) => `0x${string}`  // REQUIRED with sanitizationCID: the transform the spec defines
}

// ERC-8299 triple-hash:
//   rawInputHash             = keccak256(raw_user_input)
//   sanitizationPipelineHash = keccak256(utf8(spec_uri) || rawInputHash)
//   inputHash                = keccak256(sanitized_input)
// Identity path: spec_uri = IDENTITY_SENTINEL_CID and sanitized_input = raw_user_input, so
// inputHash == rawInputHash.
export function wyriweTripleHash(
  raw: `0x${string}`,
  spec?: { uri: string; sanitize: (raw: `0x${string}`) => `0x${string}` },
): { rawInputHash: `0x${string}`; sanitizationPipelineHash: `0x${string}`; inputHash: `0x${string}`; sanitized: `0x${string}` } {
  const rawInputHash = keccak256(raw)
  const uri = spec?.uri ?? IDENTITY_SENTINEL_CID
  const sanitized = spec ? spec.sanitize(raw) : raw
  return {
    rawInputHash,
    sanitizationPipelineHash: keccak256(concat([toHex(uri), rawInputHash])),   // both hex: utf8(uri) || rawInputHash
    inputHash: keccak256(sanitized),
    sanitized,
  }
}

// Advanced tier — wraps any ResolverFn with full WYRIWE attestation production.
export function withWyriwe(resolver: ResolverFn, opts: WyriweOpts): ResolverFn {
  const account      = privateKeyToAccount(opts.gatewayKey)
  const chainId      = opts.chainId ?? 1
  if (opts.sanitizationCID && !opts.sanitize) {
    // A spec URI alone cannot produce inputHash = keccak256(sanitized_input).
    throw new Error('withWyriwe: sanitizationCID requires a sanitize function (ERC-8299 inputHash = keccak256(sanitized_input))')
  }
  const spec = opts.sanitizationCID && opts.sanitize ? { uri: opts.sanitizationCID, sanitize: opts.sanitize } : undefined

  return async (sender, calldata, namespace) => {
    // ── Triple-hash chain (ERC-8299 §1–2) ──────────────────────────────────
    const { rawInputHash, sanitizationPipelineHash, inputHash, sanitized } =
      wyriweTripleHash(calldata as `0x${string}`, spec)

    // ── Resolver call: the resolver receives exactly what inputHash commits to ─
    const response = await resolver(sender, sanitized, namespace)

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
