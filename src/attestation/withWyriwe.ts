import { keccak256, toBytes } from 'viem'
import type { ResolverFn } from '../router/index.js'
import type { WyriweAttestation } from './eip712.js'

export type WyriweOpts = {
  gatewayKey: `0x${string}`     // hot signing key
  registryAddress: `0x${string}`
  agentId: `0x${string}`        // bytes32
  modelHash: `0x${string}`      // bytes32 — AI model identifier
}

// Advanced tier — wraps any ResolverFn with WYRIWE attestation production.
// After every resolver call:
//   1. rawInputHash  = keccak256(calldata)
//   2. call resolver → response
//   3. outputHash    = keccak256(response)
//   4. produce EIP-712 WyriweAttestation, sign with gatewayKey
//   5. write attestation to DB + mesh
//
// Basic tier callers don't use this — they pass a plain ResolverFn.
export function withWyriwe(resolver: ResolverFn, opts: WyriweOpts): ResolverFn {
  return async (sender, calldata, namespace) => {
    // WYRIWE triple-hash chain
    const rawInputHash = keccak256(toBytes(calldata))
    // IDENTITY_SENTINEL path — no sanitization pipeline applied
    // sanitizationPipelineHash = keccak256(IDENTITY_SENTINEL_CID || rawInputHash)
    // inputHash = rawInputHash
    // TODO: non-sentinel path when sanitization spec CID is provided

    const response = await resolver(sender, calldata, namespace)

    const outputHash = keccak256(toBytes(response))

    // TODO: build full WyriweAttestation struct, sign with opts.gatewayKey via viem signTypedData
    // TODO: write signed attestation to DB

    void rawInputHash
    void outputHash

    return response
  }
}
