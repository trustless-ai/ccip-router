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
    // TODO: rawInputHash = keccak256(calldata)
    // TODO: sanitizationPipelineHash — IDENTITY_SENTINEL path if no sanitization
    // TODO: inputHash = keccak256(sanitized_input)

    const response = await resolver(sender, calldata, namespace)

    // TODO: outputHash = keccak256(response)
    // TODO: build WyriweAttestation, sign with opts.gatewayKey via viem
    // TODO: write attestation to DB (feeds /verify and mesh sync)

    return response
  }
}
