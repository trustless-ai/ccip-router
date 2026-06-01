import type { MeshRecord } from '../db/types.js'
import { ATTESTATION_INDEX_ABI } from './abi.js'
import { getPublicClient, getWalletClient } from './client.js'

const ZERO_HASH = '0x0000000000000000000000000000000000000000000000000000000000000000'

export type ChainOpts = {
  rpcUrl:          string
  chainId:         number
  gatewayKey:      `0x${string}`
  contractAddress: `0x${string}`
}

export type PublishResult =
  | { status: 'published'; txHash: `0x${string}` }
  | { status: 'skipped' }
  | { status: 'error'; reason: string }

export type OnChainProof =
  | { found: false }
  | { found: true; commitmentHash: `0x${string}`; signer: `0x${string}` }

// Anchor a single WYRIWE attestation record on-chain.
// Checks isRecorded() first — skips if already anchored to avoid wasted gas.
export async function publishAttestation(
  record: MeshRecord,
  opts: ChainOpts,
): Promise<PublishResult> {
  let parsed: Record<string, unknown>
  try {
    parsed = JSON.parse(record.value) as Record<string, unknown>
  } catch {
    return { status: 'error', reason: 'malformed attestation JSON' }
  }

  const commitmentHash = parsed.commitmentHash as `0x${string}` | undefined
  if (!commitmentHash) return { status: 'error', reason: 'missing commitmentHash' }

  const publicClient = getPublicClient(opts.rpcUrl, opts.chainId)

  const already = await publicClient.readContract({
    address:      opts.contractAddress,
    abi:          ATTESTATION_INDEX_ABI,
    functionName: 'isRecorded',
    args:         [commitmentHash],
  })
  if (already) return { status: 'skipped' }

  const a = {
    agentId:                  parsed.agentId                  as `0x${string}`,
    registry:                 parsed.registry                 as `0x${string}`,
    modelHash:                parsed.modelHash                as `0x${string}`,
    rawInputHash:             parsed.rawInputHash             as `0x${string}`,
    sanitizationPipelineHash: parsed.sanitizationPipelineHash as `0x${string}`,
    inputHash:                parsed.inputHash                as `0x${string}`,
    outputHash:               parsed.outputHash               as `0x${string}`,
    commitmentHash,
    timestamp: BigInt(parsed.timestamp as string),
  }

  const walletClient = getWalletClient(opts.rpcUrl, opts.chainId, opts.gatewayKey)
  const txHash = await walletClient.writeContract({
    address:      opts.contractAddress,
    abi:          ATTESTATION_INDEX_ABI,
    functionName: 'record',
    args:         [a, record.signature as `0x${string}`],
  })

  return { status: 'published', txHash }
}

// Check whether an inputHash is anchored on-chain.
// Returns the commitmentHash + signer if found, or { found: false }.
export async function checkOnChain(
  inputHash: string,
  opts: Pick<ChainOpts, 'rpcUrl' | 'chainId' | 'contractAddress'>,
): Promise<OnChainProof> {
  const publicClient = getPublicClient(opts.rpcUrl, opts.chainId)

  const commitmentHash = await publicClient.readContract({
    address:      opts.contractAddress,
    abi:          ATTESTATION_INDEX_ABI,
    functionName: 'commitmentOf',
    args:         [inputHash as `0x${string}`],
  })

  if (commitmentHash === ZERO_HASH) return { found: false }

  const signer = await publicClient.readContract({
    address:      opts.contractAddress,
    abi:          ATTESTATION_INDEX_ABI,
    functionName: 'signerOf',
    args:         [commitmentHash],
  })

  return { found: true, commitmentHash, signer }
}
