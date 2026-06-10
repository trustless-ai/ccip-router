import { keccak256, toBytes } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { NODE_REGISTRY_ABI, NODE_REGISTRY_V2_ABI, NodeType } from './abi.js'
import { getWalletClient } from './client.js'

type RegisterOpts = {
  rpcUrl:          string
  chainId:         number
  gatewayKey:      `0x${string}`
  contractAddress: `0x${string}`
}

// Sign and submit a node registration to NodeRegistry.
// The signing key proves ownership — the signing key does not need ETH.
// The caller (opts.gatewayKey) pays gas, but the registered signer is derived from the sig.
export async function registerNode(
  url: string,
  opts: RegisterOpts,
): Promise<`0x${string}`> {
  const account   = privateKeyToAccount(opts.gatewayKey)
  const msgHash   = keccak256(toBytes('ccip-router:node:' + url))
  const signature = await account.signMessage({ message: { raw: msgHash } })

  const walletClient = getWalletClient(opts.rpcUrl, opts.chainId, opts.gatewayKey)
  return walletClient.writeContract({
    address:      opts.contractAddress,
    abi:          NODE_REGISTRY_ABI,
    functionName: 'register',
    args:         [url, signature],
  })
}

type RegisterV2Opts = RegisterOpts & { nodeType?: NodeType }

// Sign and submit a node registration to NodeRegistryV2.
// nodeType defaults to Router (1) — the standard for a ccip-router node.
export async function registerNodeV2(
  url: string,
  opts: RegisterV2Opts,
): Promise<`0x${string}`> {
  const account   = privateKeyToAccount(opts.gatewayKey)
  const msgHash   = keccak256(toBytes('ccip-router:node:' + url))
  const signature = await account.signMessage({ message: { raw: msgHash } })
  const nodeType  = opts.nodeType ?? NodeType.Router

  const walletClient = getWalletClient(opts.rpcUrl, opts.chainId, opts.gatewayKey)
  return walletClient.writeContract({
    address:      opts.contractAddress,
    abi:          NODE_REGISTRY_V2_ABI,
    functionName: 'register',
    args:         [url, nodeType, signature],
  })
}
