import { createPublicClient, createWalletClient, defineChain, http } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'

function makeChain(chainId: number, rpcUrl: string) {
  return defineChain({
    id: chainId,
    name: `chain-${chainId}`,
    nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
    rpcUrls: { default: { http: [rpcUrl] } },
  })
}

export function getPublicClient(rpcUrl: string, chainId: number) {
  return createPublicClient({ chain: makeChain(chainId, rpcUrl), transport: http(rpcUrl) })
}

export function getWalletClient(rpcUrl: string, chainId: number, privateKey: `0x${string}`) {
  return createWalletClient({
    account:   privateKeyToAccount(privateKey),
    chain:     makeChain(chainId, rpcUrl),
    transport: http(rpcUrl),
  })
}
