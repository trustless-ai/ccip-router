import { keccak256, toBytes, recoverMessageAddress } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { NODE_VERSION } from '../version.js'

export type VniDocument = {
  nodeId:        `0x${string}`   // keccak256(signerAddress) — stable node identifier
  signerAddress: `0x${string}`
  url:           string
  version:       string
  timestamp:     number          // unix seconds — freshness indicator
}

export type SignedVni = VniDocument & { signature: `0x${string}` }

// Serialise the document body for signing — must be deterministic
function vniMessage(doc: VniDocument): string {
  return 'ccip-router:vni:' + JSON.stringify(doc)
}

// Produce a fresh signed VNI for this node.
export async function makeVni(
  gatewayKey: `0x${string}`,
  url: string,
  version = NODE_VERSION,
): Promise<SignedVni> {
  const account   = privateKeyToAccount(gatewayKey)
  const timestamp = Math.floor(Date.now() / 1000)
  const nodeId    = keccak256(toBytes(account.address)) as `0x${string}`

  const doc: VniDocument = {
    nodeId,
    signerAddress: account.address,
    url,
    version,
    timestamp,
  }

  const signature = await account.signMessage({ message: vniMessage(doc) })
  return { ...doc, signature }
}

// Verify a VNI's signature — returns the recovered signer or null.
export async function verifyVni(vni: SignedVni): Promise<`0x${string}` | null> {
  try {
    const { signature, ...doc } = vni
    const recovered = await recoverMessageAddress({
      message:   vniMessage(doc as VniDocument),
      signature,
    })
    if (recovered.toLowerCase() !== vni.signerAddress.toLowerCase()) return null
    return recovered
  } catch {
    return null
  }
}

// Fetch and optionally verify a peer's VNI.
export async function fetchPeerVni(baseUrl: string): Promise<SignedVni | null> {
  try {
    const res = await fetch(new URL('/vni', baseUrl).toString(), {
      signal: AbortSignal.timeout(5_000),
    })
    if (!res.ok) return null
    return res.json() as Promise<SignedVni>
  } catch {
    return null
  }
}
