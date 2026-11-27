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
// The signed message is rebuilt from the five signed fields only, in makeVni's order. Other
// implementations add unsigned fields (the ENS Boiler gateway serves `nodeType`); including them
// in the message made a valid document fail, and they are never trusted. nodeId must be
// keccak256 of the signer's 20 address bytes.
export async function verifyVni(vni: SignedVni): Promise<`0x${string}` | null> {
  try {
    if (!vni || typeof vni.signature !== 'string' || typeof vni.signerAddress !== 'string') return null
    const doc: VniDocument = {
      nodeId:        vni.nodeId,
      signerAddress: vni.signerAddress,
      url:           vni.url,
      version:       vni.version,
      timestamp:     vni.timestamp,
    }
    if (String(doc.nodeId).toLowerCase() !== keccak256(toBytes(doc.signerAddress)).toLowerCase()) return null
    const recovered = await recoverMessageAddress({
      message:   vniMessage(doc),
      signature: vni.signature,
    })
    if (recovered.toLowerCase() !== vni.signerAddress.toLowerCase()) return null
    return recovered
  } catch {
    return null
  }
}

// Fetch AND verify a peer's /vni, distinguishing a verified signer, a reachable node that serves
// no verifiable /vni ('unverified'), and a network failure ('unreachable'). Sync treats only a
// verified signer as the peer's identity (ERC-8309: never trust a self-reported signer).
export type VniResolution =
  | { status: 'verified'; signer: `0x${string}`; vni: SignedVni }
  | { status: 'unverified' }
  | { status: 'unreachable' }

export async function resolvePeerVni(baseUrl: string): Promise<VniResolution> {
  let res: Response
  try {
    res = await fetch(new URL('/vni', baseUrl).toString(), { signal: AbortSignal.timeout(5_000) })
  } catch {
    return { status: 'unreachable' }
  }
  if (!res.ok) return { status: 'unverified' }
  let vni: SignedVni
  try { vni = await res.json() as SignedVni } catch { return { status: 'unverified' } }
  const signer = await verifyVni(vni)
  return signer ? { status: 'verified', signer, vni } : { status: 'unverified' }
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
