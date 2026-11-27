import { keccak256, toBytes, recoverMessageAddress, encodeAbiParameters, isAddress, isHex } from 'viem'
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
  | { status: 'verified'; signer: `0x${string}`; identityKey: `0x${string}`; validFrom: number; format: 'erc8309' | 'legacy'; vni: AnyVni }
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
  let vni: AnyVni
  try { vni = await res.json() as AnyVni } catch { return { status: 'unverified' } }
  const v = await verifyAnyVni(vni)
  return v ? { status: 'verified', ...v, vni } : { status: 'unverified' }
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

// ─── ERC-8309 two-tier /vni ────────────────────────────────────────────────────────────────────
// A cold identity key delegates a hot signer key: nodeId = keccak256(identityKey address bytes),
// delegation = identity key's ERC-191 signature over the 32 raw bytes of
// keccak256(abi.encode(bytes32 nodeId, address signer, uint64 validFrom)), and the document is
// signed by the signer over the 32 raw bytes of vniDigest. A single-key node sets
// identityKey == signerAddress, delegation "0x", validFrom 0.

export const VNI_PROTOCOL_VERSION = 1
const UINT64_MAX = 2n ** 64n - 1n

export type Erc8309Vni = {
  nodeId:        `0x${string}`
  identityKey:   `0x${string}`
  signerAddress: `0x${string}`
  delegation:    `0x${string}`
  validFrom:     number
  url:           string
  version:       number
  timestamp:     number
  signature:     `0x${string}`
}

export type AnyVni = Erc8309Vni | SignedVni

export type NodeDelegation = {
  identityKey: `0x${string}`
  delegation:  `0x${string}`
  validFrom:   number
}

export function nodeIdOf(identityKey: string): `0x${string}` {
  return keccak256(toBytes(identityKey as `0x${string}`))
}

export function delegationHash(nodeId: `0x${string}`, signerAddress: `0x${string}`, validFrom: number): `0x${string}` {
  return keccak256(encodeAbiParameters(
    [{ type: 'bytes32' }, { type: 'address' }, { type: 'uint64' }],
    [nodeId, signerAddress, BigInt(validFrom)],
  ))
}

export function vniDigest(doc: Omit<Erc8309Vni, 'signature' | 'delegation'>): `0x${string}` {
  return keccak256(encodeAbiParameters(
    [{ type: 'bytes32' }, { type: 'address' }, { type: 'address' }, { type: 'uint64' },
     { type: 'bytes32' }, { type: 'uint256' }, { type: 'uint64' }],
    [doc.nodeId, doc.identityKey, doc.signerAddress, BigInt(doc.validFrom),
     keccak256(toBytes(doc.url)), BigInt(doc.version), BigInt(doc.timestamp)],
  ))
}

// Run by the operator with the (cold) identity key, once per rotation. The node itself only ever
// holds the signer key plus this delegation.
export async function makeDelegation(
  identityPrivateKey: `0x${string}`,
  signerAddress: `0x${string}`,
  validFrom: number,
): Promise<NodeDelegation> {
  const identity = privateKeyToAccount(identityPrivateKey)
  const hash = delegationHash(nodeIdOf(identity.address), signerAddress, validFrom)
  return { identityKey: identity.address, delegation: await identity.signMessage({ message: { raw: hash } }), validFrom }
}

// Checks a configured delegation before the node serves it (startup).
export async function checkDelegation(signerAddress: `0x${string}`, d: NodeDelegation): Promise<boolean> {
  try {
    const recovered = await recoverMessageAddress({
      message: { raw: delegationHash(nodeIdOf(d.identityKey), signerAddress, d.validFrom) },
      signature: d.delegation,
    })
    return recovered.toLowerCase() === d.identityKey.toLowerCase()
  } catch {
    return false
  }
}

// Produce this node's ERC-8309 /vni. Without a delegation the node is single-key.
export async function makeErc8309Vni(
  gatewayKey: `0x${string}`,
  url: string,
  delegation: NodeDelegation | null = null,
  now: number = Math.floor(Date.now() / 1000),
): Promise<Erc8309Vni> {
  const signer = privateKeyToAccount(gatewayKey)
  const identityKey = delegation?.identityKey ?? signer.address
  const body = {
    nodeId:        nodeIdOf(identityKey),
    identityKey,
    signerAddress: signer.address,
    validFrom:     delegation?.validFrom ?? 0,
    url,
    version:       VNI_PROTOCOL_VERSION,
    timestamp:     now,
  }
  const signature = await signer.signMessage({ message: { raw: vniDigest(body) } })
  return { ...body, delegation: delegation?.delegation ?? '0x', signature }
}

const isUint = (n: unknown, max: bigint): n is number =>
  typeof n === 'number' && Number.isSafeInteger(n) && n >= 0 && BigInt(n) <= max

// Verify an ERC-8309 /vni. Returns the signer, identity key and validFrom, or null.
export async function verifyErc8309Vni(vni: Erc8309Vni): Promise<{ signer: `0x${string}`; identityKey: `0x${string}`; validFrom: number } | null> {
  try {
    if (!vni || !isAddress(vni.identityKey, { strict: false }) || !isAddress(vni.signerAddress, { strict: false })) return null
    if (typeof vni.url !== 'string' || !isHex(vni.signature) || !isHex(vni.delegation)) return null
    if (!isUint(vni.validFrom, UINT64_MAX) || !isUint(vni.timestamp, UINT64_MAX) || !isUint(vni.version, 2n ** 53n)) return null
    if (String(vni.nodeId).toLowerCase() !== nodeIdOf(vni.identityKey).toLowerCase()) return null

    const singleKey = vni.identityKey.toLowerCase() === vni.signerAddress.toLowerCase()
    if (singleKey) {
      if (vni.delegation !== '0x' || vni.validFrom !== 0) return null
    } else {
      const ok = await checkDelegation(vni.signerAddress, { identityKey: vni.identityKey, delegation: vni.delegation, validFrom: vni.validFrom })
      if (!ok) return null
    }
    const recovered = await recoverMessageAddress({ message: { raw: vniDigest(vni) }, signature: vni.signature })
    if (recovered.toLowerCase() !== vni.signerAddress.toLowerCase()) return null
    return { signer: recovered, identityKey: vni.identityKey, validFrom: vni.validFrom }
  } catch {
    return null
  }
}

// Accept both the ERC-8309 document and the legacy single-key one (older ccip-router nodes and
// the ENS Boiler gateway). A legacy document is a single-key identity: identity == signer, validFrom 0.
export async function verifyAnyVni(vni: AnyVni): Promise<{ signer: `0x${string}`; identityKey: `0x${string}`; validFrom: number; format: 'erc8309' | 'legacy' } | null> {
  if (vni && typeof vni === 'object' && 'identityKey' in vni) {
    const v = await verifyErc8309Vni(vni as Erc8309Vni)
    return v ? { ...v, format: 'erc8309' } : null
  }
  const signer = await verifyVni(vni as SignedVni)
  return signer ? { signer, identityKey: signer, validFrom: 0, format: 'legacy' } : null
}
