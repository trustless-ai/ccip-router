import { Hono } from 'hono'
import { privateKeyToAccount } from 'viem/accounts'
import { getConfig } from '../config.js'
import { getPublicClient } from '../chain/client.js'

// ── Mesh-side Step-1 binding recompute (non-self-attested) ────────────────────────
// A peer node RE-DERIVES an agent's source-token live-ownership verdict from its OWN
// RPC — it does not trust the issuing gateway's verdict. The gateway passes only PUBLIC
// identifiers (registry, agentId, source, sourceId, chainId); this node reads the chain
// itself and returns its independent verdict, stamped with which node computed it.
//
// Composition-note §5 Step 1, the 3-case sovereignty check:
//   valid iff ownerOf(source) is one of {agent holder, canonical ERC-6551 TBA, binding}.
// This is the one verdict that is fully recomputable from public on-chain state (no
// preimage needed), so it is the clean target for independent mesh verification.

export const bindingRouter = new Hono()

const OWNER_OF = [{
  name: 'ownerOf', type: 'function', stateMutability: 'view',
  inputs: [{ name: 'tokenId', type: 'uint256' }], outputs: [{ type: 'address' }],
}] as const

const ERC6551_REGISTRY = '0x000000006551c19487814612e58FE06813775758' as const
const REGISTRY_ACCOUNT = [{
  name: 'account', type: 'function', stateMutability: 'view',
  inputs: [
    { name: 'implementation', type: 'address' }, { name: 'salt', type: 'bytes32' },
    { name: 'chainId', type: 'uint256' }, { name: 'tokenContract', type: 'address' },
    { name: 'tokenId', type: 'uint256' },
  ],
  outputs: [{ type: 'address' }],
}] as const

const ZERO_SALT = '0x0000000000000000000000000000000000000000000000000000000000000000' as const

// GET /recompute/binding?registry=0x..&agentId=N&source=0x..&sourceId=M&chainId=1
bindingRouter.get('/binding', async (c) => {
  const config   = getConfig()
  const registry = c.req.query('registry')
  const agentId  = c.req.query('agentId')
  const source   = c.req.query('source')
  const sourceId = c.req.query('sourceId')
  const chainId  = Number(c.req.query('chainId') ?? config.chainId ?? 1)

  const signer = config.gatewayKey ? privateKeyToAccount(config.gatewayKey).address : null
  const recomputedBy = { node: config.nodeUrl ?? null, signer }

  if (!registry || !agentId || !source || !sourceId) {
    return c.json({ status: 'unverifiable', reason: 'need registry, agentId, source, sourceId', recomputedBy }, 400)
  }
  // This node can only independently recompute if it has an RPC for the agent's chain.
  if (!config.rpcUrl || chainId !== config.chainId) {
    return c.json({ status: 'unverifiable', reason: `no RPC for chainId ${chainId}`, recomputedBy })
  }

  try {
    const client = getPublicClient(config.rpcUrl, chainId)
    const [sourceOwner, agentHolder] = await Promise.all([
      client.readContract({ address: source as `0x${string}`,   abi: OWNER_OF, functionName: 'ownerOf', args: [BigInt(sourceId)] }),
      client.readContract({ address: registry as `0x${string}`, abi: OWNER_OF, functionName: 'ownerOf', args: [BigInt(agentId)] }),
    ])
    const so = String(sourceOwner).toLowerCase()

    // (a) agent holder
    if (so === String(agentHolder).toLowerCase()) {
      return c.json({ status: 'valid', matchedCase: 'holder', sourceOwner, agentHolder, recomputedBy })
    }
    // (b) canonical ERC-6551 TBA (sovereign case) — env-gated, deterministic via account()
    let derivedTba: string | undefined
    const impl = process.env.ERC6551_IMPLEMENTATION
    if (impl) {
      const salt = (process.env.ERC6551_SALT as `0x${string}`) || ZERO_SALT
      const tba = await client.readContract({
        address: ERC6551_REGISTRY, abi: REGISTRY_ACCOUNT, functionName: 'account',
        args: [impl as `0x${string}`, salt, BigInt(chainId), registry as `0x${string}`, BigInt(agentId)],
      })
      derivedTba = String(tba)
      if (so === derivedTba.toLowerCase()) {
        return c.json({ status: 'valid', matchedCase: 'tba', sourceOwner, agentHolder, tba: derivedTba, recomputedBy })
      }
    }
    // (c) binding contract — env-gated
    const binding = process.env.ERC8217_BINDING
    if (binding && so === binding.toLowerCase()) {
      return c.json({ status: 'valid', matchedCase: 'binding', sourceOwner, agentHolder, recomputedBy })
    }
    return c.json({
      status: 'invalid', sourceOwner, agentHolder, tba: derivedTba,
      reason: 'source owner is none of {holder, TBA, binding} — binding no longer live',
      recomputedBy,
    })
  } catch (e: any) {
    return c.json({ status: 'unverifiable', reason: e?.shortMessage ?? e?.message ?? 'rpc error', recomputedBy })
  }
})
