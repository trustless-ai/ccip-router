import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { privateKeyToAccount } from 'viem/accounts'
import type { DB } from '../db/types.js'
import { hashCalldata, signRecord } from '../crypto/index.js'
import { decodeRequest, encodeResponse, CcipRequestError } from '../gateway/eip3668.js'

// The function the operator supplies — all resolver logic lives here.
// ccip-router owns: CCIP-Read decode, record writing, mesh sync.
// The operator owns: what to return for a given calldata.
export type ResolverFn = (
  sender: `0x${string}`,
  calldata: `0x${string}`,
  namespace: string
) => Promise<`0x${string}`>

// ERC-8004 agent identity — optional, enables /identity endpoint.
// agentId and registryAddress flow into WyriweAttestation structs automatically
// when withWyriwe() is also used.
export type IdentityOpts = {
  agentId:         `0x${string}`  // bytes32
  registryAddress: `0x${string}`  // on-chain ERC-8004 registry
  chainId:         number         // chain where registry is deployed
}

export type CcipRouterOptions = {
  resolver:    ResolverFn
  namespace?:  string                    // defaults to 'agent-attestations'
  db?:         DB                        // omit for no persistence (dry-run)
  gatewayKey?: `0x${string}` | null      // omit or null for unsigned records
  identity?:   IdentityOpts             // ERC-8004 — optional
}

export class CcipRouter {
  private resolver:   ResolverFn
  private namespace:  string
  private db:         DB | null
  private gatewayKey: `0x${string}` | null
  private identity:   IdentityOpts | null

  constructor(opts: CcipRouterOptions) {
    this.resolver   = opts.resolver
    this.namespace  = opts.namespace ?? 'agent-attestations'
    this.db         = opts.db ?? null
    this.gatewayKey = opts.gatewayKey ?? null
    this.identity   = opts.identity ?? null
  }

  // Returns a Hono app — mount at '/' via app.route('/', router.hono())
  hono(): Hono {
    const app = new Hono()

    // EIP-3668 gateways are called directly from browser clients
    app.use('*', cors({ origin: '*', allowMethods: ['GET'] }))

    // GET /identity — ERC-8004 declared identity, machine-readable for peer discovery.
    // 404 if not configured — callers should treat absence as "identity unknown".
    app.get('/identity', (c) => {
      if (!this.identity) {
        return c.json({ declared: false }, 404)
      }
      const signerAddress = this.gatewayKey
        ? privateKeyToAccount(this.gatewayKey).address
        : null
      return c.json({
        declared:        true,
        agentId:         this.identity.agentId,
        registryAddress: this.identity.registryAddress,
        chainId:         this.identity.chainId,
        namespace:       this.namespace,
        signerAddress,
      })
    })

    app.get('/:sender/:data', async (c) => {
      let req: ReturnType<typeof decodeRequest>
      try {
        req = decodeRequest(c.req.param('sender'), c.req.param('data'))
      } catch (err) {
        if (err instanceof CcipRequestError) {
          return c.json({ error: err.message }, err.status)
        }
        return c.json({ error: 'bad request' }, 400)
      }

      let result: `0x${string}`
      try {
        result = await this.resolver(req.sender, req.calldata, this.namespace)
      } catch (err) {
        return c.json({ error: 'resolver error', detail: String(err) }, 500)
      }

      // fire-and-forget — never block the CCIP response on DB write
      this.writeRecord(req.calldata, result).catch((err) =>
        console.error('[ccip-router] writeRecord failed:', err)
      )

      return c.json(encodeResponse(result))
    })

    return app
  }

  private async writeRecord(calldata: `0x${string}`, response: `0x${string}`) {
    if (!this.db) return

    const inputHash = hashCalldata(calldata)
    const timestamp = Math.floor(Date.now() / 1000)

    const signature = this.gatewayKey
      ? await signRecord(inputHash, this.namespace, response, timestamp, this.gatewayKey)
      : '0x' // dry-run — unsigned, peers will accept with warning

    await this.db.insertRecord({
      inputHash,
      namespace:  this.namespace,
      key:        inputHash,
      value:      response,
      timestamp,
      signature,
      sourcePeer: null,
    })
  }
}
