import { Hono } from 'hono'
import { cors } from 'hono/cors'
import type { Config } from '../config.js'
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

export type CcipRouterOptions = {
  resolver: ResolverFn
  namespace?: string      // defaults to 'default' — use 'agent-attestations' for ENS Boiler
  db?: DB                 // if omitted, records are not persisted (dry-run mode)
  gatewayKey?: `0x${string}` | null  // from config — null = no signing
}

export class CcipRouter {
  private resolver: ResolverFn
  private namespace: string
  private db: DB | null
  private gatewayKey: `0x${string}` | null

  constructor(opts: CcipRouterOptions) {
    this.resolver   = opts.resolver
    this.namespace  = opts.namespace ?? 'default'
    this.db         = opts.db ?? null
    this.gatewayKey = opts.gatewayKey ?? null
  }

  // Returns a Hono app — mount wherever you need it.
  // e.g. app.route('/', router.hono())
  hono(): Hono {
    const app = new Hono()

    // EIP-3668 gateways are called directly from browser clients
    app.use('*', cors({ origin: '*', allowMethods: ['GET'] }))

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
      : '0x' // dry-run — unsigned, peers will reject on verify

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
