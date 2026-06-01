import { Hono } from 'hono'
import type { DB } from '../db/types.js'

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
  namespace?: string   // defaults to 'default' — use 'agent-attestations' for ENS Boiler
  db?: DB              // if omitted, records are not persisted (dry-run mode)
}

export class CcipRouter {
  private resolver: ResolverFn
  private namespace: string
  private db: DB | null

  constructor(opts: CcipRouterOptions) {
    this.resolver = opts.resolver
    this.namespace = opts.namespace ?? 'default'
    this.db = opts.db ?? null
  }

  // Returns a Hono app — mount wherever you need it.
  // e.g. app.route('/', router.hono())
  hono(): Hono {
    const app = new Hono()
    app.get('/:sender/:data', async (c) => {
      const sender = c.req.param('sender') as `0x${string}`
      // strip trailing .json if present (EIP-3668 clients append it)
      const raw = c.req.param('data').replace(/\.json$/, '')
      const calldata = (raw.startsWith('0x') ? raw : `0x${raw}`) as `0x${string}`

      let response: `0x${string}`
      try {
        response = await this.resolver(sender, calldata, this.namespace)
      } catch (err) {
        return c.json({ error: 'resolver error', detail: String(err) }, 500)
      }

      // write record to DB for mesh sync — fire and forget, never block the response
      if (this.db) {
        this.writeRecord(calldata, response).catch(() => {})
      }

      // EIP-3668 response: ABI-encoded (bytes)
      // TODO: wrap `response` in ABI encoding via viem encodeFunctionResult
      return c.json({ data: response })
    })

    return app
  }

  private async writeRecord(calldata: `0x${string}`, response: `0x${string}`) {
    if (!this.db) return
    // TODO: derive input_hash from calldata, write to records table
    // db.insertRecord({ namespace: this.namespace, key: inputHash, value: response, ... })
  }
}
