import { Hono } from 'hono'

export type MeshRecord = {
  key: string
  value: string
  timestamp: number
  signature: string
  namespace: string
}

// Standard mesh sync interface — any CCIP gateway implementing this is mesh-compatible
// GET /records?since=<unix_timestamp>&namespace=<string>&limit=<n>&cursor=<string>
export const recordsRouter = new Hono()

recordsRouter.get('/', async (c) => {
  const since = Number(c.req.query('since') ?? 0)
  const namespace = c.req.query('namespace') ?? 'agent-attestations'
  const limit = Number(c.req.query('limit') ?? 100)

  // TODO: query local DB for records newer than `since` in `namespace`
  const records: MeshRecord[] = []

  return c.json({
    protocol: 1,
    node_version: '0.1.0',
    namespace,
    records,
    cursor: null,
  })
})
