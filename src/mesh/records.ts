import { Hono } from 'hono'
import { getDB } from '../db/index.js'

// Standard mesh sync interface — any CCIP gateway implementing this is mesh-compatible
// GET /records?since=<unix_timestamp>&namespace=<string>&limit=<n>&cursor=<string>
export const recordsRouter = new Hono()

recordsRouter.get('/', async (c) => {
  const since     = Number(c.req.query('since') ?? 0)
  const namespace = c.req.query('namespace') ?? 'agent-attestations'
  const limit     = Math.min(Number(c.req.query('limit') ?? 100), 500)
  const cursor    = c.req.query('cursor') ?? undefined

  const db = getDB()
  const records = await db.getRecordsSince(namespace, since, limit, cursor)

  // next cursor: timestamp|input_hash of the last record returned
  const nextCursor = records.length === limit
    ? `${records[records.length - 1].timestamp}|${records[records.length - 1].inputHash}`
    : null

  return c.json({
    protocol:     1,
    node_version: '0.1.0',
    namespace,
    records,
    cursor:       nextCursor,
  })
})
