import { Hono } from 'hono'
import { getDB } from '../db/index.js'

// GET /verify/:inputHash
// Returns attestation for a given input_hash — local DB first, on-chain fallback (Phase 2)
export const verifyRouter = new Hono()

verifyRouter.get('/:inputHash', async (c) => {
  const inputHash = c.req.param('inputHash')

  const db = getDB()
  const record = await db.getRecord(inputHash)

  if (!record) {
    // TODO: Phase 2 — fall back to AttestationIndex on-chain lookup before returning 404
    return c.json({ inputHash, found: false }, 404)
  }

  return c.json({ inputHash, found: true, record })
})
