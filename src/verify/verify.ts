import { Hono } from 'hono'

// GET /verify/:inputHash
// Returns attestation for a given input_hash — local DB first, on-chain fallback (Phase 2)
export const verifyRouter = new Hono()

verifyRouter.get('/:inputHash', async (c) => {
  const inputHash = c.req.param('inputHash')

  // TODO: lookup in local DB
  // TODO: Phase 2 — fall back to AttestationIndex on-chain lookup

  return c.json({ inputHash, found: false }, 404)
})
