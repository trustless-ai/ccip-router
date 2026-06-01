import { Hono } from 'hono'
import { getDB } from '../db/index.js'
import { getConfig } from '../config.js'

export const ocpRouter = new Hono()

// GET /ocp/:inputHash
// Returns the OCP ERC-8263 observation commitment for a given inputHash.
// Lighter-weight than /verify — only returns the commitment hash and its
// component fields, no signature recovery. Useful for on-chain Phase 2
// lookups against AttestationIndex.sol.
ocpRouter.get('/:inputHash', async (c) => {
  const inputHash = c.req.param('inputHash')
  const config    = getConfig()
  const db        = getDB()

  const records = await db.getRecordsByInputHash(inputHash)
  const wyriwe  = records.find((r) => r.namespace === config.syncNamespace + ':wyriwe')

  if (!wyriwe) {
    return c.json({ inputHash, found: false }, 404)
  }

  let att: Record<string, unknown>
  try {
    att = JSON.parse(wyriwe.value)
  } catch {
    return c.json({ inputHash, found: false, error: 'malformed attestation' }, 500)
  }

  return c.json({
    inputHash,
    found:          true,
    commitmentHash: att.commitmentHash ?? null,
    observation: {
      agentId:    att.agentId,
      modelHash:  att.modelHash,
      inputHash:  att.inputHash,
      outputHash: att.outputHash,
      timestamp:  att.timestamp,
    },
    namespace:  wyriwe.namespace,
    sourcePeer: wyriwe.sourcePeer,
  })
})
