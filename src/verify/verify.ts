import { Hono } from 'hono'
import { getDB } from '../db/index.js'
import { recoverRecordSigner, recoverWyriweAttestation } from '../crypto/sign.js'

export const verifyRouter = new Hono()

// GET /verify/:inputHash
// Returns a clean, verifiable proof for all records matching this inputHash.
// Covers both basic (EIP-191) and WYRIWE (EIP-712) attestation namespaces.
// Phase 2: on-chain AttestationIndex fallback when not found locally.
verifyRouter.get('/:inputHash', async (c) => {
  const inputHash = c.req.param('inputHash')
  const db        = getDB()

  const records = await db.getRecordsByInputHash(inputHash)

  if (!records.length) {
    // TODO Phase 2: fall back to on-chain AttestationIndex lookup
    return c.json({ inputHash, found: false }, 404)
  }

  const proofs = await Promise.all(
    records.map(async (record) => {
      const isDryRun = record.signature === '0x'
      const isWyriwe = record.namespace.endsWith(':wyriwe')

      if (isDryRun) {
        return {
          namespace:  record.namespace,
          timestamp:  record.timestamp,
          sourcePeer: record.sourcePeer,
          verified:   false,
          reason:     'unsigned (dry-run node)',
          signer:     null,
          signature:  '0x',
        }
      }

      if (isWyriwe) {
        const signer = await recoverWyriweAttestation(record)
        let attestation: Record<string, unknown> | null = null
        try { attestation = JSON.parse(record.value) } catch { /* malformed */ }

        return {
          namespace:   record.namespace,
          timestamp:   record.timestamp,
          sourcePeer:  record.sourcePeer,
          verified:    signer !== null,
          signingType: 'EIP-712 WyriweAttestation',
          signer,
          signature:   record.signature,
          attestation: attestation
            ? {
                agentId:                  attestation.agentId,
                registry:                 attestation.registry,
                modelHash:                attestation.modelHash,
                rawInputHash:             attestation.rawInputHash,
                sanitizationPipelineHash: attestation.sanitizationPipelineHash,
                inputHash:                attestation.inputHash,
                outputHash:               attestation.outputHash,
                commitmentHash:           attestation.commitmentHash,
              }
            : null,
        }
      }

      // Basic EIP-191 signed record
      let signer: `0x${string}` | null = null
      try {
        signer = await recoverRecordSigner(record)
      } catch { /* malformed sig */ }

      return {
        namespace:   record.namespace,
        timestamp:   record.timestamp,
        sourcePeer:  record.sourcePeer,
        verified:    signer !== null,
        signingType: 'EIP-191',
        signer,
        signature:   record.signature,
      }
    }),
  )

  return c.json({ inputHash, found: true, proofs })
})
