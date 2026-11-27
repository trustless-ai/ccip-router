import { Hono } from 'hono'
import { getDB } from '../db/index.js'
import { getConfig } from '../config.js'
import { recoverRecordSigner, trustedWyriweSigner } from '../crypto/sign.js'
import { privateKeyToAccount } from 'viem/accounts'
import { checkOnChain } from '../chain/publish.js'

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
    const config = getConfig()
    if (config.attestationIndex && config.rpcUrl) {
      try {
        const onChain = await checkOnChain(inputHash, {
          rpcUrl:          config.rpcUrl,
          chainId:         config.chainId,
          contractAddress: config.attestationIndex,
        })
        if (onChain.found) {
          return c.json({
            inputHash, found: true,
            proofs: [{
              namespace:       'on-chain',
              signingType:     'EIP-712 WyriweAttestation (on-chain)',
              verified:        true,
              signer:          onChain.signer,
              commitmentHash:  onChain.commitmentHash,
              source:          'AttestationIndex',
              contractAddress: config.attestationIndex,
            }],
          })
        }
      } catch (err) {
        console.warn(`[verify] on-chain lookup failed for ${inputHash}: ${String(err)}`)
      }
    }
    return c.json({ inputHash, found: false }, 404)
  }

  // "verified" means signed by a key this node knows — its own, or a peer signer verified through
  // /vni — not merely that a signature recovers to some address (every well-formed one does).
  const config = getConfig()
  const known = new Set((await db.getPeers()).flatMap((p) => (p.signerAddress ? [p.signerAddress.toLowerCase()] : [])))
  if (config.gatewayKey) known.add(privateKeyToAccount(config.gatewayKey).address.toLowerCase())

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
        const match  = await trustedWyriweSigner(record, known)
        const signer = match?.signer ?? null
        let attestation: Record<string, unknown> | null = null
        try { attestation = JSON.parse(record.value) } catch { /* malformed */ }

        return {
          namespace:   record.namespace,
          timestamp:   record.timestamp,
          sourcePeer:  record.sourcePeer,
          verified:    signer !== null,
          signingType: match?.domain === 'legacy' ? 'EIP-712 WyriweAttestation (legacy domain)' : 'EIP-712 WyriweAttestation',
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
        verified:    signer !== null && known.has(signer.toLowerCase()),
        signingType: 'EIP-191',
        signer,
        signature:   record.signature,
      }
    }),
  )

  return c.json({ inputHash, found: true, proofs })
})
