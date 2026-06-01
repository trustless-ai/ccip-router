import { Hono } from 'hono'
import { getConfig } from './config.js'
import { getDB } from './db/index.js'
import { CcipRouter } from './router/index.js'
import { withWyriwe } from './attestation/withWyriwe.js'
import { recordsRouter } from './mesh/records.js'
import { verifyRouter } from './verify/verify.js'

// Boot sequence — config first, then DB, then routes
const config = getConfig()
const db = getDB(config.dbPath)

// Seed configured peers into DB on startup.
// Sync cron reads from DB, not env — peers added via UI later also persist.
await Promise.all(
  config.peers.map((url) =>
    db.upsertPeer({ url, lastSyncAt: 0, healthy: true, nodeVersion: null })
  )
)

if (config.peers.length > 0) {
  console.log(`[mesh] ${config.peers.length} peer(s) registered: ${config.peers.join(', ')}`)
} else {
  console.log('[mesh] no peers configured — running as standalone node')
}

// ---------------------------------------------------------------------------
// Basic usage — plug in any resolver, no attestation required
// ---------------------------------------------------------------------------
// const ccip = new CcipRouter({
//   namespace: 'token-metadata',
//   db,
//   resolver: async (sender, calldata, namespace) => {
//     return encodeMyResponse(calldata)
//   },
// })

// ---------------------------------------------------------------------------
// Advanced usage — wrap resolver with WYRIWE attestation (agent stack)
// ---------------------------------------------------------------------------
// const ccip = new CcipRouter({
//   namespace: config.syncNamespace,
//   db,
//   resolver: withWyriwe(myAgentResolver, {
//     gatewayKey:      config.gatewayKey!,
//     registryAddress: process.env.REGISTRY_ADDRESS as `0x${string}`,
//     agentId:         process.env.AGENT_ID as `0x${string}`,
//     modelHash:       process.env.MODEL_HASH as `0x${string}`,
//   }),
// })

// Default dev resolver — returns empty bytes, useful for testing mesh sync
const ccip = new CcipRouter({
  namespace:  config.syncNamespace,
  db,
  gatewayKey: config.gatewayKey,
  resolver:   async (_sender, _calldata, _namespace) => '0x',
})

const app = new Hono()

app.route('/', ccip.hono())
app.route('/records', recordsRouter)
app.route('/verify', verifyRouter)

app.get('/health', async (c) => {
  const [peers, count] = await Promise.all([
    db.getPeers(),
    db.recordCount(config.syncNamespace),
  ])
  return c.json({
    ok:        true,
    version:   '0.1.0',
    namespace: config.syncNamespace,
    peers:     peers.map((p) => ({ url: p.url, healthy: p.healthy, version: p.nodeVersion })),
    records:   count,
    signing:   config.gatewayKey !== null,
  })
})

console.log(`[ccip-router] listening on :${config.port}`)
console.log(`[ccip-router] namespace: ${config.syncNamespace}`)
console.log(`[ccip-router] signing: ${config.gatewayKey ? 'enabled' : 'dry-run'}`)

export default { port: config.port, fetch: app.fetch }
