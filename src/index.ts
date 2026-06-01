import { Hono } from 'hono'
import { serve } from '@hono/node-server'
import { privateKeyToAccount } from 'viem/accounts'
import { getConfig, isConfigured } from './config.js'
import { getDB } from './db/index.js'
import { CcipRouter } from './router/index.js'
import { withWyriwe } from './attestation/withWyriwe.js'
import { recordsRouter } from './mesh/records.js'
import { verifyRouter } from './verify/verify.js'
import { startSyncCron } from './mesh/cron.js'
import { setupRouter } from './ui/setup.js'
import { adminRouter } from './ui/admin.js'
import { staticRouter } from './ui/static.js'

const app = new Hono()

// Setup wizard — shown when node has no gateway key configured
app.route('/setup', setupRouter)
app.route('/admin', adminRouter)
app.route('/', staticRouter)
app.get('/', (c) => {
  if (!isConfigured()) return c.redirect('/setup')
  return c.redirect('/admin')
})

// Block all other routes until configured
app.use('*', async (c, next) => {
  if (!isConfigured() && !c.req.path.startsWith('/setup')) {
    return c.redirect('/setup')
  }
  await next()
})

// Boot sequence — config first, then DB, then routes
const config = getConfig()
const db = getDB(config.dbPath)

// Seed configured peers into DB on startup.
// Sync cron reads from DB, not env — peers added via UI later also persist.
await Promise.all(
  config.peers.map((url) =>
    db.upsertPeer({ url, lastSyncAt: 0, healthy: true, nodeVersion: null, signerAddress: null })
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

// Specific named routes must be registered before the CCIP wildcard /:sender/:data
app.route('/records', recordsRouter)
app.route('/verify', verifyRouter)
app.route('/', ccip.hono())

app.get('/health', async (c) => {
  const [peers, count] = await Promise.all([
    db.getPeers(),
    db.recordCount(config.syncNamespace),
  ])
  return c.json({
    ok:            true,
    version:       '0.1.0',
    namespace:     config.syncNamespace,
    signerAddress: signerAddress,
    peers:         peers.map((p) => ({
      url:           p.url,
      healthy:       p.healthy,
      nodeVersion:   p.nodeVersion,
      signerAddress: p.signerAddress,
      lastSyncAt:    p.lastSyncAt,
    })),
    records:       count,
  })
})

// Start mesh sync cron after routes are wired
startSyncCron(config, db)

const signerAddress = config.gatewayKey
  ? privateKeyToAccount(config.gatewayKey).address
  : null

serve({ fetch: app.fetch, port: config.port })

console.log(`[ccip-router] listening on :${config.port}`)
console.log(`[ccip-router] namespace:  ${config.syncNamespace}`)
console.log(`[ccip-router] signing:    ${signerAddress ?? 'dry-run'}`)
console.log(`[ccip-router] peers:      ${config.peers.length}`)
