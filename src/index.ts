import './log.js'  // activate console ring buffer before anything else
import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { serve } from '@hono/node-server'
import { privateKeyToAccount } from 'viem/accounts'
import { getConfig, isConfigured } from './config.js'
import { getDB } from './db/index.js'
import { CcipRouter } from './router/index.js'
import { withWyriwe } from './attestation/withWyriwe.js'
import { withEns, isEnsCalldata } from './ens/withEns.js'
import type { EnsResolverFn } from './ens/withEns.js'
import { recordsRouter } from './mesh/records.js'
import { verifyRouter } from './verify/verify.js'
import { ocpRouter } from './verify/ocp.js'
import { startSyncCron } from './mesh/cron.js'
import { peersRouter } from './mesh/records.js'
import { makeVni } from './mesh/vni.js'
import { messagesRouter } from './mesh/messages.js'
import { keccak256, toBytes, recoverAddress, hashMessage } from 'viem'
import { NODE_VERSION } from './version.js'
import { setupRouter } from './ui/setup.js'
import { adminRouter } from './ui/admin.js'
import { staticRouter } from './ui/static.js'

const app = new Hono()

// Public CCIP gateway routes are called directly from browser clients
app.use('*', cors({ origin: '*', allowMethods: ['GET', 'POST', 'OPTIONS'] }))

// Boot sequence — config first, then conditional route registration
const config = getConfig()

// Setup wizard — shown when node has no gateway key configured
app.route('/setup', setupRouter)

if (!config.disableAdmin) {
  app.route('/admin', adminRouter)
  app.route('/', staticRouter)
}

app.get('/', (c) => {
  if (!isConfigured()) return c.redirect('/setup')
  if (config.disableAdmin) return c.json({ ok: true, node: 'ccip-router', version: NODE_VERSION })
  return c.redirect('/admin')
})

// Block all other routes until configured
app.use('*', async (c, next) => {
  if (!isConfigured() && !c.req.path.startsWith('/setup')) {
    return c.redirect('/setup')
  }
  await next()
})

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

// Build identity opts from config — passed to CcipRouter and available via /identity
const identity = config.agentId && config.registryAddress
  ? { agentId: config.agentId, registryAddress: config.registryAddress, chainId: config.chainId }
  : undefined

// DB-backed ENS resolver — reads from the ens_records table managed via admin panel
const ensResolverFn: EnsResolverFn = async (name, record) => {
  if (record.type === 'addr' && 'coinType' in record) {
    return db.getNameRecordValue(name, 'addr_coin', Number(record.coinType))
  }
  if (record.type === 'addr')        return db.getNameRecordValue(name, 'addr')
  if (record.type === 'text')        return db.getNameRecordValue(name, 'text', -1, record.key)
  if (record.type === 'contenthash') return db.getNameRecordValue(name, 'contenthash')
  return null
}
const ensResolver = withEns(ensResolverFn)

// Base resolver — ENS calldata goes to the DB-backed ENS resolver; everything else returns 0x.
const baseResolver = async (sender: string, calldata: `0x${string}`, namespace: string): Promise<`0x${string}`> => {
  if (isEnsCalldata(calldata)) return ensResolver(sender as `0x${string}`, calldata, namespace)
  return '0x'
}

// Activate full attestation pipeline when all required fields are present:
//   GATEWAY_PRIVATE_KEY + AGENT_ID + REGISTRY_ADDRESS + MODEL_HASH
// Without MODEL_HASH the WyriweAttestation struct is incomplete, so we fall
// back to plain signing only.
const wyriweActive = !!(
  config.gatewayKey &&
  config.agentId &&
  config.registryAddress &&
  config.modelHash
)

const resolver = wyriweActive
  ? withWyriwe(baseResolver, {
      gatewayKey:      config.gatewayKey!,
      registryAddress: config.registryAddress!,
      agentId:         config.agentId!,
      modelHash:       config.modelHash!,
      chainId:         config.chainId,
    })
  : baseResolver

const ccip = new CcipRouter({
  namespace:  config.syncNamespace,
  db,
  gatewayKey: config.gatewayKey,
  identity,
  resolver,
})

// Specific named routes must be registered before the CCIP wildcard /:sender/:data
app.route('/records', recordsRouter)
app.route('/peers', peersRouter)
app.route('/messages', messagesRouter)
app.route('/verify', verifyRouter)
app.route('/ocp', ocpRouter)

// GET /vni — signed node identity document (VNI)
app.get('/vni', async (c) => {
  if (!config.gatewayKey || !config.nodeUrl) {
    return c.json({ declared: false, reason: 'NODE_URL and GATEWAY_PRIVATE_KEY required' }, 404)
  }
  const vni = await makeVni(config.gatewayKey, config.nodeUrl)
  return c.json(vni)
})

// GET /contributions — record attribution per source peer (ERC-8275 MVP)
app.get('/contributions', async (c) => {
  const contributions = await db.getContributions(config.syncNamespace)
  return c.json({
    namespace: config.syncNamespace,
    contributions: contributions.map((c) => ({
      source:  c.sourcePeer ?? 'local',
      records: c.count,
    })),
  })
})

// POST /join-request — public endpoint for new nodes to request mesh membership.
// Recovers the signer from the EIP-191 signature, health-checks the node, and
// stores the request for admin review. Approve in the admin panel → MetaMask → NodeRegistry.register().
app.post('/join-request', async (c) => {
  try {
    const body = await c.req.json<{ url?: string; signature?: string }>()
    const { url, signature } = body ?? {}
    if (!url || !signature) return c.json({ error: 'url and signature required' }, 400)
    if (!url.startsWith('http')) return c.json({ error: 'url must be http or https' }, 400)

    const msgHash = keccak256(toBytes('ccip-router:node:' + url))
    let signerAddress: string
    try {
      signerAddress = await recoverAddress({
        hash:      hashMessage({ raw: msgHash as `0x${string}` }),
        signature: signature as `0x${string}`,
      })
    } catch {
      return c.json({ error: 'invalid signature — personal_sign keccak256("ccip-router:node:" + url) with the node key' }, 400)
    }

    let healthOk = false
    let healthData: Record<string, unknown> | null = null
    try {
      const ac    = new AbortController()
      const timer = setTimeout(() => ac.abort(), 4000)
      const res   = await fetch(`${url}/health`, { signal: ac.signal }).finally(() => clearTimeout(timer))
      if (res.ok) { healthData = await res.json() as Record<string, unknown>; healthOk = true }
    } catch { /* unreachable node — still store the request */ }

    const id = await db.upsertJoinRequest({ url, signature, signerAddress, status: 'pending', healthOk, healthData })
    console.log(`[join-request] ${signerAddress} @ ${url} (health: ${healthOk})`)
    return c.json({ ok: true, id, signerAddress })
  } catch (err) {
    return c.json({ error: `join request failed: ${(err as Error).message ?? String(err)}` }, 500)
  }
})

app.route('/', ccip.hono())

app.get('/health', async (c) => {
  const [peers, count, wyriweCount, ensCount] = await Promise.all([
    db.getPeers(),
    db.recordCount(config.syncNamespace),
    db.recordCount(config.syncNamespace + ':wyriwe'),
    db.ensNameCount(),
  ])
  return c.json({
    ok:            true,
    version:       NODE_VERSION,
    role:          'router',
    namespace:     config.syncNamespace,
    signerAddress,
    nodeUrl:       config.nodeUrl ?? null,
    identity:      identity ?? null,
    tiers: {
      signed:       !!signerAddress,
      erc8004:      !!identity,
      wyriwe:       wyriweActive,
      ocp:          wyriweActive,
      vni:          !!(config.gatewayKey && config.nodeUrl),
      onChain:      !!(config.attestationIndex && config.rpcUrl),
    },
    peers:         peers.map((p) => ({
      url:           p.url,
      healthy:       p.healthy,
      nodeVersion:   p.nodeVersion,
      role:          p.nodeVersion && /^\d+\.\d+/.test(p.nodeVersion) ? 'router' : p.nodeVersion ? 'gateway' : 'unknown',
      signerAddress: p.signerAddress,
      lastSyncAt:    p.lastSyncAt,
    })),
    records:       count,
    ensRecords:    ensCount,
  })
})

// Start mesh sync cron after routes are wired
startSyncCron(config, db)

const signerAddress = config.gatewayKey
  ? privateKeyToAccount(config.gatewayKey).address
  : null

const server = serve({ fetch: app.fetch, port: config.port })

console.log(`[ccip-router] listening on :${config.port}`)
console.log(`[ccip-router] namespace:  ${config.syncNamespace}`)
console.log(`[ccip-router] signing:    ${signerAddress ?? 'dry-run'}`)
console.log(`[ccip-router] wyriwe:     ${wyriweActive ? 'active' : 'inactive (set AGENT_ID + REGISTRY_ADDRESS + MODEL_HASH to enable)'}`)
console.log(`[ccip-router] peers:      ${config.peers.length}`)

// Graceful shutdown — flush WAL and close DB before exiting
function shutdown(signal: string) {
  console.log(`[ccip-router] ${signal} received — shutting down`)
  server.close(() => {
    db.close()
    process.exit(0)
  })
  // Force-exit if server doesn't close within 5 s
  setTimeout(() => { db.close(); process.exit(1) }, 5_000).unref()
}
process.on('SIGTERM', () => shutdown('SIGTERM'))
process.on('SIGINT',  () => shutdown('SIGINT'))
