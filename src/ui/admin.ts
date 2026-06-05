import { Hono } from 'hono'
import { writeFileSync, existsSync, readFileSync } from 'node:fs'
import { spawn } from 'node:child_process'
import { privateKeyToAccount } from 'viem/accounts'
import { getConfig, setAdminAddress, clearAdminAddress, CONFIG_FILE_PATH, type ConfigFile } from '../config.js'
import { getDB } from '../db/index.js'
import { syncAll } from '../mesh/sync.js'
import { getLogs } from '../log.js'
import { requireAdmin, setAdminSession, clearAdminSession } from './auth.js'
import { generateNonce, verifySiwe } from './siwe.js'
import { publishAttestation, type ChainOpts } from '../chain/publish.js'
import { registerNode } from '../chain/register.js'
import { getPublicClient } from '../chain/client.js'
import { NODE_REGISTRY_ABI } from '../chain/abi.js'
import { getCdnProvider } from '../cdn/index.js'
import { namehash } from 'viem/ens'
import { NODE_VERSION } from '../version.js'
import { broadcastMessage } from '../mesh/messages.js'

export const adminRouter = new Hono()

function restartProcess(): void {
  const [bin, ...args] = process.argv
  const child = spawn(bin, args, { detached: true, stdio: 'inherit', env: process.env, cwd: process.cwd() })
  child.unref()
  process.exit(0)
}

// Auth middleware — applies to every /admin/* route.
// Admin wallet = adminAddress in config (claimed on first SIWE login, decoupled from gatewayKey).
// claimMode = unclaimed but gatewayKey is set → force login so the first wallet can claim.
// Bearer ADMIN_SECRET is a fallback for CLI / scripts.
adminRouter.use('*', async (c, next) => {
  const config = getConfig()
  const claimMode = !config.adminAddress && !!config.gatewayKey
  return requireAdmin(config.adminAddress, config.adminSecret, claimMode)(c, next)
})

// ── Auth routes ───────────────────────────────────────────────────────────────

adminRouter.get('/login', (c) => {
  const config = getConfig()
  // Dev mode: no auth configured → open access
  if (!config.adminAddress && !config.gatewayKey && !config.adminSecret) return c.redirect('/admin')
  return c.html(LOGIN_HTML)
})

// SIWE: GET /admin/siwe/nonce — return a fresh nonce + claim/auth state
adminRouter.get('/siwe/nonce', (c) => {
  const config = getConfig()
  if (!config.gatewayKey && !config.adminAddress) {
    return c.json({ error: 'SIWE unavailable — configure GATEWAY_PRIVATE_KEY first' }, 400)
  }
  const nonce  = generateNonce()
  const domain = c.req.header('host') || 'localhost'
  return c.json({
    nonce, domain, chainId: config.chainId,
    authorizedAddress: config.adminAddress ?? null,
    claimed: !!config.adminAddress,
  })
})

// SIWE: POST /admin/siwe/verify — verify signature, issue session cookie.
// Claim mode (no adminAddress set): first caller's address becomes the permanent admin.
// Normal mode: must match stored adminAddress.
adminRouter.post('/siwe/verify', async (c) => {
  const config = getConfig()
  if (!config.gatewayKey && !config.adminAddress) return c.json({ error: 'SIWE unavailable' }, 400)

  const { message, signature } = await c.req.json<{ message: string; signature: string }>()
  if (!message || !signature) return c.json({ error: 'message and signature required' }, 400)

  // Extract the signer address from the SIWE message (line 2 = address)
  const lines   = message.split('\n')
  const address = lines[1]?.trim() as `0x${string}`
  if (!address?.startsWith('0x')) return c.json({ error: 'cannot parse address from SIWE message' }, 400)

  const valid = await verifySiwe(message, signature as `0x${string}`, address)
  if (!valid) return c.json({ error: 'invalid signature or expired nonce' }, 401)

  if (!config.adminAddress) {
    // Claim mode: first wallet to sign becomes admin
    setAdminAddress(address)
    setAdminSession(c, address)
    console.log(`[admin] admin claimed by ${address}`)
    return c.json({ ok: true, address, claimed: true, redirect: '/admin' })
  }

  if (address.toLowerCase() !== config.adminAddress.toLowerCase()) {
    return c.json({ error: 'wrong wallet — expected ' + config.adminAddress }, 401)
  }

  setAdminSession(c, address)
  return c.json({ ok: true, address, claimed: false, redirect: '/admin' })
})

adminRouter.post('/logout', (c) => {
  clearAdminSession(c)
  return c.redirect('/admin/login')
})

// Reset admin: requires ADMIN_SECRET in body — clears adminAddress back to unclaimed.
// Accessible without a session so a locked-out operator can recover without SSH.
adminRouter.post('/siwe/reset', async (c) => {
  const config = getConfig()
  if (!config.adminSecret) {
    return c.json({
      error: 'No ADMIN_SECRET configured. To recover, SSH to the node and remove adminAddress from config.json.',
    }, 403)
  }
  if (process.env.ADMIN_ADDRESS?.trim()) {
    return c.json({ error: 'ADMIN_ADDRESS env var is set — remove it from your deployment environment to unclaim.' }, 403)
  }
  const body = await c.req.json<{ secret?: string }>().catch(() => ({ secret: undefined }))
  if (!body.secret || body.secret !== config.adminSecret) {
    return c.json({ error: 'invalid secret' }, 401)
  }
  clearAdminAddress()
  clearAdminSession(c)
  return c.json({ ok: true, message: 'Admin cleared — node returned to unclaimed state. Sign in with the correct wallet.' })
})

// Transfer admin: current session holder proves new wallet ownership via SIWE, then admin moves.
adminRouter.post('/siwe/transfer', async (c) => {
  const config = getConfig()
  if (!config.adminAddress) return c.json({ error: 'no admin address set' }, 400)

  const { message, signature } = await c.req.json<{ message: string; signature: string }>()
  if (!message || !signature) return c.json({ error: 'message and signature required' }, 400)

  const lines      = message.split('\n')
  const newAddress = lines[1]?.trim() as `0x${string}`
  if (!newAddress?.startsWith('0x')) return c.json({ error: 'cannot parse address from SIWE message' }, 400)
  if (newAddress.toLowerCase() === config.adminAddress.toLowerCase()) {
    return c.json({ error: 'new address is the same as current admin' }, 400)
  }

  const valid = await verifySiwe(message, signature as `0x${string}`, newAddress)
  if (!valid) return c.json({ error: 'invalid signature or expired nonce' }, 401)

  setAdminAddress(newAddress)
  // Issue new session for the new admin wallet
  clearAdminSession(c)
  setAdminSession(c, newAddress)
  console.log(`[admin] admin transferred from ${config.adminAddress} to ${newAddress}`)
  return c.json({ ok: true, address: newAddress })
})

// ── API ──────────────────────────────────────────────────────────────────────

adminRouter.get('/api/status', async (c) => {
  const config = getConfig()
  const db     = getDB()
  const [peers, count, wyriweCount, unreadMessages] = await Promise.all([
    db.getPeers(),
    db.recordCount(config.syncNamespace),
    db.recordCount(config.syncNamespace + ':wyriwe'),
    db.unreadMessageCount(),
  ])
  const signerAddress = config.gatewayKey ? privateKeyToAccount(config.gatewayKey).address : null
  return c.json({
    version: NODE_VERSION, signerAddress,
    adminAddress: config.adminAddress ?? null,
    adminClaimed: !!config.adminAddress,
    namespace: config.syncNamespace, syncInterval: config.syncInterval,
    protected: !!(config.adminSecret || config.adminAddress),
    records: count,
    tiers: {
      signed:   !!signerAddress,
      erc8004:  !!(config.agentId && config.registryAddress),
      wyriwe:   !!(config.gatewayKey && config.agentId && config.registryAddress && config.modelHash),
      ocp:      !!(config.gatewayKey && config.agentId && config.registryAddress && config.modelHash),
      vni:      !!(config.gatewayKey && config.nodeUrl),
      onChain:  !!(config.attestationIndex && config.rpcUrl),
    },
    unreadMessages,
    peers: peers.map((p) => ({
      url: p.url, healthy: p.healthy,
      signerAddress: p.signerAddress, nodeVersion: p.nodeVersion, lastSyncAt: p.lastSyncAt,
    })),
  })
})

adminRouter.get('/api/logs', (c) => {
  return c.json(getLogs())
})

adminRouter.get('/api/records', async (c) => {
  const config = getConfig()
  const db     = getDB()
  const limit  = Math.min(Number(c.req.query('limit') ?? 20), 100)
  const offset = Math.max(Number(c.req.query('offset') ?? 0), 0)
  const rows   = await db.getRecentRecords(config.syncNamespace, limit + offset)
  const page   = rows.slice(offset, offset + limit)
  return c.json({
    records: page.map((r) => ({ inputHash: r.inputHash, timestamp: r.timestamp, sourcePeer: r.sourcePeer, namespace: r.namespace })),
    hasMore: offset + limit < rows.length,
    total:   rows.length,
  })
})

adminRouter.get('/api/audit', async (c) => {
  const config = getConfig()
  const db     = getDB()
  const signerAddress = config.gatewayKey ? privateKeyToAccount(config.gatewayKey).address : null
  const [count, wyriweCount] = await Promise.all([
    db.recordCount(config.syncNamespace),
    db.recordCount(config.syncNamespace + ':wyriwe'),
  ])
  const erc8004On  = !!(config.agentId && config.registryAddress)
  const wyriweOn   = wyriweCount > 0
  const chainOn    = !!(config.attestationIndex && config.rpcUrl)
  const vniOn      = !!(config.gatewayKey && config.nodeUrl)
  const registryOn = !!(config.nodeRegistry && config.rpcUrl)

  const contributions = await db.getContributions(config.syncNamespace)
  const peers         = await db.getPeers()

  return c.json({ specs: [
    {
      key: 'eip3668', name: 'EIP-3668', label: 'CCIP-Read', status: 'pass',
      description: 'Client-to-gateway transport layer. Clients call /{sender}/{data}.json; gateway returns { data: "0x..." }.',
      details: [
        { k: 'Endpoint',   v: '/{sender}/{data}.json' },
        { k: 'Signing',    v: signerAddress ? 'EIP-191' : 'dry-run (unsigned)' },
        { k: 'Signer',     v: signerAddress ?? 'not configured' },
        { k: 'Resolver',   v: config.resolverAddress ?? 'not configured — set RESOLVER_ADDRESS' },
        { k: 'Namespace',  v: config.syncNamespace },
        { k: 'Records',    v: String(count) },
      ],
    },
    {
      key: 'wyriwe', name: 'WYRIWE', label: 'Input Attestation',
      status: wyriweOn ? 'pass' : 'inactive',
      description: 'Triple-hash input provenance. EIP-712 WyriweAttestation signed and persisted on every resolver call.',
      action: wyriweOn && chainOn ? 'publish' : null,
      details: wyriweOn
        ? [
            { k: 'Path',      v: 'sentinel (IDENTITY_SENTINEL)' },
            { k: 'Records',   v: String(wyriweCount) },
            { k: 'Namespace', v: config.syncNamespace + ':wyriwe' },
            { k: 'Signing',   v: 'EIP-712 WyriweAttestation' },
            { k: 'On-chain',  v: chainOn ? `${config.attestationIndex} (chain ${config.chainId})` : 'not configured — set ATTESTATION_INDEX + RPC_URL' },
          ]
        : [
            { k: 'Missing',   v: 'withWyriwe() not active — 0 attestation records', warn: true },
            { k: 'Enable',    v: 'Wrap your resolver with withWyriwe(resolver, opts)' },
          ],
    },
    {
      key: 'erc8004', name: 'ERC-8004', label: 'Agent Identity',
      status: erc8004On ? 'pass' : 'inactive',
      description: 'On-chain agent identity declaration. agentId + registryAddress exposed via /identity.',
      details: erc8004On
        ? [
            { k: 'Agent ID',   v: config.agentId! },
            { k: 'Registry',   v: config.registryAddress! },
            { k: 'Chain ID',   v: String(config.chainId) },
            { k: 'Endpoint',   v: '/identity' },
          ]
        : [
            { k: 'Missing',    v: [!config.agentId && 'AGENT_ID', !config.registryAddress && 'REGISTRY_ADDRESS'].filter(Boolean).join(', '), warn: true },
            { k: 'Enable',     v: 'Set AGENT_ID and REGISTRY_ADDRESS in env or config.json' },
          ],
    },
    {
      key: 'ocp', name: 'ERC-8281 (OCP)', label: 'Observation Commitment',
      status: wyriweOn ? 'pass' : 'inactive',
      description: 'Commitment shape — keccak envelope binding agent, model, input, output, and timestamp into a single verifiable hash. Produced alongside every WYRIWE attestation.',
      details: wyriweOn
        ? [
            { k: 'Records',    v: String(wyriweCount) },
            { k: 'Endpoint',   v: '/ocp/:inputHash' },
            { k: 'Formula',    v: 'keccak256(abi.encode(agentId, modelHash, inputHash, outputHash, timestamp))' },
            { k: 'Store',      v: chainOn ? config.attestationIndex! : 'not deployed — set ATTESTATION_INDEX' },
            { k: '/verify',    v: chainOn ? 'on-chain fallback active' : 'local DB only' },
          ]
        : [
            { k: 'Missing',    v: 'Requires WYRIWE to be active', warn: true },
            { k: 'Enable',     v: 'Enable WYRIWE first via withWyriwe() wrapper' },
          ],
    },
    {
      key: 'erc8263', name: 'ERC-8263', label: 'On-chain Anchor',
      status: wyriweOn ? 'pass' : 'inactive',
      description: 'Anchor/write layer — commitmentHash is carried as proofHash in TruthAnchorV1, emitting AnchorProof(agentIdScheme, agentId, proofHash, operator, aux). One valid instantiation of the opaque proofHash; the same anchor layer serves OCP, WYRIWE, and zkML uniformly.',
      details: wyriweOn
        ? [
            { k: 'proofHash',  v: 'commitmentHash (ERC-8281 keccak envelope)' },
            { k: 'Event',      v: 'AnchorProof(agentIdScheme, agentId, proofHash, operator, aux)' },
            { k: 'TruthAnchorV1 (mainnet)', v: '0xe95d6a15966984c209a62a2c188828555eb5ec3d' },
            { k: 'TruthAnchorV1 (Sepolia)', v: '0x89EE9b68c3b2f50cbE9D0fC4Dc134939a0475c1C' },
            { k: 'Author',     v: 'Vincent Wu' },
          ]
        : [
            { k: 'Missing',    v: 'Requires WYRIWE to be active', warn: true },
            { k: 'Enable',     v: 'Enable WYRIWE first via withWyriwe() wrapper' },
          ],
    },
    {
      key: 'vni', name: 'VNI', label: 'Node Identity',
      status: vniOn ? 'pass' : 'inactive',
      description: 'Verifiable Node Identity — signed document proving this node owns its signing key. Fetched by peers during sync.',
      action: vniOn && registryOn ? 'register' : null,
      details: vniOn
        ? [
            { k: 'Endpoint',   v: '/vni' },
            { k: 'Node URL',   v: config.nodeUrl! },
            { k: 'Signer',     v: signerAddress ?? 'not configured' },
            { k: 'Registry',   v: registryOn ? config.nodeRegistry! : 'not configured — set NODE_REGISTRY' },
            { k: 'Gossip',     v: config.autoDiscover ? `active — ${peers.length} known peers` : 'disabled (AUTO_DISCOVER=false)' },
          ]
        : [
            { k: 'Missing',    v: 'NODE_URL not set', warn: true },
            { k: 'Enable',     v: 'Set NODE_URL to this node\'s public URL in env or config.json' },
          ],
    },
    {
      key: 'erc8275', name: 'ERC-8275', label: 'Node Economics',
      status: contributions.length > 0 ? 'pass' : 'inactive',
      description: 'Contribution attribution — tracks how many records each peer has contributed to this node. Foundation for ERC-8275 node economics.',
      details: contributions.length > 0
        ? [
            { k: 'Total peers',  v: String(contributions.length) },
            ...contributions.slice(0, 4).map((c) => ({
              k: c.sourcePeer ? c.sourcePeer.replace(/^https?:\/\//, '').slice(0, 30) : 'local',
              v: `${c.count} record${c.count !== 1 ? 's' : ''}`,
            })),
            { k: 'Endpoint',     v: '/contributions' },
          ]
        : [
            { k: 'Status',       v: 'No synced records yet — contributions tracked once peers sync' },
            { k: 'Endpoint',     v: '/contributions' },
          ],
    },
  ]})
})

adminRouter.post('/api/sync', async (c) => {
  const config = getConfig()
  const db     = getDB()
  const synced = await syncAll(config, db)
  return c.json({ ok: true, synced })
})

adminRouter.post('/api/publish', async (c) => {
  const config = getConfig()
  if (!config.attestationIndex || !config.rpcUrl || !config.gatewayKey) {
    return c.json({ error: 'ATTESTATION_INDEX, RPC_URL, and GATEWAY_PRIVATE_KEY required' }, 400)
  }
  const db   = getDB()
  const body = await c.req.json<{ limit?: number }>().catch(() => ({ limit: undefined }))
  const limit  = Math.min(body.limit ?? 50, 200)
  const records = await db.getRecentRecords(config.syncNamespace + ':wyriwe', limit)

  const opts: ChainOpts = {
    rpcUrl:          config.rpcUrl,
    chainId:         config.chainId,
    gatewayKey:      config.gatewayKey,
    contractAddress: config.attestationIndex,
  }

  const results = await Promise.allSettled(records.map((r) => publishAttestation(r, opts)))
  let published = 0, skipped = 0
  const errors: string[] = []
  for (const r of results) {
    if (r.status === 'fulfilled') {
      if (r.value.status === 'published') published++
      else if (r.value.status === 'skipped') skipped++
      else errors.push(r.value.reason)
    } else {
      errors.push(String(r.reason))
    }
  }
  console.log(`[publish] ${published} anchored, ${skipped} already on-chain, ${errors.length} errors`)
  return c.json({ ok: true, published, skipped, errors })
})

adminRouter.get('/api/upgrade', async (c) => {
  try {
    const res     = await fetch('https://registry.npmjs.org/ccip-router/latest', { signal: AbortSignal.timeout(5000) })
    const data    = await res.json() as { version: string }
    const latest  = data.version
    const current = NODE_VERSION
    const upToDate = latest === current
    return c.json({ current, latest, upToDate })
  } catch (err) {
    return c.json({ error: `npm registry unreachable: ${(err as Error).message}` }, 502)
  }
})

adminRouter.post('/api/register', async (c) => {
  const config = getConfig()
  if (!config.nodeRegistry || !config.rpcUrl || !config.gatewayKey || !config.nodeUrl) {
    return c.json({ error: 'NODE_REGISTRY, NODE_URL, RPC_URL, and GATEWAY_PRIVATE_KEY required' }, 400)
  }
  const txHash = await registerNode(config.nodeUrl, {
    rpcUrl:          config.rpcUrl,
    chainId:         config.chainId,
    gatewayKey:      config.gatewayKey,
    contractAddress: config.nodeRegistry,
  })
  console.log(`[register] node registered on-chain: ${txHash}`)
  return c.json({ ok: true, txHash })
})

adminRouter.post('/api/peers', async (c) => {
  const { url } = await c.req.json<{ url: string }>()
  if (!url) return c.json({ error: 'url required' }, 400)
  let parsed: URL
  try { parsed = new URL(url) } catch { return c.json({ error: 'Invalid URL' }, 400) }
  await getDB().upsertPeer({ url: parsed.toString().replace(/\/$/, ''), lastSyncAt: 0, healthy: true, nodeVersion: null, signerAddress: null })
  return c.json({ ok: true })
})

adminRouter.delete('/api/peers', async (c) => {
  const { url } = await c.req.json<{ url: string }>()
  if (!url) return c.json({ error: 'url required' }, 400)
  await getDB().removePeer(url)
  return c.json({ ok: true })
})

// Discover peers from NodeRegistry — returns all registered nodes with health + already-added status.
adminRouter.get('/api/peers/discover', async (c) => {
  try {
    const config = getConfig()
    const registryAddr = config.nodeRegistry ?? config.registryAddress
    if (!registryAddr || !config.rpcUrl) {
      return c.json({ error: 'NODE_REGISTRY (or REGISTRY_ADDRESS) and RPC_URL required for peer discovery' }, 400)
    }

    const client  = getPublicClient(config.rpcUrl, config.chainId)
    const address = registryAddr as `0x${string}`

    let count: bigint
    let signers: `0x${string}`[]
    let urls: string[]
    try {
      count = await client.readContract({ address, abi: NODE_REGISTRY_ABI, functionName: 'nodeCount' }) as bigint
      if (count === 0n) return c.json({ nodes: [] })
      ;({ signers, urls } = await client.readContract({
        address, abi: NODE_REGISTRY_ABI, functionName: 'getNodes',
        args: [0n, count > 50n ? 50n : count],
      }) as unknown as { signers: `0x${string}`[]; urls: string[]; timestamps: bigint[] })
    } catch (err) {
      console.error('[discover] contract read failed:', err)
      return c.json({ error: `Registry read failed: ${(err as Error).message ?? err}` }, 502)
    }

    const existingUrls = new Set((await getDB().getPeers()).map(p => p.url.toLowerCase()))
    const ownUrl = config.nodeUrl?.toLowerCase()

    const nodes = await Promise.all(
      urls.map(async (url, i) => {
        if (!url || (ownUrl && url.toLowerCase() === ownUrl)) return null
        const signerAddress = signers[i]
        const alreadyPeer   = existingUrls.has(url.toLowerCase())
        try {
          const ac    = new AbortController()
          const timer = setTimeout(() => ac.abort(), 3000)
          const res   = await fetch(`${url}/health`, { signal: ac.signal }).finally(() => clearTimeout(timer))
          const h     = await res.json() as Record<string, unknown>
          if (h.listed === false) return null
          return {
            url, signerAddress, alreadyPeer, healthy: true,
            role:    (h.role as string) ?? ((h.version && /^\d+\.\d+/.test(h.version as string)) ? 'router' : 'gateway'),
            version: (h.version as string) ?? null,
            tiers:   (h.tiers as Record<string, boolean>) ?? null,
          }
        } catch {
          return { url, signerAddress, alreadyPeer, healthy: false, role: 'unknown', version: null, tiers: null }
        }
      })
    )

    return c.json({ nodes: nodes.filter(Boolean) })
  } catch (err) {
    console.error('[discover] unhandled error:', err)
    return c.json({ error: `Discovery error: ${(err as Error).message ?? String(err)}` }, 500)
  }
})

adminRouter.get('/api/config', (c) => {
  const config = getConfig()
  const signerAddress = config.gatewayKey ? privateKeyToAccount(config.gatewayKey).address : null
  return c.json({
    signerAddress,
    namespace:        config.syncNamespace,
    syncInterval:     config.syncInterval,
    port:             config.port,
    dbPath:           config.dbPath,
    nodeUrl:          config.nodeUrl          ?? '',
    autoDiscover:     config.autoDiscover,
    peers:            config.peers,
    agentId:          config.agentId          ?? '',
    registryAddress:  config.registryAddress  ?? '',
    modelHash:        config.modelHash        ?? '',
    chainId:          config.chainId,
    rpcUrl:           config.rpcUrl           ?? '',
    attestationIndex: config.attestationIndex ?? '',
    nodeRegistry:     config.nodeRegistry     ?? '',
    resolverAddress:  config.resolverAddress  ?? '',
    hasAdminSecret:   !!config.adminSecret,
    adminAddress:     config.adminAddress  ?? '',
    adminClaimed:     !!config.adminAddress,
  })
})

adminRouter.post('/api/config', async (c) => {
  const body = await c.req.json<{
    namespace?:        string
    syncInterval?:     string
    port?:             number
    dbPath?:           string
    nodeUrl?:          string
    autoDiscover?:     boolean
    peers?:            string[]
    agentId?:          string
    registryAddress?:  string
    modelHash?:        string
    chainId?:          number
    rpcUrl?:           string
    attestationIndex?: string
    nodeRegistry?:     string
    resolverAddress?:  string
    adminSecret?:      string
  }>()

  let existing: ConfigFile = {}
  if (existsSync(CONFIG_FILE_PATH)) {
    try { existing = JSON.parse(readFileSync(CONFIG_FILE_PATH, 'utf8')) as ConfigFile } catch {}
  }

  const config: ConfigFile = {
    gatewayKey:       existing.gatewayKey,
    adminSecret:      body.adminSecret?.trim() || existing.adminSecret,
    namespace:        body.namespace        || existing.namespace,
    syncInterval:     body.syncInterval     || existing.syncInterval,
    dbPath:           body.dbPath           || existing.dbPath,
    port:             body.port             ?? existing.port,
    peers:            body.peers            ?? existing.peers ?? [],
    nodeUrl:          body.nodeUrl          || existing.nodeUrl,
    autoDiscover:     body.autoDiscover     ?? existing.autoDiscover,
    agentId:          body.agentId          || existing.agentId,
    registryAddress:  body.registryAddress  || existing.registryAddress,
    modelHash:        body.modelHash        || existing.modelHash,
    chainId:          body.chainId          ?? existing.chainId,
    rpcUrl:           body.rpcUrl           || existing.rpcUrl,
    attestationIndex: body.attestationIndex || existing.attestationIndex,
    nodeRegistry:     body.nodeRegistry     || existing.nodeRegistry,
    resolverAddress:  body.resolverAddress  || existing.resolverAddress,
  }

  try {
    writeFileSync(CONFIG_FILE_PATH, JSON.stringify(config, null, 2), 'utf8')
  } catch (err) {
    return c.json({ error: `Could not write config: ${String(err)}` }, 500)
  }

  console.log('[config] updated via admin panel — restarting')
  setTimeout(() => restartProcess(), 500)
  return c.json({ ok: true })
})

adminRouter.post('/api/key', async (c) => {
  const body = await c.req.json<{ gatewayKey: string }>()
  const key  = body.gatewayKey?.trim()
  if (!key?.startsWith('0x') || key.length !== 66) {
    return c.json({ error: 'Invalid key — must be 32-byte hex (0x...)' }, 400)
  }

  let existing: ConfigFile = {}
  if (existsSync(CONFIG_FILE_PATH)) {
    try { existing = JSON.parse(readFileSync(CONFIG_FILE_PATH, 'utf8')) as ConfigFile } catch {}
  }

  try {
    writeFileSync(CONFIG_FILE_PATH, JSON.stringify({ ...existing, gatewayKey: key }, null, 2), 'utf8')
  } catch (err) {
    return c.json({ error: `Could not write config: ${String(err)}` }, 500)
  }

  console.log('[config] signing key rotated via admin panel — restarting')
  setTimeout(() => restartProcess(), 500)
  return c.json({ ok: true })
})

// ── ENS records API ───────────────────────────────────────────────────────────

adminRouter.get('/api/ens-records', async (c) => {
  const name = c.req.query('name') || undefined
  const records = await getDB().listNameRecords(name)
  return c.json({ records })
})

adminRouter.post('/api/ens-records', async (c) => {
  const body = await c.req.json<{
    name:     string
    type:     string
    coinType?: number
    textKey?:  string
    value:    string
  }>()
  const { name, type, value } = body
  if (!name || !type || !value) return c.json({ error: 'name, type, value required' }, 400)
  const allowed = ['addr', 'addr_coin', 'text', 'contenthash']
  if (!allowed.includes(type)) return c.json({ error: `type must be one of: ${allowed.join(', ')}` }, 400)

  await getDB().upsertNameRecord({
    name,
    type:     type as 'addr' | 'addr_coin' | 'text' | 'contenthash',
    coinType: body.coinType ?? -1,
    textKey:  body.textKey  ?? '',
    value,
  })
  return c.json({ ok: true })
})

adminRouter.delete('/api/ens-records', async (c) => {
  const body = await c.req.json<{ name: string; type: string; coinType?: number; textKey?: string }>()
  const { name, type } = body
  if (!name || !type) return c.json({ error: 'name and type required' }, 400)
  await getDB().deleteNameRecord(name, type, body.coinType ?? -1, body.textKey ?? '')
  return c.json({ ok: true })
})

// ── IPFS / CDN API ────────────────────────────────────────────────────────────

adminRouter.get('/api/cdn/status', (c) => {
  const config = getConfig()
  return c.json({ provider: config.cdnProvider ?? null, configured: !!(config.cdnProvider && config.cdnApiKey) })
})

adminRouter.post('/api/cdn/upload', async (c) => {
  const config = getConfig()
  const provider = getCdnProvider(config)
  if (!provider) return c.json({ error: 'CDN not configured — set CDN_PROVIDER and CDN_API_KEY' }, 503)

  const body = await c.req.parseBody()
  const file = body['file']
  if (!file || typeof file === 'string') return c.json({ error: 'file field required' }, 400)

  const buffer = Buffer.from(await file.arrayBuffer())
  try {
    const cid = await provider.upload(buffer, file.name, file.type || 'application/octet-stream')
    return c.json({ cid, provider: provider.name })
  } catch (err) {
    return c.json({ error: String(err) }, 502)
  }
})

// ── Messages API ──────────────────────────────────────────────────────────────

adminRouter.get('/api/messages', async (c) => {
  const limit = Math.min(Number(c.req.query('limit') ?? 50), 200)
  const messages = await getDB().getMessages(limit)
  return c.json({ messages })
})

adminRouter.post('/api/messages/read', async (c) => {
  const body = await c.req.json<{ ids?: number[] }>().catch(() => ({ ids: undefined }))
  await getDB().markMessagesRead(body.ids)
  return c.json({ ok: true })
})

adminRouter.post('/api/messages/send', async (c) => {
  const config = getConfig()
  if (!config.gatewayKey) return c.json({ error: 'GATEWAY_PRIVATE_KEY required to send messages' }, 400)
  const body = await c.req.json<{ type: string; message: string; version?: string }>()
  if (!body.type || !body.message) return c.json({ error: 'type and message required' }, 400)
  const validTypes = ['upgrade_notice', 'deprecation', 'network_announcement']
  if (!validTypes.includes(body.type)) return c.json({ error: 'invalid type' }, 400)
  try {
    const result = await broadcastMessage(body.type as any, body.message, body.version)
    return c.json(result)
  } catch (err) {
    return c.json({ error: String(err) }, 500)
  }
})

adminRouter.get('/api/cdn/namehash', (c) => {
  const name = c.req.query('name')
  if (!name) return c.json({ error: 'name required' }, 400)
  try {
    const node = namehash(name)
    return c.json({ node })
  } catch {
    return c.json({ error: 'invalid ENS name' }, 400)
  }
})

// ── Dashboard HTML ────────────────────────────────────────────────────────────

adminRouter.get('/', (c) => c.html(ADMIN_HTML))

const SHARED_CSS = /* css */`
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  :root {
    --bg:       #000;
    --s1:       rgba(255,255,255,0.04);
    --s2:       rgba(255,255,255,0.07);
    --border:   rgba(255,255,255,0.08);
    --border-h: rgba(255,255,255,0.16);
    --text:     #fff;
    --subtle:   #888;
    --muted:    #555;
    --accent:   #6366f1;
    --accent-v: #8b5cf6;
    --accent-l: rgba(99,102,241,0.15);
    --accent-b: rgba(99,102,241,0.3);
    --indigo:   #818cf8;
    --green:    #22c55e;
    --green-l:  rgba(34,197,94,0.15);
    --green-b:  rgba(34,197,94,0.3);
    --red:      #ef4444;
    --red-l:    rgba(239,68,68,0.15);
    --amber:    #f59e0b;
    --amber-l:  rgba(245,158,11,0.12);
    --amber-b:  rgba(245,158,11,0.25);
    --mono:     ui-monospace, 'SFMono-Regular', Menlo, monospace;
  }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'Poppins', sans-serif;
    font-size: 14px; font-weight: 400; line-height: 1.5;
    min-height: 100vh;
  }
`

// ── Login page ────────────────────────────────────────────────────────────────

const LOGIN_HTML = /* html */`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>ccip-router — sign in</title>
  <link rel="icon" href="/favicon.svg"/>
  <link rel="preconnect" href="https://fonts.googleapis.com"/>
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
  <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600&display=swap" rel="stylesheet"/>
  <style>
    ${SHARED_CSS}

    body { display: flex; align-items: center; justify-content: center; padding: 24px; }

    .card {
      width: 100%; max-width: 380px;
      background: var(--s1); border: 1px solid var(--border);
      border-radius: 20px; padding: 36px 32px;
      backdrop-filter: blur(8px);
    }

    .logo { display: flex; align-items: center; gap: 12px; margin-bottom: 28px; }
    .logo-icon {
      width: 38px; height: 38px; border-radius: 11px;
      background: var(--accent-l); border: 1px solid var(--accent-b);
      display: flex; align-items: center; justify-content: center;
    }
    .logo-icon img { width: 22px; height: 22px; }
    .logo-text { font-size: 15px; font-weight: 600; }
    .logo-sub  { font-size: 11px; color: var(--subtle); font-weight: 300; }

    .authorized-addr {
      font-family: var(--mono); font-size: 11px; color: var(--subtle);
      background: rgba(255,255,255,0.04); border: 1px solid var(--border);
      border-radius: 8px; padding: 8px 12px; margin-bottom: 20px;
      display: flex; align-items: center; gap: 8px;
    }
    .authorized-addr .dot { width: 6px; height: 6px; border-radius: 50%; background: var(--green); flex-shrink: 0; }

    .btn-siwe {
      width: 100%; display: flex; align-items: center; justify-content: center; gap: 10px;
      background: var(--accent); color: #fff;
      border: none; border-radius: 11px;
      font-size: 14px; font-weight: 500; font-family: inherit;
      padding: 13px; cursor: pointer;
      box-shadow: 0 0 20px rgba(99,102,241,0.25);
      transition: all 0.15s;
    }
    .btn-siwe:hover { background: var(--accent-v); box-shadow: 0 0 28px rgba(139,92,246,0.35); }
    .btn-siwe:disabled { opacity: 0.35; cursor: not-allowed; box-shadow: none; }

    .divider {
      display: flex; align-items: center; gap: 12px;
      margin: 20px 0 16px; color: var(--muted); font-size: 11px;
    }
    .divider::before, .divider::after {
      content: ''; flex: 1; height: 1px; background: var(--border);
    }

    .cli-note {
      font-size: 11px; color: var(--muted); text-align: center; line-height: 1.6;
    }
    .cli-note code {
      font-family: var(--mono); background: var(--s2);
      padding: 2px 5px; border-radius: 4px; font-size: 10px;
    }

    .msg {
      margin-top: 16px; padding: 10px 14px;
      border-radius: 9px; font-size: 12px; display: none;
    }
    .msg.error { background: var(--red-l); border: 1px solid rgba(239,68,68,0.2); color: var(--red); }
    .msg.info  { background: var(--accent-l); border: 1px solid var(--accent-b); color: var(--indigo); }
  </style>
</head>
<body>
<div class="card">
  <div class="logo">
    <div class="logo-icon"><img src="/favicon.svg" alt=""/></div>
    <div>
      <div class="logo-text">ccip-router</div>
      <div class="logo-sub">sign in with ethereum</div>
    </div>
  </div>

  <!-- claim mode: shown when no adminAddress is set -->
  <div id="claim-box" style="display:none;background:var(--amber-l);border:1px solid var(--amber-b);border-radius:10px;padding:12px 14px;margin-bottom:18px;font-size:12px;color:var(--amber);line-height:1.55">
    <strong style="display:block;font-size:13px;margin-bottom:4px">⚡ Unclaimed node</strong>
    First wallet to sign becomes the permanent admin.
    Connect any wallet below to claim.
  </div>

  <div class="authorized-addr" id="auth-addr" style="display:none">
    <span class="dot"></span>
    <span id="auth-addr-text">loading...</span>
    <button onclick="copyAuthorized()" title="Copy address"
      style="margin-left:auto;background:none;border:none;cursor:pointer;color:var(--subtle);padding:0;line-height:1">
      <svg width="12" height="12" viewBox="0 0 16 16" fill="currentColor"><path d="M4 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V2zm2-1a1 1 0 0 0-1 1v8a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1V2a1 1 0 0 0-1-1H6zM0 6a2 2 0 0 1 2-2h2v1H2a1 1 0 0 0-1 1v8a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1v-2h1v2a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2V6z"/></svg>
    </button>
  </div>

  <button class="btn-siwe" id="btn" onclick="siweLogin()">
    <svg width="18" height="18" viewBox="0 0 32 32" fill="none"><circle cx="16" cy="16" r="16" fill="#627EEA"/><path d="M16.498 4v8.87l7.497 3.35L16.498 4z" fill="#fff" fill-opacity=".6"/><path d="M16.498 4L9 16.22l7.498-3.35V4z" fill="#fff"/><path d="M16.498 21.968v6.027L24 17.616l-7.502 4.352z" fill="#fff" fill-opacity=".6"/><path d="M16.498 27.995v-6.028L9 17.616l7.498 10.379z" fill="#fff"/><path d="M16.498 20.573l7.497-4.352-7.497-3.348v7.7z" fill="#fff" fill-opacity=".2"/><path d="M9 16.22l7.498 4.353v-7.7L9 16.22z" fill="#fff" fill-opacity=".6"/></svg>
    Connect wallet
  </button>

  <div class="divider">or</div>
  <p class="cli-note">For CLI / scripts, use<br><code>Authorization: Bearer &lt;ADMIN_SECRET&gt;</code></p>

  <div class="msg error" id="err"></div>
  <div class="msg info"  id="info"></div>

  <!-- Recovery: shown only after a wrong-wallet error -->
  <div id="recovery-section" style="display:none;margin-top:20px;border-top:1px solid var(--border);padding-top:18px">
    <p class="cli-note" style="margin-bottom:10px;color:var(--subtle)">Lost access to that wallet?<br>Reset admin with your <code>ADMIN_SECRET</code></p>
    <div style="display:flex;gap:8px;margin-top:8px">
      <input id="secret-input" type="password" placeholder="ADMIN_SECRET"
        style="flex:1;background:var(--s2);border:1px solid var(--border);border-radius:8px;padding:9px 12px;font-size:12px;color:var(--text);font-family:var(--mono);outline:none"/>
      <button onclick="resetAdmin()"
        style="background:var(--red);color:#fff;border:none;border-radius:8px;padding:9px 14px;font-size:12px;cursor:pointer;font-family:inherit;font-weight:500;white-space:nowrap">
        Reset admin
      </button>
    </div>
    <div class="msg error" id="reset-err" style="margin-top:10px"></div>
  </div>
</div>

<script>
  let authorizedAddress = null
  let isClaimed = false

  async function init() {
    try {
      const res = await fetch('/admin/siwe/nonce')
      if (!res.ok) return
      const data = await res.json()
      authorizedAddress = data.authorizedAddress
      isClaimed = data.claimed

      if (!isClaimed) {
        document.getElementById('claim-box').style.display = 'block'
        document.getElementById('btn').innerHTML = ethIconHTML() + ' Claim admin'
      } else {
        const el  = document.getElementById('auth-addr')
        const txt = document.getElementById('auth-addr-text')
        el.style.display = 'flex'
        txt.textContent = authorizedAddress.slice(0,10) + '...' + authorizedAddress.slice(-6)
        el.title = authorizedAddress
        document.getElementById('btn').innerHTML = ethIconHTML() + ' Connect wallet'
      }
    } catch {}
  }

  async function siweLogin() {
    const btn   = document.getElementById('btn')
    const errEl = document.getElementById('err')
    errEl.style.display = 'none'

    if (!window.ethereum) {
      showError('No Ethereum wallet detected. Install MetaMask or use a Bearer token via CLI.')
      return
    }

    try {
      btn.disabled = true
      btn.textContent = 'Connecting...'

      const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' })
      const address  = accounts[0]

      // Normal mode: enforce address match
      if (isClaimed && authorizedAddress && address.toLowerCase() !== authorizedAddress.toLowerCase()) {
        showWrongWalletError(address, authorizedAddress)
        btn.disabled = false; btn.innerHTML = ethIconHTML() + ' Connect wallet'
        return
      }

      btn.textContent = 'Fetching nonce...'

      const nonceRes = await fetch('/admin/siwe/nonce')
      const { nonce, domain, chainId } = await nonceRes.json()

      btn.textContent = isClaimed ? 'Sign in wallet...' : 'Sign to claim...'

      const now = new Date()
      const exp = new Date(now.getTime() + 10 * 60 * 1000)
      const message = [
        domain + ' wants you to sign in with your Ethereum account:',
        address,
        '',
        isClaimed ? 'Sign in to ccip-router admin dashboard' : 'Claim admin access for ccip-router',
        '',
        'URI: ' + window.location.origin,
        'Version: 1',
        'Chain ID: ' + chainId,
        'Nonce: ' + nonce,
        'Issued At: ' + now.toISOString(),
        'Expiration Time: ' + exp.toISOString(),
      ].join('\\n')

      const signature = await window.ethereum.request({
        method: 'personal_sign',
        params: [message, address],
      })

      btn.textContent = 'Verifying...'

      const verifyRes = await fetch('/admin/siwe/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message, signature }),
      })

      if (verifyRes.ok) {
        const result = await verifyRes.json()
        window.location.href = result.redirect || '/admin'
      } else {
        const { error } = await verifyRes.json()
        showError(error || 'Signature verification failed')
        btn.disabled = false; btn.innerHTML = ethIconHTML() + (isClaimed ? ' Connect wallet' : ' Claim admin')
      }
    } catch (err) {
      if (err.code === 4001) {
        showError('Signature rejected.')
      } else {
        showError(String(err.message || err))
      }
      btn.disabled = false; btn.innerHTML = ethIconHTML() + (isClaimed ? ' Connect wallet' : ' Claim admin')
    }
  }

  function showError(msg) {
    const el = document.getElementById('err')
    el.textContent = msg
    el.style.display = 'block'
  }

  function showWrongWalletError(got, expected) {
    const short = expected.slice(0,10) + '...' + expected.slice(-6)
    const el = document.getElementById('err')
    el.innerHTML = 'Wrong wallet connected.<br>' +
      '<span style="font-family:var(--mono);font-size:10px;opacity:.8">Need: ' + short + '</span><br>' +
      '<span style="opacity:.7;margin-top:2px;display:inline-block">Switch to the correct wallet in MetaMask and try again.</span>'
    el.style.display = 'block'
    document.getElementById('recovery-section').style.display = 'block'
  }

  function copyAuthorized() {
    if (!authorizedAddress) return
    navigator.clipboard.writeText(authorizedAddress).then(() => {
      const el = document.getElementById('auth-addr-text')
      const prev = el.textContent
      el.textContent = 'Copied!'
      setTimeout(() => { el.textContent = prev }, 1500)
    })
  }

  async function resetAdmin() {
    const secret = document.getElementById('secret-input').value.trim()
    if (!secret) return
    const errEl = document.getElementById('reset-err')
    errEl.style.display = 'none'
    try {
      const res = await fetch('/admin/siwe/reset', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ secret }),
      })
      const data = await res.json()
      if (res.ok) {
        window.location.reload()
      } else {
        errEl.textContent = data.error || 'Reset failed'
        errEl.style.display = 'block'
      }
    } catch (e) {
      errEl.textContent = String(e.message || e)
      errEl.style.display = 'block'
    }
  }

  function ethIconHTML() {
    return '<svg width="18" height="18" viewBox="0 0 32 32" fill="none"><circle cx="16" cy="16" r="16" fill="#627EEA"/><path d="M16.498 4v8.87l7.497 3.35L16.498 4z" fill="#fff" fill-opacity=".6"/><path d="M16.498 4L9 16.22l7.498-3.35V4z" fill="#fff"/><path d="M16.498 21.968v6.027L24 17.616l-7.502 4.352z" fill="#fff" fill-opacity=".6"/><path d="M16.498 27.995v-6.028L9 17.616l7.498 10.379z" fill="#fff"/><path d="M16.498 20.573l7.497-4.352-7.497-3.348v7.7z" fill="#fff" fill-opacity=".2"/><path d="M9 16.22l7.498 4.353v-7.7L9 16.22z" fill="#fff" fill-opacity=".6"/></svg>'
  }

  init()
</script>
</body>
</html>`

// ── Admin dashboard ───────────────────────────────────────────────────────────

const ADMIN_HTML = /* html */`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>ccip-router — admin</title>
  <link rel="icon" href="/favicon.svg"/>
  <link rel="preconnect" href="https://fonts.googleapis.com"/>
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
  <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600&display=swap" rel="stylesheet"/>
  <style>
    ${SHARED_CSS}

    /* ── Header ── */
    header {
      display: flex; align-items: center; justify-content: space-between;
      padding: 0 28px; height: 56px;
      border-bottom: 1px solid var(--border);
      background: rgba(0,0,0,0.8);
      backdrop-filter: blur(12px);
      position: sticky; top: 0; z-index: 10;
    }

    .logo { display: flex; align-items: center; gap: 10px; text-decoration: none; }
    .logo-icon {
      width: 30px; height: 30px;
      background: var(--accent-l); border: 1px solid var(--accent-b);
      border-radius: 8px;
      display: flex; align-items: center; justify-content: center;
    }
    .logo-icon img { width: 18px; height: 18px; }
    .logo-name { font-size: 14px; font-weight: 600; color: var(--text); }

    .header-right { display: flex; align-items: center; gap: 10px; }

    .pill {
      display: inline-flex; align-items: center; gap: 6px;
      background: var(--s1); border: 1px solid var(--border);
      border-radius: 8px; padding: 5px 12px;
      font-size: 12px; color: var(--subtle);
      transition: background 0.15s, border-color 0.15s;
    }
    .pill .dot { width: 6px; height: 6px; border-radius: 50%; background: var(--green); box-shadow: 0 0 6px var(--green); flex-shrink: 0; }
    .pill .addr { font-family: var(--mono); color: var(--text); }
    .pill.copyable { cursor: pointer; }
    .pill.copyable:hover { border-color: var(--border-h); }
    .pill.copied { background: var(--green-l); border-color: var(--green-b); }

    /* ── Key reveal / addr pill (shared with setup) ── */
    .key-reveal {
      background: var(--green-l); border: 1px solid var(--green-b);
      border-radius: 10px; padding: 14px; margin-top: 14px; display: none;
    }
    .key-reveal.show { display: block; }
    .key-reveal .lbl { font-size: 11px; color: rgba(34,197,94,0.7); margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.5px; }
    .key-reveal .copy-row { display: flex; justify-content: space-between; align-items: flex-start; gap: 8px; }
    .key-reveal .val { font-family: var(--mono); font-size: 11px; color: var(--green); word-break: break-all; }
    .addr-pill {
      display: inline-flex; align-items: center;
      background: var(--accent-l); border: 1px solid var(--accent-b);
      border-radius: 8px; padding: 5px 10px;
      font-family: var(--mono); font-size: 11px; color: var(--indigo);
    }
    .btn-row { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 4px; }
    .key-warn-box {
      background: var(--amber-l); border: 1px solid var(--amber-b);
      border-radius: 10px; padding: 12px 14px; margin-bottom: 16px;
      font-size: 12px; color: var(--amber); line-height: 1.55;
    }
    .key-warn-box strong { display: block; font-size: 13px; margin-bottom: 4px; }

    /* ── Buttons ── */
    .btn {
      display: inline-flex; align-items: center; gap: 6px;
      border: none; border-radius: 9px;
      font-size: 12px; font-weight: 500; font-family: inherit;
      padding: 7px 16px; cursor: pointer; transition: all 0.15s;
    }
    .btn-ghost  { background: var(--s1); border: 1px solid var(--border); color: var(--subtle); }
    .btn-ghost:hover { border-color: var(--border-h); color: var(--text); background: var(--s2); }
    .btn-primary { background: var(--accent); color: #fff; box-shadow: 0 0 16px rgba(99,102,241,0.2); }
    .btn-primary:hover { background: var(--accent-v); box-shadow: 0 0 24px rgba(139,92,246,0.3); }
    .btn-primary:disabled { opacity: 0.35; cursor: not-allowed; box-shadow: none; }
    .btn-danger { background: var(--red-l); border: 1px solid rgba(239,68,68,0.2); color: var(--red); }
    .btn-danger:hover { background: rgba(239,68,68,0.25); }
    .btn-sm { padding: 5px 10px; font-size: 11px; border-radius: 7px; }
    .btn-icon { padding: 5px 8px; }

    .msg { padding: 10px 14px; border-radius: 9px; font-size: 12px; }
    .msg.error { background: var(--red-l); border: 1px solid rgba(239,68,68,0.2); color: var(--red); }
    .msg.info  { background: var(--accent-l); border: 1px solid var(--accent-b); color: var(--indigo); }

    /* ── Warning banner ── */
    .warn-banner {
      background: var(--amber-l); border-bottom: 1px solid var(--amber-b);
      padding: 8px 28px; font-size: 12px; color: var(--amber);
      display: none; align-items: center; gap: 6px; flex-wrap: wrap;
    }
    .warn-banner a    { color: var(--amber); text-decoration: underline; }
    .warn-banner code {
      font-family: var(--mono); font-size: 11px;
      background: rgba(245,158,11,0.15); border: 1px solid rgba(245,158,11,0.3);
      border-radius: 4px; padding: 1px 6px; color: var(--amber);
    }

    /* ── Layout ── */
    main { max-width: 1060px; margin: 0 auto; padding: 28px 24px; }

    /* ── Stats ── */
    .stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; margin-bottom: 24px; }

    .stat {
      background: var(--s1); border: 1px solid var(--border);
      border-radius: 14px; padding: 20px 22px;
      transition: border-color 0.2s;
    }
    .stat:hover { border-color: var(--border-h); }
    .stat-label { font-size: 11px; color: var(--subtle); text-transform: uppercase; letter-spacing: 0.6px; margin-bottom: 8px; }
    .stat-value { font-size: 30px; font-weight: 600; font-family: var(--mono); line-height: 1; }
    .stat-sub   { font-size: 11px; color: var(--muted); margin-top: 6px; font-weight: 300; }

    /* ── Panels ── */
    .panels { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
    @media (max-width: 700px) { .panels { grid-template-columns: 1fr; } .stats { grid-template-columns: 1fr; } }

    .panel {
      background: var(--s1); border: 1px solid var(--border);
      border-radius: 14px; overflow: hidden;
    }

    .panel-header {
      display: flex; align-items: center; justify-content: space-between;
      padding: 14px 18px; border-bottom: 1px solid var(--border);
    }
    .panel-title { font-size: 13px; font-weight: 500; }

    /* ── Peers ── */
    .peer-row {
      display: flex; align-items: center; gap: 12px;
      padding: 12px 18px; border-bottom: 1px solid var(--border);
      transition: background 0.15s;
    }
    .peer-row:last-child { border-bottom: none; }
    .peer-row:hover { background: rgba(255,255,255,0.02); }

    .health-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
    .health-dot.ok  { background: var(--green); box-shadow: 0 0 8px rgba(34,197,94,0.5); }
    .health-dot.err { background: var(--red); }

    .peer-info { flex: 1; min-width: 0; }
    .peer-url  { font-family: var(--mono); font-size: 12px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .peer-meta { font-size: 11px; color: var(--muted); margin-top: 2px; font-family: var(--mono); }

    .peer-actions { display: flex; gap: 5px; flex-shrink: 0; }

    .empty { padding: 32px 18px; text-align: center; color: var(--muted); font-size: 12px; font-weight: 300; }

    /* ── Add peer ── */
    .add-peer { display: flex; gap: 8px; padding: 12px 18px; border-top: 1px solid var(--border); }
    .add-peer input {
      flex: 1; background: rgba(255,255,255,0.03);
      border: 1px solid var(--border); border-radius: 9px;
      color: var(--text); font-size: 12px; font-family: var(--mono);
      padding: 7px 12px; outline: none; transition: border-color 0.15s;
    }
    .add-peer input:focus { border-color: rgba(99,102,241,0.4); }

    /* ── Records ── */
    .record-row {
      display: flex; align-items: center; gap: 10px;
      padding: 10px 18px; border-bottom: 1px solid var(--border);
      font-size: 12px;
    }
    .record-row:last-child { border-bottom: none; }
    .record-row:hover { background: rgba(255,255,255,0.02); }
    #records-list { max-height: 420px; overflow-y: auto; }

    .record-hash   { font-family: var(--mono); color: var(--indigo); flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 11px; }
    .record-source { font-size: 10px; flex-shrink: 0; padding: 2px 7px; border-radius: 5px; }
    .record-source.local { background: var(--accent-l); color: var(--indigo); border: 1px solid var(--accent-b); }
    .record-source.peer  { background: var(--green-l);  color: var(--green);  border: 1px solid var(--green-b); }
    .record-time   { color: var(--muted); flex-shrink: 0; font-size: 10px; font-family: var(--mono); }

    /* ── Node info ── */
    .node-bar {
      margin-top: 18px;
      background: var(--s1); border: 1px solid var(--border);
      border-radius: 14px; padding: 16px 22px;
      display: flex; gap: 32px; flex-wrap: wrap; align-items: center;
    }
    .ninfo-item .lbl { font-size: 10px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 3px; }
    .ninfo-item .val { font-family: var(--mono); font-size: 12px; color: var(--text); }

    /* ── Stack status ── */
    .stack-status {
      display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
      padding: 10px 28px; border-bottom: 1px solid var(--border);
      background: rgba(0,0,0,0.3);
    }
    .stack-lbl { font-size: 10px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.6px; margin-right: 4px; }
    .tier-pill {
      display: inline-flex; align-items: center; gap: 5px;
      border-radius: 20px; padding: 3px 10px;
      font-size: 11px; font-weight: 500;
    }
    .tier-pill .tp-dot { width: 5px; height: 5px; border-radius: 50%; flex-shrink: 0; }
    .tier-pill.on  { background: var(--green-l); border: 1px solid var(--green-b);  color: var(--green); }
    .tier-pill.off { background: var(--s1);      border: 1px solid var(--border);   color: var(--muted); }
    .tier-pill.on  .tp-dot { background: var(--green); box-shadow: 0 0 5px rgba(34,197,94,0.6); }
    .tier-pill.off .tp-dot { background: var(--muted); }

    /* ── Log panel ── */
    .log-panel {
      margin-top: 16px;
      background: var(--s1); border: 1px solid var(--border);
      border-radius: 14px; overflow: hidden;
    }
    .log-panel .panel-header { padding: 12px 18px; border-bottom: 1px solid var(--border); }
    .log-body {
      max-height: 260px; overflow-y: auto;
      font-family: var(--mono); font-size: 11px; line-height: 1.55;
      padding: 10px 18px;
    }
    .log-body::-webkit-scrollbar { width: 4px; }
    .log-body::-webkit-scrollbar-track { background: transparent; }
    .log-body::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }
    .log-row { display: flex; gap: 10px; padding: 1px 0; }
    .log-ts   { color: var(--muted); flex-shrink: 0; }
    .log-msg  { word-break: break-all; }
    .log-row.info  .log-msg { color: rgba(255,255,255,0.6); }
    .log-row.warn  .log-msg { color: var(--amber); }
    .log-row.error .log-msg { color: var(--red); }

    /* ── Spec audit ── */
    .audit-panel {
      margin-top: 16px;
      background: var(--s1); border: 1px solid var(--border);
      border-radius: 14px; overflow: hidden;
    }
    .audit-header {
      display: flex; align-items: center; justify-content: space-between;
      padding: 12px 18px; border-bottom: 1px solid transparent;
      cursor: pointer; user-select: none; transition: background 0.15s;
    }
    .audit-header:hover { background: rgba(255,255,255,0.02); }
    .audit-header.open { border-bottom-color: var(--border); }
    .audit-chevron { font-size: 10px; color: var(--muted); transition: transform 0.2s; display: inline-block; }
    .audit-chevron.open { transform: rotate(180deg); }

    .audit-summary { display: flex; align-items: center; gap: 6px; }
    .audit-mini-pill {
      display: inline-flex; align-items: center; gap: 4px;
      border-radius: 20px; padding: 2px 8px; font-size: 10px; font-weight: 500;
    }
    .audit-mini-pill.pass     { background: var(--green-l); color: var(--green);  border: 1px solid var(--green-b); }
    .audit-mini-pill.inactive { background: var(--s1);      color: var(--muted);  border: 1px solid var(--border); }

    .audit-grid {
      display: grid; grid-template-columns: repeat(2, 1fr);
      gap: 14px; padding: 16px 18px;
    }
    @media (max-width: 640px) { .audit-grid { grid-template-columns: 1fr; } }

    .spec-card {
      background: var(--s2); border: 1px solid var(--border);
      border-radius: 12px; padding: 16px;
      transition: border-color 0.15s;
    }
    .spec-card.pass     { border-color: rgba(34,197,94,0.2); }
    .spec-card.inactive { opacity: 0.8; }

    .spec-top { display: flex; align-items: flex-start; justify-content: space-between; margin-bottom: 10px; }
    .spec-name  { font-size: 13px; font-weight: 600; }
    .spec-label { font-size: 10px; color: var(--muted); margin-top: 1px; }
    .spec-badge {
      display: inline-flex; align-items: center; gap: 4px;
      border-radius: 20px; padding: 2px 9px; font-size: 10px; font-weight: 600;
      flex-shrink: 0; margin-left: 8px;
    }
    .spec-badge.pass     { background: var(--green-l); color: var(--green);  border: 1px solid var(--green-b); }
    .spec-badge.inactive { background: var(--s1);      color: var(--muted);  border: 1px solid var(--border); }

    .spec-desc { font-size: 11px; color: var(--muted); margin-bottom: 12px; line-height: 1.55; }

    .spec-rows { display: flex; flex-direction: column; gap: 5px; }
    .spec-row  { display: flex; gap: 8px; font-size: 11px; }
    .spec-row .sk { color: var(--muted); flex-shrink: 0; min-width: 72px; }
    .spec-row .sv { font-family: var(--mono); color: rgba(255,255,255,0.75); word-break: break-all; line-height: 1.4; }
    .spec-row.warn .sv { color: var(--amber); }

    /* ── Toast ── */
    .toast {
      position: fixed; bottom: 24px; right: 24px;
      background: var(--s2); border: 1px solid var(--border);
      border-radius: 10px; padding: 10px 18px;
      font-size: 12px; color: var(--green);
      opacity: 0; transform: translateY(6px);
      transition: all 0.2s; pointer-events: none;
      backdrop-filter: blur(12px);
    }
    .toast.show { opacity: 1; transform: translateY(0); }

    /* ── Node config panel ── */
    .config-form { padding: 20px 18px; }
    .config-section { margin-bottom: 24px; }
    .config-section-title {
      font-size: 10px; color: var(--muted); text-transform: uppercase;
      letter-spacing: 0.8px; font-weight: 500;
      margin-bottom: 12px; padding-bottom: 8px;
      border-bottom: 1px solid var(--border);
    }
    .cfg-field { margin-bottom: 14px; }
    .cfg-field:last-child { margin-bottom: 0; }
    .cfg-label {
      display: block; font-size: 11px; font-weight: 500;
      color: var(--subtle); margin-bottom: 6px;
      text-transform: uppercase; letter-spacing: 0.6px;
    }
    .cfg-field input[type=text],
    .cfg-field input[type=number],
    .cfg-field input[type=password],
    .cfg-field input[type=file],
    .cfg-field select,
    .cfg-field textarea {
      width: 100%; background: rgba(255,255,255,0.03);
      border: 1px solid var(--border); border-radius: 9px;
      color: var(--text); font-size: 12px; font-family: inherit;
      padding: 9px 12px; outline: none; transition: border-color 0.15s;
      box-sizing: border-box;
    }
    .cfg-field select { appearance: none; cursor: pointer; background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6'%3E%3Cpath d='M0 0l5 6 5-6z' fill='%236b7280'/%3E%3C/svg%3E"); background-repeat: no-repeat; background-position: right 12px center; padding-right: 28px; }
    .cfg-field input[type=file] { cursor: pointer; }
    .cfg-field input[type=file]::file-selector-button {
      background: var(--s2); border: 1px solid var(--border); border-radius: 6px;
      color: var(--subtle); font-size: 11px; font-family: inherit;
      padding: 4px 10px; margin-right: 10px; cursor: pointer;
      transition: border-color 0.15s, color 0.15s;
    }
    .cfg-field input[type=file]::file-selector-button:hover { border-color: var(--border-h); color: var(--text); }
    .cfg-field input:focus, .cfg-field select:focus, .cfg-field textarea:focus { border-color: rgba(99,102,241,0.5); }
    .cfg-field textarea { min-height: 72px; resize: vertical; font-family: var(--mono); }
    .cfg-save-btn {
      display: inline-flex; align-items: center; justify-content: center;
      background: var(--accent); color: #fff; border: none; border-radius: 9px;
      font-size: 12px; font-family: inherit; font-weight: 500;
      padding: 9px 16px; cursor: pointer; white-space: nowrap;
      box-shadow: 0 0 16px rgba(99,102,241,0.2); transition: background 0.15s, box-shadow 0.15s;
    }
    .cfg-save-btn:hover { background: var(--accent-v); box-shadow: 0 0 24px rgba(139,92,246,0.3); }
    .cfg-save-btn:disabled { opacity: 0.35; cursor: not-allowed; box-shadow: none; }
    .cfg-hint { font-size: 11px; color: var(--muted); margin-top: 5px; font-weight: 300; }
    .cfg-readonly {
      display: flex; align-items: center; justify-content: space-between;
      background: rgba(255,255,255,0.02); border: 1px solid var(--border);
      border-radius: 9px; padding: 9px 12px;
      font-family: var(--mono); font-size: 12px; color: var(--muted);
    }
    .cfg-readonly a {
      font-size: 11px; color: var(--accent); text-decoration: none;
      flex-shrink: 0; margin-left: 12px;
    }
    .cfg-readonly a:hover { color: var(--accent-v); }
    .cfg-row-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
    @media (max-width: 640px) { .cfg-row-2 { grid-template-columns: 1fr; } }
    .cfg-toggle {
      display: flex; align-items: center; justify-content: space-between;
      background: rgba(255,255,255,0.02); border: 1px solid var(--border);
      border-radius: 9px; padding: 9px 12px;
    }
    .cfg-toggle-label { font-size: 12px; color: rgba(255,255,255,0.6); }
    .toggle-switch {
      position: relative; width: 36px; height: 20px;
      background: var(--s2); border: 1px solid var(--border);
      border-radius: 10px; cursor: pointer; transition: all 0.2s; flex-shrink: 0;
    }
    .toggle-switch.on  { background: var(--accent); border-color: var(--accent); }
    .toggle-switch::after {
      content: ''; position: absolute;
      width: 14px; height: 14px; border-radius: 50%;
      background: var(--muted); top: 2px; left: 2px; transition: all 0.2s;
    }
    .toggle-switch.on::after { background: #fff; left: 18px; }
    .config-actions {
      display: flex; align-items: center; justify-content: space-between;
      padding-top: 18px; border-top: 1px solid var(--border);
    }
    .config-actions .note { font-size: 11px; color: var(--muted); }
  </style>
</head>
<body>

<header>
  <div class="logo">
    <div class="logo-icon"><img src="/favicon.svg" alt=""/></div>
    <div class="logo-name">ccip-router</div>
  </div>
  <div class="header-right">
    <div class="pill copyable" id="signer-pill" onclick="copySigner()" title="Click to copy address">
      <div class="dot"></div><span class="addr" id="h-addr">—</span>
    </div>
    <div class="pill" id="h-role" style="font-size:11px;font-weight:600;letter-spacing:.04em;text-transform:uppercase">—</div>
    <button class="btn btn-primary btn-sm" id="btn-sync" onclick="syncNow()">⟳ Sync</button>
    <button class="btn btn-ghost btn-sm" id="btn-logout" style="display:none" onclick="logout()">Sign out</button>
  </div>
</header>

<div class="warn-banner" id="warn-banner">
  ⚠ Admin is open — anyone who can reach this port has full access.
  Set <code>ADMIN_SECRET</code> in your environment or <a href="/setup">reconfigure</a>.
</div>
<div class="warn-banner" id="dryrun-banner" style="background:rgba(99,102,241,0.08);border-bottom-color:rgba(99,102,241,0.2);color:var(--indigo)">
  ⚡ No signing key configured — records are unsigned (dry-run mode).
  <button class="btn btn-ghost btn-sm" style="margin-left:auto;border-color:rgba(99,102,241,0.3);color:var(--indigo)" onclick="openKeyPanel()">Configure key →</button>
</div>

<div class="stack-status" id="stack-status" style="display:none">
  <span class="stack-lbl">Stack</span>
  <span class="tier-pill off" id="tier-signed"><span class="tp-dot"></span>Signing</span>
  <span class="tier-pill off" id="tier-erc8004"><span class="tp-dot"></span>ERC-8004</span>
  <span class="tier-pill off" id="tier-wyriwe"><span class="tp-dot"></span>WYRIWE</span>
  <span class="tier-pill off" id="tier-ocp"><span class="tp-dot"></span>ERC-8281</span>
  <span class="tier-pill off" id="tier-erc8263"><span class="tp-dot"></span>ERC-8263</span>
  <span class="tier-pill off" id="tier-vni"><span class="tp-dot"></span>VNI</span>
  <span class="tier-pill off" id="tier-onchain"><span class="tp-dot"></span>On-chain</span>
</div>

<main>

  <div class="node-bar" id="node-bar" style="display:none">
    <div class="ninfo-item"><div class="lbl">Signer</div><div class="val" id="ni-addr">—</div></div>
    <div class="ninfo-item"><div class="lbl">Namespace</div><div class="val" id="ni-ns">—</div></div>
    <div class="ninfo-item"><div class="lbl">Interval</div><div class="val" id="ni-interval">—</div></div>
    <div class="ninfo-item"><div class="lbl">Version</div><div class="val" id="ni-version">—</div></div>
    <div style="margin-left:auto; display:flex; gap:8px">
      <a href="/setup" class="btn btn-ghost btn-sm">⚙ Reconfigure</a>
    </div>
  </div>

  <div class="stats">
    <div class="stat">
      <div class="stat-label">Records</div>
      <div class="stat-value" id="s-records">—</div>
      <div class="stat-sub" id="s-ns-sub">—</div>
    </div>
    <div class="stat">
      <div class="stat-label">Peers</div>
      <div class="stat-value" id="s-peers">—</div>
      <div class="stat-sub" id="s-healthy">—</div>
    </div>
    <div class="stat">
      <div class="stat-label">Last sync</div>
      <div class="stat-value" style="font-size:18px;padding-top:6px" id="s-sync">—</div>
      <div class="stat-sub" id="s-interval">—</div>
    </div>
  </div>

  <div class="panels">

    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">Peers</div>
        <button class="btn btn-ghost btn-sm" id="discover-btn" onclick="discoverPeers()">⊕ Discover</button>
      </div>
      <div id="peers-list"><div class="empty">Loading...</div></div>
      <div id="discover-section" style="display:none;border-top:1px solid var(--border);margin-top:4px;padding-top:8px">
        <div style="font-size:11px;color:var(--subtle);padding:0 16px 8px;display:flex;align-items:center;justify-content:space-between">
          <span>Nodes registered on-chain (NodeRegistry)</span>
          <button onclick="document.getElementById('discover-section').style.display='none'" style="background:none;border:none;color:var(--subtle);cursor:pointer;font-size:13px;padding:0">✕</button>
        </div>
        <div id="discover-list"></div>
      </div>
      <div class="add-peer">
        <input type="text" id="peer-input" placeholder="https://gateway-b.example.com"/>
        <button class="btn btn-ghost btn-sm" onclick="addPeer()">+ Add</button>
      </div>
    </div>

    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">Recent records</div>
      </div>
      <div id="records-list"><div class="empty">Loading...</div></div>
    </div>

  </div>

  <div class="log-panel">
    <div class="panel-header">
      <div class="panel-title">Node logs</div>
      <button class="btn btn-ghost btn-sm" onclick="loadLogs()">↻ Refresh</button>
    </div>
    <div class="log-body" id="log-body"><div class="empty">Loading...</div></div>
  </div>

  <div class="audit-panel" id="audit-panel">
    <div class="audit-header" id="audit-header" onclick="toggleAudit()">
      <div style="display:flex;align-items:center;gap:10px">
        <div class="panel-title">Spec audit</div>
        <div class="audit-summary" id="audit-summary"></div>
      </div>
      <span class="audit-chevron" id="audit-chevron">▼</span>
    </div>
    <div id="audit-body" style="display:none">
      <div class="audit-grid" id="audit-grid"></div>
    </div>
  </div>

  <div class="audit-panel" id="config-panel" style="margin-top:16px">
    <div class="audit-header" id="config-header" onclick="toggleConfig()">
      <div style="display:flex;align-items:center;gap:10px">
        <div class="panel-title">Node config</div>
        <span id="config-dirty" style="display:none;font-size:10px;background:var(--amber-l);border:1px solid var(--amber-b);color:var(--amber);border-radius:4px;padding:1px 7px">unsaved</span>
      </div>
      <span class="audit-chevron" id="config-chevron">▼</span>
    </div>
    <div id="config-body" style="display:none">
      <div class="config-form">

        <div class="config-section">
          <div class="config-section-title">Core</div>
          <div class="cfg-row-2">
            <div class="cfg-field">
              <label class="cfg-label">Namespace</label>
              <input type="text" id="cfg-namespace" oninput="markDirty()"/>
              <div class="cfg-hint">Peers must share this namespace to sync.</div>
            </div>
            <div class="cfg-field">
              <label class="cfg-label">Sync interval</label>
              <input type="text" id="cfg-interval" style="font-family:var(--mono)" oninput="markDirty()"/>
              <div class="cfg-hint">Cron expression.</div>
            </div>
          </div>
          <div class="cfg-row-2">
            <div class="cfg-field">
              <label class="cfg-label">Port</label>
              <input type="number" id="cfg-port" min="1" max="65535" oninput="markDirty()"/>
            </div>
            <div class="cfg-field">
              <label class="cfg-label">DB path</label>
              <input type="text" id="cfg-dbpath" style="font-family:var(--mono)" oninput="markDirty()"/>
            </div>
          </div>
        </div>

        <div class="config-section">
          <div class="config-section-title">Signing</div>
          <div class="cfg-field">
            <label class="cfg-label">Signer address</label>
            <div class="cfg-readonly">
              <span id="cfg-signer">—</span>
              <a href="/setup">Rotate key → setup wizard</a>
            </div>
            <div class="cfg-hint">Key is write-once. Use the setup wizard to rotate it safely.</div>
          </div>
        </div>

        <div class="config-section">
          <div class="config-section-title">Network</div>
          <div class="cfg-field">
            <label class="cfg-label">Node URL</label>
            <input type="text" id="cfg-nodeurl" placeholder="https://my-node.example.com" oninput="markDirty()"/>
            <div class="cfg-hint">This node's public URL. Required for VNI and peer gossip.</div>
          </div>
          <div class="cfg-field">
            <label class="cfg-label">Auto-discover peers</label>
            <div class="cfg-toggle">
              <span class="cfg-toggle-label">Pull peer lists from synced peers automatically</span>
              <div class="toggle-switch" id="toggle-autodiscover" onclick="toggleAutoDiscover()"></div>
            </div>
          </div>
          <div class="cfg-field">
            <label class="cfg-label">Seed peers</label>
            <textarea id="cfg-peers" placeholder="https://gateway-b.example.com&#10;https://gateway-c.example.com" oninput="markDirty()"></textarea>
            <div class="cfg-hint">One URL per line. Re-seeded into DB on startup — runtime peers are managed from the Peers panel above.</div>
          </div>
        </div>

        <div class="config-section">
          <div class="config-section-title">Identity — ERC-8004</div>
          <div class="cfg-row-2">
            <div class="cfg-field">
              <label class="cfg-label">Agent ID</label>
              <input type="text" id="cfg-agentid" placeholder="0x…" style="font-family:var(--mono);font-size:11px" oninput="markDirty()"/>
            </div>
            <div class="cfg-field">
              <label class="cfg-label">Registry address</label>
              <input type="text" id="cfg-registry" placeholder="0x…" style="font-family:var(--mono);font-size:11px" oninput="markDirty()"/>
            </div>
          </div>
          <div class="cfg-field">
            <label class="cfg-label">Model hash</label>
            <input type="text" id="cfg-modelhash" placeholder="0x… (keccak256 of model weights CID)" style="font-family:var(--mono);font-size:11px" oninput="markDirty()"/>
            <div class="cfg-hint">Required to activate WYRIWE attestation. keccak256 of the IPFS CID (or any stable identifier) of the model weights.</div>
          </div>
          <div class="cfg-field" style="max-width:160px">
            <label class="cfg-label">Chain ID</label>
            <input type="number" id="cfg-chainid" min="1" oninput="markDirty()"/>
          </div>
        </div>

        <div class="config-section">
          <div class="config-section-title">Chain — on-chain anchoring</div>
          <div class="cfg-field">
            <label class="cfg-label">RPC URL</label>
            <input type="text" id="cfg-rpcurl" placeholder="https://mainnet.infura.io/v3/…" oninput="markDirty()"/>
          </div>
          <div class="cfg-row-2">
            <div class="cfg-field">
              <label class="cfg-label">AttestationIndex</label>
              <input type="text" id="cfg-attestindex" placeholder="0x…" style="font-family:var(--mono);font-size:11px" oninput="markDirty()"/>
            </div>
            <div class="cfg-field">
              <label class="cfg-label">NodeRegistry</label>
              <input type="text" id="cfg-noderegistry" placeholder="0x…" style="font-family:var(--mono);font-size:11px" oninput="markDirty()"/>
            </div>
          </div>
          <div class="cfg-hint" style="margin-top:8px">
            Don't have contract addresses yet?
            <button class="btn btn-sm" style="margin-left:6px" onclick="openDeployPanel()">Deploy contracts via wallet →</button>
          </div>
        </div>

        <div class="config-section">
          <div class="config-section-title">CCIP-Read resolver</div>
          <div class="cfg-field">
            <label class="cfg-label">OffchainResolver contract</label>
            <input type="text" id="cfg-resolveraddr" placeholder="0x… (on-chain resolver contract address)" style="font-family:var(--mono);font-size:11px" oninput="markDirty()"/>
            <div class="cfg-hint">The on-chain resolver that reverts with OffchainLookup pointing to this gateway. Shown in spec audit.</div>
          </div>
        </div>

        <div class="config-section">
          <div class="config-section-title">Admin access</div>
          <div class="cfg-field">
            <label class="cfg-label">Admin secret</label>
            <input type="password" id="cfg-adminsecret" placeholder="Leave blank to keep existing" oninput="markDirty()"/>
            <div class="cfg-hint">Enter a new value to rotate the secret. Leave blank to keep the current one.</div>
          </div>
        </div>

        <div class="config-actions">
          <span class="note">All changes require a node restart.</span>
          <button class="btn btn-primary btn-sm" id="btn-cfg-save" onclick="saveConfig()">Save &amp; restart →</button>
        </div>

      </div>
    </div>
  </div>

  <div class="audit-panel" id="key-panel" style="margin-top:16px">
    <div class="audit-header" id="key-header" onclick="toggleKeyPanel()">
      <div style="display:flex;align-items:center;gap:10px">
        <div class="panel-title">Signing key</div>
        <span class="tier-pill off" id="key-status-pill" style="font-size:10px;padding:2px 10px">
          <span class="tp-dot"></span><span id="key-status-text">not configured</span>
        </span>
      </div>
      <span class="audit-chevron" id="key-chevron">▼</span>
    </div>
    <div id="key-body" style="display:none">
      <div class="config-form">

        <div class="config-section">
          <div class="config-section-title">Current signer</div>
          <div class="cfg-field">
            <div class="cfg-readonly">
              <span id="key-signer-val" style="color:var(--text)">—</span>
            </div>
          </div>
        </div>

        <div class="config-section">
          <div class="config-section-title">Rotate key</div>
          <div class="key-warn-box">
            <strong>⚠ Rotating changes your node's signing identity</strong>
            Records previously signed by the old key still verify against the old address.
            Peers that have pinned your signer will treat new records as a new node until they re-sync.
          </div>
          <div class="btn-row">
            <button class="btn btn-ghost" onclick="generateNewKey()">⚡ Generate new key</button>
            <button class="btn btn-ghost" onclick="showKeyImport()">↓ Import existing</button>
          </div>
          <div class="key-reveal" id="new-key-reveal">
            <div class="lbl">Private key — save this now, it will not be shown again</div>
            <div class="copy-row">
              <div class="val" id="new-key-val"></div>
              <button class="btn btn-ghost btn-sm" onclick="copyNewKey()">Copy</button>
            </div>
            <div id="new-key-addr" class="addr-pill" style="margin-top:10px"></div>
          </div>
          <div id="key-import-field" style="display:none;margin-top:12px">
            <div class="cfg-field">
              <input type="password" id="import-key-val" placeholder="0x…" style="font-family:var(--mono)" oninput="onKeyImport(this.value)"/>
              <div id="import-key-addr" class="addr-pill" style="display:none;margin-top:8px">✓ Key accepted</div>
            </div>
          </div>
        </div>

        <div class="config-actions">
          <span class="note">Saves key to config.json and restarts the node.</span>
          <button class="btn btn-primary btn-sm" id="btn-key-save" onclick="saveKey()" disabled>Save &amp; restart →</button>
        </div>

      </div>
    </div>
  </div>

  <div class="audit-panel" id="admin-wallet-panel" style="margin-top:16px">
    <div class="audit-header" id="admin-wallet-header" onclick="toggleAdminWalletPanel()">
      <div style="display:flex;align-items:center;gap:10px">
        <div class="panel-title">Admin wallet</div>
        <span class="tier-pill off" id="admin-wallet-pill" style="font-size:10px;padding:2px 10px">
          <span class="tp-dot"></span><span id="admin-wallet-pill-text">unclaimed</span>
        </span>
      </div>
      <span class="audit-chevron" id="admin-wallet-chevron">▼</span>
    </div>
    <div id="admin-wallet-body" style="display:none">
      <div class="config-form">

        <div class="config-section">
          <div class="config-section-title">Current admin wallet</div>
          <div class="cfg-field">
            <div class="cfg-readonly" id="admin-wallet-addr-wrap">
              <span id="admin-wallet-addr" style="color:var(--text)">—</span>
            </div>
          </div>
          <div class="cfg-hint" id="admin-wallet-hint">
            No admin wallet claimed yet. Sign in with any wallet from the login page to claim admin access.
          </div>
        </div>

        <div class="config-section" id="transfer-section" style="display:none">
          <div class="config-section-title">Transfer admin to another wallet</div>
          <div class="key-warn-box">
            <strong>⚠ This is permanent</strong>
            Your current session will become invalid. The new wallet will be the only way to sign in.
            Make sure you have access to the new wallet before confirming.
          </div>
          <p style="font-size:12px;color:var(--subtle);margin:0 0 14px;line-height:1.5">
            Switch to the new wallet in MetaMask, then click Transfer.
            The new wallet must sign a message to prove ownership.
          </p>
          <div class="btn-row">
            <button class="btn btn-danger" id="btn-transfer" onclick="startTransfer()">Transfer admin →</button>
          </div>
          <div class="msg error" id="transfer-err" style="margin-top:10px;display:none"></div>
          <div class="msg info"  id="transfer-info" style="margin-top:10px;display:none"></div>
        </div>

      </div>
    </div>
  </div>

  <div class="audit-panel" id="ens-panel" style="margin-top:16px">
    <div class="audit-header" id="ens-header" onclick="toggleEnsPanel()">
      <div class="panel-title">ENS records</div>
      <span class="audit-chevron" id="ens-chevron">▼</span>
    </div>
    <div id="ens-body" style="display:none">
      <div class="config-form">

        <div class="config-section">
          <div class="config-section-title">Managed records</div>
          <p style="font-size:13px;color:var(--subtle);margin:0 0 14px">
            Records stored here are served automatically when your resolver receives ENS
            <code style="font-family:var(--mono);font-size:11px;background:var(--s2);padding:2px 5px;border-radius:4px">resolve(bytes,bytes)</code>
            calldata. Requires <code style="font-family:var(--mono);font-size:11px;background:var(--s2);padding:2px 5px;border-radius:4px">withEns()</code> in your resolver (default in standalone mode).
          </p>
          <div id="ens-table-wrap" style="overflow-x:auto;margin-bottom:16px">
            <table style="width:100%;border-collapse:collapse;font-size:12px">
              <thead>
                <tr style="color:var(--subtle);text-align:left">
                  <th style="padding:6px 10px;border-bottom:1px solid var(--border)">Name</th>
                  <th style="padding:6px 10px;border-bottom:1px solid var(--border)">Type</th>
                  <th style="padding:6px 10px;border-bottom:1px solid var(--border)">Key / CoinType</th>
                  <th style="padding:6px 10px;border-bottom:1px solid var(--border)">Value</th>
                  <th style="padding:6px 10px;border-bottom:1px solid var(--border)"></th>
                </tr>
              </thead>
              <tbody id="ens-records-body">
                <tr><td colspan="5" style="padding:12px 10px;color:var(--muted);font-size:12px">No records yet.</td></tr>
              </tbody>
            </table>
          </div>
        </div>

        <div class="config-section">
          <div class="config-section-title">Add / update record</div>
          <div class="cfg-row-2">
            <div class="cfg-field">
              <label class="cfg-label">Name (e.g. vitalik.eth)</label>
              <input class="cfg-input" type="text" id="ens-name" placeholder="name.eth"/>
            </div>
            <div class="cfg-field">
              <label class="cfg-label">Type</label>
              <select class="cfg-input" id="ens-type" onchange="onEnsTypeChange()">
                <option value="addr">addr — ETH address</option>
                <option value="addr_coin">addr_coin — multi-coin</option>
                <option value="text">text — text record</option>
                <option value="contenthash">contenthash — bytes</option>
              </select>
            </div>
          </div>
          <div class="cfg-row-2">
            <div class="cfg-field" id="ens-extra-wrap" style="display:none">
              <label class="cfg-label" id="ens-extra-label">Key</label>
              <input class="cfg-input" type="text" id="ens-extra" placeholder="avatar"/>
            </div>
            <div class="cfg-field">
              <label class="cfg-label">Value</label>
              <input class="cfg-input" type="text" id="ens-value" placeholder="0x... or https://..."/>
            </div>
          </div>
          <button class="cfg-save-btn" onclick="addEnsRecord()" style="margin-top:4px">Add record</button>
          <div class="cfg-hint">Changes take effect immediately — no restart needed.</div>
        </div>

      </div>
    </div>
  </div>

  <div class="audit-panel" id="ipfs-panel" style="margin-top:16px">
    <div class="audit-header" id="ipfs-header" onclick="toggleIpfsPanel()">
      <div class="panel-title">IPFS &amp; browser resolution</div>
      <span class="audit-chevron" id="ipfs-chevron">▼</span>
    </div>
    <div id="ipfs-body" style="display:none">
      <div class="config-form">

        <div class="config-section">
          <div class="config-section-title">Provider</div>
          <p style="font-size:13px;color:var(--subtle);margin:0 0 10px">
            Upload files to a decentralized CDN and set the resulting CID as the
            <code style="font-family:var(--mono);font-size:11px;background:var(--s2);padding:2px 5px;border-radius:4px">contenthash</code>
            on any ENS name via MetaMask. Native ENS browsers (Brave, eth.link) resolve
            <code style="font-family:var(--mono);font-size:11px;background:var(--s2);padding:2px 5px;border-radius:4px">contenthash</code>
            directly on-chain — no CCIP-Read involved.
          </p>
          <div id="cdn-status-row" style="font-size:12px;padding:8px 12px;border-radius:6px;background:var(--s2);margin-bottom:4px">
            Loading…
          </div>
        </div>

        <div class="config-section">
          <div class="config-section-title">Upload file</div>
          <div class="cfg-field">
            <label class="cfg-label">File</label>
            <div style="display:flex;gap:8px;align-items:stretch">
              <input class="cfg-input" type="file" id="ipfs-file" style="flex:1"/>
              <button class="cfg-save-btn" onclick="uploadToIpfs()" id="ipfs-upload-btn">Upload</button>
            </div>
          </div>
          <div id="ipfs-upload-status" style="font-size:12px;color:var(--subtle);margin-top:6px"></div>
          <div class="cfg-hint">File is pinned via your configured CDN provider. CID is auto-filled below.</div>
        </div>

        <div class="config-section">
          <div class="config-section-title">Set contenthash on ENS</div>
          <div class="cfg-row-2">
            <div class="cfg-field">
              <label class="cfg-label">ENS name (e.g. vitalik.eth)</label>
              <input class="cfg-input" type="text" id="ipfs-ens-name" placeholder="name.eth"/>
            </div>
            <div class="cfg-field">
              <label class="cfg-label">IPFS CID</label>
              <input class="cfg-input" type="text" id="ipfs-cid" placeholder="Qm... or bafy..."/>
            </div>
          </div>
          <div class="cfg-row-2" style="margin-top:8px">
            <div class="cfg-field">
              <label class="cfg-label">Network</label>
              <select class="cfg-input" id="ipfs-chain">
                <option value="1">Ethereum Mainnet</option>
                <option value="11155111">Sepolia</option>
              </select>
            </div>
            <div class="cfg-field">
              <label class="cfg-label">Resolver address <span style="font-weight:400;color:var(--subtle)">(optional)</span></label>
              <input class="cfg-input" type="text" id="ipfs-resolver" placeholder="0x231b0Ee… (default: ENS Public Resolver)"/>
            </div>
          </div>
          <div style="margin-top:8px">
            <button class="cfg-save-btn" onclick="setContenthash()" id="ipfs-set-btn">Set via MetaMask</button>
          </div>
          <div id="ipfs-set-status" style="font-size:12px;color:var(--subtle);margin-top:6px"></div>
          <div class="cfg-hint">
            Calls <code style="font-family:var(--mono);font-size:11px">setContenthash(namehash, encode(CID))</code> on the resolver.
            Leave resolver blank to use the ENS Public Resolver. Set a custom address for CCIP-Read resolvers (e.g. dinamic.eth).
            Also saves the record locally so CCIP-Read resolvers serve it dynamically.
          </div>
        </div>

      </div>
    </div>
  </div>

  <div class="audit-panel" id="msg-panel" style="margin-top:16px">
    <div class="audit-header" id="msg-header" onclick="toggleMsgPanel()">
      <div class="panel-title">
        Mesh messages
        <span id="msg-badge" style="display:none;font-size:10px;background:#ef4444;color:#fff;padding:1px 6px;border-radius:10px;margin-left:6px">0</span>
      </div>
      <span class="audit-chevron" id="msg-chevron">▼</span>
    </div>
    <div id="msg-body" style="display:none">
      <div class="config-form">

        <div class="config-section">
          <div class="config-section-title">Received messages</div>
          <p style="font-size:13px;color:var(--subtle);margin:0 0 12px">
            Signed notifications from mesh peers. Messages from the official network key are marked
            <span style="font-size:10px;background:#7c3aed;color:#fff;padding:1px 5px;border-radius:3px">official</span>.
          </p>
          <div id="msg-list" style="font-size:12px;color:var(--subtle)">Loading…</div>
          <div style="margin-top:10px;display:flex;gap:8px">
            <button class="cfg-save-btn" onclick="markAllRead()" style="background:var(--s3)">Mark all read</button>
          </div>
        </div>

        <div class="config-section">
          <div class="config-section-title">Send message to all peers</div>
          <div class="cfg-row-2">
            <div class="cfg-field">
              <label class="cfg-label">Type</label>
              <select class="cfg-input" id="msg-type">
                <option value="upgrade_notice">upgrade_notice</option>
                <option value="deprecation">deprecation</option>
                <option value="network_announcement">network_announcement</option>
              </select>
            </div>
            <div class="cfg-field">
              <label class="cfg-label">Version (optional)</label>
              <input class="cfg-input" type="text" id="msg-version" placeholder="e.g. 0.5.0"/>
            </div>
          </div>
          <div class="cfg-field" style="margin-top:8px">
            <label class="cfg-label">Message</label>
            <input class="cfg-input" type="text" id="msg-body-input" placeholder="v0.5.0 is available — upgrade when convenient"/>
          </div>
          <div style="margin-top:8px;display:flex;gap:8px;align-items:center">
            <button class="cfg-save-btn" onclick="sendMessage()" id="msg-send-btn">Sign &amp; broadcast</button>
            <span id="msg-send-status" style="font-size:12px;color:var(--subtle)"></span>
          </div>
          <div class="cfg-hint">Signed with your gateway key. Only delivered to peers that know your signer address.</div>
        </div>

      </div>
    </div>
  </div>

  <div class="audit-panel" id="deploy-panel" style="margin-top:16px">
    <div class="audit-header" id="deploy-header" onclick="toggleDeployPanel()">
      <div class="panel-title">Deploy contracts</div>
      <span class="audit-chevron" id="deploy-chevron">▼</span>
    </div>
    <div id="deploy-body" style="display:none">
      <div class="config-form">

        <div class="config-section">
          <div class="config-section-title">Select chain</div>
          <p style="font-size:13px;color:var(--text-muted);margin:0 0 12px">
            Chains with a canonical deployment let you use the shared contracts instantly — no wallet needed.
            For any other chain, deploy via your browser wallet. Your key never leaves MetaMask.
          </p>
          <div class="cfg-field" style="max-width:320px">
            <label class="cfg-label">Chain</label>
            <select id="deploy-chain" onchange="onChainPick()" style="width:100%">
              <option value="">— pick a chain —</option>
            </select>
          </div>
        </div>

        <div id="deploy-known" style="display:none">
          <div class="config-section">
            <div class="config-section-title">Canonical deployment</div>
            <div class="cfg-row-2">
              <div class="cfg-field">
                <label class="cfg-label">AttestationIndex</label>
                <div class="cfg-readonly"><span id="known-attest" style="font-family:var(--mono);font-size:11px"></span></div>
              </div>
              <div class="cfg-field">
                <label class="cfg-label">NodeRegistry</label>
                <div class="cfg-readonly"><span id="known-registry" style="font-family:var(--mono);font-size:11px"></span></div>
              </div>
            </div>
            <div style="margin-top:12px;display:flex;align-items:center;gap:10px">
              <button class="btn btn-primary btn-sm" onclick="useKnownDeployment()">Use these addresses →</button>
              <span id="known-status" style="font-size:12px;color:var(--text-muted)"></span>
            </div>
          </div>
        </div>

        <div id="deploy-new" style="display:none">
          <div class="config-section">
            <div class="config-section-title">Deploy via wallet — no private key stored</div>
            <p style="font-size:13px;color:var(--text-muted);margin:0 0 12px">
              MetaMask will prompt for two transactions (one per contract).
              Addresses are saved to config automatically on success.
            </p>
            <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
              <button class="btn btn-primary btn-sm" id="btn-deploy" onclick="deployContracts()">Connect wallet &amp; deploy →</button>
              <span id="deploy-status" style="font-size:12px;color:var(--text-muted)"></span>
            </div>
          </div>
          <div id="deploy-results" style="display:none">
            <div class="config-section">
              <div class="config-section-title">Deployed addresses</div>
              <div class="cfg-row-2">
                <div class="cfg-field">
                  <label class="cfg-label">AttestationIndex</label>
                  <div class="cfg-readonly"><span id="deployed-attest" style="font-family:var(--mono);font-size:11px"></span></div>
                </div>
                <div class="cfg-field">
                  <label class="cfg-label">NodeRegistry</label>
                  <div class="cfg-readonly"><span id="deployed-registry" style="font-family:var(--mono);font-size:11px"></span></div>
                </div>
              </div>
              <div class="cfg-row-2" style="margin-top:8px">
                <div class="cfg-field">
                  <label class="cfg-label">WyriweAttestationVerifier</label>
                  <div class="cfg-readonly"><span id="deployed-verifier" style="font-family:var(--mono);font-size:11px"></span></div>
                </div>
              </div>
              <div class="cfg-hint" style="margin-top:8px">Saved to config. Node will restart to pick up the new addresses.</div>
            </div>
          </div>
        </div>

      </div>
    </div>
  </div>

  <div class="audit-panel" id="upgrade-panel" style="margin-top:16px;display:none">
    <div class="audit-header" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'block':'none'">
      <div class="panel-title">Node version</div>
      <span class="audit-chevron">▼</span>
    </div>
    <div style="display:none;padding:16px">
      <div class="cfg-row-2" style="margin-bottom:12px">
        <div class="cfg-field"><label class="cfg-label">Running</label><div class="cfg-readonly" id="upgrade-current">—</div></div>
        <div class="cfg-field"><label class="cfg-label">Latest (npm)</label><div class="cfg-readonly" id="upgrade-latest">—</div></div>
      </div>
      <p id="upgrade-msg" style="font-size:13px;color:var(--subtle);margin:0 0 12px"></p>
      <button class="btn btn-ghost btn-sm" id="btn-upgrade" onclick="upgradeNode()">↻ Check for update</button>
      <span id="upgrade-status" style="font-size:12px;color:var(--text-muted);margin-left:10px"></span>
      <div style="margin-top:16px;padding:12px;background:var(--s2);border-radius:8px;font-size:12px;color:var(--subtle);line-height:1.7">
        <div style="font-weight:600;color:var(--text);margin-bottom:6px">How updates are applied</div>
        <div><span style="color:var(--green)">●</span> <strong>Docker + Watchtower</strong> — auto-pulls the latest image and restarts the container within 5 minutes. No action needed.</div>
        <div style="margin-top:4px"><span style="color:var(--yellow,#f59e0b)">●</span> <strong>Docker without Watchtower</strong> — run <code style="background:var(--s1);padding:1px 4px;border-radius:3px">docker pull ghcr.io/echo-merlini/ccip-router:latest</code> then restart the container.</div>
        <div style="margin-top:4px"><span style="color:var(--yellow,#f59e0b)">●</span> <strong>Railway / managed platforms</strong> — trigger a redeploy from the Railway dashboard. The latest image is pulled automatically on each deploy.</div>
        <div style="margin-top:4px"><span style="color:var(--subtle)">●</span> <strong>npm global</strong> — run <code style="background:var(--s1);padding:1px 4px;border-radius:3px">npm update -g ccip-router</code> then restart the process.</div>
        <div style="margin-top:8px;padding-top:8px;border-top:1px solid var(--border,rgba(255,255,255,0.07))">Updates preserve all records and configuration. The database is not affected by a version upgrade.</div>
      </div>
    </div>
  </div>

</main>

<div class="toast" id="toast"></div>

<script>
  function rel(ts) {
    if (!ts) return 'never'
    const s = Math.floor(Date.now()/1000) - ts
    if (s < 60)   return s + 's ago'
    if (s < 3600) return Math.floor(s/60) + 'm ago'
    return Math.floor(s/3600) + 'h ago'
  }

  function trunc(s, n) { return s && s.length > n ? s.slice(0,6)+'...'+s.slice(-4) : (s||'—') }

  function peerRole(version) {
    if (!version) return { label: 'unknown', bg: '#374151', color: '#9ca3af' }
    const isSemver = /^\d+\.\d+/.test(version)
    if (isSemver)  return { label: 'router',  bg: '#1e3a5f', color: '#60a5fa' }
    return               { label: 'gateway', bg: '#2d1b69', color: '#a78bfa' }
  }

  function renderPeers(peers, ourVersion) {
    const el = document.getElementById('peers-list')
    if (!peers.length) {
      el.innerHTML = '<div class="empty">No peers yet.<br>Add a URL below to join the mesh.</div>'
      return
    }
    el.innerHTML = peers.map(p => {
      const outdated = p.nodeVersion && ourVersion && isOlderSemver(p.nodeVersion, ourVersion)
      const upgradeBadge = outdated
        ? \` <span style="font-size:10px;background:#f59e0b;color:#000;padding:1px 5px;border-radius:3px;margin-left:4px">upgrade v\${p.nodeVersion}</span>\`
        : ''
      const role = peerRole(p.nodeVersion)
      const roleBadge = \`<span style="font-size:10px;background:\${role.bg};color:\${role.color};padding:1px 6px;border-radius:3px;margin-left:6px;letter-spacing:.03em;font-weight:600">\${role.label}</span>\`
      return \`
      <div class="peer-row">
        <div class="health-dot \${p.healthy ? 'ok' : 'err'}"></div>
        <div class="peer-info">
          <div class="peer-url">\${p.url}\${roleBadge}\${upgradeBadge}</div>
          <div class="peer-meta">\${trunc(p.signerAddress,20)} · \${rel(p.lastSyncAt)}\${p.nodeVersion ? ' · v'+p.nodeVersion : ''}</div>
        </div>
        <div class="peer-actions">
          <button class="btn btn-ghost btn-sm btn-icon" title="Sync now" onclick="syncNow()">⟳</button>
          <button class="btn btn-danger btn-sm btn-icon" title="Remove" onclick="removePeer('\${p.url}')">✕</button>
        </div>
      </div>
    \`}).join('')
  }

  async function discoverPeers() {
    const btn     = document.getElementById('discover-btn')
    const section = document.getElementById('discover-section')
    const list    = document.getElementById('discover-list')
    btn.textContent = '⊕ Discovering...'
    btn.disabled = true
    list.innerHTML = '<div class="empty" style="padding:12px 16px">Querying NodeRegistry...</div>'
    section.style.display = 'block'
    try {
      const res  = await fetch('/admin/api/peers/discover')
      let data
      try { data = await res.json() } catch { data = { error: \`Server error (HTTP \${res.status})\` } }
      if (!res.ok) {
        list.innerHTML = \`<div class="empty" style="padding:12px 16px;color:var(--red)">\${data.error || 'Discovery failed'}</div>\`
        return
      }
      renderDiscoverNodes(data.nodes)
    } catch (e) {
      list.innerHTML = \`<div class="empty" style="padding:12px 16px;color:var(--red)">\${e.message}</div>\`
    } finally {
      btn.textContent = '⊕ Discover'
      btn.disabled = false
    }
  }

  function renderDiscoverNodes(nodes) {
    const list = document.getElementById('discover-list')
    if (!nodes?.length) {
      list.innerHTML = '<div class="empty" style="padding:12px 16px">No other nodes found in NodeRegistry.</div>'
      return
    }
    list.innerHTML = nodes.map(n => {
      const role     = peerRole(n.version)
      const roleBadge = \`<span style="font-size:10px;background:\${role.bg};color:\${role.color};padding:1px 6px;border-radius:3px;margin-left:6px;font-weight:600">\${n.role}</span>\`
      const healthDot = \`<span style="display:inline-block;width:7px;height:7px;border-radius:50%;background:\${n.healthy ? 'var(--green)' : 'var(--red)'};flex-shrink:0;margin-right:8px"></span>\`
      const actionBtn = n.alreadyPeer
        ? \`<span style="font-size:11px;color:var(--subtle);padding:4px 8px">connected</span>\`
        : \`<button class="btn btn-ghost btn-sm" onclick="connectDiscovered('\${n.url}', this)">+ Connect</button>\`
      return \`
        <div class="peer-row">
          \${healthDot}
          <div class="peer-info">
            <div class="peer-url">\${n.url}\${roleBadge}</div>
            <div class="peer-meta">\${trunc(n.signerAddress, 20)}\${n.version ? ' · v' + n.version : ''}</div>
          </div>
          <div class="peer-actions">\${actionBtn}</div>
        </div>\`
    }).join('')
  }

  async function connectDiscovered(url, btn) {
    btn.disabled = true
    btn.textContent = 'Connecting...'
    try {
      const res = await fetch('/admin/api/peers', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      })
      if (res.ok) {
        btn.textContent = 'Connected'
        btn.style.color = 'var(--green)'
        btn.style.borderColor = 'var(--green)'
        load()
      } else {
        const { error } = await res.json()
        btn.textContent = error || 'Failed'
        btn.disabled = false
      }
    } catch (e) {
      btn.textContent = 'Error'
      btn.disabled = false
    }
  }

  function isOlderSemver(a, b) {
    const p = v => v.split('.').map(Number)
    const [aM, am, ap] = p(a); const [bM, bm, bp] = p(b)
    if (isNaN(aM) || isNaN(bM)) return false
    if (aM !== bM) return aM < bM
    if (am !== bm) return am < bm
    return (ap ?? 0) < (bp ?? 0)
  }

  // ── Records infinite scroll ──────────────────────────────────────────────────
  let _recordsOffset = 0
  let _recordsLoading = false
  let _recordsExhausted = false
  let _recordsObserver = null

  function recordRow(r) {
    const src = r.sourcePeer ? (r.sourcePeer.split('//')[1] ?? r.sourcePeer).split('/')[0] : null
    return \`<div class="record-row">
      <div class="record-hash">\${r.inputHash}</div>
      <div class="record-source \${src ? 'peer' : 'local'}">\${src ? '↓ ' + src : '● local'}</div>
      <div class="record-time">\${rel(r.timestamp)}</div>
    </div>\`
  }

  async function loadMoreRecords() {
    if (_recordsLoading || _recordsExhausted) return
    _recordsLoading = true
    const sentinel = document.getElementById('records-sentinel')
    if (sentinel) sentinel.textContent = 'Loading…'
    try {
      const res = await fetch(\`/admin/api/records?limit=20&offset=\${_recordsOffset}\`)
      const d = await res.json()
      const el = document.getElementById('records-list')
      if (_recordsOffset === 0 && !d.records.length) {
        el.innerHTML = '<div class="empty">No records yet.<br>Call the CCIP handler to write one.</div>'
        return
      }
      d.records.forEach(r => {
        const div = document.createElement('div')
        div.innerHTML = recordRow(r)
        el.insertBefore(div.firstElementChild, sentinel)
      })
      _recordsOffset += d.records.length
      if (!d.hasMore) {
        _recordsExhausted = true
        if (sentinel) sentinel.textContent = ''
        if (_recordsObserver) { _recordsObserver.disconnect(); _recordsObserver = null }
      } else {
        if (sentinel) sentinel.textContent = ''
      }
    } finally {
      _recordsLoading = false
    }
  }

  function initRecordsScroll() {
    _recordsOffset = 0; _recordsLoading = false; _recordsExhausted = false
    const el = document.getElementById('records-list')
    el.innerHTML = '<div id="records-sentinel" style="height:1px;text-align:center;font-size:11px;color:var(--muted);padding:4px 0"></div>'
    if (_recordsObserver) _recordsObserver.disconnect()
    _recordsObserver = new IntersectionObserver(entries => {
      if (entries[0].isIntersecting) loadMoreRecords()
    }, { threshold: 0.1 })
    _recordsObserver.observe(document.getElementById('records-sentinel'))
    loadMoreRecords()
  }

  let _signerAddress = null

  function copySigner() {
    if (!_signerAddress) return
    navigator.clipboard.writeText(_signerAddress)
    const pill = document.getElementById('signer-pill')
    pill.classList.add('copied')
    setTimeout(() => pill.classList.remove('copied'), 1200)
    toast('Address copied')
  }

  async function load() {
    const res = await fetch('/admin/api/status')
    if (res.status === 401) { window.location.href = '/admin/login'; return }
    if (!res.ok) return
    const d = await res.json()
    if (!d || !Array.isArray(d.peers)) return
    window._statusData = d

    _signerAddress = d.signerAddress
    document.getElementById('h-addr').textContent = d.signerAddress ? trunc(d.signerAddress, 20) : 'dry-run'
    const roleInfo = peerRole(d.version)
    const roleEl   = document.getElementById('h-role')
    roleEl.textContent         = roleInfo.label
    roleEl.style.background    = roleInfo.bg
    roleEl.style.color         = roleInfo.color
    roleEl.style.borderColor   = roleInfo.color + '44'

    // Dry-run banner
    document.getElementById('dryrun-banner').style.display = d.signerAddress ? 'none' : 'flex'

    // Key panel status pill + signer display
    const kpill = document.getElementById('key-status-pill')
    if (kpill) {
      kpill.className = 'tier-pill ' + (d.signerAddress ? 'on' : 'off')
      document.getElementById('key-status-text').textContent =
        d.signerAddress ? trunc(d.signerAddress, 16) : 'not configured'
    }
    const ksv = document.getElementById('key-signer-val')
    if (ksv) ksv.textContent = d.signerAddress || 'not configured'

    document.getElementById('s-records').textContent  = d.records
    document.getElementById('s-ns-sub').textContent   = d.namespace
    document.getElementById('s-peers').textContent    = d.peers.length
    document.getElementById('s-healthy').textContent  = d.peers.filter(p=>p.healthy).length + ' healthy'

    const syncs = d.peers.map(p=>p.lastSyncAt).filter(Boolean)
    document.getElementById('s-sync').textContent     = syncs.length ? rel(Math.max(...syncs)) : 'never'
    document.getElementById('s-interval').textContent = d.syncInterval

    renderPeers(d.peers, d.version)
    if (_recordsOffset === 0) initRecordsScroll()

    document.getElementById('ni-addr').textContent     = d.signerAddress || 'dry-run'
    document.getElementById('ni-ns').textContent       = d.namespace
    document.getElementById('ni-interval').textContent = d.syncInterval
    document.getElementById('ni-version').textContent  = d.version
    document.getElementById('node-bar').style.display  = 'flex'

    // Unread messages badge
    const badge = document.getElementById('msg-badge')
    if (d.unreadMessages > 0) {
      badge.textContent = String(d.unreadMessages)
      badge.style.display = 'inline'
    } else {
      badge.style.display = 'none'
    }
    if (msgOpen) loadMessages()

    document.getElementById('upgrade-panel').style.display = 'block'

    // Show warning banner if admin is open
    document.getElementById('warn-banner').style.display = d.protected ? 'none' : 'flex'
    // Show logout only if protected
    document.getElementById('btn-logout').style.display  = d.protected ? 'inline-flex' : 'none'

    // Admin wallet panel pill (if open)
    if (adminWalletOpen) refreshAdminWallet()

    // Stack status pills
    if (d.tiers) {
      document.getElementById('stack-status').style.display = 'flex'
      const setTier = (id, on) => {
        const el = document.getElementById(id)
        el.className = 'tier-pill ' + (on ? 'on' : 'off')
      }
      setTier('tier-signed',  d.tiers.signed)
      setTier('tier-erc8004', d.tiers.erc8004)
      setTier('tier-wyriwe',  d.tiers.wyriwe)
      setTier('tier-ocp',     d.tiers.ocp)
      setTier('tier-erc8263', d.tiers.ocp)
      setTier('tier-vni',     d.tiers.vni)
      setTier('tier-onchain', d.tiers.onChain)
    }
  }

  async function syncNow() {
    const btn = document.getElementById('btn-sync')
    btn.disabled = true; btn.textContent = '⟳ Syncing...'
    await fetch('/admin/api/sync', { method: 'POST' })
    await load()
    btn.disabled = false; btn.textContent = '⟳ Sync'
    toast('Sync complete')
  }

  async function addPeer() {
    const input = document.getElementById('peer-input')
    const url   = input.value.trim()
    if (!url) return
    const res = await fetch('/admin/api/peers', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url }),
    })
    if (res.ok) { input.value = ''; await load(); toast('Peer added') }
    else { const d = await res.json(); toast('✕ ' + (d.error || 'Failed to add peer')) }
  }

  async function removePeer(url) {
    if (!confirm('Remove ' + url + '?')) return
    await fetch('/admin/api/peers', {
      method: 'DELETE', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url }),
    })
    await load(); toast('Peer removed')
  }

  async function logout() {
    await fetch('/admin/logout', { method: 'POST' })
    window.location.href = '/admin/login'
  }

  function toast(msg) {
    const el = document.getElementById('toast')
    el.textContent = msg; el.classList.add('show')
    setTimeout(() => el.classList.remove('show'), 2500)
  }

  function fmtTs(ms) {
    const d = new Date(ms)
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
  }

  async function loadLogs() {
    const res = await fetch('/admin/api/logs')
    if (!res.ok) return
    const logs = await res.json()
    const el   = document.getElementById('log-body')
    if (!logs.length) { el.innerHTML = '<div class="empty">No log entries yet.</div>'; return }
    el.innerHTML = [...logs].reverse().map(e => \`
      <div class="log-row \${e.level}">
        <span class="log-ts">\${fmtTs(e.ts)}</span>
        <span class="log-msg">\${e.msg.replace(/</g,'&lt;')}</span>
      </div>
    \`).join('')
  }

  // ── Spec audit ────────────────────────────────────────────────────────────

  let auditLoaded = false
  let auditOpen   = false

  async function loadAudit() {
    const res = await fetch('/admin/api/audit')
    if (!res.ok) return
    const { specs } = await res.json()
    renderAuditSummary(specs)
    renderAuditGrid(specs)
    auditLoaded = true
  }

  function renderAuditSummary(specs) {
    if (!specs?.length) return
    document.getElementById('audit-summary').innerHTML = specs.map(s => \`
      <span class="audit-mini-pill \${s.status}">\${s.name}</span>
    \`).join('')
  }

  function renderAuditGrid(specs) {
    if (!specs?.length) return
    document.getElementById('audit-grid').innerHTML = specs.map(s => \`
      <div class="spec-card \${s.status}">
        <div class="spec-top">
          <div>
            <div class="spec-name">\${s.name}</div>
            <div class="spec-label">\${s.label}</div>
          </div>
          <span class="spec-badge \${s.status}">\${s.status === 'pass' ? '✓ Pass' : '○ Inactive'}</span>
        </div>
        <div class="spec-desc">\${s.description}</div>
        <div class="spec-rows">
          \${(s.details ?? []).map(d => \`
            <div class="spec-row \${d.warn ? 'warn' : ''}">
              <span class="sk">\${d.k}</span>
              <span class="sv">\${d.v}</span>
            </div>
          \`).join('')}
        </div>
        \${s.action === 'publish' ? \`
          <button class="btn btn-ghost btn-sm" id="btn-publish" style="margin-top:12px;width:100%" onclick="publishToChain()">
            ↑ Publish to chain
          </button>
        \` : s.action === 'register' ? \`
          <button class="btn btn-ghost btn-sm" id="btn-register" style="margin-top:12px;width:100%" onclick="registerNode()">
            ↑ Register on-chain
          </button>
        \` : ''}
      </div>
    \`).join('')
  }

  async function upgradeNode() {
    const btn    = document.getElementById('btn-upgrade')
    const status = document.getElementById('upgrade-status')
    const msg    = document.getElementById('upgrade-msg')
    btn.disabled = true; btn.textContent = '↻ Checking...'
    status.textContent = ''
    try {
      const res  = await fetch('/admin/api/upgrade')
      const data = await res.json()
      if (!res.ok) { status.textContent = data.error || 'Failed'; return }
      document.getElementById('upgrade-current').textContent = data.current
      document.getElementById('upgrade-latest').textContent  = data.latest
      if (data.upToDate) {
        msg.textContent = '✓ Running the latest version.'
        msg.style.color = 'var(--green)'
      } else {
        msg.innerHTML = 'Update available: ' + data.current + ' &rarr; ' + data.latest + '. Watchtower will auto-pull within 5 minutes, or restart the container manually.'
        msg.style.color = 'var(--subtle)'
      }
    } catch (e) {
      status.textContent = 'Error: ' + e.message
    } finally {
      btn.disabled = false; btn.textContent = '↻ Check for update'
    }
  }

  async function registerNode() {
    const btn = document.getElementById('btn-register')
    if (!btn) return
    btn.disabled = true; btn.textContent = '↑ Registering...'
    try {
      const res  = await fetch('/admin/api/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })
      const data = await res.json()
      if (!res.ok) { toast(data.error || 'Register failed'); return }
      toast('↑ Node registered: ' + data.txHash.slice(0, 10) + '…')
    } catch (e) {
      toast('Register error: ' + e.message)
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = '↑ Register on-chain' }
    }
  }

  async function publishToChain() {
    const btn = document.getElementById('btn-publish')
    if (!btn) return
    btn.disabled = true; btn.textContent = '↑ Publishing...'
    try {
      const res  = await fetch('/admin/api/publish', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })
      const data = await res.json()
      if (!res.ok) { toast(data.error || 'Publish failed'); return }
      toast(\`↑ \${data.published} anchored · \${data.skipped} already on-chain\`)
    } catch (e) {
      toast('Publish error: ' + e.message)
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = '↑ Publish to chain' }
    }
  }

  function toggleAudit() {
    auditOpen = !auditOpen
    const body    = document.getElementById('audit-body')
    const chevron = document.getElementById('audit-chevron')
    const header  = document.getElementById('audit-header')
    body.style.display  = auditOpen ? 'block' : 'none'
    chevron.className   = 'audit-chevron' + (auditOpen ? ' open' : '')
    header.className    = 'audit-header'  + (auditOpen ? ' open' : '')
    if (auditOpen && !auditLoaded) loadAudit()
  }

  // ── Key rotation panel ────────────────────────────────────────────────────

  let newGatewayKey = ''
  let keyPanelOpen  = false

  function openKeyPanel() {
    if (!keyPanelOpen) toggleKeyPanel()
    document.getElementById('key-panel').scrollIntoView({ behavior: 'smooth', block: 'start' })
  }

  function toggleKeyPanel() {
    keyPanelOpen = !keyPanelOpen
    const body    = document.getElementById('key-body')
    const chevron = document.getElementById('key-chevron')
    const header  = document.getElementById('key-header')
    body.style.display = keyPanelOpen ? 'block' : 'none'
    chevron.className  = 'audit-chevron' + (keyPanelOpen ? ' open' : '')
    header.className   = 'audit-header'  + (keyPanelOpen ? ' open' : '')
  }

  async function generateNewKey() {
    newGatewayKey = ''
    document.getElementById('btn-key-save').disabled = true
    const res = await fetch('/setup/generate-key')
    const d   = await res.json()
    newGatewayKey = d.privateKey
    document.getElementById('new-key-val').textContent  = d.privateKey
    document.getElementById('new-key-addr').textContent = d.address
    document.getElementById('new-key-reveal').classList.add('show')
    document.getElementById('key-import-field').style.display = 'none'
    document.getElementById('btn-key-save').disabled = false
  }

  function copyNewKey() { navigator.clipboard.writeText(newGatewayKey); toast('Key copied') }

  function showKeyImport() {
    newGatewayKey = ''
    document.getElementById('key-import-field').style.display = 'block'
    document.getElementById('new-key-reveal').classList.remove('show')
    document.getElementById('import-key-val').value = ''
    document.getElementById('import-key-addr').style.display = 'none'
    document.getElementById('btn-key-save').disabled = true
  }

  function onKeyImport(val) {
    const hex = val.trim()
    const ok  = hex.startsWith('0x') && hex.length === 66
    newGatewayKey = ok ? hex : ''
    document.getElementById('import-key-addr').style.display = ok ? 'inline-flex' : 'none'
    document.getElementById('btn-key-save').disabled = !ok
  }

  async function saveKey() {
    if (!newGatewayKey) return
    const btn    = document.getElementById('btn-key-save')
    btn.disabled = true; btn.textContent = 'Saving...'
    const res  = await fetch('/admin/api/key', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ gatewayKey: newGatewayKey }),
    })
    const data = await res.json()
    if (!res.ok) {
      btn.disabled = false; btn.textContent = 'Save & restart →'
      toast('✕ ' + (data.error || 'Save failed'))
      return
    }
    btn.textContent = 'Restarting...'
    toast('Key saved — restarting node')
    setTimeout(() => { window.location.href = '/admin' }, 4500)
  }

  // ── Node config panel ──────────────────────────────────────────────────────

  let configLoaded = false
  let configOpen   = false
  let configDirty  = false
  let autoDiscover = true

  function toggleConfig() {
    configOpen = !configOpen
    const body    = document.getElementById('config-body')
    const chevron = document.getElementById('config-chevron')
    const header  = document.getElementById('config-header')
    body.style.display = configOpen ? 'block' : 'none'
    chevron.className  = 'audit-chevron' + (configOpen ? ' open' : '')
    header.className   = 'audit-header'  + (configOpen ? ' open' : '')
    if (configOpen && !configLoaded) fetchConfig()
  }

  async function fetchConfig() {
    const res = await fetch('/admin/api/config')
    if (!res.ok) return
    const d = await res.json()

    document.getElementById('cfg-namespace').value    = d.namespace       ?? ''
    document.getElementById('cfg-interval').value     = d.syncInterval    ?? ''
    document.getElementById('cfg-port').value         = d.port            ?? 3000
    document.getElementById('cfg-dbpath').value       = d.dbPath          ?? ''
    document.getElementById('cfg-signer').textContent = d.signerAddress   ?? 'dry-run'
    document.getElementById('cfg-nodeurl').value      = d.nodeUrl         ?? ''
    document.getElementById('cfg-peers').value        = (d.peers ?? []).join('\\n')
    document.getElementById('cfg-agentid').value      = d.agentId         ?? ''
    document.getElementById('cfg-registry').value     = d.registryAddress ?? ''
    document.getElementById('cfg-modelhash').value    = d.modelHash       ?? ''
    document.getElementById('cfg-chainid').value      = d.chainId         ?? 1
    document.getElementById('cfg-rpcurl').value       = d.rpcUrl          ?? ''
    document.getElementById('cfg-attestindex').value  = d.attestationIndex ?? ''
    document.getElementById('cfg-noderegistry').value = d.nodeRegistry    ?? ''
    document.getElementById('cfg-resolveraddr').value = d.resolverAddress ?? ''

    autoDiscover = d.autoDiscover ?? true
    document.getElementById('toggle-autodiscover').className = 'toggle-switch' + (autoDiscover ? ' on' : '')

    configLoaded = true
    configDirty  = false
    document.getElementById('config-dirty').style.display = 'none'
  }

  function toggleAutoDiscover() {
    autoDiscover = !autoDiscover
    document.getElementById('toggle-autodiscover').className = 'toggle-switch' + (autoDiscover ? ' on' : '')
    markDirty()
  }

  function markDirty() {
    if (!configLoaded) return
    configDirty = true
    document.getElementById('config-dirty').style.display = 'inline'
  }

  async function saveConfig() {
    const btn    = document.getElementById('btn-cfg-save')
    btn.disabled = true; btn.textContent = 'Saving...'
    const peers  = document.getElementById('cfg-peers').value
      .split('\\n').map(s => s.trim()).filter(Boolean)
    const payload = {
      namespace:        document.getElementById('cfg-namespace').value.trim(),
      syncInterval:     document.getElementById('cfg-interval').value.trim(),
      port:             Number(document.getElementById('cfg-port').value),
      dbPath:           document.getElementById('cfg-dbpath').value.trim(),
      nodeUrl:          document.getElementById('cfg-nodeurl').value.trim()       || undefined,
      autoDiscover,
      peers,
      agentId:          document.getElementById('cfg-agentid').value.trim()       || undefined,
      registryAddress:  document.getElementById('cfg-registry').value.trim()      || undefined,
      modelHash:        document.getElementById('cfg-modelhash').value.trim()     || undefined,
      chainId:          Number(document.getElementById('cfg-chainid').value) || 1,
      rpcUrl:           document.getElementById('cfg-rpcurl').value.trim()        || undefined,
      attestationIndex: document.getElementById('cfg-attestindex').value.trim()   || undefined,
      nodeRegistry:     document.getElementById('cfg-noderegistry').value.trim()  || undefined,
      resolverAddress:  document.getElementById('cfg-resolveraddr').value.trim()  || undefined,
      adminSecret:      document.getElementById('cfg-adminsecret').value.trim()   || undefined,
    }
    const res  = await fetch('/admin/api/config', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    })
    const data = await res.json()
    if (!res.ok) {
      btn.disabled = false; btn.textContent = 'Save & restart →'
      toast('✕ ' + (data.error || 'Save failed'))
      return
    }
    btn.textContent = 'Restarting...'
    toast('Config saved — restarting node')
    setTimeout(() => { window.location.href = '/admin' }, 4500)
  }

  // ── Admin wallet panel ─────────────────────────────────────────────────────

  let adminWalletOpen = false
  function toggleAdminWalletPanel() {
    adminWalletOpen = !adminWalletOpen
    document.getElementById('admin-wallet-body').style.display    = adminWalletOpen ? 'block' : 'none'
    document.getElementById('admin-wallet-chevron').textContent   = adminWalletOpen ? '▲' : '▼'
    if (adminWalletOpen) refreshAdminWallet()
  }

  function refreshAdminWallet() {
    const status = window._statusData
    if (!status) return
    const pill     = document.getElementById('admin-wallet-pill')
    const pillText = document.getElementById('admin-wallet-pill-text')
    const addrEl   = document.getElementById('admin-wallet-addr')
    const hintEl   = document.getElementById('admin-wallet-hint')
    const transferSection = document.getElementById('transfer-section')

    if (status.adminClaimed && status.adminAddress) {
      pill.classList.remove('off'); pill.classList.add('on')
      pillText.textContent = 'claimed'
      addrEl.textContent   = status.adminAddress
      hintEl.style.display = 'none'
      transferSection.style.display = 'block'
    } else {
      pill.classList.add('off')
      pillText.textContent = 'unclaimed'
      addrEl.textContent   = '—'
      hintEl.style.display = 'block'
      transferSection.style.display = 'none'
    }
  }

  async function startTransfer() {
    const btn      = document.getElementById('btn-transfer')
    const errEl    = document.getElementById('transfer-err')
    const infoEl   = document.getElementById('transfer-info')
    errEl.style.display = 'none'
    infoEl.style.display = 'none'

    if (!window.ethereum) {
      errEl.textContent = 'No wallet detected.'; errEl.style.display = 'block'; return
    }

    try {
      btn.disabled = true; btn.textContent = 'Connecting new wallet...'

      const accounts   = await window.ethereum.request({ method: 'eth_requestAccounts' })
      const newAddress = accounts[0]
      const current    = window._statusData?.adminAddress

      if (current && newAddress.toLowerCase() === current.toLowerCase()) {
        errEl.textContent = 'New wallet is the same as current admin.'; errEl.style.display = 'block'
        btn.disabled = false; btn.textContent = 'Transfer admin →'; return
      }

      btn.textContent = 'Fetching nonce...'
      const nonceRes = await fetch('/admin/siwe/nonce')
      const { nonce, domain, chainId } = await nonceRes.json()

      btn.textContent = 'Sign with new wallet...'
      const now = new Date()
      const exp = new Date(now.getTime() + 10 * 60 * 1000)
      const message = [
        domain + ' wants you to sign in with your Ethereum account:',
        newAddress,
        '',
        'Transfer ccip-router admin to this wallet',
        '',
        'URI: ' + window.location.origin,
        'Version: 1',
        'Chain ID: ' + chainId,
        'Nonce: ' + nonce,
        'Issued At: ' + now.toISOString(),
        'Expiration Time: ' + exp.toISOString(),
      ].join('\\n')

      const signature = await window.ethereum.request({
        method: 'personal_sign',
        params: [message, newAddress],
      })

      btn.textContent = 'Transferring...'
      const res = await fetch('/admin/siwe/transfer', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message, signature }),
      })

      if (res.ok) {
        infoEl.textContent = 'Admin transferred to ' + newAddress.slice(0,6) + '...' + newAddress.slice(-4) + '. Redirecting...'
        infoEl.style.display = 'block'
        setTimeout(() => { window.location.href = '/admin/login' }, 2000)
      } else {
        const { error } = await res.json()
        errEl.textContent = error || 'Transfer failed'; errEl.style.display = 'block'
        btn.disabled = false; btn.textContent = 'Transfer admin →'
      }
    } catch (err) {
      if (err.code === 4001) {
        errEl.textContent = 'Signature rejected.'; errEl.style.display = 'block'
      } else {
        errEl.textContent = String(err.message || err); errEl.style.display = 'block'
      }
      btn.disabled = false; btn.textContent = 'Transfer admin →'
    }
  }

  // ── ENS records panel ─────────────────────────────────────────────────────

  let ensOpen = false
  function toggleEnsPanel() {
    ensOpen = !ensOpen
    document.getElementById('ens-body').style.display    = ensOpen ? 'block' : 'none'
    document.getElementById('ens-chevron').textContent   = ensOpen ? '▲' : '▼'
    if (ensOpen) loadEnsRecords()
  }

  // ── Messages panel ──────────────────────────────────────────────────────────

  let msgOpen = false

  function toggleMsgPanel() {
    msgOpen = !msgOpen
    document.getElementById('msg-body').style.display  = msgOpen ? 'block' : 'none'
    document.getElementById('msg-chevron').textContent = msgOpen ? '▲' : '▼'
    if (msgOpen) loadMessages()
  }

  async function loadMessages() {
    const list = document.getElementById('msg-list')
    try {
      const res  = await fetch('/admin/api/messages')
      const data = await res.json()
      if (!data.messages.length) {
        list.innerHTML = '<div style="color:var(--muted);padding:8px 0">No messages yet.</div>'
        return
      }
      const TYPE_COLORS = {
        upgrade_notice: '#2563eb',
        deprecation: '#dc2626',
        network_announcement: '#059669',
      }
      list.innerHTML = data.messages.map(m => {
        const badge   = m.official
          ? '<span style="font-size:10px;background:#7c3aed;color:#fff;padding:1px 5px;border-radius:3px;margin-left:4px">official</span>'
          : ''
        const typeBadge = \`<span style="font-size:10px;background:\${TYPE_COLORS[m.type] ?? '#666'};color:#fff;padding:1px 5px;border-radius:3px">\${m.type}</span>\`
        const unread  = !m.read ? 'font-weight:600;' : 'opacity:0.7;'
        return \`
        <div style="\${unread}padding:10px 0;border-bottom:1px solid var(--border);display:flex;gap:10px;align-items:flex-start">
          <div style="flex:1">
            <div style="margin-bottom:4px">\${typeBadge}\${badge}
              <span style="font-size:11px;color:var(--subtle);margin-left:6px">\${m.fromUrl} · \${rel(m.receivedAt)}</span>
            </div>
            <div style="font-size:13px">\${m.body}\${m.version ? ' <span style="color:var(--subtle)">v' + m.version + '</span>' : ''}</div>
          </div>
          <button class="btn btn-ghost btn-sm" onclick="markRead(\${m.id})" title="Mark read" style="opacity:0.6;font-size:11px">✓</button>
        </div>
      \`}).join('')
    } catch (err) {
      list.textContent = 'Failed to load: ' + err.message
    }
  }

  async function markRead(id) {
    await fetch('/admin/api/messages/read', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids: [id] }),
    })
    loadMessages()
    load()
  }

  async function markAllRead() {
    await fetch('/admin/api/messages/read', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    })
    loadMessages()
    load()
  }

  async function sendMessage() {
    const type    = document.getElementById('msg-type').value
    const body    = document.getElementById('msg-body-input').value.trim()
    const version = document.getElementById('msg-version').value.trim()
    const status  = document.getElementById('msg-send-status')
    const btn     = document.getElementById('msg-send-btn')

    if (!body) { status.textContent = 'Enter a message'; return }

    btn.disabled = true
    status.textContent = 'Broadcasting…'
    try {
      const res  = await fetch('/admin/api/messages/send', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type, message: body, version: version || undefined }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error)
      status.textContent = \`✓ sent: \${data.sent}, failed: \${data.failed}\`
      document.getElementById('msg-body-input').value = ''
    } catch (err) {
      status.textContent = '✕ ' + (err.message || String(err))
    } finally {
      btn.disabled = false
    }
  }

  // ── IPFS panel ──────────────────────────────────────────────────────────────

  let ipfsOpen = false

  function toggleIpfsPanel() {
    ipfsOpen = !ipfsOpen
    document.getElementById('ipfs-body').style.display   = ipfsOpen ? 'block' : 'none'
    document.getElementById('ipfs-chevron').textContent  = ipfsOpen ? '▲' : '▼'
    if (ipfsOpen) loadCdnStatus()
  }

  async function loadCdnStatus() {
    const row = document.getElementById('cdn-status-row')
    try {
      const res  = await fetch('/admin/api/cdn/status')
      const data = await res.json()
      if (data.configured) {
        row.style.color = 'var(--green, #4caf50)'
        row.textContent = '✓ Provider configured: ' + data.provider
      } else {
        row.style.color = 'var(--subtle)'
        row.textContent = 'Not configured — set CDN_PROVIDER (pinata | storacha) and CDN_API_KEY in node config or env'
      }
    } catch { row.textContent = 'Could not load CDN status' }
  }

  async function uploadToIpfs() {
    const fileInput = document.getElementById('ipfs-file')
    const status    = document.getElementById('ipfs-upload-status')
    const btn       = document.getElementById('ipfs-upload-btn')
    if (!fileInput.files.length) { status.textContent = 'Select a file first'; return }

    btn.disabled = true
    status.textContent = 'Uploading…'
    const form = new FormData()
    form.append('file', fileInput.files[0])

    try {
      const res  = await fetch('/admin/api/cdn/upload', { method: 'POST', body: form })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error || res.statusText)
      document.getElementById('ipfs-cid').value = data.cid
      status.textContent = '✓ Pinned via ' + data.provider + ': ' + data.cid
    } catch (err) {
      status.textContent = '✕ ' + (err.message || String(err))
    } finally {
      btn.disabled = false
    }
  }

  // Minimal base58 decode (for CIDv0 Qm...)
  const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
  function decodeBase58(s) {
    let n = 0n
    for (const c of s) { const i = B58.indexOf(c); if (i < 0) throw new Error('Bad base58: ' + c); n = n * 58n + BigInt(i) }
    const bytes = []; while (n > 0n) { bytes.unshift(Number(n & 0xffn)); n >>= 8n }
    for (let i = 0; i < s.length && s[i] === '1'; i++) bytes.unshift(0)
    return new Uint8Array(bytes)
  }

  // Minimal base32 decode (for CIDv1 bafy... = 'b' multibase prefix + base32lower)
  const B32 = 'abcdefghijklmnopqrstuvwxyz234567'
  function decodeBase32(s) {
    s = s.toLowerCase().replace(/=+$/, '')
    const bytes = []; let buf = 0, bits = 0
    for (const c of s) { const i = B32.indexOf(c); if (i < 0) throw new Error('Bad base32: ' + c); buf = (buf << 5) | i; bits += 5; if (bits >= 8) { bytes.push((buf >> (bits - 8)) & 0xff); bits -= 8 } }
    return new Uint8Array(bytes)
  }

  function cidToContenthash(cid) {
    cid = cid.trim()
    let cidBytes
    if (cid.startsWith('Qm'))     cidBytes = decodeBase58(cid)          // CIDv0
    else if (cid.startsWith('b')) cidBytes = decodeBase32(cid.slice(1)) // CIDv1 base32, strip 'b' multibase prefix
    else throw new Error('Unsupported CID. Expected Qm... (CIDv0) or b... (CIDv1 base32)')
    const out = new Uint8Array(2 + cidBytes.length)
    out[0] = 0xe3; out[1] = 0x01 // ipfs-ns multicodec varint
    out.set(cidBytes, 2)
    return '0x' + Array.from(out, b => b.toString(16).padStart(2, '0')).join('')
  }

  // ABI-encode setContenthash(bytes32 node, bytes calldata hash)
  function encodeSetContenthash(nodeHex, contenthashHex) {
    const selector  = '304e6ade'
    const node      = nodeHex.slice(2).padStart(64, '0')
    const offset    = '0000000000000000000000000000000000000000000000000000000000000040'
    const bytes     = contenthashHex.startsWith('0x') ? contenthashHex.slice(2) : contenthashHex
    const byteLen   = bytes.length / 2
    const lenHex    = byteLen.toString(16).padStart(64, '0')
    const padded    = bytes.padEnd(Math.ceil(byteLen / 32) * 64, '0')
    return '0x' + selector + node + offset + lenHex + padded
  }

  const ENS_RESOLVERS = {
    1:         '0x231b0Ee14048e9dCcD1d247744d114a4EB5E8E63', // Mainnet
    11155111:  '0x8FADE66B79cC9f707aB26799354482EB93a5B7dD', // Sepolia
  }

  async function setContenthash() {
    const ensName  = document.getElementById('ipfs-ens-name').value.trim()
    const cid      = document.getElementById('ipfs-cid').value.trim()
    const chainId  = parseInt(document.getElementById('ipfs-chain').value)
    const status   = document.getElementById('ipfs-set-status')
    const btn      = document.getElementById('ipfs-set-btn')

    if (!ensName) { status.textContent = 'Enter an ENS name'; return }
    if (!cid)     { status.textContent = 'Enter or upload a CID first'; return }
    if (!window.ethereum) { status.textContent = 'MetaMask not found'; return }

    btn.disabled = true
    status.textContent = 'Preparing…'

    try {
      // Get namehash from server (uses viem)
      const nhRes  = await fetch('/admin/api/cdn/namehash?name=' + encodeURIComponent(ensName))
      const nhData = await nhRes.json()
      if (!nhRes.ok) throw new Error(nhData.error)
      const node = nhData.node

      // Encode contenthash
      const contenthash = cidToContenthash(cid)
      const calldata    = encodeSetContenthash(node, contenthash)

      // Switch chain
      await window.ethereum.request({
        method: 'wallet_switchEthereumChain',
        params: [{ chainId: '0x' + chainId.toString(16) }],
      })

      const [account] = await window.ethereum.request({ method: 'eth_requestAccounts' })
      const customResolver = document.getElementById('ipfs-resolver').value.trim()
      const resolver = customResolver || ENS_RESOLVERS[chainId]
      if (!resolver) throw new Error('No known ENS resolver for chain ' + chainId + '. Enter a custom resolver address.')

      status.textContent = 'Waiting for MetaMask confirmation…'
      const txHash = await window.ethereum.request({
        method: 'eth_sendTransaction',
        params: [{ from: account, to: resolver, data: calldata }],
      })

      status.textContent = '✓ tx sent: ' + txHash

      // Also save as contenthash ENS record in local DB for CCIP-Read
      await fetch('/admin/api/ens-records', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: ensName, type: 'contenthash', value: contenthash }),
      })
      toast('Contenthash set on-chain + saved locally')
    } catch (err) {
      status.textContent = '✕ ' + (err.message || String(err))
    } finally {
      btn.disabled = false
    }
  }

  function onEnsTypeChange() {
    const type    = document.getElementById('ens-type').value
    const wrap    = document.getElementById('ens-extra-wrap')
    const label   = document.getElementById('ens-extra-label')
    const input   = document.getElementById('ens-extra')
    if (type === 'text') {
      wrap.style.display = 'block'; label.textContent = 'Key'; input.placeholder = 'avatar'
    } else if (type === 'addr_coin') {
      wrap.style.display = 'block'; label.textContent = 'Coin type (int)'; input.placeholder = '60'
    } else {
      wrap.style.display = 'none'
    }
  }

  async function loadEnsRecords() {
    try {
      const res  = await fetch('/admin/api/ens-records')
      const data = await res.json()
      const tbody = document.getElementById('ens-records-body')
      if (!data.records || data.records.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="padding:12px 10px;color:var(--muted);font-size:12px">No records yet.</td></tr>'
        return
      }
      tbody.innerHTML = data.records.map(r => {
        const extra = r.type === 'text' ? r.textKey : r.type === 'addr_coin' ? r.coinType : '—'
        const val   = r.value.length > 42 ? r.value.slice(0, 20) + '…' + r.value.slice(-8) : r.value
        return \`<tr style="border-bottom:1px solid var(--border)">
          <td style="padding:8px 10px;font-family:var(--mono);font-size:11px">\${r.name}</td>
          <td style="padding:8px 10px;color:var(--subtle)">\${r.type}</td>
          <td style="padding:8px 10px;color:var(--subtle)">\${extra}</td>
          <td style="padding:8px 10px;font-family:var(--mono);font-size:11px" title="\${r.value}">\${val}</td>
          <td style="padding:8px 10px;text-align:right">
            <button onclick="deleteEnsRecord('\${r.name}','\${r.type}',\${r.coinType},'\${r.textKey}')"
              style="background:none;border:1px solid rgba(239,68,68,0.3);color:var(--red);border-radius:6px;padding:3px 10px;font-size:11px;cursor:pointer">
              delete
            </button>
          </td>
        </tr>\`
      }).join('')
    } catch (err) {
      console.error('loadEnsRecords', err)
    }
  }

  async function addEnsRecord() {
    const name  = document.getElementById('ens-name').value.trim()
    const type  = document.getElementById('ens-type').value
    const value = document.getElementById('ens-value').value.trim()
    const extra = document.getElementById('ens-extra').value.trim()
    if (!name || !value) { toast('Name and value are required'); return }
    const body = { name, type, value }
    if (type === 'text')     body.textKey  = extra || ''
    if (type === 'addr_coin') body.coinType = parseInt(extra) || 60
    const res = await fetch('/admin/api/ens-records', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
    if (res.ok) {
      toast('Record saved')
      document.getElementById('ens-name').value  = ''
      document.getElementById('ens-value').value = ''
      document.getElementById('ens-extra').value = ''
      loadEnsRecords()
    } else {
      const { error } = await res.json()
      toast('Error: ' + (error || 'unknown'))
    }
  }

  async function deleteEnsRecord(name, type, coinType, textKey) {
    if (!confirm('Delete record for ' + name + ' (' + type + ')?')) return
    const res = await fetch('/admin/api/ens-records', {
      method: 'DELETE', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, type, coinType, textKey }),
    })
    if (res.ok) { toast('Record deleted'); loadEnsRecords() }
    else toast('Delete failed')
  }

  // ── Deploy contracts panel ─────────────────────────────────────────────────

  // Canonical shared deployments — one per chain, all nodes on the same chain share these.
  // Add an entry here after deploying to a new chain so future operators can skip deployment.
  const KNOWN_DEPLOYMENTS = {
    1: {
      attestationIndex: '0xc7BCCD785Fb994e570d0ca10D0F7899d87C82210',
      nodeRegistry:     '0x95a1e10D1508EF5CD11e3F4d296359c93f15e48D',
      wyriweVerifier:   '0xd8a09d830b27697e1b24e8c9800e562d20318a09',
    },
    11155111: {
      attestationIndex: '0x107D706112225aC57eCf6692FBbDC283fb6E3698',
      nodeRegistry:     '0x6be4966596A9CBaa7260ab6EbbFFA69bBC9a42b7',
      wyriweVerifier:   '0x9515D6e53D2D45C1CFE6181943ca11C150C2bf61',
    },
  }

  const CHAINS = [
    { id: 1,        name: 'Ethereum Mainnet' },
    { id: 11155111, name: 'Sepolia' },
    { id: 8453,     name: 'Base' },
    { id: 84532,    name: 'Base Sepolia' },
    { id: 42161,    name: 'Arbitrum One' },
    { id: 421614,   name: 'Arbitrum Sepolia' },
    { id: 10,       name: 'Optimism' },
    { id: 11155420, name: 'Optimism Sepolia' },
    { id: 137,      name: 'Polygon' },
  ]

  ;(function populateChainPicker() {
    const sel = document.getElementById('deploy-chain')
    for (const c of CHAINS) {
      const opt = document.createElement('option')
      opt.value = String(c.id)
      opt.textContent = KNOWN_DEPLOYMENTS[c.id]
        ? \`✓ \${c.name} — canonical deployment available\`
        : c.name
      sel.appendChild(opt)
    }
    const custom = document.createElement('option')
    custom.value = 'custom'
    custom.textContent = 'Other / custom chain'
    sel.appendChild(custom)
  })()

  function onChainPick() {
    const val     = document.getElementById('deploy-chain').value
    const chainId = parseInt(val)
    const known   = KNOWN_DEPLOYMENTS[chainId]
    document.getElementById('deploy-known').style.display = known ? 'block' : 'none'
    document.getElementById('deploy-new').style.display   = (!val || known) ? 'none' : 'block'
    if (known) {
      document.getElementById('known-attest').textContent    = known.attestationIndex
      document.getElementById('known-registry').textContent  = known.nodeRegistry
      document.getElementById('known-status').textContent    = ''
    }
  }

  async function useKnownDeployment() {
    const chainId = parseInt(document.getElementById('deploy-chain').value)
    const known   = KNOWN_DEPLOYMENTS[chainId]
    if (!known) return
    const status = document.getElementById('known-status')
    status.textContent = 'Saving…'
    const res = await fetch('/admin/api/config', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        attestationIndex: known.attestationIndex,
        nodeRegistry:     known.nodeRegistry,
        chainId,
      }),
    })
    if (res.ok) {
      status.textContent = '✓ Saved — restarting'
      toast('Addresses saved — restarting node')
      setTimeout(() => { window.location.href = '/admin' }, 4500)
    } else {
      status.textContent = '✕ Save failed'
    }
  }

  const ATTEST_BYTECODE   = '0x608060405234801561000f575f80fd5b50610e378061001d5f395ff3fe608060405234801561000f575f80fd5b506004361061004a575f3560e01c806312dcb7a01461004e5780639823e6861461007e578063a10bb806146100ae578063cc3f5873146100de575b5f80fd5b610068600480360381019061006391906106ce565b61010e565b6040516100759190610713565b60405180910390f35b610098600480360381019061009391906106ce565b610175565b6040516100a5919061076b565b60405180910390f35b6100c860048036038101906100c391906106ce565b6101a4565b6040516100d59190610793565b60405180910390f35b6100f860048036038101906100f39190610830565b6101b9565b604051610105919061076b565b60405180910390f35b5f8073ffffffffffffffffffffffffffffffffffffffff165f808481526020019081526020015f205f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1614159050919050565b5f602052805f5260405f205f915054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b6001602052805f5260405f205f915090505481565b5f8073ffffffffffffffffffffffffffffffffffffffff165f808660e0013581526020019081526020015f205f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff161461025b576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016102529061090f565b60405180910390fd5b5f7f8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f7fc3dc521d1237729e2c271b34397deb78b0e79a3aa49acebf066a6294c43b85ed7fc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6468860200160208101906102d39190610957565b6040516020016102e795949392919061099a565b6040516020818303038152906040528051906020012090505f7f465936ddc3693f48ac8b4c7b3e097d2b4be6011f2dac0be649291fd9a6c418a0865f01358760200160208101906103389190610957565b886040013589606001358a608001358b60a001358c60c001358d60e001358e61010001356040516020016103759a999897969594939291906109eb565b6040516020818303038152906040528051906020012090505f82826040516020016103a1929190610af9565b6040516020818303038152906040528051906020012090506103c48187876104fa565b93505f73ffffffffffffffffffffffffffffffffffffffff168473ffffffffffffffffffffffffffffffffffffffff1603610434576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161042b90610b9f565b60405180910390fd5b835f808960e0013581526020019081526020015f205f6101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055508660e0013560015f8960a0013581526020019081526020015f2081905550865f01358760a001358860e001357ffcf8a88836f197f876eec746d8290807a6ad127e2a6594918c334738513fb9e8878b61010001356040516104e8929190610bbd565b60405180910390a45050509392505050565b5f60418383905014610541576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161053890610c2e565b60405180910390fd5b5f805f853592506020860135915060408601355f1a9050601b8160ff16101561057457601b816105719190610c85565b90505b601b8160ff1614806105895750601c8160ff16145b6105c8576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016105bf90610d03565b60405180910390fd5b5f6001888386866040515f81526020016040526040516105eb9493929190610d30565b6020604051602081039080840390855afa15801561060b573d5f803e3d5ffd5b5050506020604051035190505f73ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff1603610685576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161067c90610de3565b60405180910390fd5b809450505050509392505050565b5f80fd5b5f80fd5b5f819050919050565b6106ad8161069b565b81146106b7575f80fd5b50565b5f813590506106c8816106a4565b92915050565b5f602082840312156106e3576106e2610693565b5b5f6106f0848285016106ba565b91505092915050565b5f8115159050919050565b61070d816106f9565b82525050565b5f6020820190506107265f830184610704565b92915050565b5f73ffffffffffffffffffffffffffffffffffffffff82169050919050565b5f6107558261072c565b9050919050565b6107658161074b565b82525050565b5f60208201905061077e5f83018461075c565b92915050565b61078d8161069b565b82525050565b5f6020820190506107a65f830184610784565b92915050565b5f80fd5b5f61012082840312156107c6576107c56107ac565b5b81905092915050565b5f80fd5b5f80fd5b5f80fd5b5f8083601f8401126107f0576107ef6107cf565b5b8235905067ffffffffffffffff81111561080d5761080c6107d3565b5b602083019150836001820283011115610829576108286107d7565b5b9250929050565b5f805f610140848603121561084857610847610693565b5b5f610855868287016107b0565b93505061012084013567ffffffffffffffff81111561087757610876610697565b5b610883868287016107db565b92509250509250925092565b5f82825260208201905092915050565b7f4174746573746174696f6e496e6465783a20616c7265616479207265636f72645f8201527f6564000000000000000000000000000000000000000000000000000000000000602082015250565b5f6108f960228361088f565b91506109048261089f565b604082019050919050565b5f6020820190508181035f830152610926816108ed565b9050919050565b6109368161074b565b8114610940575f80fd5b50565b5f813590506109518161092d565b92915050565b5f6020828403121561096c5761096b610693565b5b5f61097984828501610943565b91505092915050565b5f819050919050565b61099481610982565b82525050565b5f60a0820190506109ad5f830188610784565b6109ba6020830187610784565b6109c76040830186610784565b6109d4606083018561098b565b6109e1608083018461075c565b9695505050505050565b5f610140820190506109ff5f83018d610784565b610a0c602083018c610784565b610a19604083018b61075c565b610a26606083018a610784565b610a336080830189610784565b610a4060a0830188610784565b610a4d60c0830187610784565b610a5a60e0830186610784565b610a68610100830185610784565b610a7661012083018461098b565b9b9a5050505050505050505050565b5f81905092915050565b7f19010000000000000000000000000000000000000000000000000000000000005f82015250565b5f610ac3600283610a85565b9150610ace82610a8f565b600282019050919050565b5f819050919050565b610af3610aee8261069b565b610ad9565b82525050565b5f610b0382610ab7565b9150610b0f8285610ae2565b602082019150610b1f8284610ae2565b6020820191508190509392505050565b7f4174746573746174696f6e496e6465783a20696e76616c6964207369676e61745f8201527f7572650000000000000000000000000000000000000000000000000000000000602082015250565b5f610b8960238361088f565b9150610b9482610b2f565b604082019050919050565b5f6020820190508181035f830152610bb681610b7d565b9050919050565b5f604082019050610bd05f83018561075c565b610bdd602083018461098b565b9392505050565b7f4174746573746174696f6e496e6465783a2062616420736967206c656e6774685f82015250565b5f610c1860208361088f565b9150610c2382610be4565b602082019050919050565b5f6020820190508181035f830152610c4581610c0c565b9050919050565b5f60ff82169050919050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f610c8f82610c4c565b9150610c9a83610c4c565b9250828201905060ff811115610cb357610cb2610c58565b5b92915050565b7f4174746573746174696f6e496e6465783a2062616420760000000000000000005f82015250565b5f610ced60178361088f565b9150610cf882610cb9565b602082019050919050565b5f6020820190508181035f830152610d1a81610ce1565b9050919050565b610d2a81610c4c565b82525050565b5f608082019050610d435f830187610784565b610d506020830186610d21565b610d5d6040830185610784565b610d6a6060830184610784565b95945050505050565b7f4174746573746174696f6e496e6465783a2065637265636f766572206661696c5f8201527f6564000000000000000000000000000000000000000000000000000000000000602082015250565b5f610dcd60228361088f565b9150610dd882610d73565b604082019050919050565b5f6020820190508181035f830152610dfa81610dc1565b905091905056fea2646970667358221220f6f051a31888be724946767861d50dfd14487a0688cbc2bef18d17f00d7827e764736f6c63430008180033'

  const VERIFIER_BYTECODE  = '0x608060405234801561000f575f80fd5b50610a788061001d5f395ff3fe608060405234801561000f575f80fd5b5060043610610029575f3560e01c8063258ae5821461002d575b5f80fd5b610047600480360381019061004291906103de565b61005d565b6040516100549190610455565b60405180910390f35b5f805f848481019061006f9190610714565b915091505f825f015183604001518460a001518560c001518661010001516040516020016100a195949392919061078e565b6040516020818303038152906040528051906020012090508681146100cb575f935050505061026a565b868360e00151146100e1575f935050505061026a565b5f7f8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f7fc3dc521d1237729e2c271b34397deb78b0e79a3aa49acebf066a6294c43b85ed7fc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc646876020015160405160200161015f9594939291906107ee565b6040516020818303038152906040528051906020012090505f7f465936ddc3693f48ac8b4c7b3e097d2b4be6011f2dac0be649291fd9a6c418a0855f015186602001518760400151886060015189608001518a60a001518b60c001518c60e001518d61010001516040516020016101df9a9998979695949392919061083f565b6040516020818303038152906040528051906020012090505f828260405160200161020b92919061094d565b6040516020818303038152906040528051906020012090505f61022e8287610271565b90505f73ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff1614159750505050505050505b9392505050565b5f6041825114610283575f9050610333565b5f805f602085015192506040850151915060608501515f1a9050601b8160ff1610156102b957601b816102b691906109bc565b90505b601b8160ff16141580156102d15750601c8160ff1614155b156102e1575f9350505050610333565b6001868285856040515f815260200160405260405161030394939291906109ff565b6020604051602081039080840390855afa158015610323573d5f803e3d5ffd5b5050506020604051035193505050505b92915050565b5f604051905090565b5f80fd5b5f80fd5b5f819050919050565b61035c8161034a565b8114610366575f80fd5b50565b5f8135905061037781610353565b92915050565b5f80fd5b5f80fd5b5f80fd5b5f8083601f84011261039e5761039d61037d565b5b8235905067ffffffffffffffff8111156103bb576103ba610381565b5b6020830191508360018202830111156103d7576103d6610385565b5b9250929050565b5f805f604084860312156103f5576103f4610342565b5b5f61040286828701610369565b935050602084013567ffffffffffffffff81111561042357610422610346565b5b61042f86828701610389565b92509250509250925092565b5f8115159050919050565b61044f8161043b565b82525050565b5f6020820190506104685f830184610446565b92915050565b5f80fd5b5f601f19601f8301169050919050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52604160045260245ffd5b6104b882610472565b810181811067ffffffffffffffff821117156104d7576104d6610482565b5b80604052505050565b5f6104e9610339565b90506104f582826104af565b919050565b5f73ffffffffffffffffffffffffffffffffffffffff82169050919050565b5f610523826104fa565b9050919050565b61053381610519565b811461053d575f80fd5b50565b5f8135905061054e8161052a565b92915050565b5f819050919050565b61056681610554565b8114610570575f80fd5b50565b5f813590506105818161055d565b92915050565b5f610120828403121561059d5761059c61046e565b5b6105a86101206104e0565b90505f6105b784828501610369565b5f8301525060206105ca84828501610540565b60208301525060406105de84828501610369565b60408301525060606105f284828501610369565b606083015250608061060684828501610369565b60808301525060a061061a84828501610369565b60a08301525060c061062e84828501610369565b60c08301525060e061064284828501610369565b60e08301525061010061065784828501610573565b6101008301525092915050565b5f80fd5b5f67ffffffffffffffff82111561068257610681610482565b5b61068b82610472565b9050602081019050919050565b828183375f83830152505050565b5f6106b86106b384610668565b6104e0565b9050828152602081018484840111156106d4576106d3610664565b5b6106df848285610698565b509392505050565b5f82601f8301126106fb576106fa61037d565b5b813561070b8482602086016106a6565b91505092915050565b5f80610140838503121561072b5761072a610342565b5b5f61073885828601610587565b92505061012083013567ffffffffffffffff81111561075a57610759610346565b5b610766858286016106e7565b9150509250929050565b6107798161034a565b82525050565b61078881610554565b82525050565b5f60a0820190506107a15f830188610770565b6107ae6020830187610770565b6107bb6040830186610770565b6107c86060830185610770565b6107d5608083018461077f565b9695505050505050565b6107e881610519565b82525050565b5f60a0820190506108015f830188610770565b61080e6020830187610770565b61081b6040830186610770565b610828606083018561077f565b61083560808301846107df565b9695505050505050565b5f610140820190506108535f83018d610770565b610860602083018c610770565b61086d604083018b6107df565b61087a606083018a610770565b6108876080830189610770565b61089460a0830188610770565b6108a160c0830187610770565b6108ae60e0830186610770565b6108bc610100830185610770565b6108ca61012083018461077f565b9b9a5050505050505050505050565b5f81905092915050565b7f19010000000000000000000000000000000000000000000000000000000000005f82015250565b5f6109176002836108d9565b9150610922826108e3565b600282019050919050565b5f819050919050565b6109476109428261034a565b61092d565b82525050565b5f6109578261090b565b91506109638285610936565b6020820191506109738284610936565b6020820191508190509392505050565b5f60ff82169050919050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f6109c682610983565b91506109d183610983565b9250828201905060ff8111156109ea576109e961098f565b5b92915050565b6109f981610983565b82525050565b5f608082019050610a125f830187610770565b610a1f60208301866109f0565b610a2c6040830185610770565b610a396060830184610770565b9594505050505056fea2646970667358221220eb9fb45ad138f47a3bbb77c7974c3255d3c3d69a11c9d6ed9fc368ccd9a5206264736f6c63430008180033'

  const REGISTRY_BYTECODE = '0x608060405234801561000f575f80fd5b5061173c8061001d5f395ff3fe608060405234801561000f575f80fd5b506004361061004a575f3560e01c8063038d67e81461004e57806350db6b40146100805780636da49b83146100b05780639d209048146100ce575b5f80fd5b61006860048036038101906100639190610a4e565b6100ff565b60405161007793929190610d6f565b60405180910390f35b61009a60048036038101906100959190610e6f565b61051b565b6040516100a79190610efc565b60405180910390f35b6100b8610790565b6040516100c59190610f24565b60405180910390f35b6100e860048036038101906100e39190610f67565b61079c565b6040516100f6929190610fda565b60405180910390f35b60608060605f6001805490509050808610610200575f67ffffffffffffffff81111561012e5761012d611008565b5b60405190808252806020026020018201604052801561015c5781602001602082028036833780820191505090505b505f67ffffffffffffffff81111561017757610176611008565b5b6040519080825280602002602001820160405280156101aa57816020015b60608152602001906001900390816101955790505b505f67ffffffffffffffff8111156101c5576101c4611008565b5b6040519080825280602002602001820160405280156101f35781602001602082028036833780820191505090505b5093509350935050610514565b5f81868861020e9190611062565b1161022457858761021f9190611062565b610226565b815b90505f87826102359190611095565b90508067ffffffffffffffff81111561025157610250611008565b5b60405190808252806020026020018201604052801561027f5781602001602082028036833780820191505090505b5095508067ffffffffffffffff81111561029c5761029b611008565b5b6040519080825280602002602001820160405280156102cf57816020015b60608152602001906001900390816102ba5790505b5094508067ffffffffffffffff8111156102ec576102eb611008565b5b60405190808252806020026020018201604052801561031a5781602001602082028036833780820191505090505b5093505f5b8181101561050f575f6001828b6103369190611062565b81548110610347576103466110c8565b5b905f5260205f20015f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff16905080888381518110610385576103846110c8565b5b602002602001019073ffffffffffffffffffffffffffffffffffffffff16908173ffffffffffffffffffffffffffffffffffffffff16815250505f808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f01805461040890611122565b80601f016020809104026020016040519081016040528092919081815260200182805461043490611122565b801561047f5780601f106104565761010080835404028352916020019161047f565b820191905f5260205f20905b81548152906001019060200180831161046257829003601f168201915b5050505050878381518110610497576104966110c8565b5b60200260200101819052505f808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f20600101548683815181106104f5576104f46110c8565b5b60200260200101818152505050808060010191505061031f565b505050505b9250925092565b5f8085856040516020016105309291906111b4565b6040516020818303038152906040528051906020012090505f8160405160200161055a919061124e565b60405160208183030381529060405280519060200120905061057d81868661087a565b92505f805f808673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f2060010154149050604051806040016040528089898080601f0160208091040260200160405190810160405280939291908181526020018383808284375f81840152601f19601f820116905080830192505050505050508152602001428152505f808673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f820151815f01908161066b9190611410565b5060208201518160010155905050801561073457600184908060018154018082558091505060019003905f5260205f20015f9091909190916101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055508373ffffffffffffffffffffffffffffffffffffffff167f27dcab8cdfa14145566e2b9d04fea5a4e8ea320a3f04488a1de4d431ed1080ab898960405161072792919061150b565b60405180910390a2610785565b8373ffffffffffffffffffffffffffffffffffffffff167f5f9fcbc17fba60677ae056851409ca727b54b90cb63be975f68684d06613b078898960405161077c92919061150b565b60405180910390a25b505050949350505050565b5f600180549050905090565b60605f805f808573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f209050805f0181600101548180546107f290611122565b80601f016020809104026020016040519081016040528092919081815260200182805461081e90611122565b80156108695780601f1061084057610100808354040283529160200191610869565b820191905f5260205f20905b81548152906001019060200180831161084c57829003601f168201915b505050505091509250925050915091565b5f604183839050146108c1576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016108b890611577565b60405180910390fd5b5f805f853592506020860135915060408601355f1a9050601b8160ff1610156108f457601b816108f191906115a1565b90505b601b8160ff1614806109095750601c8160ff16145b610948576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161093f9061161f565b60405180910390fd5b5f6001888386866040515f815260200160405260405161096b949392919061165b565b6020604051602081039080840390855afa15801561098b573d5f803e3d5ffd5b5050506020604051035190505f73ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff1603610a05576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016109fc906116e8565b60405180910390fd5b809450505050509392505050565b5f80fd5b5f80fd5b5f819050919050565b610a2d81610a1b565b8114610a37575f80fd5b50565b5f81359050610a4881610a24565b92915050565b5f8060408385031215610a6457610a63610a13565b5b5f610a7185828601610a3a565b9250506020610a8285828601610a3a565b9150509250929050565b5f81519050919050565b5f82825260208201905092915050565b5f819050602082019050919050565b5f73ffffffffffffffffffffffffffffffffffffffff82169050919050565b5f610ade82610ab5565b9050919050565b610aee81610ad4565b82525050565b5f610aff8383610ae5565b60208301905092915050565b5f602082019050919050565b5f610b2182610a8c565b610b2b8185610a96565b9350610b3683610aa6565b805f5b83811015610b66578151610b4d8882610af4565b9750610b5883610b0b565b925050600181019050610b39565b5085935050505092915050565b5f81519050919050565b5f82825260208201905092915050565b5f819050602082019050919050565b5f81519050919050565b5f82825260208201905092915050565b5f5b83811015610bd3578082015181840152602081019050610bb8565b5f8484015250505050565b5f601f19601f8301169050919050565b5f610bf882610b9c565b610c028185610ba6565b9350610c12818560208601610bb6565b610c1b81610bde565b840191505092915050565b5f610c318383610bee565b905092915050565b5f602082019050919050565b5f610c4f82610b73565b610c598185610b7d565b935083602082028501610c6b85610b8d565b805f5b85811015610ca65784840389528151610c878582610c26565b9450610c9283610c39565b925060208a01995050600181019050610c6e565b50829750879550505050505092915050565b5f81519050919050565b5f82825260208201905092915050565b5f819050602082019050919050565b610cea81610a1b565b82525050565b5f610cfb8383610ce1565b60208301905092915050565b5f602082019050919050565b5f610d1d82610cb8565b610d278185610cc2565b9350610d3283610cd2565b805f5b83811015610d62578151610d498882610cf0565b9750610d5483610d07565b925050600181019050610d35565b5085935050505092915050565b5f6060820190508181035f830152610d878186610b17565b90508181036020830152610d9b8185610c45565b90508181036040830152610daf8184610d13565b9050949350505050565b5f80fd5b5f80fd5b5f80fd5b5f8083601f840112610dda57610dd9610db9565b5b8235905067ffffffffffffffff811115610df757610df6610dbd565b5b602083019150836001820283011115610e1357610e12610dc1565b5b9250929050565b5f8083601f840112610e2f57610e2e610db9565b5b8235905067ffffffffffffffff811115610e4c57610e4b610dbd565b5b602083019150836001820283011115610e6857610e67610dc1565b5b9250929050565b5f805f8060408587031215610e8757610e86610a13565b5b5f85013567ffffffffffffffff811115610ea457610ea3610a17565b5b610eb087828801610dc5565b9450945050602085013567ffffffffffffffff811115610ed357610ed2610a17565b5b610edf87828801610e1a565b925092505092959194509250565b610ef681610ad4565b82525050565b5f602082019050610f0f5f830184610eed565b92915050565b610f1e81610a1b565b82525050565b5f602082019050610f375f830184610f15565b92915050565b610f4681610ad4565b8114610f50575f80fd5b50565b5f81359050610f6181610f3d565b92915050565b5f60208284031215610f7c57610f7b610a13565b5b5f610f8984828501610f53565b91505092915050565b5f82825260208201905092915050565b5f610fac82610b9c565b610fb68185610f92565b9350610fc6818560208601610bb6565b610fcf81610bde565b840191505092915050565b5f6040820190508181035f830152610ff28185610fa2565b90506110016020830184610f15565b9392505050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52604160045260245ffd5b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f61106c82610a1b565b915061107783610a1b565b925082820190508082111561108f5761108e611035565b5b92915050565b5f61109f82610a1b565b91506110aa83610a1b565b92508282039050818111156110c2576110c1611035565b5b92915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52603260045260245ffd5b7f4e487b71000000000000000000000000000000000000000000000000000000005f52602260045260245ffd5b5f600282049050600182168061113957607f821691505b60208210810361114c5761114b6110f5565b5b50919050565b7f636369702d726f757465723a6e6f64653a000000000000000000000000000000815250565b5f81905092915050565b828183375f83830152505050565b5f61119b8385611178565b93506111a8838584611182565b82840190509392505050565b5f6111be82611152565b6011820191506111cf828486611190565b91508190509392505050565b7f19457468657265756d205369676e6564204d6573736167653a0a3332000000005f82015250565b5f61120f601c83611178565b915061121a826111db565b601c82019050919050565b5f819050919050565b5f819050919050565b61124861124382611225565b61122e565b82525050565b5f61125882611203565b91506112648284611237565b60208201915081905092915050565b5f819050815f5260205f209050919050565b5f6020601f8301049050919050565b5f82821b905092915050565b5f600883026112cf7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff82611294565b6112d98683611294565b95508019841693508086168417925050509392505050565b5f819050919050565b5f61131461130f61130a84610a1b565b6112f1565b610a1b565b9050919050565b5f819050919050565b61132d836112fa565b6113416113398261131b565b8484546112a0565b825550505050565b5f90565b611355611349565b611360818484611324565b505050565b5b81811015611383576113785f8261134d565b600181019050611366565b5050565b601f8211156113c85761139981611273565b6113a284611285565b810160208510156113b1578190505b6113c56113bd85611285565b830182611365565b50505b505050565b5f82821c905092915050565b5f6113e85f19846008026113cd565b1980831691505092915050565b5f61140083836113d9565b9150826002028217905092915050565b61141982610b9c565b67ffffffffffffffff81111561143257611431611008565b5b61143c8254611122565b611447828285611387565b5f60209050601f831160018114611478575f8415611466578287015190505b61147085826113f5565b8655506114d7565b601f19841661148686611273565b5f5b828110156114ad57848901518255600182019150602085019450602081019050611488565b868310156114ca57848901516114c6601f8916826113d9565b8355505b6001600288020188555050505b505050505050565b5f6114ea8385610f92565b93506114f7838584611182565b61150083610bde565b840190509392505050565b5f6020820190508181035f8301526115248184866114df565b90509392505050565b7f4e6f646552656769737472793a2062616420736967206c656e677468000000005f82015250565b5f611561601c83610f92565b915061156c8261152d565b602082019050919050565b5f6020820190508181035f83015261158e81611555565b9050919050565b5f60ff82169050919050565b5f6115ab82611595565b91506115b683611595565b9250828201905060ff8111156115cf576115ce611035565b5b92915050565b7f4e6f646552656769737472793a206261642076000000000000000000000000005f82015250565b5f611609601383610f92565b9150611614826115d5565b602082019050919050565b5f6020820190508181035f830152611636816115fd565b9050919050565b61164681611225565b82525050565b61165581611595565b82525050565b5f60808201905061166e5f83018761163d565b61167b602083018661164c565b611688604083018561163d565b611695606083018461163d565b95945050505050565b7f4e6f646552656769737472793a2065637265636f766572206661696c656400005f82015250565b5f6116d2601e83610f92565b91506116dd8261169e565b602082019050919050565b5f6020820190508181035f8301526116ff816116c6565b905091905056fea26469706673582212205e33dfd591c0fac29bce43a8b3d666b144acb6e7349b2e63f86c822cbacfabd564736f6c63430008180033'

  let deployPanelOpen = false

  function openDeployPanel() {
    if (!deployPanelOpen) toggleDeployPanel()
    document.getElementById('deploy-panel').scrollIntoView({ behavior: 'smooth', block: 'start' })
  }

  function toggleDeployPanel() {
    deployPanelOpen = !deployPanelOpen
    const body    = document.getElementById('deploy-body')
    const chevron = document.getElementById('deploy-chevron')
    const header  = document.getElementById('deploy-header')
    body.style.display = deployPanelOpen ? 'block' : 'none'
    chevron.className  = 'audit-chevron' + (deployPanelOpen ? ' open' : '')
    header.className   = 'audit-header'  + (deployPanelOpen ? ' open' : '')
  }

  async function deployContracts() {
    if (!window.ethereum) {
      toast('✕ No wallet detected — install MetaMask')
      return
    }
    const btn      = document.getElementById('btn-deploy')
    const status   = document.getElementById('deploy-status')
    btn.disabled   = true

    try {
      const [account] = await window.ethereum.request({ method: 'eth_requestAccounts' })

      // Switch wallet to the selected chain
      const pickedVal = document.getElementById('deploy-chain').value
      const targetId  = pickedVal && pickedVal !== 'custom' ? parseInt(pickedVal) : null
      if (targetId) {
        const targetHex = '0x' + targetId.toString(16)
        try {
          await window.ethereum.request({ method: 'wallet_switchEthereumChain', params: [{ chainId: targetHex }] })
        } catch (switchErr) {
          // Chain not added to wallet — that's fine, MetaMask will prompt
        }
      }

      const chainHex = await window.ethereum.request({ method: 'eth_chainId' })
      const chainId  = parseInt(chainHex, 16)
      const chain    = CHAINS.find(c => c.id === chainId)
      status.textContent = \`Connected: \${account.slice(0,6)}…\${account.slice(-4)} · \${chain?.name ?? 'chain ' + chainId}\`

      // Deploy AttestationIndex
      status.textContent = 'Deploying AttestationIndex…'
      const attestTx = await window.ethereum.request({
        method: 'eth_sendTransaction',
        params: [{ from: account, data: ATTEST_BYTECODE, gas: '0x493E0' }],
      })
      status.textContent = 'Waiting for AttestationIndex confirmation…'
      const attestAddr = await waitForContract(attestTx)
      document.getElementById('deployed-attest').textContent = attestAddr

      // Deploy NodeRegistry
      status.textContent = 'Deploying NodeRegistry…'
      const registryTx = await window.ethereum.request({
        method: 'eth_sendTransaction',
        params: [{ from: account, data: REGISTRY_BYTECODE, gas: '0x61A80' }],
      })
      status.textContent = 'Waiting for NodeRegistry confirmation…'
      const registryAddr = await waitForContract(registryTx)
      document.getElementById('deployed-registry').textContent = registryAddr

      // Deploy WyriweAttestationVerifier
      status.textContent = 'Deploying WyriweAttestationVerifier…'
      const verifierTx = await window.ethereum.request({
        method: 'eth_sendTransaction',
        params: [{ from: account, data: VERIFIER_BYTECODE, gas: '0x493E0' }],
      })
      status.textContent = 'Waiting for WyriweAttestationVerifier confirmation…'
      const verifierAddr = await waitForContract(verifierTx)
      document.getElementById('deployed-verifier').textContent = verifierAddr

      document.getElementById('deploy-results').style.display = 'block'
      status.textContent = '✓ All three contracts deployed'
      toast('Contracts deployed — saving addresses to config')

      // Auto-save addresses + chainId to config and restart
      const cfgRes = await fetch('/admin/api/config', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ attestationIndex: attestAddr, nodeRegistry: registryAddr, wyriweVerifier: verifierAddr, chainId }),
      })
      if (cfgRes.ok) {
        status.textContent = '✓ Addresses saved — restarting node'
        setTimeout(() => { window.location.href = '/admin' }, 4500)
      } else {
        status.textContent = '✓ Deployed. Copy addresses above into config manually.'
      }
    } catch (err) {
      status.textContent = '✕ ' + (err.message || String(err))
      btn.disabled = false
    }
  }

  async function waitForContract(txHash) {
    for (let i = 0; i < 60; i++) {
      await new Promise(r => setTimeout(r, 3000))
      const receipt = await window.ethereum.request({
        method: 'eth_getTransactionReceipt',
        params: [txHash],
      })
      if (receipt?.contractAddress) return receipt.contractAddress
    }
    throw new Error('Timed out waiting for receipt')
  }

  load()
  loadLogs()
  loadAudit()
  setInterval(load, 15000)
  setInterval(loadLogs, 10000)
  document.getElementById('peer-input')?.addEventListener('keydown', e => { if (e.key === 'Enter') addPeer() })
</script>
</body>
</html>`
