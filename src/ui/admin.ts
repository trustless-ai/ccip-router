import { Hono } from 'hono'
import { writeFileSync, existsSync, readFileSync } from 'node:fs'
import { privateKeyToAccount } from 'viem/accounts'
import { getConfig, CONFIG_FILE_PATH, type ConfigFile } from '../config.js'
import { getDB } from '../db/index.js'
import { syncAll } from '../mesh/sync.js'
import { getLogs } from '../log.js'
import { requireAdmin, setAdminSession, clearAdminSession } from './auth.js'
import { publishAttestation, type ChainOpts } from '../chain/publish.js'
import { registerNode } from '../chain/register.js'

export const adminRouter = new Hono()

// Auth middleware — applies to every /admin/* route
adminRouter.use('*', async (c, next) => {
  const { adminSecret } = getConfig()
  return requireAdmin(adminSecret)(c, next)
})

// ── Auth routes ───────────────────────────────────────────────────────────────

adminRouter.get('/login', (c) => {
  const { adminSecret } = getConfig()
  if (!adminSecret) return c.redirect('/admin')
  return c.html(LOGIN_HTML)
})

adminRouter.post('/login', async (c) => {
  const { adminSecret } = getConfig()
  if (!adminSecret) return c.redirect('/admin')
  const { secret } = await c.req.json<{ secret: string }>()
  if (!secret || secret !== adminSecret) {
    return c.json({ error: 'invalid secret' }, 401)
  }
  setAdminSession(c, adminSecret)
  return c.json({ ok: true })
})

adminRouter.post('/logout', (c) => {
  clearAdminSession(c)
  return c.redirect('/admin/login')
})

// ── API ──────────────────────────────────────────────────────────────────────

adminRouter.get('/api/status', async (c) => {
  const config = getConfig()
  const db     = getDB()
  const [peers, count, recent, wyriweCount] = await Promise.all([
    db.getPeers(),
    db.recordCount(config.syncNamespace),
    db.getRecentRecords(config.syncNamespace, 8),
    db.recordCount(config.syncNamespace + ':wyriwe'),
  ])
  const signerAddress = config.gatewayKey ? privateKeyToAccount(config.gatewayKey).address : null
  return c.json({
    version: '0.1.0', signerAddress,
    namespace: config.syncNamespace, syncInterval: config.syncInterval,
    protected: !!config.adminSecret,
    records: count,
    tiers: {
      signed:   !!signerAddress,
      erc8004:  !!(config.agentId && config.registryAddress),
      wyriwe:   !!(config.gatewayKey && config.agentId && config.registryAddress && config.modelHash),
      ocp:      !!(config.gatewayKey && config.agentId && config.registryAddress && config.modelHash),
      vni:      !!(config.gatewayKey && config.nodeUrl),
      onChain:  !!(config.attestationIndex && config.rpcUrl),
    },
    peers: peers.map((p) => ({
      url: p.url, healthy: p.healthy,
      signerAddress: p.signerAddress, nodeVersion: p.nodeVersion, lastSyncAt: p.lastSyncAt,
    })),
    recent: recent.map((r) => ({ inputHash: r.inputHash, timestamp: r.timestamp, sourcePeer: r.sourcePeer })),
  })
})

adminRouter.get('/api/logs', (c) => {
  return c.json(getLogs())
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
      key: 'ocp', name: 'OCP / ERC-8263', label: 'Observation Commitment',
      status: wyriweOn ? 'pass' : 'inactive',
      description: 'Verifiable commitment linking agent, model, input, and output. Produced alongside every WYRIWE attestation.',
      details: wyriweOn
        ? [
            { k: 'Records',    v: String(wyriweCount) },
            { k: 'Endpoint',   v: '/ocp/:inputHash' },
            { k: 'Commitment', v: 'keccak256(abi.encode(agentId, modelHash, inputHash, outputHash, timestamp))' },
            { k: 'Contract',   v: chainOn ? config.attestationIndex! : 'not deployed — set ATTESTATION_INDEX' },
            { k: '/verify',    v: chainOn ? 'on-chain fallback active' : 'local DB only' },
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
    hasAdminSecret:   !!config.adminSecret,
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
  }

  try {
    writeFileSync(CONFIG_FILE_PATH, JSON.stringify(config, null, 2), 'utf8')
  } catch (err) {
    return c.json({ error: `Could not write config: ${String(err)}` }, 500)
  }

  console.log('[config] updated via admin panel — restarting')
  setTimeout(() => process.exit(0), 500)
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
  setTimeout(() => process.exit(0), 500)
  return c.json({ ok: true })
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
  <title>ccip-router — login</title>
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

    label { display: block; font-size: 11px; color: var(--subtle); text-transform: uppercase; letter-spacing: 0.6px; margin-bottom: 8px; }

    .input-wrap { position: relative; }
    input[type=password], input[type=text] {
      width: 100%;
      background: rgba(255,255,255,0.03);
      border: 1px solid var(--border); border-radius: 11px;
      color: var(--text); font-size: 14px; font-family: var(--mono);
      padding: 11px 40px 11px 14px; outline: none;
      transition: border-color 0.15s;
    }
    input:focus { border-color: rgba(99,102,241,0.5); }

    .eye-btn {
      position: absolute; right: 12px; top: 50%; transform: translateY(-50%);
      background: none; border: none; color: var(--muted); cursor: pointer;
      font-size: 15px; padding: 4px;
    }
    .eye-btn:hover { color: var(--subtle); }

    .btn-submit {
      width: 100%; margin-top: 18px;
      background: var(--accent); color: #fff;
      border: none; border-radius: 11px;
      font-size: 14px; font-weight: 500; font-family: inherit;
      padding: 12px; cursor: pointer;
      box-shadow: 0 0 20px rgba(99,102,241,0.25);
      transition: all 0.15s;
    }
    .btn-submit:hover { background: var(--accent-v); box-shadow: 0 0 28px rgba(139,92,246,0.35); }
    .btn-submit:disabled { opacity: 0.35; cursor: not-allowed; box-shadow: none; }

    .error {
      margin-top: 14px; padding: 10px 14px;
      background: var(--red-l); border: 1px solid rgba(239,68,68,0.2);
      border-radius: 9px; font-size: 12px; color: var(--red);
      display: none;
    }
  </style>
</head>
<body>
<div class="card">
  <div class="logo">
    <div class="logo-icon"><img src="/favicon.svg" alt=""/></div>
    <div>
      <div class="logo-text">ccip-router</div>
      <div class="logo-sub">admin access</div>
    </div>
  </div>

  <label for="secret">Admin secret</label>
  <div class="input-wrap">
    <input type="password" id="secret" placeholder="Enter your admin secret" autofocus/>
    <button class="eye-btn" type="button" onclick="toggleEye()" id="eye-btn">👁</button>
  </div>

  <button class="btn-submit" id="btn" onclick="login()">Unlock dashboard</button>
  <div class="error" id="err">Invalid secret — check ADMIN_SECRET in your config.</div>
</div>

<script>
  function toggleEye() {
    const input = document.getElementById('secret')
    input.type = input.type === 'password' ? 'text' : 'password'
  }

  async function login() {
    const secret = document.getElementById('secret').value.trim()
    if (!secret) return
    const btn = document.getElementById('btn')
    btn.disabled = true; btn.textContent = 'Unlocking...'
    const res = await fetch('/admin/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ secret }),
    })
    if (res.ok) {
      window.location.href = '/admin'
    } else {
      btn.disabled = false; btn.textContent = 'Unlock dashboard'
      document.getElementById('err').style.display = 'block'
    }
  }

  document.getElementById('secret').addEventListener('keydown', e => {
    if (e.key === 'Enter') login()
  })
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
    .pill.ns { background: var(--accent-l); border-color: var(--accent-b); color: var(--indigo); }
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
    .cfg-field textarea {
      width: 100%; background: rgba(255,255,255,0.03);
      border: 1px solid var(--border); border-radius: 9px;
      color: var(--text); font-size: 12px; font-family: inherit;
      padding: 9px 12px; outline: none; transition: border-color 0.15s;
    }
    .cfg-field input:focus, .cfg-field textarea:focus { border-color: rgba(99,102,241,0.5); }
    .cfg-field textarea { min-height: 72px; resize: vertical; font-family: var(--mono); }
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
    <div class="pill ns" id="h-ns">—</div>
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
  <span class="tier-pill off" id="tier-ocp"><span class="tp-dot"></span>OCP</span>
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
      </div>
      <div id="peers-list"><div class="empty">Loading...</div></div>
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
              <div class="cfg-hint" style="margin-top:8px">Saved to config. Node will restart to pick up the new addresses.</div>
            </div>
          </div>
        </div>

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

  function renderPeers(peers) {
    const el = document.getElementById('peers-list')
    if (!peers.length) {
      el.innerHTML = '<div class="empty">No peers yet.<br>Add a URL below to join the mesh.</div>'
      return
    }
    el.innerHTML = peers.map(p => \`
      <div class="peer-row">
        <div class="health-dot \${p.healthy ? 'ok' : 'err'}"></div>
        <div class="peer-info">
          <div class="peer-url">\${p.url}</div>
          <div class="peer-meta">\${trunc(p.signerAddress,20)} · \${rel(p.lastSyncAt)}\${p.nodeVersion ? ' · v'+p.nodeVersion : ''}</div>
        </div>
        <div class="peer-actions">
          <button class="btn btn-ghost btn-sm btn-icon" title="Sync now" onclick="syncNow()">⟳</button>
          <button class="btn btn-danger btn-sm btn-icon" title="Remove" onclick="removePeer('\${p.url}')">✕</button>
        </div>
      </div>
    \`).join('')
  }

  function renderRecords(records) {
    const el = document.getElementById('records-list')
    if (!records.length) {
      el.innerHTML = '<div class="empty">No records yet.<br>Call the CCIP handler to write one.</div>'
      return
    }
    el.innerHTML = records.map(r => \`
      <div class="record-row">
        <div class="record-hash">\${r.inputHash}</div>
        <div class="record-source \${r.sourcePeer ? 'peer' : 'local'}">\${r.sourcePeer ? '↓ peer' : '● local'}</div>
        <div class="record-time">\${rel(r.timestamp)}</div>
      </div>
    \`).join('')
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
    const d = await res.json()

    _signerAddress = d.signerAddress
    document.getElementById('h-addr').textContent = d.signerAddress ? trunc(d.signerAddress, 20) : 'dry-run'
    document.getElementById('h-ns').textContent   = d.namespace

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

    renderPeers(d.peers)
    renderRecords(d.recent)

    document.getElementById('ni-addr').textContent     = d.signerAddress || 'dry-run'
    document.getElementById('ni-ns').textContent       = d.namespace
    document.getElementById('ni-interval').textContent = d.syncInterval
    document.getElementById('ni-version').textContent  = d.version
    document.getElementById('node-bar').style.display  = 'flex'

    // Show warning banner if admin is open
    document.getElementById('warn-banner').style.display = d.protected ? 'none' : 'flex'
    // Show logout only if protected
    document.getElementById('btn-logout').style.display  = d.protected ? 'inline-flex' : 'none'

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
    document.getElementById('audit-summary').innerHTML = specs.map(s => \`
      <span class="audit-mini-pill \${s.status}">\${s.name}</span>
    \`).join('')
  }

  function renderAuditGrid(specs) {
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
          \${s.details.map(d => \`
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
    document.getElementById('cfg-peers').value        = (d.peers ?? []).join('\n')
    document.getElementById('cfg-agentid').value      = d.agentId         ?? ''
    document.getElementById('cfg-registry').value     = d.registryAddress ?? ''
    document.getElementById('cfg-modelhash').value    = d.modelHash       ?? ''
    document.getElementById('cfg-chainid').value      = d.chainId         ?? 1
    document.getElementById('cfg-rpcurl').value       = d.rpcUrl          ?? ''
    document.getElementById('cfg-attestindex').value  = d.attestationIndex ?? ''
    document.getElementById('cfg-noderegistry').value = d.nodeRegistry    ?? ''

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
      .split('\n').map(s => s.trim()).filter(Boolean)
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

  // ── Deploy contracts panel ─────────────────────────────────────────────────

  // Canonical shared deployments — one per chain, all nodes on the same chain share these.
  // Add an entry here after deploying to a new chain so future operators can skip deployment.
  const KNOWN_DEPLOYMENTS = {
    // example (fill in after first Sepolia deploy):
    // 11155111: { name: 'Sepolia', attestationIndex: '0x...', nodeRegistry: '0x...' },
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

      document.getElementById('deploy-results').style.display = 'block'
      status.textContent = '✓ Both contracts deployed'
      toast('Contracts deployed — saving addresses to config')

      // Auto-save addresses + chainId to config and restart
      const cfgRes = await fetch('/admin/api/config', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ attestationIndex: attestAddr, nodeRegistry: registryAddr, chainId }),
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
