import { Hono } from 'hono'
import { privateKeyToAccount } from 'viem/accounts'
import { getConfig } from '../config.js'
import { getDB } from '../db/index.js'
import { syncAll } from '../mesh/sync.js'

export const adminRouter = new Hono()

// ── API ─────────────────────────────────────────────────────────────────────

adminRouter.get('/api/status', async (c) => {
  const config = getConfig()
  const db     = getDB()

  const [peers, count, recent] = await Promise.all([
    db.getPeers(),
    db.recordCount(config.syncNamespace),
    db.getRecentRecords(config.syncNamespace, 8),
  ])

  const signerAddress = config.gatewayKey
    ? privateKeyToAccount(config.gatewayKey).address
    : null

  return c.json({
    version:       '0.1.0',
    signerAddress,
    namespace:     config.syncNamespace,
    syncInterval:  config.syncInterval,
    port:          config.port,
    records:       count,
    peers:         peers.map((p) => ({
      url:           p.url,
      healthy:       p.healthy,
      signerAddress: p.signerAddress,
      nodeVersion:   p.nodeVersion,
      lastSyncAt:    p.lastSyncAt,
    })),
    recent: recent.map((r) => ({
      inputHash:  r.inputHash,
      timestamp:  r.timestamp,
      sourcePeer: r.sourcePeer,
    })),
  })
})

adminRouter.post('/api/sync', async (c) => {
  const config = getConfig()
  const db     = getDB()
  const synced = await syncAll(config, db)
  return c.json({ ok: true, synced })
})

adminRouter.post('/api/peers', async (c) => {
  const { url } = await c.req.json<{ url: string }>()
  if (!url) return c.json({ error: 'url required' }, 400)

  let parsed: URL
  try { parsed = new URL(url) } catch {
    return c.json({ error: 'Invalid URL' }, 400)
  }

  const db = getDB()
  await db.upsertPeer({
    url:           parsed.toString().replace(/\/$/, ''),
    lastSyncAt:    0,
    healthy:       true,
    nodeVersion:   null,
    signerAddress: null,
  })

  return c.json({ ok: true })
})

adminRouter.delete('/api/peers', async (c) => {
  const { url } = await c.req.json<{ url: string }>()
  if (!url) return c.json({ error: 'url required' }, 400)
  await getDB().removePeer(url)
  return c.json({ ok: true })
})

// ── Dashboard HTML ───────────────────────────────────────────────────────────

adminRouter.get('/', (c) => c.html(ADMIN_HTML))

const ADMIN_HTML = /* html */`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>ccip-router — admin</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    :root {
      --bg:      #0d0d0d;
      --surface: #161616;
      --surface2:#1e1e1e;
      --border:  #2a2a2a;
      --muted:   #555;
      --text:    #e8e8e8;
      --subtle:  #888;
      --accent:  #7c6af7;
      --green:   #4ade80;
      --red:     #f87171;
      --yellow:  #fbbf24;
      --mono:    'JetBrains Mono', 'Fira Code', monospace;
    }

    body {
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      font-size: 14px;
      line-height: 1.5;
      min-height: 100vh;
    }

    /* ── Header ── */
    header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 14px 24px;
      border-bottom: 1px solid var(--border);
      background: var(--surface);
      position: sticky; top: 0; z-index: 10;
    }

    .logo { display: flex; align-items: center; gap: 10px; }
    .logo-mark {
      width: 28px; height: 28px;
      background: var(--accent); border-radius: 6px;
      display: flex; align-items: center; justify-content: center;
      font-size: 14px;
    }
    .logo-name { font-size: 14px; font-weight: 600; }

    .header-meta {
      display: flex; align-items: center; gap: 16px;
    }

    .badge {
      display: inline-flex; align-items: center; gap: 5px;
      background: var(--surface2); border: 1px solid var(--border);
      border-radius: 6px; padding: 4px 10px;
      font-size: 12px; color: var(--subtle);
    }
    .badge .dot {
      width: 6px; height: 6px; border-radius: 50%;
      background: var(--green);
    }
    .badge .addr { font-family: var(--mono); color: var(--text); }

    .ns-badge {
      background: #1a1730; border: 1px solid #2d2550;
      border-radius: 6px; padding: 4px 10px;
      font-size: 12px; color: var(--accent);
    }

    /* ── Buttons ── */
    .btn {
      display: inline-flex; align-items: center; gap: 6px;
      border: none; border-radius: 7px;
      font-size: 12px; font-weight: 500;
      padding: 7px 14px; cursor: pointer;
      transition: all 0.15s;
    }
    .btn-ghost {
      background: transparent; border: 1px solid var(--border); color: var(--subtle);
    }
    .btn-ghost:hover { border-color: var(--text); color: var(--text); }
    .btn-primary { background: var(--accent); color: #fff; }
    .btn-primary:hover { background: #9585ff; }
    .btn-primary:disabled { opacity: 0.4; cursor: not-allowed; }
    .btn-danger { background: transparent; border: 1px solid #3a1a1a; color: var(--red); }
    .btn-danger:hover { background: #1a0808; }
    .btn-sm { padding: 5px 10px; font-size: 11px; }

    /* ── Layout ── */
    main { max-width: 1100px; margin: 0 auto; padding: 28px 24px; }

    /* ── Stats row ── */
    .stats {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 14px;
      margin-bottom: 28px;
    }

    .stat-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 18px 20px;
    }
    .stat-label { font-size: 11px; color: var(--subtle); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 6px; }
    .stat-value { font-size: 28px; font-weight: 600; font-family: var(--mono); }
    .stat-sub   { font-size: 11px; color: var(--muted); margin-top: 4px; }

    /* ── Panels ── */
    .panels {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 18px;
    }

    @media (max-width: 720px) {
      .panels { grid-template-columns: 1fr; }
      .stats  { grid-template-columns: 1fr; }
    }

    .panel {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      overflow: hidden;
    }

    .panel-header {
      display: flex; align-items: center; justify-content: space-between;
      padding: 14px 18px;
      border-bottom: 1px solid var(--border);
    }
    .panel-title { font-size: 13px; font-weight: 600; }
    .panel-body  { padding: 0; }

    /* ── Peers table ── */
    .peer-row {
      display: flex; align-items: center; gap: 12px;
      padding: 12px 18px;
      border-bottom: 1px solid var(--border);
    }
    .peer-row:last-child { border-bottom: none; }

    .peer-dot {
      width: 8px; height: 8px; border-radius: 50%;
      flex-shrink: 0;
    }
    .peer-dot.healthy   { background: var(--green); box-shadow: 0 0 6px var(--green); }
    .peer-dot.unhealthy { background: var(--red); }

    .peer-info { flex: 1; min-width: 0; }
    .peer-url  { font-family: var(--mono); font-size: 12px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .peer-meta { font-size: 11px; color: var(--subtle); margin-top: 2px; font-family: var(--mono); }

    .peer-actions { display: flex; gap: 6px; flex-shrink: 0; }

    .empty-state {
      padding: 28px 18px;
      text-align: center;
      color: var(--muted);
      font-size: 13px;
    }

    /* ── Add peer form ── */
    .add-peer-form {
      display: flex; gap: 8px;
      padding: 12px 18px;
      border-top: 1px solid var(--border);
    }
    .add-peer-form input {
      flex: 1;
      background: var(--bg); border: 1px solid var(--border);
      border-radius: 7px; color: var(--text);
      font-size: 12px; font-family: var(--mono);
      padding: 7px 10px; outline: none;
      transition: border-color 0.15s;
    }
    .add-peer-form input:focus { border-color: var(--accent); }

    /* ── Records list ── */
    .record-row {
      display: flex; align-items: center; gap: 10px;
      padding: 10px 18px;
      border-bottom: 1px solid var(--border);
      font-size: 12px;
    }
    .record-row:last-child { border-bottom: none; }

    .record-hash { font-family: var(--mono); color: var(--accent); flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .record-time { color: var(--muted); flex-shrink: 0; font-size: 11px; }
    .record-source { color: var(--subtle); font-size: 11px; flex-shrink: 0; }

    /* ── Sync feedback ── */
    .sync-toast {
      position: fixed; bottom: 24px; right: 24px;
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 8px; padding: 10px 16px;
      font-size: 13px; color: var(--green);
      opacity: 0; transform: translateY(8px);
      transition: all 0.2s;
      pointer-events: none;
    }
    .sync-toast.show { opacity: 1; transform: translateY(0); }

    /* ── Node info footer ── */
    .node-info {
      margin-top: 20px;
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 10px; padding: 16px 20px;
      display: flex; gap: 28px; flex-wrap: wrap;
    }
    .info-item { }
    .info-label { font-size: 11px; color: var(--subtle); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 3px; }
    .info-value { font-family: var(--mono); font-size: 12px; }
  </style>
</head>
<body>

<header>
  <div class="logo">
    <div class="logo-mark">⬡</div>
    <div class="logo-name">ccip-router</div>
  </div>
  <div class="header-meta">
    <div class="badge">
      <div class="dot"></div>
      <span class="addr" id="h-addr">loading...</span>
    </div>
    <div class="ns-badge" id="h-ns">—</div>
    <button class="btn btn-primary btn-sm" id="btn-sync" onclick="syncNow()">⟳ Sync now</button>
  </div>
</header>

<main>

  <!-- Stats -->
  <div class="stats">
    <div class="stat-card">
      <div class="stat-label">Records</div>
      <div class="stat-value" id="s-records">—</div>
      <div class="stat-sub" id="s-namespace">—</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Peers</div>
      <div class="stat-value" id="s-peers">—</div>
      <div class="stat-sub" id="s-healthy">—</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Last sync</div>
      <div class="stat-value" style="font-size:20px;padding-top:4px" id="s-lastsync">—</div>
      <div class="stat-sub" id="s-interval">—</div>
    </div>
  </div>

  <!-- Panels -->
  <div class="panels">

    <!-- Peers panel -->
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">Peers</div>
      </div>
      <div class="panel-body" id="peers-list">
        <div class="empty-state">Loading...</div>
      </div>
      <div class="add-peer-form">
        <input type="text" id="peer-input" placeholder="https://gateway-b.example.com" />
        <button class="btn btn-ghost btn-sm" onclick="addPeer()">+ Add</button>
      </div>
    </div>

    <!-- Records panel -->
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">Recent records</div>
      </div>
      <div class="panel-body" id="records-list">
        <div class="empty-state">Loading...</div>
      </div>
    </div>

  </div>

  <!-- Node info -->
  <div class="node-info" id="node-info" style="display:none">
    <div class="info-item">
      <div class="info-label">Signer address</div>
      <div class="info-value" id="ni-addr">—</div>
    </div>
    <div class="info-item">
      <div class="info-label">Sync interval</div>
      <div class="info-value" id="ni-interval">—</div>
    </div>
    <div class="info-item">
      <div class="info-label">DB path</div>
      <div class="info-value" id="ni-db">—</div>
    </div>
    <div class="info-item">
      <div class="info-label">Version</div>
      <div class="info-value" id="ni-version">—</div>
    </div>
  </div>

</main>

<div class="sync-toast" id="toast"></div>

<script>
  let status = null

  function rel(ts) {
    if (!ts) return 'never'
    const s = Math.floor(Date.now() / 1000) - ts
    if (s < 60)   return s + 's ago'
    if (s < 3600) return Math.floor(s / 60) + 'm ago'
    return Math.floor(s / 3600) + 'h ago'
  }

  function truncate(str, n) {
    if (!str) return '—'
    return str.length > n ? str.slice(0, n) + '...' : str
  }

  function renderPeers(peers) {
    const el = document.getElementById('peers-list')
    if (!peers.length) {
      el.innerHTML = '<div class="empty-state">No peers configured.<br>Add one below to join the mesh.</div>'
      return
    }
    el.innerHTML = peers.map(p => \`
      <div class="peer-row">
        <div class="peer-dot \${p.healthy ? 'healthy' : 'unhealthy'}"></div>
        <div class="peer-info">
          <div class="peer-url">\${p.url}</div>
          <div class="peer-meta">
            \${p.signerAddress ? truncate(p.signerAddress, 20) : 'signer unknown'} &nbsp;·&nbsp;
            \${rel(p.lastSyncAt)}
            \${p.nodeVersion ? ' &nbsp;·&nbsp; v' + p.nodeVersion : ''}
          </div>
        </div>
        <div class="peer-actions">
          <button class="btn btn-ghost btn-sm" onclick="syncPeer('\${p.url}')">⟳</button>
          <button class="btn btn-danger btn-sm" onclick="removePeer('\${p.url}')">✕</button>
        </div>
      </div>
    \`).join('')
  }

  function renderRecords(records) {
    const el = document.getElementById('records-list')
    if (!records.length) {
      el.innerHTML = '<div class="empty-state">No records yet.<br>Call the CCIP handler to write one.</div>'
      return
    }
    el.innerHTML = records.map(r => \`
      <div class="record-row">
        <div class="record-hash">\${r.inputHash}</div>
        <div class="record-source">\${r.sourcePeer ? '↓ peer' : '● local'}</div>
        <div class="record-time">\${rel(r.timestamp)}</div>
      </div>
    \`).join('')
  }

  async function load() {
    const res = await fetch('/admin/api/status')
    status = await res.json()

    // header
    document.getElementById('h-addr').textContent = status.signerAddress
      ? status.signerAddress.slice(0, 6) + '...' + status.signerAddress.slice(-4)
      : 'dry-run'
    document.getElementById('h-ns').textContent = status.namespace

    // stats
    document.getElementById('s-records').textContent  = status.records
    document.getElementById('s-namespace').textContent = status.namespace
    document.getElementById('s-peers').textContent    = status.peers.length
    const healthy = status.peers.filter(p => p.healthy).length
    document.getElementById('s-healthy').textContent  = healthy + ' healthy'

    const lastSyncs = status.peers.map(p => p.lastSyncAt).filter(Boolean)
    const lastSync  = lastSyncs.length ? Math.max(...lastSyncs) : 0
    document.getElementById('s-lastsync').textContent = rel(lastSync)
    document.getElementById('s-interval').textContent  = status.syncInterval

    // panels
    renderPeers(status.peers)
    renderRecords(status.recent)

    // node info
    document.getElementById('ni-addr').textContent     = status.signerAddress || 'dry-run'
    document.getElementById('ni-interval').textContent = status.syncInterval
    document.getElementById('ni-version').textContent  = status.version
    document.getElementById('node-info').style.display = 'flex'
  }

  async function syncNow() {
    const btn = document.getElementById('btn-sync')
    btn.disabled = true
    btn.textContent = '⟳ Syncing...'
    await fetch('/admin/api/sync', { method: 'POST' })
    await load()
    btn.disabled = false
    btn.textContent = '⟳ Sync now'
    toast('Sync complete')
  }

  async function syncPeer(url) {
    await fetch('/admin/api/sync', { method: 'POST' })
    await load()
    toast('Synced ' + url)
  }

  async function addPeer() {
    const input = document.getElementById('peer-input')
    const url   = input.value.trim()
    if (!url) return
    const res = await fetch('/admin/api/peers', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    })
    if (res.ok) {
      input.value = ''
      await load()
      toast('Peer added')
    } else {
      const data = await res.json()
      alert(data.error || 'Failed to add peer')
    }
  }

  async function removePeer(url) {
    if (!confirm('Remove peer ' + url + '?')) return
    await fetch('/admin/api/peers', {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    })
    await load()
    toast('Peer removed')
  }

  function toast(msg) {
    const el = document.getElementById('toast')
    el.textContent = msg
    el.classList.add('show')
    setTimeout(() => el.classList.remove('show'), 2500)
  }

  // initial load + auto-refresh every 15s
  load()
  setInterval(load, 15000)

  // add peer on Enter
  document.getElementById('peer-input')?.addEventListener('keydown', e => {
    if (e.key === 'Enter') addPeer()
  })
</script>
</body>
</html>`
