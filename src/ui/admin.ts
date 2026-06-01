import { Hono } from 'hono'
import { privateKeyToAccount } from 'viem/accounts'
import { getConfig } from '../config.js'
import { getDB } from '../db/index.js'
import { syncAll } from '../mesh/sync.js'
import { requireAdmin, setAdminSession, clearAdminSession } from './auth.js'

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
  const [peers, count, recent] = await Promise.all([
    db.getPeers(),
    db.recordCount(config.syncNamespace),
    db.getRecentRecords(config.syncNamespace, 8),
  ])
  const signerAddress = config.gatewayKey ? privateKeyToAccount(config.gatewayKey).address : null
  return c.json({
    version: '0.1.0', signerAddress,
    namespace: config.syncNamespace, syncInterval: config.syncInterval,
    protected: !!config.adminSecret,
    records: count,
    peers: peers.map((p) => ({
      url: p.url, healthy: p.healthy,
      signerAddress: p.signerAddress, nodeVersion: p.nodeVersion, lastSyncAt: p.lastSyncAt,
    })),
    recent: recent.map((r) => ({ inputHash: r.inputHash, timestamp: r.timestamp, sourcePeer: r.sourcePeer })),
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
    }
    .pill .dot { width: 6px; height: 6px; border-radius: 50%; background: var(--green); box-shadow: 0 0 6px var(--green); flex-shrink: 0; }
    .pill .addr { font-family: var(--mono); color: var(--text); }
    .pill.ns { background: var(--accent-l); border-color: var(--accent-b); color: var(--indigo); }

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
      display: none; align-items: center; gap: 8px;
    }
    .warn-banner a { color: var(--amber); }

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
  </style>
</head>
<body>

<header>
  <div class="logo">
    <div class="logo-icon"><img src="/favicon.svg" alt=""/></div>
    <div class="logo-name">ccip-router</div>
  </div>
  <div class="header-right">
    <div class="pill"><div class="dot"></div><span class="addr" id="h-addr">—</span></div>
    <div class="pill ns" id="h-ns">—</div>
    <button class="btn btn-primary btn-sm" id="btn-sync" onclick="syncNow()">⟳ Sync</button>
    <button class="btn btn-ghost btn-sm" id="btn-logout" style="display:none" onclick="logout()">Sign out</button>
  </div>
</header>

<div class="warn-banner" id="warn-banner">
  ⚠ Admin is open — anyone who can reach this port has full access.
  Set <code>ADMIN_SECRET</code> in your environment or <a href="/setup">reconfigure</a>.
</div>

<main>

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

  <div class="node-bar" id="node-bar" style="display:none">
    <div class="ninfo-item"><div class="lbl">Signer</div><div class="val" id="ni-addr">—</div></div>
    <div class="ninfo-item"><div class="lbl">Interval</div><div class="val" id="ni-interval">—</div></div>
    <div class="ninfo-item"><div class="lbl">Version</div><div class="val" id="ni-version">—</div></div>
    <div style="margin-left:auto; display:flex; gap:8px">
      <a href="/setup" class="btn btn-ghost btn-sm">⚙ Reconfigure</a>
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

  async function load() {
    const res = await fetch('/admin/api/status')
    if (res.status === 401) { window.location.href = '/admin/login'; return }
    const d = await res.json()

    document.getElementById('h-addr').textContent = d.signerAddress ? trunc(d.signerAddress, 20) : 'dry-run'
    document.getElementById('h-ns').textContent   = d.namespace

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
    document.getElementById('ni-interval').textContent = d.syncInterval
    document.getElementById('ni-version').textContent  = d.version
    document.getElementById('node-bar').style.display  = 'flex'

    // Show warning banner if admin is open
    document.getElementById('warn-banner').style.display = d.protected ? 'none' : 'flex'
    // Show logout only if protected
    document.getElementById('btn-logout').style.display  = d.protected ? 'inline-flex' : 'none'
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
    else { const d = await res.json(); alert(d.error || 'Failed') }
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

  load()
  setInterval(load, 15000)
  document.getElementById('peer-input')?.addEventListener('keydown', e => { if (e.key === 'Enter') addPeer() })
</script>
</body>
</html>`
