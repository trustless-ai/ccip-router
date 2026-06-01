import { Hono } from 'hono'
import { writeFileSync, existsSync, readFileSync } from 'node:fs'
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'
import { CONFIG_FILE_PATH, type ConfigFile } from '../config.js'

export const setupRouter = new Hono()

// Returns safe current config snapshot for the reconfigure flow — no private key exposed
setupRouter.get('/current-config', (c) => {
  if (!existsSync(CONFIG_FILE_PATH)) return c.json({ configured: false })
  try {
    const f = JSON.parse(readFileSync(CONFIG_FILE_PATH, 'utf8')) as ConfigFile
    return c.json({
      configured:     !!f.gatewayKey,
      namespace:      f.namespace      ?? 'agent-attestations',
      port:           f.port           ?? 3000,
      syncInterval:   f.syncInterval   ?? '*/5 * * * *',
      dbPath:         f.dbPath         ?? './data.db',
      hasAdminSecret: !!f.adminSecret,
      peers:          f.peers          ?? [],
    })
  } catch {
    return c.json({ configured: false })
  }
})

setupRouter.get('/generate-key', (c) => {
  const privateKey = generatePrivateKey()
  const address = privateKeyToAccount(privateKey).address
  return c.json({ privateKey, address })
})

setupRouter.post('/', async (c) => {
  const body = await c.req.json<{
    gatewayKey?:     string
    keepGatewayKey?: boolean
    adminSecret?:    string
    namespace:       string
    syncInterval:    string
    dbPath:          string
    port:            number
    peers:           string[]
  }>()

  // Resolve gateway key — either new key or keep existing from config file
  let gatewayKey: string | undefined
  if (body.keepGatewayKey) {
    if (!existsSync(CONFIG_FILE_PATH)) return c.json({ error: 'No existing config to keep key from' }, 400)
    const existing = JSON.parse(readFileSync(CONFIG_FILE_PATH, 'utf8')) as ConfigFile
    gatewayKey = existing.gatewayKey
  } else {
    gatewayKey = body.gatewayKey
  }

  if (!gatewayKey?.startsWith('0x') || gatewayKey.length !== 66) {
    return c.json({ error: 'Invalid gateway key — must be 32-byte hex (0x...)' }, 400)
  }

  // If admin secret is blank and we're reconfiguring, keep the existing one
  let adminSecret: string | undefined = body.adminSecret?.trim() || undefined
  if (!adminSecret && body.keepGatewayKey && existsSync(CONFIG_FILE_PATH)) {
    const existing = JSON.parse(readFileSync(CONFIG_FILE_PATH, 'utf8')) as ConfigFile
    adminSecret = existing.adminSecret
  }

  const config: ConfigFile = {
    gatewayKey,
    adminSecret,
    namespace:    body.namespace    || 'agent-attestations',
    syncInterval: body.syncInterval || '*/5 * * * *',
    dbPath:       body.dbPath       || './data.db',
    port:         Number(body.port) || 3000,
    peers:        (body.peers ?? []).filter(Boolean),
  }

  try {
    writeFileSync(CONFIG_FILE_PATH, JSON.stringify(config, null, 2), 'utf8')
  } catch (err) {
    return c.json({ error: `Could not write config: ${String(err)}` }, 500)
  }

  setTimeout(() => process.exit(0), 500)
  return c.json({ ok: true })
})

setupRouter.get('/', (c) => c.html(SETUP_HTML))

const SETUP_HTML = /* html */`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>ccip-router — setup</title>
  <link rel="icon" href="/favicon.svg"/>
  <link rel="preconnect" href="https://fonts.googleapis.com"/>
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
  <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600&display=swap" rel="stylesheet"/>
  <style>
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
      --accent-l: rgba(99,102,241,0.2);
      --accent-b: rgba(99,102,241,0.3);
      --indigo:   #818cf8;
      --green:    #22c55e;
      --green-l:  rgba(34,197,94,0.15);
      --green-b:  rgba(34,197,94,0.3);
      --red:      #ef4444;
      --amber:    #f59e0b;
      --amber-l:  rgba(245,158,11,0.12);
      --amber-b:  rgba(245,158,11,0.3);
      --mono:     ui-monospace, 'SFMono-Regular', Menlo, monospace;
    }

    body {
      background: var(--bg);
      color: var(--text);
      font-family: 'Poppins', sans-serif;
      font-size: 14px; font-weight: 400; line-height: 1.6;
      min-height: 100vh;
      display: flex; align-items: center; justify-content: center;
      padding: 24px;
    }

    .shell { width: 100%; max-width: 520px; }

    .logo { display: flex; align-items: center; gap: 12px; margin-bottom: 36px; }
    .logo-icon {
      width: 36px; height: 36px;
      background: var(--accent-l); border: 1px solid var(--accent-b);
      border-radius: 10px;
      display: flex; align-items: center; justify-content: center;
    }
    .logo-icon img { width: 20px; height: 20px; }
    .logo-name { font-size: 15px; font-weight: 600; }
    .logo-tag  { font-size: 11px; color: var(--subtle); font-weight: 300; }

    /* progress */
    .progress { display: flex; align-items: center; margin-bottom: 28px; }
    .step-dot {
      width: 26px; height: 26px; border-radius: 50%;
      border: 1px solid var(--border); background: var(--s1);
      color: var(--muted); font-size: 11px; font-weight: 600;
      display: flex; align-items: center; justify-content: center;
      transition: all 0.2s; z-index: 1; flex-shrink: 0;
    }
    .step-dot.active { border-color: var(--accent); color: var(--accent); background: var(--accent-l); }
    .step-dot.done   { border-color: var(--green);  background: var(--green-l); color: var(--green); }
    .step-line { flex: 1; height: 1px; background: var(--border); margin: 0 6px; }

    /* card */
    .card {
      background: var(--s1); border: 1px solid var(--border);
      border-radius: 16px; padding: 28px; backdrop-filter: blur(8px);
    }
    .card-title { font-size: 15px; font-weight: 600; margin-bottom: 4px; }
    .card-sub   { font-size: 13px; color: var(--subtle); margin-bottom: 24px; font-weight: 300; }

    /* fields */
    .field { margin-bottom: 18px; }
    .field label {
      display: block; font-size: 11px; font-weight: 500;
      color: var(--subtle); margin-bottom: 7px;
      text-transform: uppercase; letter-spacing: 0.6px;
    }

    input, textarea {
      width: 100%; background: rgba(255,255,255,0.03);
      border: 1px solid var(--border); border-radius: 10px;
      color: var(--text); font-size: 13px; font-family: inherit;
      padding: 10px 14px; outline: none;
      transition: border-color 0.15s, background 0.15s;
    }
    input:focus, textarea:focus {
      border-color: rgba(99,102,241,0.5);
      background: rgba(99,102,241,0.04);
    }
    textarea { resize: vertical; min-height: 80px; font-family: var(--mono); font-size: 12px; }
    .mono { font-family: var(--mono); font-size: 12px; }

    .row-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
    .hint { font-size: 11px; color: var(--muted); margin-top: 6px; font-weight: 300; }
    .warn { font-size: 11px; color: var(--amber); margin-top: 8px; }

    /* buttons */
    .btn-row { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 14px; }
    .btn {
      display: inline-flex; align-items: center; gap: 6px;
      border: none; border-radius: 10px;
      font-size: 13px; font-weight: 500; font-family: inherit;
      padding: 9px 18px; cursor: pointer; transition: all 0.15s;
    }
    .btn-ghost { background: var(--s1); border: 1px solid var(--border); color: var(--subtle); }
    .btn-ghost:hover { border-color: var(--border-h); color: var(--text); background: var(--s2); }
    .btn-primary { background: var(--accent); color: #fff; box-shadow: 0 0 20px rgba(99,102,241,0.25); }
    .btn-primary:hover { background: var(--accent-v); box-shadow: 0 0 28px rgba(139,92,246,0.35); }
    .btn-primary:disabled { opacity: 0.35; cursor: not-allowed; box-shadow: none; }
    .btn-danger { background: var(--amber-l); border: 1px solid var(--amber-b); color: var(--amber); }
    .btn-danger:hover { background: rgba(245,158,11,0.2); }
    .btn-sm { padding: 6px 12px; font-size: 12px; }

    .actions { display: flex; justify-content: space-between; align-items: center; margin-top: 24px; }

    /* key reveal */
    .key-reveal {
      background: var(--green-l); border: 1px solid var(--green-b);
      border-radius: 10px; padding: 14px; margin-top: 14px; display: none;
    }
    .key-reveal.show { display: block; }
    .key-reveal .lbl { font-size: 11px; color: rgba(34,197,94,0.7); margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.5px; }
    .key-reveal .copy-row { display: flex; justify-content: space-between; align-items: flex-start; gap: 8px; }
    .key-reveal .val { font-family: var(--mono); font-size: 11px; color: var(--green); word-break: break-all; }

    .addr-pill {
      display: inline-flex; align-items: center; gap: 6px;
      background: var(--accent-l); border: 1px solid var(--accent-b);
      border-radius: 8px; padding: 5px 10px;
      font-family: var(--mono); font-size: 11px; color: var(--indigo);
      margin-top: 10px;
    }

    /* admin step */
    .secret-box {
      background: var(--amber-l); border: 1px solid var(--amber-b);
      border-radius: 10px; padding: 14px; margin-bottom: 18px;
      font-size: 12px; color: var(--amber); line-height: 1.55;
    }
    .secret-box strong { display: block; font-size: 13px; margin-bottom: 4px; }
    .open-access-confirm {
      display: none;
      background: var(--amber-l); border: 1px solid var(--amber-b);
      border-radius: 10px; padding: 14px; margin-top: 14px;
    }
    .open-access-confirm.show { display: block; }
    .open-access-confirm p { font-size: 12px; color: var(--amber); margin-bottom: 10px; }

    /* summary */
    .summary-row {
      display: flex; justify-content: space-between;
      padding: 9px 0; border-bottom: 1px solid var(--border); font-size: 13px;
    }
    .summary-row:last-child { border-bottom: none; }
    .summary-row .k { color: var(--subtle); font-size: 12px; }
    .summary-row .v { font-family: var(--mono); font-size: 11px; color: var(--text); text-align: right; max-width: 280px; word-break: break-all; }
    .summary-row.warn .v { color: var(--amber); }

    /* checklist */
    .checklist { display: flex; flex-direction: column; gap: 10px; margin-top: 20px; }
    .check-item {
      display: flex; align-items: flex-start; gap: 12px;
      padding: 12px 14px; border-radius: 10px;
      border: 1px solid var(--border); background: var(--s2);
    }
    .check-item.ok   { border-color: var(--green-b); background: var(--green-l); }
    .check-item.warn { border-color: var(--amber-b); background: var(--amber-l); }
    .check-item.todo { opacity: 0.7; }
    .check-icon { font-size: 14px; flex-shrink: 0; margin-top: 1px; }
    .check-label { font-size: 13px; font-weight: 500; }
    .check-hint  { font-size: 11px; color: var(--muted); margin-top: 2px; font-weight: 300; }
    .check-item.ok   .check-label { color: var(--green); }
    .check-item.warn .check-label { color: var(--amber); }

    /* step panels */
    .step-panel { display: none; }
    .step-panel.active { display: block; }

    .tag {
      display: inline-block; font-size: 10px;
      background: var(--s2); border: 1px solid var(--border);
      border-radius: 4px; padding: 1px 6px; color: var(--muted);
      margin-left: 6px; vertical-align: middle;
    }

    .import-field { display: none; margin-top: 12px; }
  </style>
</head>
<body>
<div class="shell">

  <div class="logo">
    <div class="logo-icon"><img src="/favicon.svg" alt="ccip-router"/></div>
    <div>
      <div class="logo-name">ccip-router</div>
      <div class="logo-tag" id="logo-tag">node setup</div>
    </div>
  </div>

  <div class="progress">
    <div class="step-dot active" id="dot-1">1</div>
    <div class="step-line"></div>
    <div class="step-dot" id="dot-2">2</div>
    <div class="step-line"></div>
    <div class="step-dot" id="dot-3">3</div>
    <div class="step-line"></div>
    <div class="step-dot" id="dot-4">4</div>
  </div>

  <div class="card">

    <!-- Step 1: Signing key -->
    <div class="step-panel active" id="step-1">
      <div class="card-title" id="s1-title">Gateway key</div>
      <div class="card-sub" id="s1-sub">Signs every record this node produces. Use a dedicated hot key — not your main wallet.</div>

      <div class="field">
        <label>Key source</label>
        <div class="btn-row">
          <button class="btn btn-ghost" id="btn-keep-key" style="display:none" onclick="keepExistingKey()">⟲ Keep existing key</button>
          <button class="btn btn-ghost" onclick="generateKey()">⚡ Generate new key</button>
          <button class="btn btn-ghost" onclick="showImport()">↓ Import existing</button>
        </div>

        <div id="keep-key-indicator" style="display:none;margin-top:10px">
          <div class="addr-pill">⟲ Existing signing key will be kept</div>
        </div>

        <div class="key-reveal" id="key-reveal">
          <div class="lbl">Private key — save this now, it will not be shown again</div>
          <div class="copy-row">
            <div class="val" id="generated-key"></div>
            <button class="btn btn-ghost btn-sm" onclick="copyKey()">Copy</button>
          </div>
          <div id="generated-address" class="addr-pill"></div>
        </div>

        <div class="import-field" id="import-field">
          <input type="password" id="import-key" placeholder="0x..." class="mono" oninput="onImportKey(this.value)"/>
          <div id="import-address" class="addr-pill" style="display:none">Key accepted</div>
        </div>
      </div>

      <div class="warn" id="key-warn" style="display:none">
        ⚠ Save the private key before continuing — you will not see it again after setup.
      </div>

      <div class="actions">
        <div></div>
        <button class="btn btn-primary" id="btn-next-1" onclick="goStep(2)" disabled>Next →</button>
      </div>
    </div>

    <!-- Step 2: Admin access -->
    <div class="step-panel" id="step-2">
      <div class="card-title">Admin access</div>
      <div class="card-sub" id="s2-sub">Protect the /admin dashboard. Required for any non-local deployment.</div>

      <div class="secret-box">
        <strong>🔒 Secure your node</strong>
        Without an admin secret, anyone who can reach this port has full control over your node — peers, config, and signing operations.
      </div>

      <div class="field">
        <label>Admin secret</label>
        <input type="password" id="s-admin-secret" placeholder="Choose a strong secret…" oninput="onSecretInput()"/>
        <div class="hint" id="hint-admin-secret">Min 12 characters recommended. Store it somewhere safe — you'll need it to log in.</div>
      </div>

      <div id="open-access-confirm" class="open-access-confirm">
        <p>⚠ Running without an admin secret means the dashboard is publicly accessible. Only do this on localhost or a private network.</p>
        <button class="btn btn-danger btn-sm" onclick="confirmOpenAccess()">I understand — skip anyway</button>
      </div>

      <div class="actions">
        <button class="btn btn-ghost" onclick="goStep(1)">← Back</button>
        <button class="btn btn-primary" id="btn-next-2" onclick="tryNextFromAdmin()">Next →</button>
      </div>
    </div>

    <!-- Step 3: Node settings -->
    <div class="step-panel" id="step-3">
      <div class="card-title">Node settings</div>
      <div class="card-sub">Configure how this node runs. Defaults work for most setups.</div>

      <div class="field">
        <label>Namespace</label>
        <input type="text" id="s-namespace" value="agent-attestations"/>
        <div class="hint">Records are scoped by namespace. Peers must share the same namespace to sync.</div>
      </div>
      <div class="row-2">
        <div class="field">
          <label>Port</label>
          <input type="number" id="s-port" value="3000" min="1" max="65535"/>
        </div>
        <div class="field">
          <label>Sync interval</label>
          <input type="text" id="s-interval" value="*/5 * * * *" class="mono"/>
        </div>
      </div>
      <div class="field">
        <label>DB path</label>
        <input type="text" id="s-db" value="./data.db" class="mono"/>
        <div class="hint">SQLite file path relative to working directory.</div>
      </div>

      <div class="actions">
        <button class="btn btn-ghost" onclick="goStep(2)">← Back</button>
        <button class="btn btn-primary" onclick="goStep(4)">Next →</button>
      </div>
    </div>

    <!-- Step 4: Peers + Confirm -->
    <div class="step-panel" id="step-4">
      <div class="card-title">Peers <span class="tag">optional</span></div>
      <div class="card-sub">Add peer node URLs to join the mesh. You can add more from the admin panel.</div>

      <div class="field">
        <label>Peer URLs</label>
        <textarea id="s-peers" placeholder="https://gateway-b.example.com&#10;https://gateway-c.example.com"></textarea>
        <div class="hint">One URL per line. Leave blank to run as a standalone node.</div>
      </div>

      <div style="border-top:1px solid var(--border);margin:20px 0"></div>
      <div class="card-title" style="margin-bottom:14px;font-size:13px;color:var(--subtle)">Confirm</div>
      <div id="summary"></div>

      <div class="actions">
        <button class="btn btn-ghost" onclick="goStep(3)">← Back</button>
        <button class="btn btn-primary" id="btn-save" onclick="save()">Save &amp; restart →</button>
      </div>
    </div>

    <!-- Done: post-setup checklist -->
    <div class="step-panel" id="step-done">
      <div style="text-align:center;margin-bottom:20px">
        <div style="width:52px;height:52px;border-radius:50%;background:var(--green-l);border:1px solid var(--green-b);display:flex;align-items:center;justify-content:center;margin:0 auto 12px;font-size:22px">✓</div>
        <div style="font-size:17px;font-weight:600;margin-bottom:4px">Node configured</div>
        <div style="font-size:13px;color:var(--subtle);font-weight:300">Restarting — redirecting to admin panel in a moment.</div>
      </div>
      <div id="checklist" class="checklist"></div>
    </div>

  </div>
</div>

<script>
  let gatewayKey = '', gatewayAddr = '', currentStep = 1
  let reconfigure = false, keepKey = false
  let adminSecretSet = false, openAccessConfirmed = false

  async function init() {
    const res = await fetch('/setup/current-config')
    const d   = await res.json()
    if (!d.configured) return

    reconfigure = true
    document.getElementById('logo-tag').textContent = 'reconfigure'
    document.getElementById('s1-title').textContent = 'Gateway key'
    document.getElementById('s1-sub').textContent   = 'Keep your existing signing key or replace it with a new one.'
    document.getElementById('btn-keep-key').style.display = 'inline-flex'

    document.getElementById('s-namespace').value = d.namespace
    document.getElementById('s-port').value      = d.port
    document.getElementById('s-interval').value  = d.syncInterval
    document.getElementById('s-db').value        = d.dbPath

    if (d.hasAdminSecret) {
      adminSecretSet = true
      document.getElementById('s-admin-secret').placeholder = 'Leave blank to keep existing secret'
      document.getElementById('s2-sub').textContent =
        'Admin secret is set. Leave blank to keep it, or enter a new one to replace it.'
      document.getElementById('hint-admin-secret').textContent =
        'Leave blank to keep the existing admin secret.'
    }

    if (d.peers && d.peers.length) {
      document.getElementById('s-peers').value = d.peers.join('\\n')
    }
  }

  function onSecretInput() {
    const val = document.getElementById('s-admin-secret').value.trim()
    adminSecretSet = val.length > 0
    openAccessConfirmed = false
    document.getElementById('open-access-confirm').classList.remove('show')
  }

  function tryNextFromAdmin() {
    const val = document.getElementById('s-admin-secret').value.trim()
    if (!val && !reconfigure && !openAccessConfirmed) {
      document.getElementById('open-access-confirm').classList.add('show')
      return
    }
    goStep(3)
  }

  function confirmOpenAccess() {
    openAccessConfirmed = true
    document.getElementById('open-access-confirm').classList.remove('show')
    goStep(3)
  }

  function keepExistingKey() {
    keepKey = true; gatewayAddr = '(existing key)'
    document.getElementById('keep-key-indicator').style.display  = 'block'
    document.getElementById('key-reveal').classList.remove('show')
    document.getElementById('import-field').style.display        = 'none'
    document.getElementById('key-warn').style.display            = 'none'
    document.getElementById('btn-next-1').disabled               = false
  }

  function goStep(n) {
    const prevPanel = document.getElementById('step-' + currentStep)
    const prevDot   = document.getElementById('dot-' + currentStep)
    if (prevPanel) prevPanel.classList.remove('active')
    if (prevDot)   { prevDot.classList.remove('active'); prevDot.classList.add('done') }
    currentStep = n
    const panel = document.getElementById('step-' + n) || document.getElementById('step-done')
    if (panel) panel.classList.add('active')
    const dot = document.getElementById('dot-' + n)
    if (dot) { dot.classList.remove('done'); dot.classList.add('active') }
    if (n === 4) buildSummary()
  }

  async function generateKey() {
    keepKey = false
    const res = await fetch('/setup/generate-key')
    const d   = await res.json()
    gatewayKey = d.privateKey; gatewayAddr = d.address
    document.getElementById('generated-key').textContent        = d.privateKey
    document.getElementById('generated-address').textContent    = d.address
    document.getElementById('key-reveal').classList.add('show')
    document.getElementById('import-field').style.display       = 'none'
    document.getElementById('keep-key-indicator').style.display = 'none'
    document.getElementById('key-warn').style.display           = 'block'
    document.getElementById('btn-next-1').disabled              = false
  }

  function copyKey() { navigator.clipboard.writeText(gatewayKey) }

  function showImport() {
    keepKey = false
    document.getElementById('import-field').style.display       = 'block'
    document.getElementById('key-reveal').classList.remove('show')
    document.getElementById('keep-key-indicator').style.display = 'none'
    document.getElementById('key-warn').style.display           = 'none'
  }

  function onImportKey(val) {
    const hex = val.trim()
    const ok  = hex.startsWith('0x') && hex.length === 66
    if (ok) gatewayKey = hex
    document.getElementById('import-address').style.display = ok ? 'inline-flex' : 'none'
    document.getElementById('btn-next-1').disabled          = !ok
  }

  function buildSummary() {
    const peers  = document.getElementById('s-peers').value.split('\\n').map(s=>s.trim()).filter(Boolean)
    const secret = document.getElementById('s-admin-secret').value.trim()
    const secretLabel = secret ? '●●●●●● (set)' : (reconfigure ? '(keep existing)' : 'none — open access ⚠')
    const rows = [
      { k: 'Signer',        v: keepKey ? '(keep existing)' : (gatewayAddr || '—') },
      { k: 'Admin secret',  v: secretLabel, warn: !secret && !reconfigure },
      { k: 'Namespace',     v: document.getElementById('s-namespace').value },
      { k: 'Port',          v: document.getElementById('s-port').value },
      { k: 'Sync interval', v: document.getElementById('s-interval').value },
      { k: 'DB path',       v: document.getElementById('s-db').value },
      { k: 'Peers',         v: peers.length ? peers.join(', ') : 'none (standalone)' },
    ]
    document.getElementById('summary').innerHTML = rows.map(r =>
      \`<div class="summary-row \${r.warn ? 'warn' : ''}">
        <span class="k">\${r.k}</span><span class="v">\${r.v}</span>
      </div>\`
    ).join('')
  }

  function buildChecklist(secret) {
    const items = [
      { ok: true,  warn: false, icon: '✓', label: 'Signing key', hint: 'Gateway key configured — records will be EIP-191 signed.' },
      {
        ok:   !!secret,
        warn: !secret,
        icon: secret ? '✓' : '⚠',
        label: secret ? 'Admin access secured' : 'Admin dashboard is open',
        hint:  secret ? 'Dashboard protected by admin secret.' : 'Set ADMIN_SECRET in your env or reconfigure to lock it down.',
      },
      { ok: false, warn: false, icon: '○', label: 'WYRIWE attestation', hint: 'Wrap your resolver with withWyriwe() to enable EIP-712 attestations.' },
      { ok: false, warn: false, icon: '○', label: 'ERC-8004 identity',  hint: 'Set AGENT_ID + REGISTRY_ADDRESS to declare on-chain agent identity.' },
      { ok: false, warn: false, icon: '○', label: 'VNI node identity',  hint: 'Set NODE_URL to enable signed node identity and peer gossip.' },
    ]
    document.getElementById('checklist').innerHTML = items.map(i => \`
      <div class="check-item \${i.ok ? 'ok' : i.warn ? 'warn' : 'todo'}">
        <div class="check-icon">\${i.icon}</div>
        <div>
          <div class="check-label">\${i.label}</div>
          <div class="check-hint">\${i.hint}</div>
        </div>
      </div>
    \`).join('')
  }

  async function save() {
    const btn    = document.getElementById('btn-save')
    btn.disabled = true; btn.textContent = reconfigure ? 'Applying...' : 'Saving...'
    const peers  = document.getElementById('s-peers').value.split('\\n').map(s=>s.trim()).filter(Boolean)
    const secret = document.getElementById('s-admin-secret').value.trim()
    const payload = {
      keepGatewayKey: keepKey || undefined,
      gatewayKey:     keepKey ? undefined : gatewayKey,
      adminSecret:    secret  || undefined,
      namespace:      document.getElementById('s-namespace').value,
      syncInterval:   document.getElementById('s-interval').value,
      dbPath:         document.getElementById('s-db').value,
      port:           Number(document.getElementById('s-port').value),
      peers,
    }
    const res  = await fetch('/setup', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    })
    const data = await res.json()
    if (!res.ok) {
      btn.disabled = false
      btn.textContent = reconfigure ? 'Apply changes →' : 'Save & restart →'
      alert(data.error || 'Save failed')
      return
    }
    goStep('done')
    buildChecklist(secret)
    setTimeout(() => { window.location.href = '/admin' }, 5000)
  }

  init()
</script>
</body>
</html>`
