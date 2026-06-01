import { Hono } from 'hono'
import { writeFileSync } from 'node:fs'
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'
import { CONFIG_FILE_PATH, type ConfigFile } from '../config.js'

export const setupRouter = new Hono()

// GET /setup/generate-key — generates a fresh hot key server-side
setupRouter.get('/generate-key', (c) => {
  const privateKey = generatePrivateKey()
  const address = privateKeyToAccount(privateKey).address
  return c.json({ privateKey, address })
})

// POST /setup — write config.json then restart
setupRouter.post('/', async (c) => {
  const body = await c.req.json<{
    gatewayKey: string
    namespace: string
    syncInterval: string
    dbPath: string
    port: number
    peers: string[]
  }>()

  if (!body.gatewayKey?.startsWith('0x') || body.gatewayKey.length !== 66) {
    return c.json({ error: 'Invalid gateway key — must be 32-byte hex (0x...)' }, 400)
  }

  const config: ConfigFile = {
    gatewayKey:   body.gatewayKey,
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

  // restart after a short delay so the response can be sent
  setTimeout(() => process.exit(0), 500)

  return c.json({ ok: true, message: 'Config saved — restarting node...' })
})

// GET /setup — the wizard UI
setupRouter.get('/', (c) => {
  return c.html(SETUP_HTML)
})

const SETUP_HTML = /* html */ `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>ccip-router — setup</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    :root {
      --bg:       #0d0d0d;
      --surface:  #161616;
      --border:   #2a2a2a;
      --muted:    #555;
      --text:     #e8e8e8;
      --subtle:   #999;
      --accent:   #7c6af7;
      --accent-h: #9585ff;
      --green:    #4ade80;
      --red:      #f87171;
      --mono:     'JetBrains Mono', 'Fira Code', monospace;
    }

    body {
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      font-size: 14px;
      line-height: 1.6;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
    }

    .shell {
      width: 100%;
      max-width: 560px;
    }

    .logo {
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 32px;
    }

    .logo-mark {
      width: 32px; height: 32px;
      background: var(--accent);
      border-radius: 8px;
      display: flex; align-items: center; justify-content: center;
      font-size: 16px;
    }

    .logo-text { font-size: 16px; font-weight: 600; letter-spacing: -0.3px; }
    .logo-sub  { font-size: 12px; color: var(--subtle); }

    /* progress */
    .progress {
      display: flex;
      align-items: center;
      gap: 0;
      margin-bottom: 28px;
    }

    .step-dot {
      width: 28px; height: 28px;
      border-radius: 50%;
      border: 1.5px solid var(--border);
      background: var(--surface);
      color: var(--muted);
      font-size: 11px; font-weight: 600;
      display: flex; align-items: center; justify-content: center;
      transition: all 0.2s;
      position: relative;
      z-index: 1;
    }

    .step-dot.active  { border-color: var(--accent); color: var(--accent); background: #1a1730; }
    .step-dot.done    { border-color: var(--green);  background: #0f2318; color: var(--green); }

    .step-line {
      flex: 1;
      height: 1px;
      background: var(--border);
      margin: 0 4px;
    }

    /* card */
    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 28px;
    }

    .card-title { font-size: 16px; font-weight: 600; margin-bottom: 4px; }
    .card-sub   { font-size: 13px; color: var(--subtle); margin-bottom: 24px; }

    .field { margin-bottom: 18px; }
    .field label { display: block; font-size: 12px; font-weight: 500; color: var(--subtle); margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.5px; }

    input, textarea, select {
      width: 100%;
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      color: var(--text);
      font-size: 13px;
      padding: 10px 12px;
      outline: none;
      transition: border-color 0.15s;
      font-family: inherit;
    }

    input:focus, textarea:focus { border-color: var(--accent); }
    textarea { resize: vertical; min-height: 80px; font-family: var(--mono); font-size: 12px; }

    .mono { font-family: var(--mono); font-size: 12px; }

    .key-box {
      display: flex;
      gap: 8px;
      align-items: stretch;
    }

    .key-box input { flex: 1; font-family: var(--mono); font-size: 11px; }

    .hint { font-size: 11px; color: var(--muted); margin-top: 6px; }
    .warn { font-size: 11px; color: #f59e0b; margin-top: 6px; }

    .row-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }

    /* buttons */
    .btn {
      display: inline-flex; align-items: center; justify-content: center; gap: 6px;
      border: none; border-radius: 8px;
      font-size: 13px; font-weight: 500;
      padding: 9px 16px;
      cursor: pointer;
      transition: all 0.15s;
    }

    .btn-ghost {
      background: transparent;
      border: 1px solid var(--border);
      color: var(--subtle);
    }
    .btn-ghost:hover { border-color: var(--text); color: var(--text); }

    .btn-primary {
      background: var(--accent);
      color: #fff;
    }
    .btn-primary:hover { background: var(--accent-h); }
    .btn-primary:disabled { opacity: 0.4; cursor: not-allowed; }

    .btn-sm { padding: 6px 12px; font-size: 12px; white-space: nowrap; }

    .actions { display: flex; justify-content: space-between; align-items: center; margin-top: 24px; }
    .actions-right { display: flex; gap: 8px; }

    /* generated key reveal */
    .key-reveal {
      background: #0f2318;
      border: 1px solid #1a3a28;
      border-radius: 8px;
      padding: 14px;
      margin-top: 14px;
      display: none;
    }
    .key-reveal.show { display: block; }
    .key-reveal .label { font-size: 11px; color: var(--subtle); margin-bottom: 4px; text-transform: uppercase; letter-spacing: 0.5px; }
    .key-reveal .value { font-family: var(--mono); font-size: 11px; color: var(--green); word-break: break-all; }
    .key-reveal .copy-row { display: flex; justify-content: space-between; align-items: flex-start; gap: 8px; }

    /* address pill */
    .address-pill {
      display: inline-flex; align-items: center; gap: 6px;
      background: #1a1730; border: 1px solid #2d2550;
      border-radius: 6px; padding: 6px 10px;
      font-family: var(--mono); font-size: 11px; color: var(--accent);
      margin-top: 8px;
    }

    /* summary */
    .summary-row {
      display: flex; justify-content: space-between;
      padding: 8px 0;
      border-bottom: 1px solid var(--border);
      font-size: 13px;
    }
    .summary-row:last-child { border-bottom: none; }
    .summary-row .key  { color: var(--subtle); }
    .summary-row .val  { font-family: var(--mono); font-size: 11px; color: var(--text); text-align: right; max-width: 300px; word-break: break-all; }

    /* success */
    .success-state { text-align: center; padding: 20px 0; }
    .success-icon  { font-size: 40px; margin-bottom: 12px; }
    .success-title { font-size: 18px; font-weight: 600; margin-bottom: 8px; }
    .success-sub   { font-size: 13px; color: var(--subtle); }

    /* step panels */
    .step-panel { display: none; }
    .step-panel.active { display: block; }

    /* tag for optional */
    .tag { display: inline-block; font-size: 10px; background: #222; border: 1px solid var(--border); border-radius: 4px; padding: 1px 6px; color: var(--muted); margin-left: 6px; vertical-align: middle; }
  </style>
</head>
<body>
<div class="shell">

  <div class="logo">
    <div class="logo-mark">⬡</div>
    <div>
      <div class="logo-text">ccip-router</div>
      <div class="logo-sub">node setup</div>
    </div>
  </div>

  <div class="progress" id="progress">
    <div class="step-dot active" id="dot-1">1</div>
    <div class="step-line"></div>
    <div class="step-dot" id="dot-2">2</div>
    <div class="step-line"></div>
    <div class="step-dot" id="dot-3">3</div>
  </div>

  <div class="card">

    <!-- Step 1: Gateway Key -->
    <div class="step-panel active" id="step-1">
      <div class="card-title">Gateway key</div>
      <div class="card-sub">Signs every record this node produces. Use a dedicated hot key — not your main wallet.</div>

      <div class="field">
        <label>Key source</label>
        <div style="display:flex;gap:8px;margin-bottom:12px">
          <button class="btn btn-ghost" id="btn-generate" onclick="generateKey()">⚡ Generate new key</button>
          <button class="btn btn-ghost" id="btn-import" onclick="showImport()">↓ Import existing</button>
        </div>

        <div class="key-reveal" id="key-reveal">
          <div class="label">Private key — save this now, it won't be shown again</div>
          <div class="copy-row">
            <div class="value" id="generated-key"></div>
            <button class="btn btn-ghost btn-sm" onclick="copyKey()">Copy</button>
          </div>
          <div id="generated-address" class="address-pill" style="margin-top:10px"></div>
        </div>

        <div id="import-field" style="display:none;margin-top:12px">
          <input type="password" id="import-key" placeholder="0x..." class="mono"
            oninput="onImportKey(this.value)" />
          <div id="import-address" class="address-pill" style="display:none"></div>
        </div>
      </div>

      <div class="warn" id="key-warn" style="display:none">
        ⚠ Save the private key before continuing — you won't see it again after setup.
      </div>

      <div class="actions">
        <div></div>
        <button class="btn btn-primary" id="btn-next-1" onclick="goStep(2)" disabled>Next →</button>
      </div>
    </div>

    <!-- Step 2: Node Settings -->
    <div class="step-panel" id="step-2">
      <div class="card-title">Node settings</div>
      <div class="card-sub">Configure how this node runs. Defaults work for most setups.</div>

      <div class="field">
        <label>Namespace</label>
        <input type="text" id="s-namespace" value="agent-attestations" />
        <div class="hint">Records are scoped by namespace. Peers must share the same namespace to sync.</div>
      </div>

      <div class="row-2">
        <div class="field">
          <label>Port</label>
          <input type="number" id="s-port" value="3000" min="1" max="65535" />
        </div>
        <div class="field">
          <label>Sync interval</label>
          <input type="text" id="s-interval" value="*/5 * * * *" class="mono" />
        </div>
      </div>

      <div class="field">
        <label>DB path</label>
        <input type="text" id="s-db" value="./data.db" class="mono" />
        <div class="hint">SQLite file path relative to the working directory.</div>
      </div>

      <div class="actions">
        <button class="btn btn-ghost" onclick="goStep(1)">← Back</button>
        <button class="btn btn-primary" onclick="goStep(3)">Next →</button>
      </div>
    </div>

    <!-- Step 3: Peers + Confirm -->
    <div class="step-panel" id="step-3">
      <div class="card-title">Peers <span class="tag">optional</span></div>
      <div class="card-sub">Add peer node URLs to join the mesh. You can add more later from the admin panel.</div>

      <div class="field">
        <label>Peer URLs</label>
        <textarea id="s-peers" placeholder="https://gateway-b.example.com&#10;https://gateway-c.example.com"></textarea>
        <div class="hint">One URL per line. Leave blank to run as a standalone node.</div>
      </div>

      <div style="border-top:1px solid var(--border);margin: 20px 0"></div>

      <div class="card-title" style="margin-bottom:14px">Confirm</div>
      <div id="summary"></div>

      <div class="actions">
        <button class="btn btn-ghost" onclick="goStep(2)">← Back</button>
        <button class="btn btn-primary" id="btn-save" onclick="save()">Save &amp; start →</button>
      </div>
    </div>

    <!-- Success -->
    <div class="step-panel" id="step-done">
      <div class="success-state">
        <div class="success-icon">✓</div>
        <div class="success-title">Node configured</div>
        <div class="success-sub">Restarting... you'll be redirected to the admin panel shortly.</div>
      </div>
    </div>

  </div>
</div>

<script>
  let gatewayKey  = ''
  let gatewayAddr = ''
  let currentStep = 1

  function goStep(n) {
    document.getElementById('step-' + currentStep).classList.remove('active')
    document.getElementById('dot-'  + currentStep).classList.remove('active')
    document.getElementById('dot-'  + currentStep).classList.add('done')

    currentStep = n
    const panel = document.getElementById('step-' + n) || document.getElementById('step-done')
    panel.classList.add('active')

    const dot = document.getElementById('dot-' + n)
    if (dot) { dot.classList.remove('done'); dot.classList.add('active') }

    if (n === 3) buildSummary()
  }

  async function generateKey() {
    const res  = await fetch('/setup/generate-key')
    const data = await res.json()
    gatewayKey  = data.privateKey
    gatewayAddr = data.address

    document.getElementById('generated-key').textContent    = data.privateKey
    document.getElementById('generated-address').textContent = data.address
    document.getElementById('key-reveal').classList.add('show')
    document.getElementById('import-field').style.display    = 'none'
    document.getElementById('key-warn').style.display        = 'block'
    document.getElementById('btn-next-1').disabled           = false
  }

  function copyKey() {
    navigator.clipboard.writeText(gatewayKey)
  }

  function showImport() {
    document.getElementById('import-field').style.display = 'block'
    document.getElementById('key-reveal').classList.remove('show')
    document.getElementById('key-warn').style.display     = 'none'
  }

  function onImportKey(val) {
    const hex = val.trim()
    if (hex.startsWith('0x') && hex.length === 66) {
      gatewayKey = hex
      // derive address client-side via a quick call
      fetch('/setup/generate-key').then(() => {}) // just wake up; address shown after save
      document.getElementById('import-address').style.display = 'inline-flex'
      document.getElementById('import-address').textContent   = 'Key accepted — address shown after save'
      document.getElementById('btn-next-1').disabled = false
    } else {
      document.getElementById('btn-next-1').disabled = true
    }
  }

  function buildSummary() {
    const peers = document.getElementById('s-peers').value
      .split('\\n').map(s => s.trim()).filter(Boolean)

    const rows = [
      { k: 'Signer address', v: gatewayAddr || '(derived from key)' },
      { k: 'Namespace',      v: document.getElementById('s-namespace').value },
      { k: 'Port',           v: document.getElementById('s-port').value },
      { k: 'Sync interval',  v: document.getElementById('s-interval').value },
      { k: 'DB path',        v: document.getElementById('s-db').value },
      { k: 'Peers',          v: peers.length ? peers.join(', ') : 'none (standalone)' },
    ]

    document.getElementById('summary').innerHTML = rows.map(r =>
      '<div class="summary-row"><span class="key">' + r.k + '</span><span class="val">' + r.v + '</span></div>'
    ).join('')
  }

  async function save() {
    const btn   = document.getElementById('btn-save')
    btn.disabled = true
    btn.textContent = 'Saving...'

    const peers = document.getElementById('s-peers').value
      .split('\\n').map(s => s.trim()).filter(Boolean)

    const body = {
      gatewayKey,
      namespace:    document.getElementById('s-namespace').value,
      syncInterval: document.getElementById('s-interval').value,
      dbPath:       document.getElementById('s-db').value,
      port:         Number(document.getElementById('s-port').value),
      peers,
    }

    const res = await fetch('/setup', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(body),
    })

    const data = await res.json()

    if (!res.ok) {
      btn.disabled    = false
      btn.textContent = 'Save & start →'
      alert(data.error || 'Save failed')
      return
    }

    // show success, then redirect to admin after restart window
    goStep('done')
    setTimeout(() => { window.location.href = '/admin' }, 4000)
  }
</script>
</body>
</html>`
