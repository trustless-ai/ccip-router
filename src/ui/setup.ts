import { Hono } from 'hono'
import { writeFileSync } from 'node:fs'
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'
import { CONFIG_FILE_PATH, type ConfigFile } from '../config.js'

export const setupRouter = new Hono()

setupRouter.get('/generate-key', (c) => {
  const privateKey = generatePrivateKey()
  const address = privateKeyToAccount(privateKey).address
  return c.json({ privateKey, address })
})

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
      --green:    #22c55e;
      --green-l:  rgba(34,197,94,0.2);
      --red:      #ef4444;
      --amber:    #f59e0b;
      --mono:     ui-monospace, 'SFMono-Regular', Menlo, monospace;
    }

    body {
      background: var(--bg);
      color: var(--text);
      font-family: 'Poppins', sans-serif;
      font-size: 14px;
      font-weight: 400;
      line-height: 1.6;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
    }

    .shell { width: 100%; max-width: 520px; }

    /* logo */
    .logo { display: flex; align-items: center; gap: 12px; margin-bottom: 36px; }
    .logo-icon {
      width: 36px; height: 36px;
      background: var(--accent-l);
      border: 1px solid var(--accent-b);
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
      border: 1px solid var(--border);
      background: var(--s1);
      color: var(--muted); font-size: 11px; font-weight: 600;
      display: flex; align-items: center; justify-content: center;
      transition: all 0.2s; z-index: 1;
    }
    .step-dot.active { border-color: var(--accent); color: var(--accent); background: var(--accent-l); }
    .step-dot.done   { border-color: var(--green);  background: var(--green-l); color: var(--green); }
    .step-line { flex: 1; height: 1px; background: var(--border); margin: 0 6px; }

    /* card */
    .card {
      background: var(--s1);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 28px;
      backdrop-filter: blur(8px);
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
      width: 100%;
      background: rgba(255,255,255,0.03);
      border: 1px solid var(--border);
      border-radius: 10px;
      color: var(--text);
      font-size: 13px; font-family: inherit;
      padding: 10px 14px;
      outline: none;
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
    .warn { font-size: 11px; color: var(--amber); margin-top: 6px; }

    /* buttons */
    .btn-row { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 14px; }
    .btn {
      display: inline-flex; align-items: center; gap: 6px;
      border: none; border-radius: 10px;
      font-size: 13px; font-weight: 500; font-family: inherit;
      padding: 9px 18px; cursor: pointer;
      transition: all 0.15s;
    }
    .btn-ghost {
      background: var(--s1); border: 1px solid var(--border); color: var(--subtle);
    }
    .btn-ghost:hover { border-color: var(--border-h); color: var(--text); background: var(--s2); }
    .btn-primary {
      background: var(--accent); color: #fff;
      box-shadow: 0 0 20px rgba(99,102,241,0.25);
    }
    .btn-primary:hover { background: var(--accent-v); box-shadow: 0 0 28px rgba(139,92,246,0.35); }
    .btn-primary:disabled { opacity: 0.35; cursor: not-allowed; box-shadow: none; }
    .btn-sm { padding: 6px 12px; font-size: 12px; }

    .actions { display: flex; justify-content: space-between; align-items: center; margin-top: 24px; }

    /* key reveal */
    .key-reveal {
      background: var(--green-l);
      border: 1px solid rgba(34,197,94,0.25);
      border-radius: 10px; padding: 14px;
      margin-top: 14px; display: none;
    }
    .key-reveal.show { display: block; }
    .key-reveal .lbl { font-size: 11px; color: rgba(34,197,94,0.7); margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.5px; }
    .key-reveal .copy-row { display: flex; justify-content: space-between; align-items: flex-start; gap: 8px; }
    .key-reveal .val { font-family: var(--mono); font-size: 11px; color: var(--green); word-break: break-all; }

    .addr-pill {
      display: inline-flex; align-items: center; gap: 6px;
      background: var(--accent-l); border: 1px solid var(--accent-b);
      border-radius: 8px; padding: 5px 10px;
      font-family: var(--mono); font-size: 11px; color: #818cf8;
      margin-top: 10px;
    }

    /* summary */
    .summary-row {
      display: flex; justify-content: space-between;
      padding: 9px 0; border-bottom: 1px solid var(--border);
      font-size: 13px;
    }
    .summary-row:last-child { border-bottom: none; }
    .summary-row .k { color: var(--subtle); font-size: 12px; }
    .summary-row .v { font-family: var(--mono); font-size: 11px; color: var(--text); text-align: right; max-width: 280px; word-break: break-all; }

    /* success */
    .success-state { text-align: center; padding: 24px 0; }
    .success-ring {
      width: 56px; height: 56px; border-radius: 50%;
      background: var(--green-l); border: 1px solid rgba(34,197,94,0.3);
      display: flex; align-items: center; justify-content: center;
      margin: 0 auto 16px; font-size: 22px;
    }
    .success-title { font-size: 17px; font-weight: 600; margin-bottom: 6px; }
    .success-sub   { font-size: 13px; color: var(--subtle); font-weight: 300; }

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
    <div class="logo-icon">
      <img src="/favicon.svg" alt="ccip-router"/>
    </div>
    <div>
      <div class="logo-name">ccip-router</div>
      <div class="logo-tag">node setup</div>
    </div>
  </div>

  <div class="progress">
    <div class="step-dot active" id="dot-1">1</div>
    <div class="step-line"></div>
    <div class="step-dot" id="dot-2">2</div>
    <div class="step-line"></div>
    <div class="step-dot" id="dot-3">3</div>
  </div>

  <div class="card">

    <!-- Step 1: Key -->
    <div class="step-panel active" id="step-1">
      <div class="card-title">Gateway key</div>
      <div class="card-sub">Signs every record this node produces. Use a dedicated hot key — not your main wallet.</div>

      <div class="field">
        <label>Key source</label>
        <div class="btn-row">
          <button class="btn btn-ghost" onclick="generateKey()">⚡ Generate new key</button>
          <button class="btn btn-ghost" onclick="showImport()">↓ Import existing</button>
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

    <!-- Step 2: Settings -->
    <div class="step-panel" id="step-2">
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
        <button class="btn btn-ghost" onclick="goStep(1)">← Back</button>
        <button class="btn btn-primary" onclick="goStep(3)">Next →</button>
      </div>
    </div>

    <!-- Step 3: Peers + Confirm -->
    <div class="step-panel" id="step-3">
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
        <button class="btn btn-ghost" onclick="goStep(2)">← Back</button>
        <button class="btn btn-primary" id="btn-save" onclick="save()">Save &amp; start →</button>
      </div>
    </div>

    <!-- Done -->
    <div class="step-panel" id="step-done">
      <div class="success-state">
        <div class="success-ring">✓</div>
        <div class="success-title">Node configured</div>
        <div class="success-sub">Restarting — redirecting to admin panel shortly.</div>
      </div>
    </div>

  </div>
</div>

<script>
  let gatewayKey = '', gatewayAddr = '', currentStep = 1

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
    const res = await fetch('/setup/generate-key')
    const d   = await res.json()
    gatewayKey = d.privateKey; gatewayAddr = d.address
    document.getElementById('generated-key').textContent     = d.privateKey
    document.getElementById('generated-address').textContent = d.address
    document.getElementById('key-reveal').classList.add('show')
    document.getElementById('import-field').style.display    = 'none'
    document.getElementById('key-warn').style.display        = 'block'
    document.getElementById('btn-next-1').disabled           = false
  }

  function copyKey() { navigator.clipboard.writeText(gatewayKey) }

  function showImport() {
    document.getElementById('import-field').style.display = 'block'
    document.getElementById('key-reveal').classList.remove('show')
    document.getElementById('key-warn').style.display     = 'none'
  }

  function onImportKey(val) {
    const hex = val.trim()
    const ok  = hex.startsWith('0x') && hex.length === 66
    if (ok) { gatewayKey = hex }
    document.getElementById('import-address').style.display = ok ? 'inline-flex' : 'none'
    document.getElementById('btn-next-1').disabled           = !ok
  }

  function buildSummary() {
    const peers = document.getElementById('s-peers').value.split('\\n').map(s=>s.trim()).filter(Boolean)
    const rows  = [
      { k:'Signer address', v: gatewayAddr || '(derived from key)' },
      { k:'Namespace',      v: document.getElementById('s-namespace').value },
      { k:'Port',           v: document.getElementById('s-port').value },
      { k:'Sync interval',  v: document.getElementById('s-interval').value },
      { k:'DB path',        v: document.getElementById('s-db').value },
      { k:'Peers',          v: peers.length ? peers.join(', ') : 'none (standalone)' },
    ]
    document.getElementById('summary').innerHTML = rows.map(r =>
      '<div class="summary-row"><span class="k">' + r.k + '</span><span class="v">' + r.v + '</span></div>'
    ).join('')
  }

  async function save() {
    const btn = document.getElementById('btn-save')
    btn.disabled = true; btn.textContent = 'Saving...'
    const peers = document.getElementById('s-peers').value.split('\\n').map(s=>s.trim()).filter(Boolean)
    const res = await fetch('/setup', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({
        gatewayKey,
        namespace:    document.getElementById('s-namespace').value,
        syncInterval: document.getElementById('s-interval').value,
        dbPath:       document.getElementById('s-db').value,
        port:         Number(document.getElementById('s-port').value),
        peers,
      }),
    })
    const data = await res.json()
    if (!res.ok) { btn.disabled=false; btn.textContent='Save & start →'; alert(data.error||'Save failed'); return }
    goStep('done')
    setTimeout(() => { window.location.href = '/admin' }, 4000)
  }
</script>
</body>
</html>`
