# ccip-router

**The coordination layer CCIP-Read was missing.**

EIP-3668 defines how clients talk to CCIP-Read gateways. It says nothing about how gateways talk to each other. `ccip-router` fills that gap — peer sync, deduplication, signed records, and cryptographic attestation for any CCIP-Read gateway.

No ENS required. No agents required. Any CCIP-Read project can plug in a resolver and get a mesh-ready gateway in minutes.

---

## Two tiers

### Basic — plug in a resolver, get a gateway + mesh

```typescript
import { CcipRouter } from 'ccip-router'

const ccip = new CcipRouter({
  namespace: 'token-metadata',
  db,
  gatewayKey: process.env.GATEWAY_PRIVATE_KEY,
  resolver: async (sender, calldata, namespace) => {
    return encodeMyResponse(calldata)
  },
})

app.route('/', ccip.hono())
```

What you get:
- CCIP-Read handler (`/{sender}/{data}.json`)
- EIP-191 signed records written to SQLite on every call
- Mesh peer sync (`GET /records?since=&namespace=&limit=&cursor=`)
- Record deduplication — same `inputHash` never inserted twice
- Admin dashboard at `/admin` with peer management + sync controls
- Setup wizard at `/setup` on first boot

### Advanced — wrap any resolver with WYRIWE EIP-712 attestation

```typescript
import { CcipRouter, withWyriwe } from 'ccip-router'

const ccip = new CcipRouter({
  namespace: 'agent-attestations',
  db,
  gatewayKey: config.gatewayKey,
  resolver: withWyriwe(myAgentResolver, {
    gatewayKey:      config.gatewayKey,
    registryAddress: process.env.REGISTRY_ADDRESS as `0x${string}`,
    agentId:         process.env.AGENT_ID as `0x${string}`,
    modelHash:       process.env.MODEL_HASH as `0x${string}`,
    chainId:         1,
  }),
})
```

What `withWyriwe()` adds on top of basic:
- Triple-hash chain: `rawInputHash → sanitizationPipelineHash → inputHash`
- `IDENTITY_SENTINEL` path (no sanitization pipeline) fully implemented
- EIP-712 `WyriweAttestation` signed with the gateway key on every resolver call
- Attestation records persisted to `{namespace}:wyriwe` — synced by the mesh automatically
- Verifiable by any peer: recover signer from signature, match against known gateway address

---

## Quick start (setup wizard)

```bash
npm install
npm run dev
# → open http://localhost:3000
# → setup wizard walks you through key generation + config
# → config.json is written, node restarts, /admin loads
```

Or configure via environment (no wizard needed):

```bash
cp .env.example .env
# set GATEWAY_PRIVATE_KEY, ADMIN_SECRET, PEERS, etc.
npm run dev
```

---

## Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `GATEWAY_PRIVATE_KEY` | Yes* | — | 32-byte hex signing key (`0x...`). Without it the node runs in dry-run mode (unsigned records). |
| `ADMIN_SECRET` | No | — | Protects `/admin`. Set for any non-local deployment. Without it the dashboard is open. |
| `PORT` | No | `3000` | HTTP port |
| `DB_PATH` | No | `./data.db` | SQLite file path |
| `SYNC_NAMESPACE` | No | `agent-attestations` | Record namespace — peers must match |
| `SYNC_INTERVAL` | No | `*/5 * * * *` | Cron expression for peer sync |
| `PEERS` | No | — | Comma-separated peer URLs |

\* Can also come from `config.json` written by the setup wizard.

---

## Admin dashboard

Visit `/admin` after setup. Features:
- Live stats: record count, peer count, last sync time
- Peer panel: add/remove peers, per-peer health + signer address + last sync
- Recent records panel: local vs peer-synced, timestamps
- Manual sync trigger
- Auto-refresh every 15 seconds

**Auth:** If `ADMIN_SECRET` is set, `/admin` requires a login (cookie session, 7-day). API routes also accept `Authorization: Bearer <secret>` for programmatic access.

---

## Two-node local test

Uses Hardhat dev keys — safe for local testing only, **never use in production**.

### Option A — two terminals

**Terminal 1 — node A**
```bash
PORT=3001 DB_PATH=./node-a.db \
  GATEWAY_PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  PEERS=http://localhost:3002 SYNC_INTERVAL="*/1 * * * *" \
  npm run dev
```

**Terminal 2 — node B**
```bash
PORT=3002 DB_PATH=./node-b.db \
  GATEWAY_PRIVATE_KEY=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d \
  PEERS=http://localhost:3001 SYNC_INTERVAL="*/1 * * * *" \
  npm run dev
```

### Option B — Docker

```bash
docker compose up --build
```

### Verify mesh sync

```bash
# trigger a CCIP call on node A — writes a signed record
curl http://localhost:3001/0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266/0xdeadbeef

# check node A recorded it
curl http://localhost:3001/health | jq .records  # → 1

# wait ~1 minute for sync cron, then check node B
curl http://localhost:3002/health | jq .records  # → 1 (synced from A)

# verify by inputHash on node B
curl http://localhost:3002/verify/<inputHash>
```

---

## API reference

### CCIP-Read handler
```
GET /{sender}/{data}.json
→ { data: "0x..." }        EIP-3668 response
```

### Mesh sync (any peer can pull this)
```
GET /records?namespace=<str>&since=<unix>&limit=<n>&cursor=<str>
→ {
    protocol: 1,
    node_version: "0.1.0",
    namespace: "agent-attestations",
    records: [{ inputHash, namespace, key, value, timestamp, signature, sourcePeer }],
    cursor: "<next>" | null
  }
```

### Attestation lookup
```
GET /verify/:inputHash
→ { inputHash, found: true, record: { ... } }
→ { inputHash, found: false }   (404)
```

### Health
```
GET /health
→ { ok, version, namespace, signerAddress, peers, records }
```

### Admin API (requires auth if ADMIN_SECRET set)
```
GET  /admin/api/status          node info, peers, recent records
POST /admin/api/sync            trigger immediate peer sync
POST /admin/api/peers           { url } — add peer
DEL  /admin/api/peers           { url } — remove peer
POST /admin/login               { secret } — set session cookie
POST /admin/logout              clear session cookie
```

---

## Mesh sync protocol

Any CCIP-Read gateway implementing `/records` is mesh-compatible:

```
GET /records?since=<unix>&namespace=<string>&limit=<n>&cursor=<string>
→ { protocol: 1, node_version, namespace, records: [...], cursor: string | null }
```

Protocol version `1` is the current stable spec. Nodes on a different version are skipped during sync with a warning.

**Namespaces** are application-defined and scoped at the record level:
- `agent-attestations` — ENS Boiler / ERC-8004 agents
- `agent-attestations:wyriwe` — WYRIWE EIP-712 attestations (auto-produced by `withWyriwe()`)
- `token-metadata` — NFT gateways
- anything — define your own

---

## ERC / spec alignment

| Spec | Layer | Role | Status |
|---|---|---|---|
| EIP-3668 | Transport | CCIP-Read client-to-gateway | ✅ implemented |
| WYRIWE | L2 Input trust | Triple-hash commitment, EIP-712 attestation | ✅ implemented |
| ERC-8004 | L1 Identity | Agent identity `agentId` + `registryAddress` in attestation | 🔜 identity block in options |
| OCP / ERC-8263 | L3 Observation | Observation commitment hash | 🔜 next |
| EIP-712 | L4 Attestation | Structured signing (via `withWyriwe`) | ✅ implemented |

---

## Roadmap

### Done
- [x] CCIP-Read gateway (EIP-3668)
- [x] SQLite record store — WAL mode, dedup on `inputHash`, cursor pagination
- [x] EIP-191 signed records (basic tier)
- [x] Mesh peer sync with protocol version check
- [x] Setup wizard (`/setup`) — key generation, config.json persistence
- [x] Admin dashboard (`/admin`) — peers, records, sync
- [x] Admin auth — cookie session + Bearer token (`ADMIN_SECRET`)
- [x] `withWyriwe()` — EIP-712 attestation, triple-hash chain, IDENTITY_SENTINEL path
- [x] Router SVG favicon, dinamic.eth design language

### Next
- [ ] `/verify` — clean proof response (`{ signer, signature, verified }` + signature recovery)
- [ ] ERC-8004 identity block in `CcipRouterOptions` (`agentId`, `registryAddress`)
- [ ] OCP / ERC-8263 observation commitment hash in attestation
- [ ] Peer signer pinning — reject records with unexpected signer after first sync
- [ ] Peer health polling (dedicated `/health` fetch loop, separate from sync)
- [ ] Graceful shutdown (SIGTERM → flush WAL)
- [ ] DB versioned migrations (`schema_version` table)
- [ ] In-memory log buffer → `/admin/api/logs` + log panel in dashboard
- [ ] Top-level `index.ts` re-export (library mode)
- [ ] `withWyriwe()` non-sentinel path (sanitization pipeline CID)

### Phase 2
- [ ] `AttestationIndex.sol` — chain as source of truth, no shared DB
- [ ] `/verify` on-chain fallback

### Phase 3
- [ ] Open node network, VNI integration, ERC-8275 economics

---

## Related

- [ens-boiler](https://github.com/Echo-Merlini/ens-boiler) — opinionated ENS agent stack built on `ccip-router`
- [WYRIWE](https://github.com/TMerlini/wyriwe) — input provenance spec
- [OCP](https://github.com/damonzwicker/observation-commitment-protocol) — observation commitment protocol

---

*dinamic.eth*
