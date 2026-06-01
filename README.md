# ccip-router

**The coordination layer CCIP-Read was missing.**

EIP-3668 defines how clients talk to CCIP-Read gateways. It says nothing about how gateways talk to each other. `ccip-router` fills that gap — peer sync, deduplication, signed records, and cryptographic attestation for any CCIP-Read gateway.

No ENS required. No agents required. Any CCIP-Read project can plug in a resolver and get a mesh-ready gateway in minutes.

**→ [Integration guide](GUIDE.md)** — install, quickstart, attestation setup, contracts, mesh join.

---

## Architecture

### System overview

```mermaid
flowchart LR
    Client(["CCIP-Read client\nbrowser / contract"])

    subgraph Node["ccip-router node"]
        Handler["GET /{sender}/{data}.json\nEIP-3668 handler"]
        Resolver["Resolver fn\ncustom logic"]
        Wyriwe["withWyriwe()\nEIP-712 attestation"]
        DB[("SQLite\nWAL · dedup · cursor")]
        Cron["sync cron\n*/5 * * * *"]
    end

    subgraph Peers["Peer mesh"]
        NodeB["Node B"]
        NodeC["Node C"]
    end

    subgraph Sepolia["Sepolia (chain 11155111)"]
        AI["AttestationIndex\n0x107D…3698"]
        NR["NodeRegistry\n0x6be4…42b7"]
    end

    Client -- "EIP-3668 request" --> Handler
    Handler -- "{ data: 0x... }" --> Client
    Handler --> Resolver --> Wyriwe --> DB
    Cron -- "GET /records" --> NodeB & NodeC
    NodeB & NodeC -- "signed records" --> DB
    DB -. "publishAttestation()" .-> AI
    DB -. "register(url, sig)" .-> NR
```

### Per-request attestation flow

```mermaid
sequenceDiagram
    participant Client as CCIP-Read client
    participant GW as ccip-router
    participant Res as Resolver fn
    participant DB as SQLite
    participant Chain as AttestationIndex

    Client->>GW: GET /{sender}/{data}.json
    GW->>Res: resolve(sender, calldata, namespace)
    Res-->>GW: response bytes

    Note over GW: withWyriwe() — attestation pipeline
    GW->>GW: rawInputHash = keccak256(calldata)
    GW->>GW: inputHash = rawInputHash (sentinel)<br/>or keccak256(abi.encode(raw, pipelineHash))
    GW->>GW: outputHash = keccak256(response)
    GW->>GW: commitmentHash = keccak256(agentId · modelHash · inputHash · outputHash · ts)
    GW->>GW: EIP-712 sign WyriweAttestation
    GW->>DB: INSERT OR IGNORE signed attestation record
    GW-->>Client: { data: "0x..." }

    Note over DB,Chain: async — admin-triggered batch publish
    DB->>Chain: record(attestation, sig)
    Chain-->>DB: signerOf[commitmentHash] anchored
```

### Attestation stack

```mermaid
graph TB
    T["EIP-3668 · Transport\nCCIP-Read client-to-gateway"]
    S["EIP-191 · Record signing\nkeccak256(inputHash · namespace · valueHash · ts)"]
    W["WYRIWE · Input provenance\nsentinel path: inputHash = rawInputHash\nnon-sentinel: inputHash = keccak256(abi.encode(raw, pipelineHash))"]
    I["ERC-8004 · Agent identity\nagentId · registryAddress declared on-chain"]
    O["OCP / ERC-8263 · Observation commitment\ncommitmentHash = keccak256(agentId · modelHash · inputHash · outputHash · ts)"]
    A["EIP-712 · WyriweAttestation\nstructured signing · verifiable by any peer · synced by mesh"]
    V["VNI · Node identity\nEIP-191 signed { nodeId · signerAddress · url · version · ts }"]
    C["On-chain anchoring · Sepolia\nAttestationIndex — signerOf · commitmentOf\nNodeRegistry — register(url, sig)"]

    T --> S --> W --> I --> O --> A --> V --> C
```

---

## Contracts

Both contracts are permissionless — no owner, no admin. One deployment per chain serves all nodes.

| Contract | Sepolia address | Purpose |
|---|---|---|
| `AttestationIndex` | [`0x107D706112225aC57eCf6692FBbDC283fb6E3698`](https://sepolia.etherscan.io/address/0x107D706112225aC57eCf6692FBbDC283fb6E3698) | Anchors EIP-712 `WyriweAttestation` records on-chain. Stores `signerOf[commitmentHash]` and `commitmentOf[inputHash]`. |
| `NodeRegistry` | [`0x6be4966596A9CBaa7260ab6EbbFFA69bBC9a42b7`](https://sepolia.etherscan.io/address/0x6be4966596A9CBaa7260ab6EbbFFA69bBC9a42b7) | Public directory of nodes. `register(url, sig)` proves key ownership via EIP-191 — the relayer (`msg.sender`) does not need to be the signing key. |

Deployed by [`0xFf9a176577Fb42b6bc9c19fd05a241e8fCd0ca14`](https://sepolia.etherscan.io/address/0xFf9a176577Fb42b6bc9c19fd05a241e8fCd0ca14) · Solc 0.8.24 · optimizer 200 runs.

**To use on Sepolia:** open the admin panel → Deploy contracts → select Sepolia → "Use these addresses →". Addresses are saved to config automatically, no deployment needed.

**To deploy to another chain:** open the admin panel → Deploy contracts → select the chain → connect wallet → two transactions (one per contract). No private key is stored — MetaMask signs everything in-browser.

Source: [`contracts/AttestationIndex.sol`](contracts/AttestationIndex.sol) · [`contracts/NodeRegistry.sol`](contracts/NodeRegistry.sol)

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
    gatewayKey:       config.gatewayKey,
    registryAddress:  process.env.REGISTRY_ADDRESS as `0x${string}`,
    agentId:          process.env.AGENT_ID as `0x${string}`,
    modelHash:        process.env.MODEL_HASH as `0x${string}`,
    chainId:          1,
    // sanitizationCID: 'ipfs://Qm...',  // omit for sentinel (identity) path
  }),
})
```

What `withWyriwe()` adds on top of basic:
- Triple-hash chain — two paths:
  - **Sentinel** (default): `sanitizationPipelineHash = keccak256("IDENTITY_SENTINEL")`, `inputHash = rawInputHash`
  - **Non-sentinel** (`sanitizationCID` set): `sanitizationPipelineHash = keccak256(CID)`, `inputHash = keccak256(abi.encode(rawInputHash, sanitizationPipelineHash))`
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
| `AGENT_ID` | No | — | ERC-8004 agent identity (bytes32 hex). Enables `/identity` endpoint. |
| `REGISTRY_ADDRESS` | No | — | ERC-8004 on-chain registry address. Required alongside `AGENT_ID`. |
| `CHAIN_ID` | No | `1` | Chain where the ERC-8004 registry is deployed. |
| `ATTESTATION_INDEX` | No | — | Deployed `AttestationIndex` contract address. Enables on-chain anchoring. |
| `NODE_REGISTRY` | No | — | Deployed `NodeRegistry` contract address. Enables on-chain node registration. |
| `RPC_URL` | No | — | JSON-RPC endpoint. Required alongside `ATTESTATION_INDEX`. |
| `MODEL_HASH` | No | — | `keccak256` of model weights CID. Required to activate WYRIWE attestation. |

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

**Stack status row:** A compact pill row below the header shows which tiers are active — Signing / ERC-8004 / WYRIWE / OCP — derived from `/admin/api/status`. Green = active, grey = unconfigured.

**Node logs panel:** Live ring buffer of the last 200 log lines (info/warn/error), colour-coded. Auto-refreshes every 10 seconds.

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

### OCP observation commitment (ERC-8263)
```
GET /ocp/:inputHash
→ {
    inputHash,
    found: true,
    commitmentHash: "0x...",
    observation: { agentId, modelHash, inputHash, outputHash, timestamp },
    namespace, sourcePeer
  }
→ { inputHash, found: false }   (404 — no WYRIWE attestation for this inputHash)
```

### Attestation lookup
```
GET /verify/:inputHash
→ {
    inputHash,
    found: true,
    proofs: [
      {
        namespace:   "agent-attestations",
        signingType: "EIP-191",
        verified:    true,
        signer:      "0x...",
        signature:   "0x...",
        timestamp:   1234567890,
        sourcePeer:  null | "https://..."
      },
      {
        namespace:   "agent-attestations:wyriwe",
        signingType: "EIP-712 WyriweAttestation",
        verified:    true,
        signer:      "0x...",
        signature:   "0x...",
        timestamp:   1234567890,
        attestation: { agentId, registry, modelHash, rawInputHash,
                       sanitizationPipelineHash, inputHash, outputHash }
      }
    ]
  }
→ { inputHash, found: false }   (404)
```

### Identity (ERC-8004)
```
GET /identity
→ { declared: true, agentId, registryAddress, chainId, namespace, signerAddress }
→ { declared: false }   (404 — AGENT_ID not configured)
```

### Node identity (VNI)
```
GET /vni
→ { nodeId, signerAddress, url, version, timestamp, signature }
→ { declared: false }   (404 — NODE_URL not configured)
```

### Peer gossip
```
GET /peers
→ { protocol: 1, node_version, signerAddress, peers: [{ url, signerAddress, healthy, lastSyncAt }] }
```

### Contributions (ERC-8275)
```
GET /contributions
→ { namespace, contributions: [{ source, records }] }
```

### Health
```
GET /health
→ {
    ok, version, namespace, signerAddress,
    identity: { agentId, registryAddress, chainId } | null,
    tiers: { signed, erc8004, wyriwe, ocp },
    peers, records
  }
```

### Admin API (requires auth if ADMIN_SECRET set)
```
GET  /admin/api/status          node info, peers, recent records, tiers
GET  /admin/api/logs            last 200 log lines [{ ts, level, msg }]
GET  /admin/api/audit           per-spec compliance report (EIP-3668/WYRIWE/ERC-8004/OCP)
POST /admin/api/sync            trigger immediate peer sync
POST /admin/api/publish         batch-publish recent WYRIWE records to AttestationIndex
                                  body: { limit?: number }  (default 50, max 200)
                                  → { published, skipped, errors }
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
| ERC-8004 | L1 Identity | Agent identity `agentId` + `registryAddress` in attestation | ✅ implemented |
| OCP / ERC-8263 | L3 Observation | Observation commitment hash | ✅ implemented |
| EIP-712 | L4 Attestation | Structured signing (via `withWyriwe`) | ✅ implemented |
| VNI | L5 Node Identity | Signed node identity, peer gossip | ✅ implemented |
| ERC-8275 | L6 Economics | Contribution attribution (MVP) | ✅ implemented |

---

## Roadmap

### Done
- [x] CCIP-Read gateway (EIP-3668)
- [x] SQLite record store — WAL mode, composite PK `(inputHash, namespace)`, cursor pagination
- [x] DB versioned migrations (`schema_version` table, v1 applied on first boot)
- [x] EIP-191 signed records (basic tier)
- [x] Mesh peer sync with protocol version check
- [x] Setup wizard (`/setup`) — key generation, config.json persistence
- [x] Admin dashboard (`/admin`) — peers, records, sync
- [x] Admin auth — cookie session + Bearer token (`ADMIN_SECRET`)
- [x] `withWyriwe()` — EIP-712 attestation, triple-hash chain, IDENTITY_SENTINEL path
- [x] `/verify` — clean proof per namespace: `{ verified, signer, signingType, signature, attestation }`
- [x] ERC-8004 identity — `AGENT_ID` + `REGISTRY_ADDRESS` + `CHAIN_ID`, `/identity` endpoint, `/health` field
- [x] OCP / ERC-8263 — `commitmentHash` in `WyriweAttestation`, `/ocp/:inputHash` endpoint
- [x] Router SVG favicon, dinamic.eth design language
- [x] Peer signer pinning — reject records with unexpected signer after first sync
- [x] Peer health polling — fetch `/health` after every sync, populate `nodeVersion` + `signerAddress`
- [x] Graceful shutdown — `SIGTERM`/`SIGINT` → `server.close()` → `db.close()` → `process.exit(0)`
- [x] In-memory log ring buffer (200 lines, console-patched) → `/admin/api/logs` + colour-coded log panel
- [x] Stack status pills in admin header bar — Signing / ERC-8004 / WYRIWE / OCP
- [x] Library re-export (`src/lib.ts`) — `CcipRouter`, `withWyriwe`, `IdentityOpts`, `WyriweOpts`, `ResolverFn`, DB types

- [x] `withWyriwe()` non-sentinel path — `sanitizationCID` option; `inputHash = keccak256(abi.encode(rawInputHash, sanitizationPipelineHash))`
- [x] Setup wizard reconfigure flow — pre-fills current config, "Keep existing key", `/setup/current-config` endpoint, inherited admin secret

- [x] Spec audit accordion panel in admin — per-spec cards (EIP-3668 / WYRIWE / ERC-8004 / OCP), inline summary pills, expandable detail grid with missing-config hints
- [x] `contracts/AttestationIndex.sol` — on-chain anchor for WyriweAttestations; verifies EIP-712 sig against ERC-8004 registry domain, stores `signerOf[commitmentHash]` + `commitmentOf[inputHash]`
- [x] `src/chain/` — viem public + wallet clients, `publishAttestation()`, `checkOnChain()`
- [x] `/verify` on-chain fallback — if `inputHash` not in local DB and `ATTESTATION_INDEX` + `RPC_URL` configured, queries contract and returns on-chain proof
- [x] `POST /admin/api/publish` — batch-publish recent WYRIWE records to `AttestationIndex`; skips already-anchored; "Publish to chain" button in spec audit panel
- [x] Open node network — `GET /peers` gossip endpoint; auto-discovery pulls peer lists during sync (bounded at 10/cycle, disable with `AUTO_DISCOVER=false`)
- [x] VNI (Verifiable Node Identity) — `GET /vni` returns EIP-191 signed `{ nodeId, signerAddress, url, version, timestamp }`; peers verify during sync for authoritative signer resolution
- [x] `contracts/NodeRegistry.sol` — on-chain node directory; `register(url, sig)` proves key ownership; `POST /admin/api/register` + "Register on-chain" button in VNI spec card
- [x] ERC-8275 economics (MVP) — contribution attribution via `getContributions(namespace)`; `GET /contributions`; per-peer record counts surfaced in spec audit panel
- [x] Config: `NODE_URL`, `NODE_REGISTRY`, `AUTO_DISCOVER`; `/health` exposes `tiers.vni` + `tiers.onChain`

### Next — UI & node management

**Stack status bar**
- [x] Add VNI + On-chain tier pills
- [x] Click signer address pill to copy to clipboard (green flash feedback)

**Node info & layout**
- [x] Move node info bar above the peers/records panels; add namespace field
- [x] Toast-based error feedback in add-peer form (replaces `alert()`)

**Node config panel** *(in-dashboard, no env editing required)*
- [x] Full config panel — Core / Signing / Network / Identity / Chain / Admin sections
- [x] `GET /admin/api/config` — safe config snapshot (signer address, never the key)
- [x] `POST /admin/api/config` — writes `config.json`, preserves gateway key, restarts node
- [x] Auto-discover toggle, seed peers textarea, unsaved-changes indicator

**Wallet & signing**
- [x] Signing key panel — generate or import, rotate with identity-change warning, `POST /admin/api/key`
- [x] Dry-run banner — shown when no key configured, "Configure key →" scrolls to key panel

**Setup wizard — node owner onboarding**
- [x] Admin secret as dedicated step 2 — prominent warning box, two-step skip confirmation
- [x] Post-setup checklist — signing ✓, admin ✓/⚠, WYRIWE/ERC-8004/VNI ○ with next-step hints

---

## Testing

The test suite uses the Node.js built-in test runner (`node:test`) with `tsx` for ESM TypeScript — no extra test framework required.

```bash
npm test
```

Expected output:

```
ℹ tests 49
ℹ suites 16
ℹ pass 49
ℹ fail 0
```

### What is tested

| File | Coverage |
|---|---|
| `src/__tests__/gateway.test.ts` | `decodeRequest` — address + calldata parsing, `.json` suffix stripping, `CcipRequestError` on bad inputs; `encodeResponse` envelope |
| `src/__tests__/crypto.test.ts` | `signRecord` / `recoverRecordSigner` round-trip; `verifyRecord` correct signer → `true`, wrong signer / tampered value → `false` |
| `src/__tests__/db.test.ts` | `insertRecord`, `getRecord` (with/without namespace), `getRecordsByInputHash`, `INSERT OR IGNORE` deduplication, cursor pagination, `getContributions` grouping, peer upsert + remove |
| `src/__tests__/ocp.test.ts` | `buildCommitmentHash` determinism, 32-byte hex output, field-sensitivity (agentId / outputHash / timestamp) |
| `src/__tests__/wyriwe.test.ts` | Sentinel path (`inputHash === rawInputHash`), non-sentinel path (`keccak256(abi.encode(rawInputHash, sanitizationPipelineHash))`), paths produce distinct hashes for same calldata |
| `src/__tests__/vni.test.ts` | `makeVni` field shape + stable `nodeId`; `verifyVni` round-trip; tamper detection (url / signerAddress / nodeId → `null`) |

Tests use `SQLiteDB(':memory:')` directly (bypassing the runtime singleton) and Hardhat dev key 0 for any signing operations — both are safe to commit and require no external services.

---

## Related

- [ens-boiler](https://github.com/Echo-Merlini/ens-boiler) — opinionated ENS agent stack built on `ccip-router`
- [WYRIWE](https://github.com/TMerlini/wyriwe) — input provenance spec
- [OCP](https://github.com/damonzwicker/observation-commitment-protocol) — observation commitment protocol

---

*dinamic.eth*
