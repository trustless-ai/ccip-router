# ccip-router

**The coordination layer CCIP-Read was missing.**

EIP-3668 defines how clients talk to CCIP-Read gateways. It says nothing about how gateways talk to each other. `ccip-router` fills that gap — peer sync, deduplication, mesh messaging, and cryptographic attestation for any CCIP-Read gateway.

No ENS required. No agents required. Any CCIP-Read project can use this.

---

## Two tiers

### Basic
- CCIP-Read gateway (`/{sender}/{data}.json`)
- Mesh peer sync (`GET /records?since=&namespace=`)
- Deduplication — same `input_hash` never inserted twice
- Node health UI — peer status, sync cursors, version indicators

### Advanced
- EIP-712 attestation production after execution (WYRIWE profile)
- `/verify/:inputHash` — local DB + on-chain fallback
- `AttestationIndex` writer (Phase 2)
- Mesh messaging — upgrade notifications across nodes

---

## Quick start

```bash
cp .env.example .env
# fill GATEWAY_PRIVATE_KEY + PEERS
npm install
npm run dev
```

## Two-node test

Both methods spin up node-a (:3001) and node-b (:3002) pointing at each other as peers.
Uses Hardhat dev keys — safe for local testing only, never use in production.

### Option A — two terminals (no Docker)

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

### Verify the mesh

```bash
# write a record to node A via the CCIP handler
curl http://localhost:3001/0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266/0xdeadbeef

# check node A has it
curl http://localhost:3001/health

# wait ~1 minute for the sync cron to fire, then check node B
curl http://localhost:3002/health
# records: 1 — synced from node A

# verify by inputHash on node B
# inputHash = keccak256(0xdeadbeef) = 0x...
curl http://localhost:3002/verify/<inputHash>
```

Expected node B `/health` after sync:
```json
{
  "records": 1,
  "peers": [{
    "url": "http://localhost:3001",
    "healthy": true,
    "signerAddress": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
    "lastSyncAt": 1780311900
  }]
}
```

---

## Mesh sync interface

Any CCIP-Read gateway implementing this endpoint is mesh-compatible:

```
GET /records?since=<unix_timestamp>&namespace=<string>
→ { protocol, node_version, namespace, records: [{ key, value, timestamp, signature }] }
```

`namespace` is application-agnostic:
- `agent-attestations` — ENS Boiler / ERC-8004 agents
- `token-metadata` — NFT gateways
- anything — define your own, same protocol

---

## ERC alignment

| Standard | Role |
|---|---|
| EIP-3668 | Transport — CCIP-Read client-to-gateway |
| WYRIWE | Input trust — triple-hash commitment |
| OCP | L3 observation commitment — independent verification |
| ERC-8273 | Attestation standard — advanced tier output |
| ERC-8274 | Proof verification interface |
| ERC-8275 | Node discovery + escrow (Phase 3) |

---

## Roadmap

- **Now** — Basic gateway + mesh sync (this repo)
- **Phase 2** — `AttestationIndex.sol` — chain as source of truth, no shared DB
- **Phase 3** — Open node network, ERC-8275 economics, slashing via ERC-8274
- **Companion EIP** — Formalise `/records` sync interface as a network standard alongside EIP-3668

---

## Related

- [ens-boiler](https://github.com/Echo-Merlini/ens-boiler) — opinionated ENS agent stack built on `ccip-router`
- [WYRIWE](https://github.com/TMerlini/wyriwe) — input provenance spec
- [OCP](https://github.com/damonzwicker/observation-commitment-protocol) — observation commitment protocol

---

*dinamic.eth — [gateway.ensub.org](https://gateway.ensub.org)*
