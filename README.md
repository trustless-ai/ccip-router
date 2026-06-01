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
