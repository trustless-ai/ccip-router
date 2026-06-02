# ccip-router — Deployment Guide

Two node modes, any combination of which can form a mesh.

---

## Node modes

### Operator node (full)
Runs the admin dashboard, holds the gateway private key, produces attestations, manages ENS records. Self-hosted — your infrastructure, your key.

### Public node (mesh-only)
Serves CCIP-Read queries and syncs records with peers. No admin surface, no key management UI. Safe to deploy on any public PaaS (Railway, Fly, Render, etc.).

Both modes use the same Docker image and the same `npm` package. The difference is configuration only.

---

## Environment variables

### Core (both modes)

| Variable | Required | Description |
|---|---|---|
| `GATEWAY_PRIVATE_KEY` | Yes | `0x`-prefixed private key. Signs all records and CCIP-Read responses. |
| `PORT` | No | HTTP port. Default: `3000`. |
| `DB_PATH` | No | SQLite database path. Default: `./data.db`. Mount a volume here in Docker. |
| `SYNC_NAMESPACE` | No | Record namespace. Default: `agent-attestations`. All peers must match. |
| `SYNC_INTERVAL` | No | Cron expression for peer sync. Default: `*/5 * * * *`. |
| `PEERS` | No | Comma-separated peer URLs. E.g. `https://node-a.example.com,https://node-b.example.com`. |
| `AUTO_DISCOVER` | No | Pull peer lists from synced peers. Default: `true`. |
| `NODE_URL` | No | This node's public URL. Required for VNI (signed node identity). |

### Operator node extras

| Variable | Required | Description |
|---|---|---|
| `AGENT_ID` | No | ERC-8004 agent identity (`0x`-prefixed bytes32). Enables WYRIWE attestation pipeline when combined with `REGISTRY_ADDRESS` and `MODEL_HASH`. |
| `REGISTRY_ADDRESS` | No | ERC-8004 registry contract address. |
| `MODEL_HASH` | No | keccak256 of the model weights CID. Completes the WYRIWE attestation struct. |
| `ATTESTATION_INDEX` | No | Deployed `AttestationIndex` contract address. Enables on-chain anchoring. |
| `RPC_URL` | No | JSON-RPC endpoint for on-chain reads and writes. |
| `NODE_REGISTRY` | No | Deployed `NodeRegistry` contract address (Phase 3). |
| `CDN_PROVIDER` | No | `pinata` or `storacha`. Enables IPFS upload from admin panel. |
| `CDN_API_KEY` | No | API key / JWT for the configured CDN provider. |
| `NETWORK_KEY` | No | Ethereum address. Messages signed by this key are marked as official network announcements. |
| `CHAIN_ID` | No | Chain ID for ENS contenthash and on-chain operations. Default: `1` (mainnet). |

### Public node extras

| Variable | Required | Description |
|---|---|---|
| `DISABLE_ADMIN` | No | Set `true` to skip mounting `/admin` and `/static` routes entirely. Recommended for any publicly-accessible deployment. |

---

## Operator node — self-hosted (Docker / Coolify)

Use `network_mode: host` and a dedicated port (e.g. `4100`) so Traefik/Coolify can route to it without NAT complexity.

```yaml
services:
  ccip-router:
    image: ghcr.io/echo-merlini/ccip-router:latest
    restart: unless-stopped
    network_mode: host
    volumes:
      - /your/data/path:/data
    environment:
      PORT: "4100"
      GATEWAY_PRIVATE_KEY: "0x..."
      NODE_URL: "https://your-gateway.example.com"
      PEERS: "https://public-node.up.railway.app"
      DB_PATH: /data/data.db
      SYNC_NAMESPACE: agent-attestations
      AUTO_DISCOVER: "true"
```

### Traefik dynamic config (if behind Coolify/Traefik)

Drop a file in your Traefik dynamic config directory:

```yaml
# /path/to/traefik/dynamic/ccip-router.yaml
http:
  routers:
    ccip-router:
      entryPoints: [http]
      rule: "Host(`your-gateway.example.com`)"
      service: ccip-router
      priority: 200
  services:
    ccip-router:
      loadBalancer:
        servers:
          - url: "http://172.17.0.1:4100"
```

### Cloudflare Tunnel (if using cloudflared)

In Cloudflare Zero Trust → Networks → Tunnels → your tunnel → Public Hostnames:
- Subdomain: `gateway` (or your choice)
- Domain: `your-domain.com`
- Service: `http://localhost:8090` (Traefik HTTP entrypoint)

After first boot, open `https://your-gateway.example.com/admin` and sign in with MetaMask (the wallet that holds `GATEWAY_PRIVATE_KEY`). The first wallet to sign claims the admin session permanently.

---

## Public node — Railway

1. Fork or connect `Echo-Merlini/ccip-router` to Railway.
2. Railway auto-detects `railway.toml` and builds from the Dockerfile.
3. Set environment variables in the Railway dashboard (Settings → Variables):

```
GATEWAY_PRIVATE_KEY = 0x<fresh key — never reuse>
DISABLE_ADMIN       = true
SYNC_NAMESPACE      = agent-attestations
NODE_URL            = https://<your-railway-url>.up.railway.app
PEERS               = https://<your-operator-node-url>
```

4. After first deploy, copy the Railway public URL and add it as a `PEERS` entry on your operator node (via admin panel → Node config → Network, or restart with updated `PEERS` env var).

**One-click deploy:**

[![Deploy on Railway](https://railway.com/button.svg)](https://railway.com/template/ccip-router)

---

## Peering two nodes

Once both nodes are running and have each other's URLs in `PEERS`, they will sync automatically every `SYNC_INTERVAL`. To verify:

```bash
# Check peer health on operator node
curl https://your-operator-node/health | jq '.peers'

# Check records synced on public node
curl https://your-public-node/records?namespace=agent-attestations&since=0&limit=10
```

Both nodes should show each other as healthy with matching record counts after the first sync cycle.

---

## CCIP-Read resolver — multi-URL

To get true redundancy, return both gateway URLs from your on-chain CCIP-Read resolver:

```solidity
string[] memory urls = new string[](2);
urls[0] = "https://your-operator-node/{sender}/{data}.json";
urls[1] = "https://your-public-node/{sender}/{data}.json";
revert OffchainLookup(address(this), urls, callData, selector, extraData);
```

If the first URL fails, the client automatically falls back to the second. No single point of failure.

---

## Generating a fresh gateway key

```bash
node --input-type=module -e "
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'
const key = generatePrivateKey()
console.log('PRIVATE KEY:', key)
console.log('ADDRESS:    ', privateKeyToAccount(key).address)
"
```

Never commit private keys. Use environment variables or a secrets manager.

---

## Mesh security notes

- **Signer pinning:** on first sync from a peer, the recovered signer address is stored. Subsequent records from a different signer are rejected — a compromised peer cannot inject records on behalf of another node.
- **Rate limiting:** the `/messages` endpoint accepts at most 10 messages per peer signer per hour.
- **Admin surface:** always set `DISABLE_ADMIN=true` on any publicly-accessible node unless you specifically need the dashboard reachable. The dashboard is SIWE-protected, but reducing attack surface is always better.
- **Key rotation:** if your gateway key is compromised, generate a new key and restart. Existing peers will see the signer change on next sync and may reject records until you re-establish trust out of band.
