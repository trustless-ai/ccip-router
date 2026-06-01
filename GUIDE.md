# ccip-router — Integration Guide

> **New here?** This guide gets you from zero to a running node in minutes.  
> The [README](README.md) is the full technical reference.

---

## What you're building

A **CCIP-Read gateway** that:
- Responds to EIP-3668 requests from any browser or smart contract
- Signs every record with your gateway key
- Syncs records with peer nodes automatically
- Optionally produces cryptographic attestations for every resolver call (WYRIWE + OCP)
- Anchors those attestations on-chain to an immutable shared index

You can run it as a **standalone node** (Docker / `npm run dev`) or embed `CcipRouter` into an existing Node.js server.

---

## Install

```bash
npm install ccip-router
```

Requires Node.js ≥ 20. Peer dependencies: none beyond what's bundled.

---

## Quickstart — embedded library

The minimum working setup: a resolver that returns some bytes, signed records written to SQLite, mesh sync ready.

```typescript
import { Hono } from 'hono'
import { serve } from '@hono/node-server'
import { CcipRouter } from 'ccip-router'

const app  = new Hono()
const ccip = new CcipRouter({
  namespace:  'my-gateway',
  gatewayKey: process.env.GATEWAY_PRIVATE_KEY as `0x${string}`,
  resolver: async (sender, calldata, namespace) => {
    // decode calldata, do your lookup, return ABI-encoded response
    return '0x'
  },
})

app.route('/', ccip.hono())
serve({ fetch: app.fetch, port: 3000 })
```

Every call to `/{sender}/{data}.json` now:
1. Decodes the EIP-3668 request
2. Calls your resolver
3. Signs the record with your gateway key (EIP-191)
4. Writes it to SQLite with deduplication
5. Returns `{ data: "0x..." }` to the client

---

## Add WYRIWE attestation

Wrap your resolver with `withWyriwe()` to produce a full EIP-712 `WyriweAttestation` on every call — cryptographic proof of what input your agent received, what model processed it, and what it returned.

```typescript
import { CcipRouter, withWyriwe } from 'ccip-router'

const ccip = new CcipRouter({
  namespace:  'agent-attestations',
  gatewayKey: process.env.GATEWAY_PRIVATE_KEY as `0x${string}`,
  resolver: withWyriwe(myAgentResolver, {
    gatewayKey:      process.env.GATEWAY_PRIVATE_KEY as `0x${string}`,
    registryAddress: process.env.REGISTRY_ADDRESS   as `0x${string}`,  // ERC-8004
    agentId:         process.env.AGENT_ID            as `0x${string}`,  // bytes32
    modelHash:       process.env.MODEL_HASH          as `0x${string}`,  // keccak256 of weights CID
    chainId:         11155111,                                           // Sepolia
  }),
})
```

Each resolver call now produces and persists a signed `WyriweAttestation` containing:

| Field | Value |
|---|---|
| `rawInputHash` | `keccak256(calldata)` |
| `inputHash` | same as raw (sentinel path) or `keccak256(abi.encode(raw, pipelineHash))` |
| `outputHash` | `keccak256(response)` |
| `commitmentHash` | `keccak256(agentId · modelHash · inputHash · outputHash · timestamp)` |
| `signature` | EIP-712 signed by your gateway key |

Attestations sync to peers automatically alongside regular records.

### Sentinel vs non-sentinel path

By default (no `sanitizationCID`) the **sentinel path** is used: `inputHash` equals `rawInputHash`. The pipeline hash is fixed at `keccak256("IDENTITY_SENTINEL")` — meaning "no sanitization was applied."

If your agent pre-processes inputs through a defined pipeline, pass the IPFS CID of that pipeline:

```typescript
withWyriwe(resolver, {
  ...opts,
  sanitizationCID: 'ipfs://QmYourSanitizationPipeline',
})
```

This switches to the **non-sentinel path**: `inputHash = keccak256(abi.encode(rawInputHash, keccak256(CID)))`. Different pipelines produce different input hashes, so attestations are bound to the exact transformation applied.

---

## ENS wildcard resolution

`withEns()` decodes ENS `resolve(bytes name, bytes data)` calldata (EIP-137 wildcard pattern) and calls your resolver with a clean `(name, record)` interface. It handles DNS wire-format decoding, selector dispatch, and ABI encoding — you just return the value.

```typescript
import { CcipRouter, withEns } from 'ccip-router'
import type { EnsResolverFn } from 'ccip-router'

const myResolver: EnsResolverFn = async (name, record) => {
  // name  → "vitalik.eth", "sub.name.eth", etc.
  // record → { type: 'addr' }
  //           { type: 'addr', coinType: 60n }
  //           { type: 'text', key: 'avatar' }
  //           { type: 'contenthash' }

  if (record.type === 'addr') {
    return db.getAddress(name)         // return "0x..." or null
  }
  if (record.type === 'text') {
    return db.getText(name, record.key) // return string or null
  }
  if (record.type === 'contenthash') {
    return db.getContenthash(name)     // return "0x..." or null
  }
  return null  // not found — withEns returns the zero value for each type
}

const ccip = new CcipRouter({
  namespace:  'ens-offchain',
  gatewayKey: process.env.GATEWAY_PRIVATE_KEY as `0x${string}`,
  resolver:   withEns(myResolver),
})
```

**Null returns:** `withEns` maps `null` to the right zero value per record type — zero address for `addr`, empty string for `text`, `0x` for `contenthash`.

**Unknown selectors:** any inner call selector not in the ENS spec returns `0x` rather than throwing.

**Composing with attestation:** put `withEns` inside `withWyriwe` so the attestation captures the raw ENS calldata hash:

```typescript
resolver: withWyriwe(withEns(myResolver), attestationOpts)
```

---

## Run a standalone node

The fastest way to run a full node with admin UI, setup wizard, peer sync, and all features wired up:

### Option A — npm

```bash
git clone https://github.com/Echo-Merlini/ccip-router.git
cd ccip-router
npm install
npm run dev
# → open http://localhost:3000
# → setup wizard guides you through key generation and config
```

### Option B — Docker

```bash
docker run -p 3000:3000 \
  -e GATEWAY_PRIVATE_KEY=0x... \
  -e ADMIN_SECRET=your-secret \
  ghcr.io/echo-merlini/ccip-router:latest
```

### Option C — Docker Compose (two-node local mesh)

```bash
docker compose up --build
# node A: http://localhost:3001/admin
# node B: http://localhost:3002/admin
# records written to A sync to B within ~1 minute
```

---

## Connect to the Sepolia contracts

Both contracts are deployed and shared — no need to deploy your own.

| Contract | Address |
|---|---|
| `AttestationIndex` | [`0x107D706112225aC57eCf6692FBbDC283fb6E3698`](https://sepolia.etherscan.io/address/0x107D706112225aC57eCf6692FBbDC283fb6E3698) |
| `NodeRegistry` | [`0x6be4966596A9CBaa7260ab6EbbFFA69bBC9a42b7`](https://sepolia.etherscan.io/address/0x6be4966596A9CBaa7260ab6EbbFFA69bBC9a42b7) |
| `WyriweAttestationVerifier` | [`0x9515D6e53D2D45C1CFE6181943ca11C150C2bf61`](https://sepolia.etherscan.io/address/0x9515D6e53D2D45C1CFE6181943ca11C150C2bf61) |

**Via admin panel:** Deploy contracts → select Sepolia → "Use these addresses →". Done.

**Via env:**

```bash
ATTESTATION_INDEX=0x107D706112225aC57eCf6692FBbDC283fb6E3698
NODE_REGISTRY=0x6be4966596A9CBaa7260ab6EbbFFA69bBC9a42b7
RPC_URL=https://eth-sepolia.g.alchemy.com/v2/YOUR_KEY
CHAIN_ID=11155111
```

Once set, the admin panel shows an **On-chain** pill in the stack status bar, and "Publish to chain" batches your local WYRIWE records to `AttestationIndex`.

---

## Register your node

After setting `NODE_URL` and `NODE_REGISTRY`, click "Register on-chain" in the admin VNI panel. This calls `NodeRegistry.register(url, sig)` using your gateway key's EIP-191 signature — no ETH needed in the hot key (the relayer pays gas).

Your node then appears in the shared directory at:

```
cast call 0x6be4966596A9CBaa7260ab6EbbFFA69bBC9a42b7 \
  "getNode(address)(string,uint256)" YOUR_SIGNER_ADDRESS \
  --rpc-url https://eth-sepolia.g.alchemy.com/v2/YOUR_KEY
```

---

## Verify an attestation

```bash
# by inputHash — returns proofs from every namespace
curl https://your-node.example.com/verify/0xINPUT_HASH | jq

# OCP commitment hash
curl https://your-node.example.com/ocp/0xINPUT_HASH | jq
```

Response includes:
- EIP-191 proof with recovered signer
- EIP-712 `WyriweAttestation` with full struct
- On-chain fallback if the record isn't local but `ATTESTATION_INDEX` is configured

---

## Join the mesh

Add any node that implements `GET /records` to your peer list:

```bash
# via env
PEERS=https://gateway-b.example.com,https://gateway-c.example.com

# via admin panel — Peers section → add URL
```

Records sync every 5 minutes by default (`SYNC_INTERVAL`). Each node verifies signatures before inserting — a peer can't forge records on your behalf.

Auto-discovery is on by default: after syncing, nodes pull each peer's `/peers` list and add up to 10 new nodes per cycle. Disable with `AUTO_DISCOVER=false`.

---

## Key management

Generate a fresh gateway key:

```bash
cast wallet new
```

Or use the setup wizard / signing key panel in the admin dashboard — generates a key in-browser, saves to `config.json`, restarts the node.

Never use Hardhat dev keys (`0xac0974...`) outside local testing.

---

## Spec alignment

| Spec | What it does in ccip-router |
|---|---|
| [EIP-3668](https://eips.ethereum.org/EIPS/eip-3668) | CCIP-Read transport — `GET /{sender}/{data}.json` |
| [EIP-191](https://eips.ethereum.org/EIPS/eip-191) | Record signing on every resolver call |
| [EIP-712](https://eips.ethereum.org/EIPS/eip-712) | Structured `WyriweAttestation` signing via `withWyriwe()` |
| [WYRIWE](https://github.com/TMerlini/wyriwe) | Input provenance — triple-hash chain, sentinel / non-sentinel paths |
| [ERC-8004](https://github.com/ethereum/ERCs/pull/8004) | Agent identity — `agentId` + `registryAddress` in every attestation |
| [OCP / ERC-8263](https://github.com/damonzwicker/observation-commitment-protocol) | Observation commitment — `commitmentHash` anchored on-chain |
| VNI | Verifiable node identity — EIP-191 signed `{ nodeId, signerAddress, url }` |
| ERC-8275 | Contribution attribution — per-peer record counts at `GET /contributions` |

---

## Public API exports

```typescript
import {
  CcipRouter,           // core gateway class
  withWyriwe,           // attestation wrapper
  withEns,              // ENS resolve(bytes,bytes) decoder wrapper
  publishAttestation,   // push a record to AttestationIndex
  checkOnChain,         // query AttestationIndex by inputHash
  registerNode,         // call NodeRegistry.register()
  makeVni,              // produce a signed VNI document
  verifyVni,            // verify a VNI document
  encodeDnsName,        // DNS wire-format encoder
  decodeDnsName,        // DNS wire-format decoder
  ATTESTATION_INDEX_ABI,
  NODE_REGISTRY_ABI,
  WYRIWE_ATTESTATION_VERIFIER_ABI,
} from 'ccip-router'
```

---

*Built by [dinamic.eth](https://github.com/Echo-Merlini/ccip-router) · MIT license*
