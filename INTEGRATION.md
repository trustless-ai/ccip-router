# ccip-router — Integration Guide

*A practical companion to the Gateway Mesh Sync ERC. The ERC specifies the `/records` protocol (what a conformant node MUST do); this guide is the how-to of running `ccip-router` as a node and composing its signed records with the broader proof/anchor stack.*

**Spec:** [Gateway Mesh Sync Protocol for CCIP-Read](https://gist.github.com/TMerlini/a079a712ef078cbbb5668e48428c91ad) · **Package:** `npm i ccip-router` (`0.6.5`) · **Source:** `github.com/Echo-Merlini/ccip-router` · **Live:** 4-node mainnet mesh.

---

## 1. Run a node / join the mesh

> *Shell — to expand.*

```bash
npm i ccip-router        # or run the published image: ghcr.io/echo-merlini/ccip-router:latest
```

Minimum config (env): `NODE_URL` (your public URL), `RPC_URL`, `GATEWAY_PRIVATE_KEY` (the node's signing key), `PEERS` (seed peer URLs), optional `NODE_REGISTRY` (on-chain discovery). The node serves `GET /records`, `GET /peers`, `GET /vni`, and an admin UI; it polls peers on an interval and replicates the records it verifies.

- Register on-chain (optional, for permissionless discovery): the admin UI's **register** button signs `keccak256("ccip-router:node:" + url)` with your node key and calls `NodeRegistry.register(url, sig)` — the contract derives your identity from the signature (self-sovereign; no one registers you).
- Two-tier identity (when you need to rotate): keep a cold **identity key** that delegates a hot **signer key**; peers pin the identity key, so rotation is a fresh delegation, not a new `nodeId`. See the ERC's *Node identity and key rotation*.

## 2. Records: produce, sign, replicate

> *Shell — to expand.*

A record commits to `keccak256(abi.encodePacked(inputHash, namespace, valueHash, timestamp))`, EIP-191-signed by the node's signer. Peers verify the signature, deduplicate by content, and re-serve — `sourcePeer` carries the **originating** node across hops. Trust derives from the signature, never from who served it. (See the ERC's *Record commitment and signing* + *Test Vectors* for a live, recomputable example.)

## 3. Anchoring a record on ERC-8263

> **🖊 This section is owned by Vincent Wu (@TruthAnchor-AI) — stub for his text.**
>
> **Scope:** how to anchor a mesh record's `commitmentHash` as an **opaque `proofHash`** on ERC-8263 (`TruthAnchorV1`), giving each record an independent, recomputable on-chain `committed_at` — *without coupling the mesh-sync protocol to any anchor* (the ERC keeps anchoring out of the wire format on purpose; it composes here, in the integration layer).
>
> Suggested shape for the section (Vincent to write):
> - The composition: a node takes a record's `commitmentHash` and submits it as the opaque `proofHash` to the 8263 anchor; the anchor emits `AnchorProof(proofHash, committed_at)` with no interpretation of the value.
> - The interface used (`TruthAnchorV1` address + the `AnchorProof` event, `proofHash` as an indexed topic for O(1) lookup).
> - The recompute path: any party recovers the record from `/records`, recomputes `commitmentHash`, finds the anchor by `proofHash`, and reads `committed_at` from the block — no trust in the node, no trust in the anchor's content.
> - What it adds: a tamper-evident timestamp a record existed by a block time, outside the node's control — and why the mesh protocol deliberately leaves this to the anchor layer rather than baking it in.

## 4. Further composition (optional stubs)

> *Placeholders — add as the stack settles.*
- Input provenance (ERC-8281/OCP + ERC-8299/WYRIWE) — committing a record's `inputHash` pre-execution.
- Validation networks (ERC-8294) — a composing network's `verificationProfile` over anchored records.

## References

- **Gateway Mesh Sync ERC** — the `/records` protocol this guide implements.
- **ERC-8263** — the anchor used in §3.
- `ccip-router` source + npm; live mesh nodes.

---

*Authoring note: §3 is Vincent's to write — ping him when this shell is in the repo. Everything else is a scaffold to flesh out alongside it.*
